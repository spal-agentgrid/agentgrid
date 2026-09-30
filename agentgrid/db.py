"""Database backends for the Store: SQLite (default, stdlib) and Postgres
(optional, via the pure-Python ``pg8000`` driver when ``DATABASE_URL`` is set).

Both backends expose the same tiny interface. SQL is written once with ``?``
placeholders; the Postgres backend rewrites them to pg8000 named parameters.
Callers serialise access with the Store's lock (one connection per process)."""
from __future__ import annotations

import re
import sqlite3
import ssl
from urllib.parse import parse_qs, unquote, urlsplit


class IntegrityError(Exception):
    """Unique/foreign-key violation, normalised across backends."""


class SQLiteBackend:
    name = "sqlite"

    def __init__(self, path: str = ":memory:"):
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")

    def query(self, sql: str, params=()) -> list[dict]:
        try:
            return [dict(r) for r in self.conn.execute(sql, tuple(params))]
        except sqlite3.IntegrityError as exc:
            raise IntegrityError(str(exc)) from exc

    def execute(self, sql: str, params=()) -> int:
        try:
            return self.conn.execute(sql, tuple(params)).rowcount
        except sqlite3.IntegrityError as exc:
            raise IntegrityError(str(exc)) from exc

    def script(self, sql: str):
        self.conn.executescript(sql)

    def begin(self, lock_key: str | None = None):
        self.conn.execute("BEGIN IMMEDIATE")

    def commit(self):
        self.conn.execute("COMMIT")

    def rollback(self):
        self.conn.execute("ROLLBACK")

    def has_column(self, table: str, column: str) -> bool:
        return any(r["name"] == column for r in self.query(f"PRAGMA table_info({table})"))

    def close(self):
        self.conn.close()


_QMARK = re.compile(r"\?")


def parse_database_url(url: str) -> dict:
    """postgres[ql]://user:pass@host:port/db?sslmode=require -> pg8000 kwargs."""
    u = urlsplit(url)
    if u.scheme not in ("postgres", "postgresql"):
        raise ValueError("DATABASE_URL must start with postgres:// or postgresql://")
    q = {k: v[-1] for k, v in parse_qs(u.query).items()}
    host = u.hostname or "localhost"
    kw = {"user": unquote(u.username or ""), "password": unquote(u.password) if u.password else None,
          "host": host, "port": u.port or 5432, "database": unquote(u.path.lstrip("/")) or None,
          "application_name": "agentgrid", "timeout": 30}
    sslmode = q.get("sslmode") or ("disable" if host in ("localhost", "127.0.0.1", "::1") else "require")
    if sslmode in ("require", "verify-ca", "verify-full"):
        ctx = ssl.create_default_context()
        kw["ssl_context"] = ctx
    elif sslmode not in ("disable", "allow", "prefer"):
        raise ValueError(f"unsupported sslmode '{sslmode}'")
    if q.get("options"):  # e.g. Neon "endpoint=<id>" for clients without SNI
        kw["startup_params"] = {"options": q["options"]}
    return kw


class PostgresBackend:
    name = "postgres"

    def __init__(self, url: str):
        try:
            import pg8000.native  # noqa: F401  (optional dependency)
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise RuntimeError("DATABASE_URL is set but the 'pg8000' package is not installed "
                               "(pip install -r requirements.txt)") from exc
        self._kw = parse_database_url(url)
        self._in_tx = False
        self.conn = self._connect()

    def _connect(self):
        import pg8000.native
        return pg8000.native.Connection(**self._kw)

    @staticmethod
    def _convert(sql: str, params) -> tuple[str, dict]:
        params = tuple(params)
        counter = iter(range(len(params)))
        sql = _QMARK.sub(lambda _m: f":p{next(counter)}", sql)
        return sql, {f"p{i}": v for i, v in enumerate(params)}

    def _run(self, sql: str, params=()):
        import pg8000.exceptions as pgx
        q, kw = self._convert(sql, params)
        for attempt in (0, 1):
            try:
                rows = self.conn.run(q, **kw)
                return rows, self.conn.columns, self.conn.row_count
            except pgx.DatabaseError as exc:
                code = exc.args[0].get("C") if exc.args and isinstance(exc.args[0], dict) else None
                if code in ("23505", "23503"):
                    raise IntegrityError(str(exc)) from exc
                raise
            except (pgx.InterfaceError, OSError):
                # Connection dropped (e.g. Neon scale-to-zero). Reconnect once,
                # but never silently inside a transaction.
                if attempt or self._in_tx:
                    raise
                self.conn = self._connect()

    def query(self, sql: str, params=()) -> list[dict]:
        rows, cols, _ = self._run(sql, params)
        names = [c["name"] for c in (cols or [])]
        return [dict(zip(names, r)) for r in (rows or [])]

    def execute(self, sql: str, params=()) -> int:
        return self._run(sql, params)[2]

    def script(self, sql: str):
        for stmt in (s.strip() for s in sql.split(";")):
            if stmt:
                self._run(stmt)

    def begin(self, lock_key: str | None = None):
        self._run("BEGIN")
        self._in_tx = True
        if lock_key:  # serialise per-account ledger writes across processes
            self._run("SELECT pg_advisory_xact_lock(hashtext(?))", (lock_key,))

    def commit(self):
        try:
            self._run("COMMIT")
        finally:
            self._in_tx = False

    def rollback(self):
        try:
            self._run("ROLLBACK")
        finally:
            self._in_tx = False

    def has_column(self, table: str, column: str) -> bool:
        return bool(self.query("SELECT 1 FROM information_schema.columns WHERE table_name=? AND column_name=?",
                               (table, column)))

    def close(self):
        self.conn.close()


def open_backend(path: str = ":memory:", database_url: str | None = None):
    return PostgresBackend(database_url) if database_url else SQLiteBackend(path)
