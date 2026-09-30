"""Persistence: accounts, hashed API keys, credits ledger, execution records and
audit log. SQLite by default; Postgres (e.g. Neon) when a DATABASE_URL is given
(see ``agentgrid/db.py``). The same SQL runs on both backends."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from .db import IntegrityError, open_backend

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'free', created_at TEXT NOT NULL,
  email TEXT);
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), key_hash TEXT NOT NULL,
  scopes TEXT NOT NULL, rate_per_min INTEGER NOT NULL DEFAULT 60, created_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE IF NOT EXISTS ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT, account_id TEXT NOT NULL REFERENCES accounts(id),
  delta INTEGER NOT NULL, reason TEXT NOT NULL, request_id TEXT, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ledger_account ON ledger(account_id);
CREATE TABLE IF NOT EXISTS executions (
  request_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, account_id TEXT NOT NULL, api_key_id TEXT,
  capability TEXT NOT NULL, capability_version TEXT NOT NULL, status TEXT NOT NULL, http_status INTEGER,
  input_hash TEXT, target_host TEXT, duration_ms INTEGER, cpu_ms REAL, bytes_in INTEGER,
  measured_infra_cost_usd REAL, billable_units INTEGER NOT NULL DEFAULT 0,
  credits_charged INTEGER NOT NULL DEFAULT 0, verification_result TEXT, evidence_hash TEXT,
  signature TEXT, error_code TEXT, error_message TEXT, result_json TEXT);
CREATE INDEX IF NOT EXISTS exec_account ON executions(account_id, created_at);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT, ts TEXT NOT NULL, event TEXT NOT NULL,
  detail_json TEXT);
CREATE INDEX IF NOT EXISTS audit_req ON audit_log(request_id);
"""
# Applied after SCHEMA, so older databases (created before the column existed) get migrated first.
POST_MIGRATION = "CREATE UNIQUE INDEX IF NOT EXISTS accounts_email ON accounts(email)"


def schema_for(backend_name: str) -> str:
    if backend_name == "postgres":
        return (SCHEMA.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
                .replace(" REAL", " DOUBLE PRECISION"))
    return SCHEMA


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sha256_hex(s: str | bytes) -> str:
    if isinstance(s, str):
        s = s.encode()
    return hashlib.sha256(s).hexdigest()


class InsufficientCredits(Exception):
    pass


class EmailAlreadyRegistered(Exception):
    pass


class Store:
    def __init__(self, path: str = ":memory:", database_url: str | None = None):
        self._lock = threading.RLock()
        self.backend = open_backend(path, database_url)
        self.backend_name = self.backend.name
        with self._lock:
            self.backend.script(schema_for(self.backend_name))
            if not self.backend.has_column("accounts", "email"):
                self.backend.execute("ALTER TABLE accounts ADD COLUMN email TEXT")
            self.backend.execute(POST_MIGRATION)

    # ---- low-level helpers (all DB access goes through the lock)
    def query(self, sql: str, params=()) -> list[dict]:
        with self._lock:
            return self.backend.query(sql, params)

    def execute(self, sql: str, params=()) -> int:
        with self._lock:
            return self.backend.execute(sql, params)

    def _one(self, sql: str, params=()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    @contextmanager
    def transaction(self, lock_key: str | None = None):
        with self._lock:
            self.backend.begin(lock_key)
            try:
                yield
            except BaseException:
                self.backend.rollback()
                raise
            self.backend.commit()

    # ---- accounts & keys
    def create_account(self, name: str, plan: str = "free", email: str | None = None) -> str:
        acc = "acct_" + uuid.uuid4().hex[:16]
        try:
            self.execute("INSERT INTO accounts(id,name,plan,created_at,email) VALUES (?,?,?,?,?)",
                         (acc, name, plan, now_iso(), email))
        except IntegrityError as exc:
            raise EmailAlreadyRegistered(email) from exc
        return acc

    def get_account(self, account_id: str) -> dict | None:
        return self._one("SELECT id,name,plan,created_at,email FROM accounts WHERE id=?", (account_id,))

    def account_by_email(self, email: str) -> dict | None:
        return self._one("SELECT id,name,plan,created_at,email FROM accounts WHERE email=?", (email,))

    def signup(self, email: str, credits: int) -> tuple[str, str]:
        """Create account + key + free-tier grant atomically. Returns (account_id, raw_key)."""
        with self.transaction():
            if self.account_by_email(email):
                raise EmailAlreadyRegistered(email)
            acct = self.create_account(email.split("@", 1)[0][:64] or "user", email=email)
            key = self.issue_key(acct)
            if credits:
                self.grant(acct, credits, reason="signup_free_tier")
        return acct, key

    def list_accounts(self, limit: int = 50, offset: int = 0) -> list[dict]:
        return self.query(
            "SELECT a.id, a.email, a.name, a.plan, a.created_at, "
            "(SELECT COALESCE(SUM(l.delta),0) FROM ledger l WHERE l.account_id=a.id) AS balance_credits, "
            "(SELECT COUNT(*) FROM api_keys k WHERE k.account_id=a.id AND k.revoked_at IS NULL) AS active_keys "
            "FROM accounts a ORDER BY a.created_at DESC, a.id LIMIT ? OFFSET ?", (limit, offset))

    def count_accounts(self) -> int:
        return int(self._one("SELECT COUNT(*) AS n FROM accounts")["n"])

    def issue_key(self, account_id: str, scopes: list[str] | None = None, rate_per_min: int = 60) -> str:
        """Returns the raw key once. Only a SHA-256 hash of the 192-bit random secret is stored."""
        key_id = secrets.token_hex(4)
        secret = secrets.token_urlsafe(24)
        self.execute("INSERT INTO api_keys(id,account_id,key_hash,scopes,rate_per_min,created_at,revoked_at) "
                     "VALUES (?,?,?,?,?,?,NULL)",
                     (key_id, account_id, sha256_hex(secret), json.dumps(scopes or ["*"]), rate_per_min, now_iso()))
        return f"ag_live_{key_id}_{secret}"

    def revoke_key(self, key_id: str):
        self.execute("UPDATE api_keys SET revoked_at=? WHERE id=?", (now_iso(), key_id))

    def authenticate(self, raw_key: str | None) -> dict | None:
        if not raw_key or not raw_key.startswith("ag_live_"):
            return None
        try:
            _, _, key_id, secret = raw_key.split("_", 3)
        except ValueError:
            return None
        row = self._one("SELECT * FROM api_keys WHERE id=?", (key_id,))
        if not row or row["revoked_at"]:
            return None
        if not hmac.compare_digest(row["key_hash"], sha256_hex(secret)):
            return None
        return {"key_id": row["id"], "account_id": row["account_id"], "scopes": json.loads(row["scopes"]),
                "rate_per_min": row["rate_per_min"]}

    # ---- ledger
    def balance(self, account_id: str) -> int:
        r = self._one("SELECT COALESCE(SUM(delta),0) AS b FROM ledger WHERE account_id=?", (account_id,))
        return int(r["b"])

    def grant(self, account_id: str, credits: int, reason: str = "grant", request_id: str | None = None):
        self.execute("INSERT INTO ledger(account_id,delta,reason,request_id,created_at) VALUES (?,?,?,?,?)",
                     (account_id, credits, reason, request_id, now_iso()))

    def reserve(self, account_id: str, credits: int, request_id: str):
        """Atomically debit credits before execution (refunded on failure)."""
        with self.transaction(lock_key=account_id):
            b = self.balance(account_id)
            if b < credits:
                raise InsufficientCredits(f"balance {b} < required {credits}")
            self.execute("INSERT INTO ledger(account_id,delta,reason,request_id,created_at) VALUES (?,?,?,?,?)",
                         (account_id, -credits, "reserve", request_id, now_iso()))

    def ledger_entries(self, account_id: str) -> list[dict]:
        return self.query("SELECT delta,reason,request_id,created_at FROM ledger WHERE account_id=? ORDER BY id",
                          (account_id,))

    # ---- executions & audit
    def audit(self, request_id: str | None, event: str, detail: dict | None = None):
        self.execute("INSERT INTO audit_log(request_id,ts,event,detail_json) VALUES (?,?,?,?)",
                     (request_id, now_iso(), event, json.dumps(detail or {})))

    def audit_events(self, request_id: str) -> list[dict]:
        return [{"ts": r["ts"], "event": r["event"], "detail": json.loads(r["detail_json"])}
                for r in self.query("SELECT * FROM audit_log WHERE request_id=? ORDER BY id", (request_id,))]

    def save_execution(self, rec: dict):
        cols = ",".join(rec)
        self.execute(f"INSERT INTO executions({cols}) VALUES ({','.join('?' * len(rec))})", tuple(rec.values()))

    def get_execution(self, request_id: str) -> dict | None:
        return self._one("SELECT * FROM executions WHERE request_id=?", (request_id,))

    def capability_health(self, capability: str, window: int = 50) -> dict:
        rows = self.query("SELECT status, error_code, duration_ms FROM executions WHERE capability=? "
                          "ORDER BY created_at DESC LIMIT ?", (capability, window))
        if not rows:
            return {"status": "unknown", "sample_size": 0}
        # Target-side failures (unreachable/timeout/not allowed) are not our outages.
        ours = [r for r in rows if r["error_code"] in ("INTERNAL",)]
        ok_ratio = 1 - len(ours) / len(rows)
        durs = sorted(r["duration_ms"] or 0 for r in rows)
        return {"status": "healthy" if ok_ratio >= 0.99 else ("degraded" if ok_ratio >= 0.9 else "down"),
                "sample_size": len(rows), "internal_error_ratio": round(1 - ok_ratio, 4),
                "p50_ms": durs[len(durs) // 2], "p95_ms": durs[min(len(durs) - 1, int(len(durs) * 0.95))]}

    def purge_older_than(self, days: int) -> int:
        cutoff = datetime.fromtimestamp(time.time() - days * 86400, timezone.utc).isoformat()
        return self.execute("UPDATE executions SET result_json=NULL WHERE created_at < ?", (cutoff,))
