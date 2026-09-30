"""SQLite persistence: accounts, hashed API keys, credits ledger, execution
records and audit log. Schema is Postgres-compatible in spirit so V1 can move
to Neon/Supabase Postgres without redesign."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'free', created_at TEXT NOT NULL);
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


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sha256_hex(s: str | bytes) -> str:
    if isinstance(s, str):
        s = s.encode()
    return hashlib.sha256(s).hexdigest()


class InsufficientCredits(Exception):
    pass


class Store:
    def __init__(self, path: str = ":memory:"):
        self._lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL") if path != ":memory:" else None
        self.db.executescript(SCHEMA)

    # ---- accounts & keys
    def create_account(self, name: str, plan: str = "free") -> str:
        acc = "acct_" + uuid.uuid4().hex[:16]
        with self._lock:
            self.db.execute("INSERT INTO accounts VALUES (?,?,?,?)", (acc, name, plan, now_iso()))
        return acc

    def issue_key(self, account_id: str, scopes: list[str] | None = None, rate_per_min: int = 60) -> str:
        key_id = secrets.token_hex(4)
        secret = secrets.token_urlsafe(24)
        with self._lock:
            self.db.execute("INSERT INTO api_keys VALUES (?,?,?,?,?,?,NULL)",
                            (key_id, account_id, sha256_hex(secret), json.dumps(scopes or ["*"]),
                             rate_per_min, now_iso()))
        return f"ag_live_{key_id}_{secret}"

    def revoke_key(self, key_id: str):
        with self._lock:
            self.db.execute("UPDATE api_keys SET revoked_at=? WHERE id=?", (now_iso(), key_id))

    def authenticate(self, raw_key: str | None) -> dict | None:
        if not raw_key or not raw_key.startswith("ag_live_"):
            return None
        try:
            _, _, key_id, secret = raw_key.split("_", 3)
        except ValueError:
            return None
        with self._lock:
            row = self.db.execute("SELECT * FROM api_keys WHERE id=?", (key_id,)).fetchone()
        if not row or row["revoked_at"]:
            return None
        if not hmac.compare_digest(row["key_hash"], sha256_hex(secret)):
            return None
        return {"key_id": row["id"], "account_id": row["account_id"], "scopes": json.loads(row["scopes"]),
                "rate_per_min": row["rate_per_min"]}

    # ---- ledger
    def balance(self, account_id: str) -> int:
        with self._lock:
            r = self.db.execute("SELECT COALESCE(SUM(delta),0) b FROM ledger WHERE account_id=?",
                                (account_id,)).fetchone()
        return int(r["b"])

    def grant(self, account_id: str, credits: int, reason: str = "grant", request_id: str | None = None):
        with self._lock:
            self.db.execute("INSERT INTO ledger(account_id,delta,reason,request_id,created_at) VALUES (?,?,?,?,?)",
                            (account_id, credits, reason, request_id, now_iso()))

    def reserve(self, account_id: str, credits: int, request_id: str):
        """Atomically debit credits before execution (refunded on failure)."""
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                b = self.db.execute("SELECT COALESCE(SUM(delta),0) b FROM ledger WHERE account_id=?",
                                    (account_id,)).fetchone()["b"]
                if b < credits:
                    raise InsufficientCredits(f"balance {b} < required {credits}")
                self.db.execute("INSERT INTO ledger(account_id,delta,reason,request_id,created_at) "
                                "VALUES (?,?,?,?,?)", (account_id, -credits, "reserve", request_id, now_iso()))
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def ledger_entries(self, account_id: str) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self.db.execute(
                "SELECT delta,reason,request_id,created_at FROM ledger WHERE account_id=? ORDER BY id",
                (account_id,))]

    # ---- executions & audit
    def audit(self, request_id: str | None, event: str, detail: dict | None = None):
        with self._lock:
            self.db.execute("INSERT INTO audit_log(request_id,ts,event,detail_json) VALUES (?,?,?,?)",
                            (request_id, now_iso(), event, json.dumps(detail or {})))

    def audit_events(self, request_id: str) -> list[dict]:
        with self._lock:
            return [{"ts": r["ts"], "event": r["event"], "detail": json.loads(r["detail_json"])}
                    for r in self.db.execute("SELECT * FROM audit_log WHERE request_id=? ORDER BY id",
                                             (request_id,))]

    def save_execution(self, rec: dict):
        cols = ",".join(rec)
        with self._lock:
            self.db.execute(f"INSERT INTO executions({cols}) VALUES ({','.join('?' * len(rec))})",
                            tuple(rec.values()))

    def get_execution(self, request_id: str) -> dict | None:
        with self._lock:
            r = self.db.execute("SELECT * FROM executions WHERE request_id=?", (request_id,)).fetchone()
        return dict(r) if r else None

    def capability_health(self, capability: str, window: int = 50) -> dict:
        with self._lock:
            rows = self.db.execute("SELECT status, error_code, duration_ms FROM executions WHERE capability=? "
                                   "ORDER BY created_at DESC LIMIT ?", (capability, window)).fetchall()
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
        with self._lock:
            cur = self.db.execute("UPDATE executions SET result_json=NULL WHERE created_at < ?", (cutoff,))
        return cur.rowcount
