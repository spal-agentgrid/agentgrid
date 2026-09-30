"""Self-serve signup and the admin API (account listing, credit grants)."""
from __future__ import annotations

import hmac
import os
import re

from .ratelimit import RateLimiter
from .store import EmailAlreadyRegistered, Store

MAX_EMAIL_LEN = 254
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}")


def normalize_email(value) -> str | None:
    """Returns the normalised address (domain lower-cased; whole address lower-cased
    for uniqueness) or None if it is not a plausible email address."""
    if not isinstance(value, str):
        return None
    email = value.strip()
    if not email or len(email) > MAX_EMAIL_LEN or not _EMAIL_RE.fullmatch(email):
        return None
    local, _, domain = email.rpartition("@")
    if len(local) > 64:
        return None
    return f"{local}@{domain}".lower()


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


class Accounts:
    def __init__(self, store: Store, admin_token: str | None = None, signup_credits: int | None = None,
                 signup_per_ip_per_hour: int | None = None, signup_global_per_hour: int | None = None,
                 signup_enabled: bool | None = None):
        self.store = store
        self.admin_token = admin_token if admin_token is not None else os.environ.get("AGENTGRID_ADMIN_TOKEN", "")
        self.signup_credits = (signup_credits if signup_credits is not None
                               else _env_int("AGENTGRID_SIGNUP_CREDITS", 100))
        self.per_ip = (signup_per_ip_per_hour if signup_per_ip_per_hour is not None
                       else _env_int("AGENTGRID_SIGNUP_PER_IP_PER_HOUR", 5))
        self.global_per_hour = (signup_global_per_hour if signup_global_per_hour is not None
                                else _env_int("AGENTGRID_SIGNUP_GLOBAL_PER_HOUR", 200))
        self.signup_enabled = (signup_enabled if signup_enabled is not None
                               else os.environ.get("AGENTGRID_SIGNUP_ENABLED", "1") != "0")
        self.limiter = RateLimiter()

    # ---- signup
    def signup(self, body, client_ip: str) -> tuple[int, dict, float | None]:
        """Returns (http_status, body, retry_after_s)."""
        from .service import error_body
        if not self.signup_enabled:
            return 403, error_body("SIGNUP_DISABLED", "self-serve signup is disabled", None), None
        ok, retry = self.limiter.allow_window(f"signup:ip:{client_ip}", self.per_ip, 3600.0)
        if ok:
            ok, retry = self.limiter.allow_window("signup:global", self.global_per_hour, 3600.0)
        if not ok:
            return 429, error_body("RATE_LIMITED", "too many signups, try again later", None,
                                   retry_after=retry), retry
        email = normalize_email(body.get("email") if isinstance(body, dict) else None)
        if email is None:
            return 400, error_body("INVALID_INPUT", "a valid 'email' is required", None,
                                   details=[{"path": "email", "error": "invalid email address"}]), None
        try:
            acct, key = self.store.signup(email, self.signup_credits)
        except EmailAlreadyRegistered:
            return 409, error_body("EMAIL_ALREADY_REGISTERED",
                                   "an account with this email already exists", None), None
        self.store.audit(None, "account.signup", {"account_id": acct})
        return 201, {"account_id": acct, "email": email, "api_key": key,
                     "credits_granted": self.signup_credits,
                     "note": "Store this API key now: it is shown only once and stored hashed on our side."}, None

    # ---- admin
    def admin_authorized(self, auth_header: str | None) -> bool:
        if not self.admin_token:
            return False
        if not auth_header or not auth_header.lower().startswith("bearer "):
            return False
        return hmac.compare_digest(auth_header[7:].strip().encode(), self.admin_token.encode())

    def admin_list(self, query: dict) -> tuple[int, dict]:
        from .service import error_body
        try:
            limit = int(query.get("limit", 50))
            offset = int(query.get("offset", 0))
        except ValueError:
            return 400, error_body("INVALID_INPUT", "limit/offset must be integers", None)
        limit, offset = max(1, min(limit, 500)), max(0, offset)
        accounts = self.store.list_accounts(limit, offset)
        for a in accounts:
            a["balance_credits"] = int(a["balance_credits"])
            a["active_keys"] = int(a["active_keys"])
        return 200, {"total": self.store.count_accounts(), "limit": limit, "offset": offset,
                     "accounts": accounts}

    def admin_grant(self, account_id: str, body) -> tuple[int, dict]:
        from .service import error_body
        if not isinstance(body, dict):
            return 400, error_body("INVALID_INPUT", "JSON object body required", None)
        credits = body.get("credits")
        reason = body.get("reason", "admin_grant")
        if (not isinstance(credits, int) or isinstance(credits, bool) or credits == 0
                or abs(credits) > 1_000_000):
            return 400, error_body("INVALID_INPUT", "'credits' must be a non-zero integer (|credits| <= 1000000)",
                                   None)
        if not isinstance(reason, str) or not (1 <= len(reason) <= 100):
            return 400, error_body("INVALID_INPUT", "'reason' must be a string of 1-100 characters", None)
        if not self.store.get_account(account_id):
            return 404, error_body("NOT_FOUND", "account not found", None)
        self.store.grant(account_id, credits, reason=f"admin:{reason}")
        self.store.audit(None, "admin.grant", {"account_id": account_id, "credits": credits, "reason": reason})
        return 200, {"account_id": account_id, "granted": credits, "balance_credits": self.store.balance(account_id)}
