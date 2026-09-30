"""Execution pipeline shared by the REST API and the MCP server:
auth -> scope -> validate -> rate limit -> reserve credits -> run -> verify/sign
-> settle or refund -> execution record + audit log."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from urllib.parse import urlsplit

from . import registry
from .ratelimit import RateLimiter
from .siteqa import AuditError, canonical_json
from .store import InsufficientCredits, Store, now_iso, sha256_hex

# Cost model constants used to turn *measured* resources into a USD estimate.
# They are ESTIMATES (see decision/first-capability.md), tuned to the paid tier
# we would move to first, so the figure is conservative even on free tiers.
USD_PER_CPU_SECOND = 0.00002     # est. ~4x Render Starter ($7/mo, 0.5 CPU) per CPU-second
USD_PER_GB_TRANSFER = 0.15       # Render bandwidth overage rate
USD_PER_RECORD = 0.000001        # est. Postgres storage/IO per execution record

ERROR_HTTP = {
    "INVALID_INPUT": 400, "UNAUTHORIZED": 401, "INSUFFICIENT_CREDITS": 402, "FORBIDDEN_SCOPE": 403,
    "CAPABILITY_NOT_FOUND": 404, "TARGET_NOT_ALLOWED": 422, "RATE_LIMITED": 429, "INTERNAL": 500,
    "TARGET_UNREACHABLE": 502, "TARGET_TIMEOUT": 504,
}
RETRYABLE = {"RATE_LIMITED", "TARGET_UNREACHABLE", "TARGET_TIMEOUT", "INTERNAL"}


def error_body(code: str, message: str, request_id: str | None, details=None, retry_after=None) -> dict:
    err = {"code": code, "message": message, "retryable": code in RETRYABLE, "request_id": request_id}
    if details:
        err["details"] = details
    if retry_after is not None:
        err["retry_after_s"] = round(retry_after, 2)
    return {"error": err}


class Service:
    def __init__(self, store: Store, signing_secret: str | None = None, allow_private_targets: bool = False):
        self.store = store
        self.limiter = RateLimiter()
        self.secret = (signing_secret or os.environ.get("AGENTGRID_SIGNING_SECRET") or "dev-only-secret").encode()
        self.allow_private = allow_private_targets

    def sign(self, request_id: str, evidence_hash: str) -> str:
        return "hmac-sha256:" + hmac.new(self.secret, f"{request_id}.{evidence_hash}".encode(),
                                         hashlib.sha256).hexdigest()

    def verify(self, request_id: str) -> dict:
        rec = self.store.get_execution(request_id)
        if not rec or not rec["result_json"]:
            return {"request_id": request_id, "valid": False, "reason": "not_found_or_expired"}
        result = json.loads(rec["result_json"])
        recomputed = "sha256:" + hashlib.sha256(canonical_json(result["findings"]).encode()).hexdigest()
        ok = (recomputed == rec["evidence_hash"]
              and hmac.compare_digest(self.sign(request_id, recomputed), rec["signature"] or ""))
        return {"request_id": request_id, "valid": ok, "evidence_hash": recomputed}

    def execute(self, key: dict | None, capability: str, params, request_id: str | None = None) -> tuple[int, dict]:
        rid = request_id or "req_" + uuid.uuid4().hex[:24]
        st = self.store
        st.audit(rid, "request.received", {"capability": capability, "key_id": key and key["key_id"]})
        if key is None:
            st.audit(rid, "auth.failed")
            return 401, error_body("UNAUTHORIZED", "missing or invalid API key", rid)
        cap = registry.CAPABILITIES.get(capability)
        if not cap:
            return 404, error_body("CAPABILITY_NOT_FOUND", f"unknown capability '{capability}'", rid)
        if "*" not in key["scopes"] and f"capability:{capability}" not in key["scopes"]:
            st.audit(rid, "auth.scope_denied")
            return 403, error_body("FORBIDDEN_SCOPE", "API key lacks scope for this capability", rid)
        ok, retry = self.limiter.allow(key["key_id"], key["rate_per_min"])
        if not ok:
            st.audit(rid, "rate_limited", {"retry_after_s": retry})
            return 429, error_body("RATE_LIMITED", "rate limit exceeded", rid, retry_after=retry)
        try:
            clean = registry.validate(cap["input_schema"], params)
        except registry.ValidationError as exc:
            st.audit(rid, "input.invalid", {"errors": exc.errors})
            return 400, error_body("INVALID_INPUT", "input failed validation", rid, details=exc.errors)

        cost = cap["credits_per_call"]
        acct = key["account_id"]
        try:
            st.reserve(acct, cost, rid)
        except InsufficientCredits as exc:
            st.audit(rid, "credits.insufficient", {"required": cost})
            return 402, error_body("INSUFFICIENT_CREDITS", str(exc), rid)
        st.audit(rid, "credits.reserved", {"credits": cost})

        t0, c0 = time.monotonic(), time.thread_time()
        status, http_status, result, err_code, err_msg = "succeeded", 200, None, None, None
        try:
            result = cap["handler"](clean, allow_private=self.allow_private)
        except AuditError as exc:
            status, err_code, err_msg = "failed", exc.code, exc.message
        except Exception as exc:  # noqa: BLE001 - never leak internals, always record
            status, err_code, err_msg = "failed", "INTERNAL", f"{type(exc).__name__}"
        duration_ms = int((time.monotonic() - t0) * 1000)
        cpu_ms = (time.thread_time() - c0) * 1000
        meta = (result or {}).pop("_meta", {}) if result else {}
        bytes_in = meta.get("bytes_in", 0)
        infra_cost = cpu_ms / 1000 * USD_PER_CPU_SECOND + bytes_in / 1e9 * USD_PER_GB_TRANSFER + USD_PER_RECORD

        if status == "succeeded":
            billable, charged = 1, cost
            evidence = result["verification"]["evidence_hash"]
            sig = self.sign(rid, evidence)
            result = {"request_id": rid, **result}
            result["verification"]["signature"] = sig
            result["usage"] = {"billable_units": billable, "credits_charged": charged,
                               "links_checked": meta.get("links_checked", 0), "duration_ms": duration_ms}
            verification_result = "evidence_hash_signed"
            st.audit(rid, "execution.succeeded", {"verdict": result["verdict"], "counts": result["counts"]})
            body = result
        else:
            billable, charged, evidence, sig, verification_result = 0, 0, None, None, "not_applicable"
            st.grant(acct, cost, reason="refund", request_id=rid)
            st.audit(rid, "credits.refunded", {"credits": cost, "error": err_code})
            http_status = ERROR_HTTP.get(err_code, 500)
            body = error_body(err_code, err_msg, rid)

        target_host = urlsplit(clean.get("url", "")).hostname
        st.save_execution({
            "request_id": rid, "created_at": now_iso(), "account_id": acct, "api_key_id": key["key_id"],
            "capability": capability, "capability_version": cap["version"], "status": status,
            "http_status": http_status, "input_hash": "sha256:" + sha256_hex(canonical_json(clean)),
            "target_host": target_host, "duration_ms": duration_ms, "cpu_ms": round(cpu_ms, 2),
            "bytes_in": bytes_in, "measured_infra_cost_usd": round(infra_cost, 8), "billable_units": billable,
            "credits_charged": charged, "verification_result": verification_result, "evidence_hash": evidence,
            "signature": sig, "error_code": err_code, "error_message": err_msg,
            "result_json": json.dumps(result) if status == "succeeded" else None,
        })
        st.audit(rid, "execution.recorded", {"status": status, "credits_charged": charged})
        return http_status, body

    def execution_record(self, key: dict, request_id: str) -> dict | None:
        rec = self.store.get_execution(request_id)
        if not rec or rec["account_id"] != key["account_id"]:
            return None
        out = {k: v for k, v in rec.items() if k != "result_json"}
        out["audit_log"] = self.store.audit_events(request_id)
        return out
