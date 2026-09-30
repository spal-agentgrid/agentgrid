"""HTTP API gateway (stdlib). Routes:

GET  /healthz                            liveness probe (no DB access; for load balancers)
GET  /v1/health                         service + per-capability health
GET  /v1/capabilities                   registry listing (public)
GET  /v1/capabilities/{name}            one capability spec (public)
POST /v1/capabilities/{name}/run        execute (auth, metered)
GET  /v1/executions/{request_id}        execution record + audit log (auth)
GET  /v1/executions/{request_id}/verify recompute evidence hash + signature (auth)
GET  /v1/account                        balance + ledger (auth)
POST /v1/signup                         self-serve signup: email -> one-time API key + free credits
POST /mcp                               MCP JSON-RPC (auth for tools/call)
GET  /v1/admin/accounts                 list accounts (admin bearer token)
POST /v1/admin/accounts/{id}/credits    grant (or deduct) credits (admin bearer token)
GET  /v1/admin/request-info             shows the derived client IP (admin; for proxy tuning)
"""
from __future__ import annotations

import argparse
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl

from . import __version__, mcp, registry
from .service import Service, error_body
from .store import Store

MAX_REQUEST_BYTES = 64 * 1024
ADMIN_ACCOUNT_CREDITS = re.compile(r"/v1/admin/accounts/(acct_[a-f0-9]{1,64})/credits")


def trusted_proxy_hops() -> int:
    try:
        return max(0, int(os.environ.get("AGENTGRID_TRUSTED_PROXY_HOPS", "0")))
    except ValueError:
        return 0


def make_handler(service: Service):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AgentGrid/" + __version__
        sys_version = ""

        def log_message(self, fmt, *args):  # structured logs go to the audit table instead
            if os.environ.get("AGENTGRID_ACCESS_LOG"):
                super().log_message(fmt, *args)

        def _send(self, status: int, body: dict, extra_headers: dict | None = None):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            rid = body.get("request_id") or (body.get("error") or {}).get("request_id")
            if rid:
                self.send_header("X-Request-Id", rid)
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _key(self):
            auth = self.headers.get("Authorization", "")
            raw = auth[7:].strip() if auth.lower().startswith("bearer ") else self.headers.get("X-API-Key")
            return service.store.authenticate(raw)

        def _client_ip(self) -> str:
            """Socket peer, or the N-th entry from the right of X-Forwarded-For when
            AGENTGRID_TRUSTED_PROXY_HOPS=N (entries appended by our own proxies)."""
            hops = trusted_proxy_hops()
            if hops:
                xff = [p.strip() for p in (self.headers.get("X-Forwarded-For") or "").split(",") if p.strip()]
                if len(xff) >= hops:
                    return xff[-hops]
            return self.client_address[0]

        def _admin_guard(self):
            """Returns None if authorised, else sends the error response and returns True."""
            acc = service.accounts
            if not acc.admin_token:
                self._send(404, error_body("NOT_FOUND", "no such route", None))
                return True
            if acc.admin_authorized(self.headers.get("Authorization")):
                return None
            ok, retry = acc.limiter.allow_window(f"admin_fail:{self._client_ip()}", 20, 60.0)
            if not ok:
                self._send(429, error_body("RATE_LIMITED", "too many failed admin attempts", None,
                                           retry_after=retry), {"Retry-After": str(int(retry) + 1)})
                return True
            self._send(401, error_body("UNAUTHORIZED", "missing or invalid admin token", None),
                       {"WWW-Authenticate": "Bearer"})
            return True

        def _json_body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_REQUEST_BYTES:
                raise ValueError("request body too large")
            raw = self.rfile.read(n) if n else b""
            return json.loads(raw or b"{}")

        def do_GET(self):
            path = self.path.split("?")[0].rstrip("/")
            if path == "/healthz":
                return self._send(200, {"status": "ok", "version": __version__})
            if path == "/v1/health":
                caps = {n: service.store.capability_health(n) for n in registry.CAPABILITIES}
                return self._send(200, {"status": "ok", "version": __version__,
                                        "storage": service.store.backend_name, "capabilities": caps})
            if path.startswith("/v1/admin/"):
                if self._admin_guard():
                    return
                if path == "/v1/admin/accounts":
                    query = dict(parse_qsl(self.path.partition("?")[2]))
                    return self._send(*service.accounts.admin_list(query))
                if path == "/v1/admin/request-info":
                    return self._send(200, {"client_ip": self._client_ip(), "peer": self.client_address[0],
                                            "x_forwarded_for": self.headers.get("X-Forwarded-For"),
                                            "trusted_proxy_hops": trusted_proxy_hops()})
                return self._send(404, error_body("NOT_FOUND", "no such route", None))
            if path == "/v1/capabilities":
                return self._send(200, {"capabilities": [registry.public_view(c)
                                                         for c in registry.CAPABILITIES.values()]})
            m = re.fullmatch(r"/v1/capabilities/([a-z0-9_.-]+)", path)
            if m:
                cap = registry.CAPABILITIES.get(m.group(1))
                if not cap:
                    return self._send(404, error_body("CAPABILITY_NOT_FOUND", "unknown capability", None))
                return self._send(200, registry.public_view(cap))
            key = self._key()
            if key is None:
                return self._send(401, error_body("UNAUTHORIZED", "missing or invalid API key", None))
            m = re.fullmatch(r"/v1/executions/(req_[a-f0-9]+)(/verify)?", path)
            if m:
                if m.group(2):
                    rec = service.execution_record(key, m.group(1))
                    if not rec:
                        return self._send(404, error_body("NOT_FOUND", "execution not found", None))
                    return self._send(200, service.verify(m.group(1)))
                rec = service.execution_record(key, m.group(1))
                if not rec:
                    return self._send(404, error_body("NOT_FOUND", "execution not found", None))
                return self._send(200, rec)
            if path == "/v1/account":
                acct = key["account_id"]
                return self._send(200, {"account_id": acct, "balance_credits": service.store.balance(acct),
                                        "ledger": service.store.ledger_entries(acct)[-50:]})
            return self._send(404, error_body("NOT_FOUND", "no such route", None))

        def do_POST(self):
            path = self.path.split("?")[0].rstrip("/")
            try:
                body = self._json_body()
            except (ValueError, json.JSONDecodeError) as exc:
                return self._send(400, error_body("INVALID_INPUT", f"invalid JSON body: {exc}", None))
            if path == "/v1/signup":
                status, out, retry = service.accounts.signup(body, self._client_ip())
                return self._send(status, out, {"Retry-After": str(int(retry) + 1)} if retry else None)
            if path.startswith("/v1/admin/"):
                if self._admin_guard():
                    return
                m = ADMIN_ACCOUNT_CREDITS.fullmatch(path)
                if m:
                    return self._send(*service.accounts.admin_grant(m.group(1), body))
                return self._send(404, error_body("NOT_FOUND", "no such route", None))
            m = re.fullmatch(r"/v1/capabilities/([a-z0-9_.-]+)/run", path)
            if m:
                status, out = service.execute(self._key(), m.group(1), body)
                headers = {}
                if status == 429:
                    headers["Retry-After"] = str(int(out["error"].get("retry_after_s", 1)) + 1)
                return self._send(status, out, headers)
            if path == "/mcp":
                key = self._key()
                if not isinstance(body, dict):
                    return self._send(400, {"jsonrpc": "2.0", "id": None,
                                            "error": {"code": -32600, "message": "batch not supported"}})
                if body.get("method") == "tools/call" and key is None:
                    return self._send(401, {"jsonrpc": "2.0", "id": body.get("id"),
                                            "error": {"code": -32001, "message": "missing or invalid API key"}},
                                      {"WWW-Authenticate": "Bearer"})
                resp = mcp.handle(body, lambda cap, args: service.execute(key, cap, args))
                if resp is None:
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                return self._send(200, resp)
            return self._send(404, error_body("NOT_FOUND", "no such route", None))

    return Handler


def build_server(host: str, port: int, service: Service) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(service))


def main():
    ap = argparse.ArgumentParser(description="Run the AgentGrid V1 prototype API")
    ap.add_argument("--host", default=os.environ.get("AGENTGRID_HOST", "127.0.0.1"),
                    help="bind address (env AGENTGRID_HOST; use 0.0.0.0 in containers)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT") or 8787),
                    help="listen port (env PORT, as set by Render)")
    ap.add_argument("--db", default=os.environ.get("AGENTGRID_DB", "agentgrid.db"),
                    help="SQLite path (ignored when DATABASE_URL is set)")
    args = ap.parse_args()
    if os.environ.get("AGENTGRID_ENV") == "production" and not os.environ.get("AGENTGRID_SIGNING_SECRET"):
        raise SystemExit("AGENTGRID_SIGNING_SECRET must be set when AGENTGRID_ENV=production")
    admin = os.environ.get("AGENTGRID_ADMIN_TOKEN", "")
    if admin and len(admin) < 32:
        raise SystemExit("AGENTGRID_ADMIN_TOKEN must be at least 32 characters (e.g. `openssl rand -hex 32`)")
    database_url = os.environ.get("DATABASE_URL") or None
    store = Store(args.db, database_url=database_url)
    service = Service(store, allow_private_targets=os.environ.get("AGENTGRID_ALLOW_PRIVATE") == "1")
    srv = build_server(args.host, args.port, service)
    where = "Postgres (DATABASE_URL)" if database_url else f"SQLite at {args.db}"
    print(f"AgentGrid listening on http://{args.host}:{args.port} (storage: {where}; "
          f"admin API {'enabled' if admin else 'disabled'})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
