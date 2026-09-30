import json
import os
import subprocess
import sys
import threading
import unittest
import urllib.error
import urllib.request

from agentgrid.server import build_server
from agentgrid.service import Service
from tests.fixtures import Fixture, make_store


class Client:
    def __init__(self, base, key=None):
        self.base, self.key = base, key

    def req(self, method, path, body=None, key="__default__"):
        key = self.key if key == "__default__" else key
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        r = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(r, timeout=30) as resp:
                return resp.status, json.loads(resp.read() or b"{}"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}"), dict(e.headers)


class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = Fixture().__enter__()
        cls.store = make_store()
        cls.service = Service(cls.store, signing_secret="test-secret", allow_private_targets=True)
        cls.srv = build_server("127.0.0.1", 0, cls.service)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.fx.__exit__(None, None, None)

    def new_account(self, credits=5, rate=60, scopes=None):
        acct = self.store.create_account("t")
        if credits:
            self.store.grant(acct, credits, "free_tier")
        return acct, Client(self.base, self.store.issue_key(acct, scopes=scopes, rate_per_min=rate))

    def run_audit(self, client, path="/bad", **kw):
        return client.req("POST", "/v1/capabilities/siteqa.audit/run",
                          {"url": self.fx.url(path), "checks": ["http", "seo", "headers"], **kw})

    def test_public_registry_and_health(self):
        c = Client(self.base)
        s, body, _ = c.req("GET", "/v1/capabilities")
        self.assertEqual(s, 200)
        self.assertEqual(body["capabilities"][0]["name"], "siteqa.audit")
        self.assertNotIn("handler", body["capabilities"][0])
        s, body, _ = c.req("GET", "/v1/health")
        self.assertEqual((s, body["status"]), (200, "ok"))

    def test_healthz_liveness_probe(self):
        s, body, _ = Client(self.base).req("GET", "/healthz", key=None)
        self.assertEqual((s, body["status"]), (200, "ok"))
        self.assertIn("version", body)

    def test_successful_run_charges_records_and_verifies(self):
        acct, c = self.new_account(credits=5)
        s, body, headers = self.run_audit(c)
        self.assertEqual(s, 200, body)
        rid = body["request_id"]
        self.assertEqual(headers.get("X-Request-Id"), rid)
        self.assertEqual(body["usage"]["credits_charged"], 1)
        self.assertTrue(body["verification"]["signature"].startswith("hmac-sha256:"))
        self.assertEqual(self.store.balance(acct), 4)
        s, rec, _ = c.req("GET", f"/v1/executions/{rid}")
        self.assertEqual(s, 200)
        for field in ["request_id", "created_at", "account_id", "capability_version", "status",
                      "measured_infra_cost_usd", "billable_units", "verification_result", "error_code",
                      "audit_log"]:
            self.assertIn(field, rec)
        self.assertEqual((rec["status"], rec["billable_units"]), ("succeeded", 1))
        self.assertGreater(rec["measured_infra_cost_usd"], 0)
        events = [e["event"] for e in rec["audit_log"]]
        self.assertEqual(events[0], "request.received")
        self.assertIn("credits.reserved", events)
        self.assertEqual(events[-1], "execution.recorded")
        s, v, _ = c.req("GET", f"/v1/executions/{rid}/verify")
        self.assertTrue(v["valid"])
        # another account cannot read this record
        _, other = self.new_account()
        self.assertEqual(other.req("GET", f"/v1/executions/{rid}")[0], 404)

    def test_tampered_record_fails_verification(self):
        acct, c = self.new_account()
        _, body, _ = self.run_audit(c)
        rid = body["request_id"]
        tampered = dict(body)
        tampered["findings"] = []
        self.store.execute("UPDATE executions SET result_json=? WHERE request_id=?",
                              (json.dumps(tampered), rid))
        self.assertFalse(c.req("GET", f"/v1/executions/{rid}/verify")[1]["valid"])

    def test_auth_errors(self):
        c = Client(self.base)
        s, body, _ = c.req("POST", "/v1/capabilities/siteqa.audit/run", {"url": "https://example.com"})
        self.assertEqual((s, body["error"]["code"]), (401, "UNAUTHORIZED"))
        s, body, _ = c.req("POST", "/v1/capabilities/siteqa.audit/run", {"url": "https://example.com"},
                           key="ag_live_deadbeef_wrong")
        self.assertEqual(s, 401)
        acct = self.store.create_account("r")
        key = self.store.issue_key(acct)
        self.store.revoke_key(key.split("_")[2])
        self.assertEqual(Client(self.base, key).req("GET", "/v1/account")[0], 401)

    def test_scope_enforced(self):
        _, c = self.new_account(scopes=["capability:other.thing"])
        s, body, _ = self.run_audit(c)
        self.assertEqual((s, body["error"]["code"]), (403, "FORBIDDEN_SCOPE"))

    def test_invalid_input_not_charged(self):
        acct, c = self.new_account(credits=2)
        s, body, _ = c.req("POST", "/v1/capabilities/siteqa.audit/run", {"url": "ftp://nope", "max_links": 500})
        self.assertEqual((s, body["error"]["code"]), (400, "INVALID_INPUT"))
        self.assertEqual(len(body["error"]["details"]), 2)
        self.assertEqual(self.store.balance(acct), 2)
        s, body, _ = c.req("POST", "/v1/capabilities/siteqa.audit/run", b"{not json")
        self.assertEqual(s, 400)

    def test_insufficient_credits(self):
        acct, c = self.new_account(credits=1)
        self.assertEqual(self.run_audit(c)[0], 200)
        s, body, _ = self.run_audit(c)
        self.assertEqual((s, body["error"]["code"]), (402, "INSUFFICIENT_CREDITS"))
        self.assertEqual(self.store.balance(acct), 0)

    def test_target_failure_is_refunded(self):
        acct, c = self.new_account(credits=3)
        s, body, _ = c.req("POST", "/v1/capabilities/siteqa.audit/run",
                           {"url": "http://127.0.0.1:1/", "timeout_ms": 2000})
        self.assertEqual((s, body["error"]["code"], body["error"]["retryable"]), (502, "TARGET_UNREACHABLE", True))
        self.assertEqual(self.store.balance(acct), 3)
        reasons = [e["reason"] for e in self.store.ledger_entries(acct)]
        self.assertEqual(reasons, ["free_tier", "reserve", "refund"])
        rec = self.store.get_execution(body["error"]["request_id"])
        self.assertEqual((rec["status"], rec["billable_units"], rec["credits_charged"]), ("failed", 0, 0))

    def test_ssrf_blocked_in_production_mode(self):
        prod = Service(self.store, signing_secret="x", allow_private_targets=False)
        acct = self.store.create_account("p")
        self.store.grant(acct, 2)
        key = self.store.authenticate(self.store.issue_key(acct))
        status, body = prod.execute(key, "siteqa.audit", {"url": "http://169.254.169.254/latest/meta-data/"})
        self.assertEqual((status, body["error"]["code"]), (422, "TARGET_NOT_ALLOWED"))
        self.assertEqual(self.store.balance(acct), 2)

    def test_rate_limit(self):
        _, c = self.new_account(credits=10, rate=2)
        codes = [c.req("GET", "/v1/account")[0] for _ in range(1)]
        s1 = c.req("POST", "/v1/capabilities/siteqa.audit/run", {"url": "ftp://x"})[0]
        s2 = c.req("POST", "/v1/capabilities/siteqa.audit/run", {"url": "ftp://x"})[0]
        s3, body, headers = c.req("POST", "/v1/capabilities/siteqa.audit/run", {"url": "ftp://x"})
        self.assertEqual((codes[0], s1, s2, s3), (200, 400, 400, 429))
        self.assertEqual(body["error"]["code"], "RATE_LIMITED")
        self.assertIn("Retry-After", headers)

    def test_mcp_over_http(self):
        acct, c = self.new_account(credits=2)
        s, r, _ = c.req("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                    "clientInfo": {"name": "t", "version": "0"}}})
        self.assertEqual(r["result"]["protocolVersion"], "2025-06-18")
        s, r, _ = c.req("POST", "/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertEqual(s, 202)
        _, r, _ = c.req("POST", "/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tool = r["result"]["tools"][0]
        self.assertEqual(tool["name"], "siteqa_audit")
        self.assertTrue(tool["annotations"]["readOnlyHint"])
        _, r, _ = c.req("POST", "/mcp", {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                         "params": {"name": "siteqa_audit",
                                                    "arguments": {"url": self.fx.url("/good"), "checks": ["seo"]}}})
        self.assertFalse(r["result"]["isError"])
        self.assertEqual(r["result"]["structuredContent"]["verdict"], "pass")
        _, r, _ = c.req("POST", "/mcp", {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                         "params": {"name": "siteqa_audit", "arguments": {"url": "bad"}}})
        self.assertTrue(r["result"]["isError"])
        s, r, _ = Client(self.base).req("POST", "/mcp", {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                                                          "params": {"name": "siteqa_audit", "arguments": {}}})
        self.assertEqual(s, 401)
        self.assertEqual(self.store.balance(acct), 1)

    def test_mcp_stdio_proxy(self):
        acct, c = self.new_account(credits=2)
        msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "siteqa_audit", "arguments": {"url": self.fx.url("/bad"), "checks": ["a11y"]}}}]
        env = dict(os.environ, AGENTGRID_API_KEY=c.key, AGENTGRID_BASE_URL=self.base)
        out = subprocess.run([sys.executable, "-m", "agentgrid.mcp_stdio"], input="\n".join(map(json.dumps, msgs)),
                             capture_output=True, text=True, env=env, timeout=60,
                             cwd=os.path.dirname(os.path.dirname(__file__)))
        lines = [json.loads(l) for l in out.stdout.splitlines()]
        self.assertEqual(len(lines), 2, out.stderr)
        self.assertEqual(lines[0]["result"]["protocolVersion"], "2025-11-25")
        self.assertIn("a11y.missing_lang", {f["id"] for f in lines[1]["result"]["structuredContent"]["findings"]})


if __name__ == "__main__":
    unittest.main()
