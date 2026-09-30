import os
import threading
import unittest
import uuid

from agentgrid.accounts import Accounts, normalize_email
from agentgrid.db import parse_database_url
from agentgrid.server import build_server
from agentgrid.service import Service
from agentgrid.store import EmailAlreadyRegistered
from tests.fixtures import Fixture, make_store
from tests.test_api import Client

ADMIN = "a" * 64


def unique_email(prefix="user"):
    return f"{prefix}.{uuid.uuid4().hex[:10]}@Example.COM"


class EmailValidationTests(unittest.TestCase):
    def test_valid_and_normalised(self):
        self.assertEqual(normalize_email("  Alice.Smith+qa@Example.co.uk "), "alice.smith+qa@example.co.uk")

    def test_invalid(self):
        for bad in [None, 42, "", "no-at-sign", "a@b", "a@@b.com", "a b@c.com", "a@-b.com", "a@b.c",
                    ".a@b.com", "a..b@c.com", "x" * 65 + "@b.com", "a@" + "b" * 250 + ".com",
                    "a@b.com\nx", "<a@b.com>"]:
            self.assertIsNone(normalize_email(bad), bad)


class DatabaseUrlTests(unittest.TestCase):
    def test_parse(self):
        kw = parse_database_url("postgresql://u%40x:p%2Fw@ep-1-pooler.neon.tech/agentgrid?sslmode=require")
        self.assertEqual((kw["user"], kw["password"], kw["host"], kw["port"], kw["database"]),
                         ("u@x", "p/w", "ep-1-pooler.neon.tech", 5432, "agentgrid"))
        self.assertIn("ssl_context", kw)
        kw = parse_database_url("postgres://u:p@localhost:5433/db")
        self.assertNotIn("ssl_context", kw)  # local default: no TLS
        self.assertEqual(kw["port"], 5433)
        with self.assertRaises(ValueError):
            parse_database_url("mysql://u:p@h/db")


class StoreSignupTests(unittest.TestCase):
    def test_signup_atomic_and_unique(self):
        st = make_store()
        email = unique_email().lower()
        acct, key = st.signup(email, 100)
        self.assertEqual(st.balance(acct), 100)
        self.assertEqual(st.authenticate(key)["account_id"], acct)
        with self.assertRaises(EmailAlreadyRegistered):
            st.signup(email, 100)
        # the failed second signup left nothing behind
        self.assertEqual(len([a for a in st.list_accounts(500) if a["email"] == email]), 1)
        self.assertEqual(st.balance(acct), 100)

    def test_key_is_stored_hashed(self):
        st = make_store()
        acct, key = st.signup(unique_email().lower(), 1)
        secret = key.split("_", 3)[3]
        rows = st.query("SELECT key_hash FROM api_keys WHERE account_id=?", (acct,))
        self.assertEqual(len(rows), 1)
        self.assertNotIn(secret, rows[0]["key_hash"])
        self.assertEqual(len(rows[0]["key_hash"]), 64)

    @unittest.skipUnless(os.environ.get("AGENTGRID_TEST_DATABASE_URL"), "Postgres not configured")
    def test_postgres_backend_in_use(self):
        self.assertEqual(make_store().backend_name, "postgres")


class SignupAndAdminAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = Fixture().__enter__()
        cls.store = make_store()
        cls.accounts = Accounts(cls.store, admin_token=ADMIN, signup_credits=100, signup_per_ip_per_hour=1000,
                                signup_global_per_hour=1000, signup_enabled=True)
        cls.service = Service(cls.store, signing_secret="t", allow_private_targets=True, accounts=cls.accounts)
        cls.srv = build_server("127.0.0.1", 0, cls.service)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.fx.__exit__(None, None, None)

    def signup(self, email):
        return Client(self.base).req("POST", "/v1/signup", {"email": email}, key=None)

    def test_signup_returns_working_key_with_free_credits(self):
        email = unique_email("New")
        s, body, _ = self.signup(email)
        self.assertEqual(s, 201, body)
        self.assertEqual((body["email"], body["credits_granted"]), (email.lower(), 100))
        self.assertTrue(body["api_key"].startswith("ag_live_"))
        c = Client(self.base, body["api_key"])
        s, acct, _ = c.req("GET", "/v1/account")
        self.assertEqual((s, acct["account_id"], acct["balance_credits"]), (200, body["account_id"], 100))
        self.assertEqual(acct["ledger"][0]["reason"], "signup_free_tier")
        s, run, _ = c.req("POST", "/v1/capabilities/siteqa.audit/run", {"url": self.fx.url("/good"),
                                                                         "checks": ["seo"]})
        self.assertEqual(s, 200, run)
        self.assertEqual(c.req("GET", "/v1/account")[1]["balance_credits"], 99)

    def test_duplicate_email_rejected_case_insensitive(self):
        email = unique_email()
        self.assertEqual(self.signup(email)[0], 201)
        s, body, _ = self.signup(email.upper())
        self.assertEqual((s, body["error"]["code"]), (409, "EMAIL_ALREADY_REGISTERED"))
        self.assertNotIn("api_key", body)

    def test_invalid_email_and_body(self):
        for payload in [{"email": "nope"}, {}, {"email": ["a@b.com"]}, ["a@b.com"]]:
            s, body, _ = Client(self.base).req("POST", "/v1/signup", payload, key=None)
            self.assertEqual((s, body["error"]["code"]), (400, "INVALID_INPUT"), payload)

    def test_signup_per_ip_rate_limit(self):
        acc = Accounts(self.store, admin_token="", signup_per_ip_per_hour=2, signup_global_per_hour=100,
                       signup_enabled=True)
        codes = [acc.signup({"email": unique_email()}, "203.0.113.7")[0] for _ in range(3)]
        self.assertEqual(codes, [201, 201, 429])
        status, body, retry = acc.signup({"email": unique_email()}, "203.0.113.7")
        self.assertEqual((status, body["error"]["code"]), (429, "RATE_LIMITED"))
        self.assertGreater(retry, 0)
        self.assertEqual(acc.signup({"email": unique_email()}, "198.51.100.9")[0], 201)  # other IP unaffected

    def test_signup_global_rate_limit_and_disable(self):
        acc = Accounts(self.store, admin_token="", signup_per_ip_per_hour=100, signup_global_per_hour=1,
                       signup_enabled=True)
        self.assertEqual(acc.signup({"email": unique_email()}, "192.0.2.1")[0], 201)
        self.assertEqual(acc.signup({"email": unique_email()}, "192.0.2.2")[0], 429)
        off = Accounts(self.store, admin_token="", signup_enabled=False)
        self.assertEqual(off.signup({"email": unique_email()}, "192.0.2.3")[0], 403)

    def test_rate_limit_over_http_sets_retry_after(self):
        acc = Accounts(self.store, admin_token="", signup_per_ip_per_hour=1, signup_global_per_hour=100,
                       signup_enabled=True)
        srv = build_server("127.0.0.1", 0, Service(self.store, signing_secret="t", accounts=acc))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            c = Client(f"http://127.0.0.1:{srv.server_address[1]}")
            self.assertEqual(c.req("POST", "/v1/signup", {"email": unique_email()}, key=None)[0], 201)
            s, body, headers = c.req("POST", "/v1/signup", {"email": unique_email()}, key=None)
            self.assertEqual(s, 429)
            self.assertIn("Retry-After", headers)
        finally:
            srv.shutdown()

    def test_admin_requires_token(self):
        c = Client(self.base)
        for key in [None, "wrong", "a" * 63, "ag_live_x_y"]:
            s, body, _ = c.req("GET", "/v1/admin/accounts", key=key)
            self.assertEqual((s, body["error"]["code"]), (401, "UNAUTHORIZED"), key)
            s, _, _ = c.req("POST", "/v1/admin/accounts/acct_0/credits", {"credits": 5}, key=key)
            self.assertEqual(s, 401)
        # a user API key is not an admin token
        _, body, _ = self.signup(unique_email())
        self.assertEqual(Client(self.base, body["api_key"]).req("GET", "/v1/admin/accounts")[0], 401)

    def test_admin_disabled_without_token(self):
        srv = build_server("127.0.0.1", 0, Service(self.store, signing_secret="t",
                                                   accounts=Accounts(self.store, admin_token="")))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            c = Client(f"http://127.0.0.1:{srv.server_address[1]}")
            self.assertEqual(c.req("GET", "/v1/admin/accounts", key="")[0], 404)
            self.assertEqual(c.req("GET", "/v1/admin/accounts", key=ADMIN)[0], 404)
        finally:
            srv.shutdown()

    def test_admin_list_and_grant(self):
        email = unique_email("admin-target")
        _, su, _ = self.signup(email)
        admin = Client(self.base, ADMIN)
        s, listing, _ = admin.req("GET", "/v1/admin/accounts?limit=500")
        self.assertEqual(s, 200, listing)
        row = next(a for a in listing["accounts"] if a["id"] == su["account_id"])
        self.assertEqual((row["email"], row["balance_credits"], row["active_keys"]), (email.lower(), 100, 1))
        self.assertGreaterEqual(listing["total"], 1)
        self.assertNotIn("key_hash", row)
        s, g, _ = admin.req("POST", f"/v1/admin/accounts/{su['account_id']}/credits",
                            {"credits": 250, "reason": "pilot"})
        self.assertEqual((s, g["balance_credits"]), (200, 350), g)
        s, g, _ = admin.req("POST", f"/v1/admin/accounts/{su['account_id']}/credits", {"credits": -50})
        self.assertEqual((s, g["balance_credits"]), (200, 300))
        ledger = Client(self.base, su["api_key"]).req("GET", "/v1/account")[1]["ledger"]
        self.assertEqual([e["reason"] for e in ledger], ["signup_free_tier", "admin:pilot", "admin:admin_grant"])

    def test_admin_grant_validation(self):
        admin = Client(self.base, ADMIN)
        _, su, _ = self.signup(unique_email())
        path = f"/v1/admin/accounts/{su['account_id']}/credits"
        for bad in [{}, {"credits": 0}, {"credits": "5"}, {"credits": True}, {"credits": 10**7},
                    {"credits": 5, "reason": ""}, {"credits": 5, "reason": "x" * 101}]:
            self.assertEqual(admin.req("POST", path, bad)[0], 400, bad)
        s, body, _ = admin.req("POST", "/v1/admin/accounts/acct_ffffffffffffffff/credits", {"credits": 5})
        self.assertEqual((s, body["error"]["code"]), (404, "NOT_FOUND"))
        self.assertEqual(admin.req("GET", "/v1/admin/accounts?limit=abc")[0], 400)

    def test_health_reports_storage_backend(self):
        s, body, _ = Client(self.base).req("GET", "/v1/health", key=None)
        self.assertEqual(s, 200)
        self.assertIn(body["storage"], ("sqlite", "postgres"))


if __name__ == "__main__":
    unittest.main()
