import shutil
import ssl
import unittest

from agentgrid import siteqa
from agentgrid.registry import SITEQA_INPUT_SCHEMA, ValidationError, validate
from agentgrid.siteqa import AuditError, run_audit
from tests.fixtures import Fixture, FixtureHandler, make_self_signed


def ids(result):
    return {f["id"] for f in result["findings"]}


class SiteQATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = Fixture().__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.fx.__exit__(None, None, None)

    def audit(self, path, **kw):
        params = validate(SITEQA_INPUT_SCHEMA, {"url": self.fx.url(path), **kw})
        return run_audit(params, allow_private=True)

    def test_good_page_has_no_content_findings(self):
        r = self.audit("/good", checks=["seo", "a11y", "headers", "links"])
        self.assertEqual(r["summary"]["status_code"], 200)
        # Only plain-HTTP related items may appear for a local http fixture.
        self.assertFalse(ids(r) - {"links.mixed_content"}, ids(r))
        self.assertEqual(r["verdict"], "pass")
        self.assertEqual(r["_meta"]["links_checked"], 1)

    def test_bad_page_findings_with_evidence(self):
        r = self.audit("/bad")
        expected = {"seo.missing_title", "seo.noindex_present", "seo.canonical_host_mismatch",
                    "seo.invalid_json_ld", "seo.multiple_h1", "seo.missing_viewport", "a11y.missing_lang",
                    "a11y.img_missing_alt", "a11y.input_missing_label", "links.broken", "links.unverifiable",
                    "headers.missing_csp", "headers.server_version_disclosed", "http.not_https",
                    "robots.disallow_all", "robots.sitemap_missing"}
        self.assertTrue(expected <= ids(r), expected - ids(r))
        broken = next(f for f in r["findings"] if f["id"] == "links.broken")
        self.assertEqual(broken["evidence"]["links"][0]["status"], 404)
        self.assertTrue(broken["evidence"]["links"][0]["url"].endswith("/missing"))
        alt = next(f for f in r["findings"] if f["id"] == "a11y.img_missing_alt")
        self.assertEqual((alt["evidence"]["count"], alt["evidence"]["total"]), (1, 2))  # alt="" is valid
        self.assertEqual(r["verdict"], "fail")  # http.not_https is critical
        self.assertEqual(r["findings"][0]["severity"], "critical")  # sorted by severity

    def test_fail_on_threshold(self):
        self.assertEqual(self.audit("/bad", fail_on="never")["verdict"], "pass")
        r = self.audit("/good", checks=["seo"], fail_on="warning")
        self.assertEqual(r["verdict"], "pass")
        r = self.audit("/bad", checks=["seo"], fail_on="warning")
        self.assertEqual(r["verdict"], "fail")

    def test_http_error_status_is_a_result_not_an_error(self):
        r = self.audit("/boom", checks=["http"])
        self.assertIn("http.status_not_ok", ids(r))
        self.assertEqual(r["summary"]["status_code"], 500)

    def test_redirect_chain(self):
        r = self.audit("/hop0", checks=["http"])
        self.assertIn("http.redirect_chain_long", ids(r))
        self.assertTrue(r["final_url"].endswith("/good"))
        self.assertEqual(len(r["summary"]["redirects"]), 6)

    def test_slow_response(self):
        old = siteqa.SLOW_TTFB_MS
        siteqa.SLOW_TTFB_MS, FixtureHandler.slow_seconds = 100, 0.3
        try:
            self.assertIn("http.slow_response", ids(self.audit("/slow", checks=["http"])))
        finally:
            siteqa.SLOW_TTFB_MS, FixtureHandler.slow_seconds = old, 0.0

    def test_non_html_skips_page_checks(self):
        r = self.audit("/data.json")
        skipped = {s["check"] for s in r["checks_skipped"]}
        self.assertTrue({"seo", "a11y", "links", "tls"} <= skipped)

    def test_deterministic_evidence_hash(self):
        a = self.audit("/bad", checks=["seo", "a11y", "headers"])
        b = self.audit("/bad", checks=["seo", "a11y", "headers"])
        self.assertEqual(a["verification"]["evidence_hash"], b["verification"]["evidence_hash"])
        self.assertTrue(a["verification"]["evidence_hash"].startswith("sha256:"))

    def test_unreachable_target_raises_typed_error(self):
        with self.assertRaises(AuditError) as cm:
            run_audit({"url": "http://127.0.0.1:1/", "timeout_ms": 2000}, allow_private=True)
        self.assertEqual(cm.exception.code, "TARGET_UNREACHABLE")

    def test_forbidden_target_without_allow_private(self):
        with self.assertRaises(AuditError) as cm:
            run_audit({"url": self.fx.url("/good")})
        self.assertEqual(cm.exception.code, "TARGET_NOT_ALLOWED")

    def test_input_validation(self):
        for bad in [{}, {"url": "ftp://x"}, {"url": "https://x", "max_links": 99},
                    {"url": "https://x", "checks": ["nope"]}, {"url": "https://x", "extra": 1},
                    {"url": "https://x", "timeout_ms": "5"}, {"url": "https://x", "checks": []}]:
            with self.assertRaises(ValidationError, msg=bad):
                validate(SITEQA_INPUT_SCHEMA, bad)
        v = validate(SITEQA_INPUT_SCHEMA, {"url": "https://example.com"})
        self.assertEqual((v["max_links"], v["timeout_ms"], v["fail_on"]), (25, 15000, "critical"))


@unittest.skipUnless(shutil.which("openssl"), "openssl required")
class TLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert, cls.key, cls.tmp = make_self_signed(days=5)
        cls.fx = Fixture(tls_cert=(cls.cert, cls.key)).__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.fx.__exit__(None, None, None)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_untrusted_cert_is_critical_finding(self):
        r = run_audit({"url": self.fx.url("/good")}, allow_private=True)
        self.assertIn("tls.handshake_failed", ids(r))
        self.assertEqual(r["verdict"], "fail")

    def test_trusted_cert_expiring_soon(self):
        ctx = ssl.create_default_context(cafile=self.cert)
        r = run_audit({"url": self.fx.url("/good"), "checks": ["tls", "headers"]}, allow_private=True,
                      ssl_context=ctx)
        self.assertIn("tls.cert_expiring_soon", ids(r))
        self.assertNotIn("headers.missing_hsts", ids(r))
        self.assertIn(r["summary"]["tls"]["days_remaining"], (3, 4, 5))
        self.assertIn(r["summary"]["tls"]["protocol"], ("TLSv1.2", "TLSv1.3"))


if __name__ == "__main__":
    unittest.main()
