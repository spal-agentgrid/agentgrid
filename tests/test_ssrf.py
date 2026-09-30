import unittest

from agentgrid.ssrf import TargetForbidden, resolve_and_check


class SSRFTests(unittest.TestCase):
    def assertBlocked(self, url):
        with self.assertRaises(TargetForbidden, msg=url):
            resolve_and_check(url)

    def test_blocks_private_and_special_targets(self):
        for url in ["http://127.0.0.1/", "http://10.0.0.5/", "http://192.168.1.1/", "http://172.16.0.1/",
                    "http://169.254.169.254/latest/meta-data/", "http://[::1]/", "http://[::ffff:127.0.0.1]/",
                    "http://0.0.0.0/", "http://100.64.0.1/", "http://localhost/", "http://db.internal/",
                    "http://printer.local/"]:
            self.assertBlocked(url)

    def test_blocks_bad_schemes_ports_and_credentials(self):
        for url in ["file:///etc/passwd", "ftp://example.com/", "gopher://x/", "http://user:pw@example.com/",
                    "http://93.184.215.14:22/", "", "x" * 3000, "javascript:alert(1)"]:
            self.assertBlocked(url)

    def test_allows_public_ip_literal(self):
        t = resolve_and_check("https://1.1.1.1/dns-query?x=1")
        self.assertEqual((t.scheme, t.host, t.port, t.path, t.ip), ("https", "1.1.1.1", 443, "/dns-query?x=1",
                                                                     "1.1.1.1"))

    def test_allow_private_flag_for_local_testing(self):
        t = resolve_and_check("http://127.0.0.1:9/", allow_private=True)
        self.assertEqual(t.ip, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
