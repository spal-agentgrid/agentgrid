"""Local fixture website used by the tests (no internet needed)."""
from __future__ import annotations

import json
import os
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GOOD = """<!doctype html><html lang="en"><head><title>Acme Widgets - Home page</title>
<meta name="description" content="Widgets"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta property="og:title" content="Acme"><link rel="canonical" href="/good">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"Acme"}</script>
</head><body><h1>Acme</h1><img src="/a.png" alt="logo"><a href="/ok">ok</a>
<form><label for="e">Email</label><input id="e" name="email"></form></body></html>"""

BAD = """<!doctype html><html><head>
<meta name="robots" content="noindex"><link rel="canonical" href="https://other.example.com/x">
<script type="application/ld+json">{"@type": "Product", broken}</script></head>
<body><h1>A</h1><h1>B</h1><img src="/x.png"><img src="/y.png" alt="">
<a href="/missing">dead</a><a href="/ok">fine</a><a href="/forbidden">auth</a><a href="mailto:a@b.c">m</a>
<input name="q"></body></html>"""

SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=31536000",
}


class FixtureHandler(BaseHTTPRequestHandler):
    slow_seconds = 0.0
    server_version = "fixture"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _out(self, status, body=b"", ctype="text/html; charset=utf-8", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        p = self.path
        if p == "/good":
            return self._out(200, GOOD.encode(), headers=SECURE_HEADERS)
        if p == "/bad":
            return self._out(200, BAD.encode(), headers={"Server": "Apache/2.4.1", "X-Powered-By": "PHP/8.1"})
        if p == "/ok":
            return self._out(200, b"<html></html>")
        if p == "/forbidden":
            return self._out(403, b"no")
        if p == "/head-not-allowed":
            if self.command == "HEAD":
                return self._out(405)
            return self._out(200, b"ok")
        if p.startswith("/hop"):
            n = int(p[4:] or 0)
            return self._out(302, headers={"Location": "/good" if n >= 4 else f"/hop{n + 1}"})
        if p == "/slow":
            time.sleep(self.slow_seconds)
            return self._out(200, GOOD.encode(), headers=SECURE_HEADERS)
        if p == "/data.json":
            return self._out(200, json.dumps({"a": 1}).encode(), ctype="application/json")
        if p == "/robots.txt":
            return self._out(200, b"User-agent: *\nDisallow: /\n", ctype="text/plain")
        if p == "/boom":
            return self._out(500, b"err")
        return self._out(404, b"not found")


class Fixture:
    def __init__(self, tls_cert: tuple[str, str] | None = None):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        self.scheme = "http"
        if tls_cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls_cert)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
            self.scheme = "https"
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def url(self, path):
        return f"{self.scheme}://127.0.0.1:{self.port}{path}"


def make_self_signed(days: int = 5) -> tuple[str, str, str]:
    d = tempfile.mkdtemp()
    cert, key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                    "-days", str(days), "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
                   check=True, capture_output=True)
    return cert, key, d


def make_store():
    """Store for tests: Postgres when AGENTGRID_TEST_DATABASE_URL is set (CI job), else in-memory SQLite."""
    from agentgrid.store import Store
    url = os.environ.get("AGENTGRID_TEST_DATABASE_URL")
    return Store(database_url=url) if url else Store(":memory:")
