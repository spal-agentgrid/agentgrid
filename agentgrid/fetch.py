"""Bounded, SSRF-safe HTTP client built on http.client.

- connects to the pre-validated IP, sends the real Host header and SNI
- manual redirect handling (each hop re-validated)
- body size cap, per-request timeout, timing and TLS certificate capture
"""
from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

from .ssrf import Target, resolve_and_check

USER_AGENT = "SPAL-AgentGrid-SiteQA/1.0 (+https://github.com/spal-agentgrid; deterministic QA audit)"
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5


@dataclass
class TLSInfo:
    ok: bool
    error: str | None = None
    protocol: str | None = None
    issuer: str | None = None
    subject: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    ttfb_ms: int
    total_ms: int
    truncated: bool = False
    tls: TLSInfo | None = None


@dataclass
class FetchResult:
    final: Response
    chain: list[dict] = field(default_factory=list)  # [{url, status}]
    bytes_in: int = 0


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, target: Target, timeout: float):
        super().__init__(target.host, target.port, timeout=timeout)
        self._ip = target.ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, target: Target, timeout: float, context: ssl.SSLContext):
        super().__init__(target.host, target.port, timeout=timeout, context=context)
        self._ip = target.ip
        self._ctx = context

    def connect(self):
        raw = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._ctx.wrap_socket(raw, server_hostname=self.host)


def _tls_info_from_sock(sock: ssl.SSLSocket) -> TLSInfo:
    cert = sock.getpeercert() or {}
    not_after = cert.get("notAfter")
    days = None
    if not_after:
        expires = ssl.cert_time_to_seconds(not_after)
        days = int((expires - time.time()) // 86400)

    def _name(field_):
        out = []
        for rdn in cert.get(field_, ()):
            for k, v in rdn:
                if k in ("organizationName", "commonName"):
                    out.append(v)
        return ", ".join(out) or None

    return TLSInfo(ok=True, protocol=sock.version(), issuer=_name("issuer"), subject=_name("subject"),
                   not_after=not_after, days_remaining=days)


def request_once(url: str, method: str = "GET", timeout: float = 10.0, allow_private: bool = False,
                 ssl_context: ssl.SSLContext | None = None, max_body: int = MAX_BODY_BYTES) -> Response:
    target = resolve_and_check(url, allow_private=allow_private)
    start = time.monotonic()
    if target.scheme == "https":
        ctx = ssl_context or ssl.create_default_context()
        conn: http.client.HTTPConnection = _PinnedHTTPSConnection(target, timeout, ctx)
    else:
        conn = _PinnedHTTPConnection(target, timeout)
    tls = None
    try:
        conn.connect()
        if target.scheme == "https":
            tls = _tls_info_from_sock(conn.sock)  # type: ignore[arg-type]
        conn.putrequest(method, target.path, skip_accept_encoding=True)
        conn.putheader("User-Agent", USER_AGENT)
        conn.putheader("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
        conn.putheader("Accept-Encoding", "identity")
        conn.endheaders()
        resp = conn.getresponse()
        ttfb = int((time.monotonic() - start) * 1000)
        body = b""
        truncated = False
        if method != "HEAD":
            body = resp.read(max_body + 1)
            if len(body) > max_body:
                body, truncated = body[:max_body], True
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return Response(url=url, status=resp.status, headers=headers, body=body, ttfb_ms=ttfb,
                        total_ms=int((time.monotonic() - start) * 1000), truncated=truncated, tls=tls)
    finally:
        conn.close()


def fetch(url: str, timeout: float = 10.0, allow_private: bool = False, method: str = "GET",
          ssl_context: ssl.SSLContext | None = None, max_redirects: int = MAX_REDIRECTS) -> FetchResult:
    chain: list[dict] = []
    current = url
    bytes_in = 0
    deadline = time.monotonic() + timeout
    for _ in range(max_redirects + 1):
        remaining = max(0.5, deadline - time.monotonic())
        resp = request_once(current, method=method, timeout=remaining, allow_private=allow_private,
                            ssl_context=ssl_context)
        bytes_in += len(resp.body)
        chain.append({"url": current, "status": resp.status})
        if resp.status in (301, 302, 303, 307, 308) and "location" in resp.headers:
            current = urljoin(current, resp.headers["location"])
            if time.monotonic() > deadline:
                raise TimeoutError("redirect chain exceeded timeout")
            continue
        return FetchResult(final=resp, chain=chain, bytes_in=bytes_in)
    raise ConnectionError(f"too many redirects (> {max_redirects})")
