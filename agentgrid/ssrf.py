"""Target validation to prevent SSRF.

Every outbound request made on behalf of a caller goes through
``resolve_and_check`` and connects to the *validated IP* (not a second DNS
lookup), which defeats DNS-rebinding between check and use.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, 8080, 8443}
MAX_URL_LENGTH = 2048


class TargetForbidden(Exception):
    """Raised when a URL/host must not be fetched."""


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str  # path + query, never empty
    ip: str


def _is_public_ip(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"))
    )


def parse_url(url: str) -> tuple[str, str, int, str]:
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
        raise TargetForbidden("url must be a non-empty string of at most 2048 chars")
    parts = urlsplit(url.strip())
    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise TargetForbidden(f"scheme '{scheme}' not allowed (http/https only)")
    if parts.username or parts.password:
        raise TargetForbidden("credentials in URL are not allowed")
    host = (parts.hostname or "").lower()
    if not host:
        raise TargetForbidden("url has no host")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise TargetForbidden("invalid port") from exc
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return scheme, host, port, path


def resolve_and_check(url: str, allow_private: bool = False) -> Target:
    scheme, host, port, path = parse_url(url)
    if not allow_private:
        if port not in ALLOWED_PORTS:
            raise TargetForbidden(f"port {port} not allowed")
        if host == "localhost" or host.endswith(".localhost") or host.endswith(".internal") or host.endswith(".local"):
            raise TargetForbidden("internal hostnames are not allowed")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ConnectionError(f"DNS resolution failed for {host}") from exc
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not allow_private and not _is_public_ip(ip):
            raise TargetForbidden(f"{host} resolves to non-public address {ip}")
        ips.append(str(ip))
    if not ips:
        raise ConnectionError(f"no addresses for {host}")
    # Prefer IPv4 for predictability.
    ips.sort(key=lambda s: ":" in s)
    return Target(scheme, host, port, path, ips[0])
