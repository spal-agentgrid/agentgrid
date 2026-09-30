"""siteqa.audit v1 — deterministic website QA audit (no LLM).

Every finding carries machine-checkable evidence (status codes, header values,
element counts) so a caller can verify it independently by re-fetching.
"""
from __future__ import annotations

import hashlib
import json
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

from . import fetch as fetchmod
from .ssrf import TargetForbidden

CAPABILITY = "siteqa.audit"
VERSION = "1.0.0"
ALL_CHECKS = ["http", "tls", "headers", "seo", "links", "a11y", "robots"]
SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}
SLOW_TTFB_MS = 1500
CERT_WARN_DAYS = 14


class AuditError(Exception):
    def __init__(self, code: str, message: str, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


# ---------------------------------------------------------------- HTML parsing
class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.html_lang = None
        self.title_parts: list[str] = []
        self._in_title = False
        self.metas: list[dict] = []
        self.links: list[dict] = []  # <link>
        self.anchors: list[str] = []
        self.resources: list[tuple[str, str]] = []  # (tag, url) for mixed-content
        self.imgs_total = 0
        self.imgs_missing_alt: list[str] = []
        self.h1_count = 0
        self.inputs: list[dict] = []
        self.label_for: set[str] = set()
        self._label_depth = 0
        self.json_ld: list[str] = []
        self._in_jsonld = False
        self._jsonld_buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "html" and self.html_lang is None:
            self.html_lang = a.get("lang", "").strip()
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            self.metas.append(a)
        elif tag == "link":
            self.links.append(a)
            if a.get("rel", "").lower() in ("stylesheet", "icon", "preload") and a.get("href"):
                self.resources.append(("link", a["href"]))
        elif tag == "a" and a.get("href"):
            self.anchors.append(a["href"])
        elif tag == "img":
            self.imgs_total += 1
            if "alt" not in a:
                self.imgs_missing_alt.append(a.get("src", "")[:200])
            if a.get("src"):
                self.resources.append(("img", a["src"]))
        elif tag in ("script", "iframe", "source", "video", "audio") and a.get("src"):
            self.resources.append((tag, a["src"]))
            if tag == "script" and a.get("type", "").lower() == "application/ld+json":
                pass
        if tag == "script" and a.get("type", "").lower() == "application/ld+json":
            self._in_jsonld = True
            self._jsonld_buf = []
        elif tag == "h1":
            self.h1_count += 1
        elif tag == "label":
            self._label_depth += 1
            if a.get("for"):
                self.label_for.add(a["for"])
        elif tag in ("input", "select", "textarea"):
            itype = a.get("type", "text").lower()
            if itype not in ("hidden", "submit", "button", "reset", "image"):
                self.inputs.append({
                    "id": a.get("id", ""),
                    "name": a.get("name", ""),
                    "wrapped": self._label_depth > 0,
                    "aria": bool(a.get("aria-label") or a.get("aria-labelledby") or a.get("title")),
                })

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "label" and self._label_depth:
            self._label_depth -= 1
        elif tag == "script" and self._in_jsonld:
            self._in_jsonld = False
            self.json_ld.append("".join(self._jsonld_buf))

    def handle_data(self, data):
        if self._in_title:
            self.title_parts.append(data)
        if self._in_jsonld:
            self._jsonld_buf.append(data)

    # helpers
    @property
    def title(self) -> str:
        return " ".join("".join(self.title_parts).split())

    def meta(self, name: str) -> str | None:
        for m in self.metas:
            if m.get("name", "").lower() == name or m.get("property", "").lower() == name:
                return m.get("content", "")
        return None

    def link_rel(self, rel: str) -> str | None:
        for l in self.links:
            if rel in l.get("rel", "").lower().split():
                return l.get("href", "")
        return None


# ------------------------------------------------------------------ utilities
def _finding(fid, check, severity, title, evidence, recommendation):
    return {"id": fid, "check": check, "severity": severity, "title": title,
            "evidence": evidence, "recommendation": recommendation}


def _decode(body: bytes, headers: dict) -> str:
    ctype = headers.get("content-type", "")
    charset = "utf-8"
    if "charset=" in ctype:
        charset = ctype.split("charset=")[-1].split(";")[0].strip() or "utf-8"
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def evidence_hash(findings: list[dict]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(findings).encode()).hexdigest()


# ---------------------------------------------------------------- the checks
def _check_http(url, res, findings):
    final = res.final
    if final.status >= 400:
        findings.append(_finding("http.status_not_ok", "http", "critical",
                                 f"Page returned HTTP {final.status}", {"status": final.status, "url": final.url},
                                 "Fix the route or deployment so the page returns 2xx."))
    if len(res.chain) - 1 > 3:
        findings.append(_finding("http.redirect_chain_long", "http", "warning",
                                 f"{len(res.chain) - 1} redirects before final page", {"chain": res.chain},
                                 "Link directly to the final URL; keep redirects to at most 1-2 hops."))
    if final.ttfb_ms > SLOW_TTFB_MS:
        findings.append(_finding("http.slow_response", "http", "warning",
                                 f"Time to first byte {final.ttfb_ms} ms", {"ttfb_ms": final.ttfb_ms,
                                                                             "threshold_ms": SLOW_TTFB_MS},
                                 "Add caching/CDN or reduce server work on this route."))
    if urlsplit(final.url).scheme != "https":
        findings.append(_finding("http.not_https", "http", "critical", "Final page is served over plain HTTP",
                                 {"final_url": final.url}, "Serve the site over HTTPS and redirect HTTP to HTTPS."))
    if final.truncated:
        findings.append(_finding("http.body_truncated", "http", "info", "HTML larger than 2 MB; audited first 2 MB",
                                 {"max_bytes": fetchmod.MAX_BODY_BYTES}, "Reduce page weight."))


def _check_https_redirect(url, timeout, allow_private, findings):
    parts = urlsplit(url)
    if parts.scheme != "https":
        return
    http_url = urlunsplit(("http", parts.netloc, parts.path or "/", parts.query, ""))
    try:
        r = fetchmod.fetch(http_url, timeout=timeout, allow_private=allow_private, max_redirects=5)
    except (ConnectionError, OSError, TimeoutError):
        return  # port 80 closed is acceptable
    if urlsplit(r.final.url).scheme != "https" and r.final.status < 400:
        findings.append(_finding("http.http_not_redirected_to_https", "http", "warning",
                                 "HTTP version of the page does not redirect to HTTPS",
                                 {"http_url": http_url, "chain": r.chain},
                                 "Return a 301/308 from http:// to https://."))


def _check_tls(res, findings):
    tls = res.final.tls
    if tls is None:
        return
    if tls.days_remaining is not None:
        if tls.days_remaining < 0:
            findings.append(_finding("tls.cert_expired", "tls", "critical", "TLS certificate has expired",
                                     {"not_after": tls.not_after}, "Renew the certificate now."))
        elif tls.days_remaining < CERT_WARN_DAYS:
            findings.append(_finding("tls.cert_expiring_soon", "tls", "warning",
                                     f"TLS certificate expires in {tls.days_remaining} days",
                                     {"not_after": tls.not_after, "days_remaining": tls.days_remaining},
                                     "Check that automatic renewal is working."))
    if tls.protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(_finding("tls.old_protocol", "tls", "warning", f"Negotiated {tls.protocol}",
                                 {"protocol": tls.protocol}, "Disable TLS < 1.2."))


def _check_headers(res, findings):
    h = res.final.headers
    is_https = urlsplit(res.final.url).scheme == "https"
    if is_https and "strict-transport-security" not in h:
        findings.append(_finding("headers.missing_hsts", "headers", "warning", "Missing Strict-Transport-Security",
                                 {"header": "strict-transport-security", "present": False},
                                 "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."))
    csp = h.get("content-security-policy")
    if not csp:
        findings.append(_finding("headers.missing_csp", "headers", "warning", "Missing Content-Security-Policy",
                                 {"header": "content-security-policy", "present": False},
                                 "Define a Content-Security-Policy appropriate for the site."))
    if h.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(_finding("headers.missing_x_content_type_options", "headers", "info",
                                 "X-Content-Type-Options is not 'nosniff'",
                                 {"value": h.get("x-content-type-options")}, "Add 'X-Content-Type-Options: nosniff'."))
    if "x-frame-options" not in h and "frame-ancestors" not in (csp or ""):
        findings.append(_finding("headers.missing_frame_protection", "headers", "info",
                                 "No clickjacking protection (X-Frame-Options or CSP frame-ancestors)",
                                 {"x-frame-options": None, "csp_frame_ancestors": False},
                                 "Add CSP 'frame-ancestors' or X-Frame-Options."))
    if "referrer-policy" not in h:
        findings.append(_finding("headers.missing_referrer_policy", "headers", "info", "Missing Referrer-Policy",
                                 {"header": "referrer-policy", "present": False},
                                 "Add 'Referrer-Policy: strict-origin-when-cross-origin'."))
    server = h.get("server", "")
    if any(ch.isdigit() for ch in server) or h.get("x-powered-by"):
        findings.append(_finding("headers.server_version_disclosed", "headers", "info",
                                 "Server software/version disclosed in headers",
                                 {"server": server or None, "x-powered-by": h.get("x-powered-by")},
                                 "Remove version details from Server/X-Powered-By."))


def _check_seo(res, page: PageParser, findings):
    final_host = urlsplit(res.final.url).hostname
    title = page.title
    if not title:
        findings.append(_finding("seo.missing_title", "seo", "warning", "Page has no <title>", {"title": None},
                                 "Add a descriptive <title>."))
    elif not (10 <= len(title) <= 70):
        findings.append(_finding("seo.title_length", "seo", "info", f"Title length {len(title)} chars",
                                 {"title": title[:200], "length": len(title), "recommended": [10, 70]},
                                 "Keep titles roughly 10-70 characters."))
    desc = page.meta("description")
    if not desc:
        findings.append(_finding("seo.missing_meta_description", "seo", "info", "No meta description",
                                 {"meta_description": None}, "Add <meta name=\"description\">."))
    if not page.meta("viewport"):
        findings.append(_finding("seo.missing_viewport", "seo", "warning", "No viewport meta tag (mobile layout)",
                                 {"meta_viewport": None},
                                 "Add <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">."))
    robots_meta = (page.meta("robots") or "") + "," + res.final.headers.get("x-robots-tag", "")
    if "noindex" in robots_meta.lower():
        findings.append(_finding("seo.noindex_present", "seo", "warning", "Page is marked noindex",
                                 {"robots": robots_meta.strip(",")},
                                 "Remove noindex if this page should be discoverable."))
    canonical = page.link_rel("canonical")
    if not canonical:
        findings.append(_finding("seo.missing_canonical", "seo", "info", "No canonical link",
                                 {"canonical": None}, "Add <link rel=\"canonical\">."))
    else:
        c_host = urlsplit(urljoin(res.final.url, canonical)).hostname
        if c_host and final_host and c_host != final_host:
            findings.append(_finding("seo.canonical_host_mismatch", "seo", "warning",
                                     "Canonical URL points to a different host",
                                     {"canonical": canonical, "page_host": final_host},
                                     "Point the canonical at this site's own host."))
    if not page.meta("og:title"):
        findings.append(_finding("seo.missing_open_graph", "seo", "info", "No Open Graph tags (og:title)",
                                 {"og:title": None}, "Add og:title / og:description / og:image for link previews."))
    if page.h1_count == 0:
        findings.append(_finding("seo.missing_h1", "seo", "info", "No <h1> heading", {"h1_count": 0},
                                 "Add one <h1> describing the page."))
    elif page.h1_count > 1:
        findings.append(_finding("seo.multiple_h1", "seo", "info", f"{page.h1_count} <h1> headings",
                                 {"h1_count": page.h1_count}, "Prefer a single <h1>."))
    for i, raw in enumerate(page.json_ld):
        try:
            json.loads(raw)
        except json.JSONDecodeError as exc:
            findings.append(_finding("seo.invalid_json_ld", "seo", "warning", "JSON-LD block is not valid JSON",
                                     {"block_index": i, "error": str(exc)[:200]},
                                     "Fix the JSON syntax in the application/ld+json script."))


def _check_a11y(page: PageParser, findings):
    if not page.html_lang:
        findings.append(_finding("a11y.missing_lang", "a11y", "warning", "<html> has no lang attribute",
                                 {"html_lang": None}, "Add lang, e.g. <html lang=\"en\">."))
    if page.imgs_missing_alt:
        findings.append(_finding("a11y.img_missing_alt", "a11y", "warning",
                                 f"{len(page.imgs_missing_alt)} of {page.imgs_total} images lack alt",
                                 {"count": len(page.imgs_missing_alt), "total": page.imgs_total,
                                  "examples": page.imgs_missing_alt[:5]},
                                 "Add alt text (alt=\"\" for decorative images)."))
    unlabeled = [i for i in page.inputs if not (i["wrapped"] or i["aria"] or (i["id"] and i["id"] in page.label_for))]
    if unlabeled:
        findings.append(_finding("a11y.input_missing_label", "a11y", "info",
                                 f"{len(unlabeled)} form fields without an associated label",
                                 {"count": len(unlabeled), "examples": [u["id"] or u["name"] for u in unlabeled[:5]]},
                                 "Associate each field with a <label for> or aria-label."))


def _check_mixed_content(res, page: PageParser, findings):
    if urlsplit(res.final.url).scheme != "https":
        return
    insecure = sorted({urljoin(res.final.url, u) for _, u in page.resources if u.lower().startswith("http://")})
    if insecure:
        findings.append(_finding("links.mixed_content", "links", "warning",
                                 f"{len(insecure)} resources loaded over plain HTTP on an HTTPS page",
                                 {"count": len(insecure), "examples": insecure[:5]},
                                 "Load all subresources over HTTPS."))


def _check_one_link(link, timeout, allow_private):
    try:
        r = fetchmod.fetch(link, timeout=timeout, allow_private=allow_private, method="HEAD", max_redirects=5)
        status = r.final.status
        if status in (405, 501):
            r = fetchmod.fetch(link, timeout=timeout, allow_private=allow_private, method="GET", max_redirects=5)
            status = r.final.status
        return {"url": link, "status": status}
    except TargetForbidden as exc:
        return {"url": link, "status": None, "skipped": str(exc)}
    except (ConnectionError, OSError, TimeoutError, ssl.SSLError) as exc:
        return {"url": link, "status": None, "error": type(exc).__name__}


def _check_links(res, page: PageParser, max_links, timeout, allow_private, findings) -> int:
    base = res.final.url
    base_host = urlsplit(base).hostname
    seen, internal, external = set(), [], []
    for href in page.anchors:
        absu = urljoin(base, href.strip())
        parts = urlsplit(absu)
        if parts.scheme not in ("http", "https"):
            continue
        absu = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
        if absu in seen or absu == base:
            continue
        seen.add(absu)
        (internal if parts.hostname == base_host else external).append(absu)
    targets = (internal + external)[:max_links]
    if not targets:
        return 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda u: _check_one_link(u, timeout, allow_private), targets))
    broken = [r for r in results if (r["status"] is not None and r["status"] >= 400
                                     and r["status"] not in (401, 403, 429)) or "error" in r]
    blocked = [r for r in results if r["status"] in (401, 403, 429)]
    if broken:
        findings.append(_finding("links.broken", "links", "warning", f"{len(broken)} broken links",
                                 {"count": len(broken), "checked": len(results), "links": broken[:20]},
                                 "Fix or remove the broken links."))
    if blocked:
        findings.append(_finding("links.unverifiable", "links", "info",
                                 f"{len(blocked)} links refused automated checks (401/403/429)",
                                 {"count": len(blocked), "links": blocked[:20]},
                                 "Not necessarily broken; verify manually if important."))
    return len(results)


def _check_robots(res, timeout, allow_private, findings):
    p = urlsplit(res.final.url)
    robots_url = urlunsplit((p.scheme, p.netloc, "/robots.txt", "", ""))
    try:
        r = fetchmod.fetch(robots_url, timeout=timeout, allow_private=allow_private, max_redirects=3)
    except (ConnectionError, OSError, TimeoutError, ssl.SSLError, TargetForbidden):
        return
    if r.final.status >= 400:
        findings.append(_finding("robots.robots_txt_missing", "robots", "info", "No robots.txt",
                                 {"url": robots_url, "status": r.final.status}, "Add a robots.txt."))
        return
    text = _decode(r.final.body, r.final.headers)
    agent_all, disallow_root, sitemap = False, False, False
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        low = line.lower()
        if low.startswith("user-agent:"):
            agent_all = low.split(":", 1)[1].strip() == "*"
        elif low.startswith("disallow:") and agent_all and low.split(":", 1)[1].strip() == "/":
            disallow_root = True
        elif low.startswith("sitemap:"):
            sitemap = True
    if disallow_root:
        findings.append(_finding("robots.disallow_all", "robots", "warning",
                                 "robots.txt disallows all crawlers from the whole site",
                                 {"url": robots_url, "rule": "User-agent: * / Disallow: /"},
                                 "Remove 'Disallow: /' if the site should be indexed."))
    if not sitemap:
        findings.append(_finding("robots.sitemap_missing", "robots", "info", "robots.txt lists no Sitemap",
                                 {"url": robots_url}, "Add a 'Sitemap:' line."))


# ------------------------------------------------------------------- driver
def run_audit(params: dict, allow_private: bool = False, ssl_context: ssl.SSLContext | None = None) -> dict:
    url = params["url"]
    checks = params.get("checks") or ALL_CHECKS
    max_links = params.get("max_links", 25)
    timeout = params.get("timeout_ms", 15000) / 1000.0
    fail_on = params.get("fail_on", "critical")
    started = time.monotonic()
    findings: list[dict] = []
    skipped: list[dict] = []

    try:
        res = fetchmod.fetch(url, timeout=timeout, allow_private=allow_private, ssl_context=ssl_context)
    except TargetForbidden as exc:
        raise AuditError("TARGET_NOT_ALLOWED", str(exc)) from exc
    except ssl.SSLCertVerificationError as exc:
        # A failed TLS handshake is itself a valid (critical) audit result.
        findings.append(_finding("tls.handshake_failed", "tls", "critical", "TLS certificate verification failed",
                                 {"error": exc.verify_message or str(exc)[:200]},
                                 "Install a valid certificate chain for this hostname."))
        return _assemble(url, url, None, [], findings, ["tls"], [{"check": c, "reason": "tls_failed"}
                         for c in checks if c != "tls"], fail_on, started, 0, 0)
    except TimeoutError as exc:
        raise AuditError("TARGET_TIMEOUT", f"target did not respond within {timeout}s", retryable=True) from exc
    except (ConnectionError, OSError, ssl.SSLError) as exc:
        raise AuditError("TARGET_UNREACHABLE", f"could not connect: {type(exc).__name__}: {exc}"[:300],
                         retryable=True) from exc

    ctype = res.final.headers.get("content-type", "")
    is_html = "html" in ctype or res.final.body[:200].lstrip().lower().startswith((b"<!doctype html", b"<html"))
    page = PageParser()
    if is_html:
        try:
            page.feed(_decode(res.final.body, res.final.headers))
        except Exception:  # malformed HTML must never crash an audit
            pass

    if "http" in checks:
        _check_http(url, res, findings)
        _check_https_redirect(url, min(timeout, 8.0), allow_private, findings)
    if "tls" in checks:
        if res.final.tls:
            _check_tls(res, findings)
        else:
            skipped.append({"check": "tls", "reason": "not_https"})
    if "headers" in checks:
        _check_headers(res, findings)
    links_checked = 0
    if is_html:
        if "seo" in checks:
            _check_seo(res, page, findings)
        if "a11y" in checks:
            _check_a11y(page, findings)
        if "links" in checks:
            _check_mixed_content(res, page, findings)
            if max_links > 0:
                links_checked = _check_links(res, page, max_links, min(timeout, 5.0), allow_private, findings)
    else:
        skipped += [{"check": c, "reason": "not_html"} for c in ("seo", "a11y", "links") if c in checks]
    if "robots" in checks:
        _check_robots(res, min(timeout, 5.0), allow_private, findings)

    run = [c for c in checks if c not in {s["check"] for s in skipped}]
    return _assemble(url, res.final.url, res, res.chain, findings, run, skipped, fail_on, started,
                     links_checked, res.bytes_in)


def _assemble(url, final_url, res, chain, findings, run, skipped, fail_on, started, links_checked, bytes_in):
    findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["id"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ("critical", "warning", "info")}
    threshold = None if fail_on == "never" else SEVERITY_RANK[fail_on]
    failed = threshold is not None and any(SEVERITY_RANK[f["severity"]] >= threshold for f in findings)
    summary = None
    if res is not None:
        t = res.final.tls
        summary = {
            "status_code": res.final.status,
            "redirects": chain,
            "ttfb_ms": res.final.ttfb_ms,
            "total_ms": res.final.total_ms,
            "bytes": len(res.final.body),
            "content_type": res.final.headers.get("content-type"),
            "tls": None if t is None else {"protocol": t.protocol, "issuer": t.issuer,
                                           "not_after": t.not_after, "days_remaining": t.days_remaining},
        }
    return {
        "capability": CAPABILITY,
        "version": VERSION,
        "url": url,
        "final_url": final_url,
        "verdict": "fail" if failed else "pass",
        "fail_on": fail_on,
        "counts": counts,
        "summary": summary,
        "findings": findings,
        "checks_run": run,
        "checks_skipped": skipped,
        "verification": {"method": "deterministic-evidence", "evidence_hash": evidence_hash(findings)},
        "_meta": {"links_checked": links_checked, "bytes_in": bytes_in,
                  "duration_ms": int((time.monotonic() - started) * 1000)},
    }
