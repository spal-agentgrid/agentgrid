# Decision: first capability = `siteqa.audit` (Site QA Audit)

## Why it wins
| Factor | Evidence |
|---|---|
| Highest weighted score (79.6/100) | `research/candidates.md` |
| Real, current pain: agents ship broken or insecure sites | 78% of 49 Show HN launches had a critical day-one bug (https://prufa.dev/mcp/); 89–99% of vibe-coded apps lack CSP/HSTS (https://reeve.page/research/vibe-coded-app-security-2026) |
| Demand is validated by paying and free competitors | Prufa Pro $99/mo; SiteAudit MCP tiers; DataForSEO On-Page sells page audits per page (market-2026.md §3) |
| Near-zero cost, no LLM | Local prototype measured 29 ms CPU and 713 bytes for example.com; $0.0000017 estimated infra cost |
| Easy to verify | Every finding carries raw evidence (status code, header value, element count); results are deterministic, hashed and HMAC-signed |
| Low legal/anti-bot risk | Callers audit their own sites; ≤ ~30 requests per audit, all public GETs/HEADs |

**Honest weaknesses:** competition is real (Prufa offers free anonymous audits, and the PSI API is free). Pricing power is moderate. The edge is price, determinism, CI gating (`fail_on`) and signed evidence, not novelty.

**Runners-up:** (2) web page change monitor, 77.6: the next capability, sharing the fetch core. (3) Uptime monitor, 77.0: bundle it with #2. (4) MCP server health probe, 76.6. (5) Domain/TLS/email-auth checks, 76.0: fold into `siteqa.audit` v1.1.

## Capability spec
| Field | Value |
|---|---|
| Name / version | `siteqa.audit` v1.0.0 (semver; breaking changes → v2 on a new path) |
| Description | Deterministic QA audit of one public page: HTTP status, redirects and TTFB; HTTP→HTTPS redirect; TLS cert (expiry, protocol); security headers; SEO meta, canonical and JSON-LD validity; broken links (≤50) and mixed content; basic a11y (lang, img alt, labels); robots.txt/sitemap. |
| Use cases | Post-deploy check by coding agents (Claude Code/Cursor via MCP); CI gate (`fail_on`); agency or SaaS nightly QA of client sites; pre-launch checklists |
| Auth | `Authorization: Bearer ag_live_<keyid>_<secret>` (only the SHA-256 of the secret is stored); MCP uses the same bearer |
| Permissions / scopes | Key scope `capability:siteqa.audit` or `*`. Worker egress restricted to public http(s) on ports 80/443/8080/8443. SSRF guard blocks private, loopback, link-local, metadata and CGNAT addresses and pins the validated IP (no DNS rebinding). |
| Timeout | 45 s hard; main page `timeout_ms` 1–30 s (default 15 s); each link ≤5 s; body cap 2 MB; ≤5 redirects |
| Est. execution time | p50 ~2.5 s, p95 ~9 s **(est.)**; measured 0.58 s for example.com |
| Usage cost (ours) | ~$0.00002–0.0003 per audit **(est.)**; see table below |
| Customer price | 1 credit = 1 audit = **$0.005**. Packs: $5 = 1,000 credits. Free tier 100 audits/month. Failed or refused calls are refunded automatically. |
| Privacy / retention | Raw HTML is never stored. Result JSON is kept 30 days, then purged (`purge_older_than`). Execution metadata (no page content) is kept 13 months for billing. Only target URL host and input hash are logged. No third-party processors on the request path. |
| Health | `GET /v1/health` gives per-capability status (healthy/degraded/down) from the internal-error ratio over the last 50 runs, plus p50/p95 |
| API endpoint | `POST https://<AGENTGRID_HOST>/v1/capabilities/siteqa.audit/run` (domain TBD) |
| Verification method | (1) Each finding includes evidence the caller can re-check; (2) `verification.evidence_hash` = sha256 of canonical findings JSON; (3) `signature` = HMAC-SHA256(server key, `request_id.evidence_hash`); (4) `GET /v1/executions/{id}/verify` recomputes both; (5) the same site state gives the same hash, so a re-run is a check too |

### Input schema
```json
{"type":"object","additionalProperties":false,"required":["url"],
 "properties":{
  "url":{"type":"string","format":"uri","maxLength":2048},
  "checks":{"type":"array","uniqueItems":true,"minItems":1,"items":{"enum":["http","tls","headers","seo","links","a11y","robots"]}},
  "max_links":{"type":"integer","minimum":0,"maximum":50,"default":25},
  "timeout_ms":{"type":"integer","minimum":1000,"maximum":30000,"default":15000},
  "fail_on":{"enum":["critical","warning","never"],"default":"critical"}}}
```
### Output schema (abridged; full version in `agentgrid/registry.py`)
```json
{"request_id":"req_…","capability":"siteqa.audit","version":"1.0.0","url":"…","final_url":"…",
 "verdict":"pass|fail","counts":{"critical":0,"warning":3,"info":8},
 "summary":{"status_code":200,"redirects":[{"url":"…","status":200}],"ttfb_ms":97,"total_ms":97,"bytes":713,
            "content_type":"text/html","tls":{"protocol":"TLSv1.3","issuer":"…","not_after":"…","days_remaining":86}},
 "findings":[{"id":"headers.missing_hsts","check":"headers","severity":"warning","title":"…",
              "evidence":{"header":"strict-transport-security","present":false},"recommendation":"…"}],
 "checks_run":["http","tls","…"],"checks_skipped":[{"check":"seo","reason":"not_html"}],
 "verification":{"method":"deterministic-evidence","evidence_hash":"sha256:…","signature":"hmac-sha256:…"},
 "usage":{"billable_units":1,"credits_charged":1,"links_checked":5,"duration_ms":584}}
```
Finding IDs are stable: `http.status_not_ok`, `http.not_https`, `http.http_not_redirected_to_https`, `http.redirect_chain_long`, `http.slow_response`, `tls.handshake_failed`, `tls.cert_expired`, `tls.cert_expiring_soon`, `tls.old_protocol`, `headers.missing_{hsts,csp,x_content_type_options,frame_protection,referrer_policy}`, `headers.server_version_disclosed`, `seo.{missing_title,title_length,missing_meta_description,missing_viewport,noindex_present,missing_canonical,canonical_host_mismatch,missing_open_graph,missing_h1,multiple_h1,invalid_json_ld}`, `links.{broken,unverifiable,mixed_content}`, `a11y.{missing_lang,img_missing_alt,input_missing_label}`, `robots.{robots_txt_missing,disallow_all,sitemap_missing}`.

### Error schema
```json
{"error":{"code":"TARGET_UNREACHABLE","message":"…","retryable":true,"request_id":"req_…","details":[],"retry_after_s":1.5}}
```
| Code | HTTP | Charged? |
|---|---|---|
| INVALID_INPUT | 400 | no |
| UNAUTHORIZED | 401 | no |
| INSUFFICIENT_CREDITS | 402 | no |
| FORBIDDEN_SCOPE | 403 | no |
| CAPABILITY_NOT_FOUND | 404 | no |
| TARGET_NOT_ALLOWED (SSRF) | 422 | refunded |
| RATE_LIMITED | 429 + Retry-After | no |
| INTERNAL | 500 | refunded |
| TARGET_UNREACHABLE | 502 | refunded |
| TARGET_TIMEOUT | 504 | refunded |

A target that returns 4xx/5xx is a **successful audit** (finding `http.status_not_ok`), and is charged.

### MCP tool definition
```json
{"name":"siteqa_audit","title":"Site QA Audit",
 "description":"Deterministic QA audit of a public web page … Costs 1 credit per successful call; failed calls are refunded.",
 "inputSchema":{…input schema…},"outputSchema":{…output schema…},
 "annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true}}
```
Transports: remote `POST /mcp` (Streamable HTTP, JSON responses, bearer auth) and local stdio (`python -m agentgrid.mcp_stdio`, which proxies to the API).

### SDK examples
```bash
curl -s -X POST https://$AGENTGRID_HOST/v1/capabilities/siteqa.audit/run \
  -H "Authorization: Bearer $AGENTGRID_API_KEY" -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","max_links":10,"fail_on":"warning"}'
```
```python
import os, requests
r = requests.post(f"https://{os.environ['AGENTGRID_HOST']}/v1/capabilities/siteqa.audit/run",
                  headers={"Authorization": f"Bearer {os.environ['AGENTGRID_API_KEY']}"},
                  json={"url": "https://example.com", "max_links": 10}, timeout=60)
r.raise_for_status(); report = r.json()
print(report["verdict"], [f["id"] for f in report["findings"] if f["severity"] != "info"])
```
```typescript
const res = await fetch(`https://${process.env.AGENTGRID_HOST}/v1/capabilities/siteqa.audit/run`, {
  method: "POST",
  headers: { Authorization: `Bearer ${process.env.AGENTGRID_API_KEY}`, "Content-Type": "application/json" },
  body: JSON.stringify({ url: "https://example.com", max_links: 10 }),
});
if (!res.ok) throw new Error((await res.json()).error.code);
const report = await res.json();
console.log(report.verdict, report.counts);
```

## Per-execution record (table `executions` + `audit_log`)
| Field | Example |
|---|---|
| request_id | `req_b5e74cebfa6e4ab5ac98c710` |
| created_at (UTC timestamp) | `2026-09-30T07:22:58.412Z` |
| account_id / api_key_id | `acct_…` / `3796272b` |
| capability / capability_version | `siteqa.audit` / `1.0.0` |
| status / http_status | `succeeded` / 200 |
| measured_infra_cost_usd | 0.0000017 (measured CPU-ms & bytes × estimated rates) |
| billable_units / credits_charged | 1 / 1 |
| verification_result / evidence_hash / signature | `evidence_hash_signed` / `sha256:…` / `hmac-sha256:…` |
| error_code / error_message | null |
| input_hash, target_host, duration_ms, cpu_ms, bytes_in | privacy-preserving metadata |
| audit_log | `request.received → credits.reserved → execution.succeeded → execution.recorded` (plus `credits.refunded`, `rate_limited`, `auth.failed`, etc.) |

## Unit economics per audit (all **estimates** unless noted)
| Line | Typical (0.2 MB, Razorpay intl) | Worst (2 MB, Paddle MoR, $10 pack) | Basis |
|---|---|---|---|
| Price | $0.005000 | $0.005000 | proposed |
| – LLM inference | 0 | 0 | none used |
| – Compute | $0.000005 | $0.000005 | ~30–250 ms CPU × $0.00002/CPU-s (est., ~4× Render Starter rate) |
| – Bandwidth | $0.000030 | $0.000300 | $0.15/GB Render overage (https://render.com/pricing); $0 while inside the free 5 GB |
| – Storage | $0.000001 | $0.000001 | ~5 KB row on Neon/Supabase free tiers |
| – Third-party APIs | 0 | 0 | none |
| – Payment fee | $0.000177 | $0.000500 | Razorpay intl cards up to 3% + 18% GST (https://razorpay.com/pricing/); Paddle 5% + $0.50 on a $10 pack (https://www.merchantofrecordfinder.com/providers/paddle) |
| – Support | $0.000250 | $0.000250 | est. 5% of revenue |
| **Contribution margin** | **$0.004537 (≈91%)** | **$0.003944 (≈79%)** | |

Fixed costs: **$0/month** on free tiers. The first paid step is Render Starter at $7/mo (https://render.com/pricing), which breaks even at about 1,550 paid audits/month **(est.)**.
