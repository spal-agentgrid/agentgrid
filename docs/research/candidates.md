# Candidate capabilities (24) — scored

All scores (1–5) are **analyst estimates** built on the evidence in `market-2026.md`. 5 = better on every axis (cost 5 = cheap, competition 5 = little, verification 5 = easy, distribution 5 = easy, security 5 = low risk).
Weights: demand .15, repeat .10, cost .10, competition .10, pricing power .10, automation .08, verification .10, distribution .10, security .07, scalability .10. Weighted total ×20 = /100. Reproduce with `tools/score_candidates.py`.
Unit economics are **estimates**: price is the proposed per-call price; cost covers compute + bandwidth on free or cheapest-paid tiers, with no LLM inference.

| # | Capability | Dem | Rep | Cost | Comp | Price | Auto | Verif | Dist | Sec | Scale | **Total** | Price/call (est.) | Cost/call (est.) | Rationale |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Site QA audit (deterministic deploy check) | 4 | 4 | 5 | 2 | 3 | 5 | 5 | 3 | 4 | 5 | **79.6** | $0.005 | ~$0.00002–0.0003 | Coding agents need an evidence-based check after deploy; runs on stdlib HTTP, no LLM. Competition from Prufa, SiteAudit MCP, PSI. |
| 2 | Web page change monitor (diff + alert) | 4 | 5 | 4 | 2 | 4 | 5 | 4 | 3 | 4 | 4 | **77.6** | $0.002/check | ~$0.00005 | Subscription-style recurring revenue, but needs a scheduler and storage; needs the site-QA fetch core first. |
| 3 | Uptime / API endpoint monitor | 4 | 5 | 5 | 1 | 2 | 5 | 5 | 2 | 5 | 5 | **77.0** | $0.0005/check | ~$0.00001 | Proven demand, but saturated with generous free tiers. |
| 4 | MCP server health & conformance probe | 3 | 4 | 5 | 2 | 2 | 5 | 5 | 4 | 4 | 5 | **76.6** | $0.003 | ~$0.00002 | Registries can't show liveness (54.5% of servers stale), but free checkers already exist (Merlonix, OpenStatus). |
| 5 | Domain/TLS/email-auth health (SPF/DKIM/DMARC) | 3 | 4 | 5 | 2 | 2 | 5 | 5 | 3 | 5 | 5 | **76.0** | $0.002 | ~$0.00001 | Cheap DNS work that is easy to verify; low pricing power; good add-on to site QA. |
| 6 | OpenAPI spec lint + contract smoke test | 3 | 4 | 5 | 3 | 2 | 5 | 5 | 2 | 4 | 5 | **74.6** | $0.005 | ~$0.00005 | Useful for agent-built APIs; buyers are hard to reach. |
| 7 | Verified web extract (URL->markdown + block detect) | 5 | 5 | 5 | 1 | 2 | 5 | 3 | 3 | 3 | 4 | **73.2** | $0.001 | ~$0.00005 (no proxies) | Highest demand, but competes with Jina/Firecrawl/Exa at ~$1/1k and runs into anti-bot walls. |
| 8 | JSON Schema validate + repair (LLM output guard) | 2 | 5 | 5 | 2 | 1 | 5 | 5 | 3 | 5 | 5 | **73.0** | $0.0002 | ~$0.000005 | Free libraries (ajv, jsonschema) are substitutes. |
| 9 | robots.txt / crawl-permission checker for agents | 2 | 5 | 5 | 2 | 1 | 5 | 5 | 3 | 5 | 5 | **73.0** | $0.0002 | ~$0.000005 | Trivial with stdlib urllib.robotparser; nobody will pay for it. |
| 10 | Structured metadata extract (JSON-LD/OG/meta) | 3 | 4 | 5 | 2 | 2 | 5 | 4 | 3 | 4 | 5 | **72.6** | $0.001 | ~$0.00002 | Deterministic, but Microlink and link-preview APIs are established. |
| 11 | Dependency vulnerability check (OSV data) | 3 | 5 | 5 | 1 | 1 | 5 | 5 | 2 | 5 | 5 | **72.0** | $0.001 | ~$0.00001 | Free osv-scanner and Dependabot are substitutes. |
| 12 | Broken-link crawler (bounded site crawl) | 3 | 4 | 4 | 2 | 2 | 5 | 5 | 3 | 4 | 4 | **70.6** | $0.01/100 links | ~$0.0005 | Subset of site QA; more fetches per call. |
| 13 | Prompt-injection heuristic scan of untrusted text | 3 | 5 | 5 | 2 | 2 | 5 | 2 | 3 | 4 | 5 | **70.6** | $0.0005 | ~$0.000005 | Real pain, but heuristics are hard to verify and have false negatives. |
| 14 | PDF text-layer extraction (no OCR) | 4 | 4 | 4 | 2 | 3 | 5 | 3 | 3 | 3 | 4 | **70.2** | $0.002/page | ~$0.0001/page | Unstructured charges $0.015/page, but LlamaParse basic is ~$0.00125/page; uploads carry privacy risk. |
| 15 | Security headers + exposed-file scan (own sites) | 3 | 3 | 5 | 2 | 3 | 5 | 5 | 2 | 2 | 5 | **69.8** | $0.005 | ~$0.0001 | Probing for exposed files is dual-use and needs proof of site ownership. |
| 16 | Email address syntax/MX verification | 4 | 4 | 5 | 1 | 2 | 5 | 4 | 3 | 1 | 5 | **69.4** | $0.002 | ~$0.00001 | Mostly used for list-cleaning and outreach; spam-adjacent, which conflicts with the mandate. |
| 17 | Office docs -> markdown (DOCX/PPTX/XLSX) | 3 | 3 | 4 | 3 | 2 | 5 | 3 | 3 | 3 | 4 | **65.2** | $0.002/doc | ~$0.0001 | Easy to do with open source, so pricing power is low. |
| 18 | HTML/PDF table extraction to CSV/JSON | 3 | 3 | 4 | 3 | 3 | 4 | 3 | 2 | 4 | 4 | **65.0** | $0.003 | ~$0.0002 | Accuracy is hard to verify. |
| 19 | SERP / web search API (resold upstream) | 5 | 5 | 1 | 1 | 1 | 5 | 3 | 3 | 4 | 3 | **62.6** | $0.005 | ≥$0.004 upstream | Needs a paid upstream; negative margin at $0 budget. |
| 20 | Screenshot / render API (headless Chromium) | 4 | 4 | 2 | 1 | 2 | 5 | 4 | 3 | 3 | 3 | **62.2** | $0.003 | ~$0.001 | Browser RAM is expensive; many incumbents. |
| 21 | Accessibility audit (axe-core, headless browser) | 3 | 3 | 2 | 2 | 3 | 5 | 4 | 2 | 4 | 3 | **60.6** | $0.01 | ~$0.002 | Needs a browser; a good V2 add-on. |
| 22 | OCR for scanned PDFs/images (Tesseract) | 4 | 3 | 2 | 2 | 3 | 5 | 2 | 3 | 3 | 3 | **60.2** | $0.005/page | ~$0.001 | CPU-heavy; quality is hard to verify. |
| 23 | Code test runner in sandbox | 4 | 4 | 1 | 1 | 3 | 4 | 4 | 2 | 1 | 2 | **53.8** | $0.01/min | ~$0.005/min | Needs sandbox isolation; E2B exists; highest security risk. |
| 24 | Lighthouse performance audit | 3 | 3 | 1 | 1 | 2 | 5 | 4 | 2 | 4 | 2 | **52.6** | $0.005 | ~$0.003 | The free PSI API (25k/day) kills pricing power. |

## Top 5
1. **Site QA audit (79.6)**: chosen. See `decision/first-capability.md`.
2. Web page change monitor (77.6): V2, reusing the same fetch core.
3. Uptime / endpoint monitor (77.0): saturated; bundle it with the monitor rather than selling it alone.
4. MCP server health probe (76.6): cheap, strong fit for the MCP ecosystem; V2/V3.
5. Domain/TLS/email-auth health (76.0): fold into site QA as an extra check group.
