# V1 architecture (lean, ~$0/month)

```
Agent / SDK / CI ──HTTPS──► Cloudflare (DNS, TLS, WAF, edge rate-limit)          [free]
                                 │
                                 ▼
                 Render free web service: one Python process                     [free; spins down after 15 min idle]
                 ┌──────────────────────────────────────────────────────────┐
                 │ API gateway (REST /v1/*) + MCP endpoint (/mcp)           │
                 │  → auth (hashed API keys, scopes) → rate limit (bucket)  │
                 │  → capability registry (schemas, price, limits)          │
                 │  → reserve credits → worker (siteqa.audit, SSRF-guarded) │
                 │  → verification (evidence hash + HMAC) → settle/refund   │
                 │  → execution record + audit log                          │
                 └──────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                 Neon Free Postgres: accounts, api_keys, ledger, executions, audit_log   [free]
GitHub: code, Actions CI (tests), scheduled health probe, releases; PyPI/npm for SDK + stdio MCP package
```

| Component | V1 choice | Built in prototype? |
|---|---|---|
| API gateway | stdlib `ThreadingHTTPServer` (swap for FastAPI/uvicorn when deploying) | yes: `agentgrid/server.py` |
| API keys | `ag_live_<id>_<secret>`, SHA-256 stored, constant-time compare, revocation, scopes | yes: `store.py` |
| Capability registry | Python dict holding schemas, price, timeout and retention; served at `/v1/capabilities` | yes: `registry.py` |
| Worker | in-process (move to a queue later); SSRF guard with IP pinning | yes: `siteqa.py`, `fetch.py`, `ssrf.py` |
| Verification | evidence hash + HMAC signature + `/verify` endpoint | yes |
| Rate limiting | per-key token bucket (later Cloudflare rate-limit rules) | yes: `ratelimit.py` |
| Metering + credits ledger | append-only ledger with reserve / refund / grant rows; balance = SUM | yes: SQLite (use Postgres on Neon) |
| Logs | `audit_log` table + platform logs (Render 7 days on Hobby) | yes |
| MCP server | remote `/mcp` + stdio proxy | yes: `mcp.py`, `mcp_stdio.py` |
| Payments | manual credit grants during beta, then Razorpay/Paddle webhook → ledger `grant` | no (BLOCKED on KYC) |

## Minimum free stack (verified Sep 30, 2026)
| Need | Service & free tier | Source |
|---|---|---|
| Compute | **Render Hobby free web service**: 512 MB; 750 instance-hrs/mo; spins down after 15 min idle (~1 min cold start); 5 GB bandwidth | https://render.com/pricing , https://render.com/docs/free |
| Compute (alt) | Koyeb: 1 free web service, 512 MB, 0.1 vCPU, scales to zero after 1 h | https://www.koyeb.com/docs/reference/instances |
| Not free | Fly.io: new accounts get a 2 VM-hr / 7-day trial only. Railway: $5 one-time trial, then $1/mo credit | https://fly.io/docs/about/free-trial/ , https://docs.railway.com/pricing/free-trial |
| Database | **Neon Free**: 0.5 GB/project, 100 CU-hrs/project, scale-to-zero, no card | https://neon.com/pricing |
| DB (alt) | Supabase Free: 500 MB, pauses after 1 week of inactivity. Render free Postgres expires after 30 days, so avoid it | https://supabase.com/pricing , https://render.com/docs/free |
| Edge / DNS | **Cloudflare Free** + Workers Free: 100k req/day, 10 ms CPU/invocation; D1 5 GB; KV 100k reads/day | https://developers.cloudflare.com/workers/platform/pricing/ |
| Code / CI | **GitHub Free**: Actions unlimited on public repos, 2,000 min/mo on private | https://docs.github.com/en/billing/concepts/product-billing/github-actions |
| Domain (first spend) | Cloudflare Registrar .com at $10.46/yr (rising to $11.17 on Nov 1, 2026) | https://domainoffer.net/tld/com/cloudflare |
| First paid upgrade | Render Starter $7/mo (always-on) or Workers Paid $5/mo | Render / Cloudflare pages above |

Why Cloudflare Workers are not the main runtime: the 10 ms CPU limit on the free tier is tight for HTML parsing (the prototype measured ~29 ms), and Workers `fetch` exposes no TLS certificate details. They stay optional for edge auth/rate limiting.

## External accounts, in the order needed
| # | Account | Purpose | Cost | Owner identity / KYC? |
|---|---|---|---|---|
| 1 | **GitHub org** (e.g. `spal-agentgrid`) | repo, CI, releases, `io.github.<org>/*` MCP Registry namespace, SSO into Render/Neon | $0 | Owner's GitHub login + email; no KYC |
| 2 | Render | host API | $0 (card may be asked for verification) | email/GitHub; no KYC |
| 3 | Neon | Postgres | $0 | email/GitHub; no KYC |
| 4 | Cloudflare | DNS/WAF (+ Registrar) | $0 (+$10.46/yr domain) | email; domain registration needs accurate registrant details (ICANN) |
| 5 | PyPI + npm | publish SDKs and stdio MCP package | $0 | email + 2FA; no KYC |
| 6 | MCP Registry (via GitHub or DNS auth), Smithery, Glama, PulseMCP | distribution | $0 | GitHub login; no KYC |
| 7 | Payment processor: **Razorpay** (intl cards up to 3% + GST, auto eFIRC) or **Paddle** (MoR, 5% + $0.50, supports India-based sellers) | sell credit packs | per-transaction | **Yes: KYC** (PAN, bank account, business proof; Paddle does seller/website review). Stripe India is invite-only; Lemon Squeezy reportedly rejecting Indian applicants | 
| 8 | Business current account / GST registration (as required) | settlement, invoicing | varies | **Yes: government KYC** |
| 9 | (Optional) Coinbase Developer Platform, for x402 per-call payments | agent-native payments | free up to 1k tx/mo | **Likely yes** (identity for account/off-ramp) |

Sources for #7: https://razorpay.com/pricing/ , https://www.paddle.com/blog/payments-in-india , https://docs.stripe.com/india-accept-international-payments , https://www.reddit.com/r/StartUpIndia/comments/1tcfbp0/built_a_saas_in_india_lemonsqueezy_rejected_me/ ; #9: https://docs.cdp.coinbase.com/x402/welcome.md
