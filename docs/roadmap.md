# SPAL AgentGrid roadmap

Status key: PLANNED / BUILT / TESTED / LIVE / BLOCKED. **Nothing is LIVE.** As of Sep 30, 2026.

## Phase 1: research & decision
| Item | Status |
|---|---|
| Market research (`research/market-2026.md`) | BUILT |
| 24 scored candidates (`research/candidates.md`) | BUILT |
| First capability + spec (`decision/first-capability.md`) | BUILT |
| V1 architecture + free stack (`decision/v1-architecture.md`) | BUILT |

## Phase 2: V1 build (local)
| Item | Status |
|---|---|
| `siteqa.audit` worker (7 check groups, evidence, deterministic hash) | TESTED (local unit tests + live smoke test on example.com) |
| SSRF guard with IP pinning | TESTED |
| API keys, scopes, rate limit, credits ledger (reserve/refund), execution records, audit log | TESTED (SQLite) |
| REST API + remote MCP (`/mcp`) + stdio MCP proxy | TESTED |
| Postgres (Neon) storage adapter | PLANNED |
| FastAPI/uvicorn production server + Dockerfile + `render.yaml` | PLANNED |
| Python + TypeScript SDK packages | PLANNED |
| Result retention purge job (30 days) | BUILT (function exists; scheduler PLANNED) |
| Owner picks the license (Apache-2.0 proposed) | PLANNED |

## Phase 3: deploy & private beta
| Item | Status |
|---|---|
| GitHub org + repo + Actions CI | BLOCKED (owner must create GitHub org) |
| Render service + Neon DB | BLOCKED (accounts) |
| Cloudflare DNS + domain | BLOCKED (account + ~$10.46 domain spend) |
| Public docs page + OpenAPI | PLANNED |
| Free tier (100 audits/mo) with manual key issuance | PLANNED |
| 10 beta users (coding-agent builders, agencies) | PLANNED |

## Phase 4: launch
| Item | Status |
|---|---|
| Publish to official MCP Registry, Smithery, Glama, PulseMCP | BLOCKED (GitHub org + PyPI/npm) |
| Payments: Razorpay or Paddle credit packs → ledger webhook | BLOCKED (owner KYC) |
| Terms, privacy policy, acceptable-use policy (own-site audits) | PLANNED |
| Status page from `/v1/health` + GitHub Actions probe | PLANNED |
| Show HN / dev.to launch post with a sample dataset | PLANNED |

## Phase 5: growth
| Item | Status |
|---|---|
| `siteqa.audit` v1.1: DNS/SPF/DMARC + TLS chain checks | PLANNED |
| Capability #2: page change monitor (scheduled, webhooks) | PLANNED |
| Capability #3: MCP server health probe | PLANNED |
| GitHub Action `agentgrid/siteqa-action` (CI gate) | PLANNED |
| x402 pay-per-call option | PLANNED (depends on CDP account) |
| Upgrade to Render Starter $7/mo once revenue exceeds it | PLANNED |
