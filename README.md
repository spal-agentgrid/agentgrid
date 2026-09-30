# SPAL AgentGrid: `siteqa.audit`

[![CI](https://github.com/spal-agentgrid/agentgrid/actions/workflows/ci.yml/badge.svg)](https://github.com/spal-agentgrid/agentgrid/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Deterministic website QA audits that AI agents can call over REST or MCP. Every finding comes with evidence, and every result is hashed and signed.**

> **Status: TESTED locally, not LIVE.** This is the V1 prototype. The unit test suite passes locally, but there is no hosted endpoint yet, no public signup, and no payments. The Render deployment, MCP Registry listing and pricing below are **PLANNED**.

## What is `siteqa.audit`?

`siteqa.audit` is the first capability on SPAL AgentGrid, a pay-per-call capability gateway for AI agents. Given a public URL, it runs a fixed set of checks and returns structured findings:

| Check | What it looks at |
|---|---|
| `http` | status code, redirect chain, TTFB/total latency, HTTP→HTTPS redirect |
| `tls` | certificate validity, issuer, days to expiry |
| `headers` | security headers (HSTS, CSP, X-Content-Type-Options, …) |
| `seo` | title/meta description, canonical, robots meta, JSON-LD validity |
| `links` | broken links on the page (internal first, up to `max_links`), mixed content |
| `a11y` | basic accessibility (lang, alt text, labels, …) |
| `robots` | `robots.txt` presence and rules |

- **Deterministic, no LLM:** the same input and the same site state give the same findings and the same `evidence_hash`.
- **Verifiable:** each finding carries `evidence`. The result includes `verification.evidence_hash` (SHA-256 of the canonical findings) and an HMAC `signature`, which you can re-check at `GET /v1/executions/{id}/verify`.
- **CI-friendly:** `fail_on` (`critical` | `warning` | `never`) sets `verdict: pass|fail`.
- **Safe by default:** SSRF guard with DNS pinning. Private, loopback, link-local and CGNAT targets are rejected.
- **Fair billing:** credits are reserved before a run and refunded automatically if the audit fails on our side or the target is unreachable.

## Quickstart (local)

Requires Python 3.11+. No third-party dependencies.

```bash
git clone https://github.com/spal-agentgrid/agentgrid.git
cd agentgrid

# Run the tests (local fixture servers only; no internet needed)
python3 -m unittest discover -s tests

# Create a local account + API key (stored hashed in SQLite)
python3 -m agentgrid.cli --db dev.db create-account me --credits 100
# → account_id=acct_…  api_key=ag_live_…  credits=100
export AGENTGRID_API_KEY=ag_live_...        # paste the printed key

# Start the API (REST + MCP) on http://127.0.0.1:8787
python3 -m agentgrid.server --db dev.db --port 8787
```

Health: `curl -s localhost:8787/healthz` (liveness) and `curl -s localhost:8787/v1/health` (per-capability health).

## REST usage

```bash
curl -s -X POST http://127.0.0.1:8787/v1/capabilities/siteqa.audit/run \
  -H "Authorization: Bearer $AGENTGRID_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "checks": ["http","tls","headers","seo"], "max_links": 10, "fail_on": "warning"}'
```

Response (abridged):

```json
{
  "request_id": "req_…",
  "capability": "siteqa.audit",
  "url": "https://example.com",
  "final_url": "https://example.com/",
  "verdict": "fail",
  "counts": {"critical": 0, "warning": 3, "info": 2},
  "findings": [
    {"id": "headers.missing_hsts", "check": "headers", "severity": "warning",
     "title": "…", "evidence": {"…": "…"}, "recommendation": "…"}
  ],
  "verification": {"method": "deterministic-evidence", "evidence_hash": "sha256:…", "signature": "hmac-sha256:…"},
  "usage": {"billable_units": 1, "credits_charged": 1, "links_checked": 0, "duration_ms": 812}
}
```

Other endpoints:

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /healthz` | – | liveness probe |
| `GET /v1/health` | – | service + per-capability health (p50/p95, error ratio) |
| `GET /v1/capabilities[/{name}]` | – | registry: schemas, price, limits |
| `POST /v1/capabilities/{name}/run` | key | run a capability (metered) |
| `GET /v1/executions/{request_id}` | key | execution record + audit log |
| `GET /v1/executions/{request_id}/verify` | key | recompute evidence hash + check signature |
| `GET /v1/account` | key | balance + recent ledger |
| `POST /mcp` | key for `tools/call` | MCP JSON-RPC |

Errors look like `{"error": {"code", "message", "retryable", "request_id"}}`, using the codes `INVALID_INPUT` 400, `UNAUTHORIZED` 401, `INSUFFICIENT_CREDITS` 402, `FORBIDDEN_SCOPE` 403, `TARGET_NOT_ALLOWED` 422, `RATE_LIMITED` 429 (+`Retry-After`), `TARGET_UNREACHABLE` 502 and `TARGET_TIMEOUT` 504. Failed runs are not charged.

## MCP usage

The tool is exposed as **`siteqa_audit`** (read-only, idempotent).

**Remote (Streamable HTTP):** point an MCP client at `http://127.0.0.1:8787/mcp` with the header `Authorization: Bearer ag_live_…`.

```bash
curl -s -X POST http://127.0.0.1:8787/mcp -H "Authorization: Bearer $AGENTGRID_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"siteqa_audit","arguments":{"url":"https://example.com"}}}'
```

**Local stdio proxy** (for clients that only speak stdio, such as Claude Desktop and Cursor). It forwards to the HTTP API:

```json
{
  "mcpServers": {
    "agentgrid-siteqa": {
      "command": "python3",
      "args": ["-m", "agentgrid.mcp_stdio"],
      "env": {
        "AGENTGRID_API_KEY": "ag_live_…",
        "AGENTGRID_BASE_URL": "http://127.0.0.1:8787"
      }
    }
  }
}
```

(Run it from the repo directory, or put the repo on `PYTHONPATH`.) Registry metadata lives in [`server.json`](server.json) as `io.github.spal-agentgrid/siteqa`. It is **not yet published** to the MCP Registry.

## Pricing (PLANNED)

| Tier | Price |
|---|---|
| Free | **100 audits / month** |
| Pay as you go | **$5 per 1,000 credits** (1 credit = 1 successful `siteqa.audit` call ≈ $0.005) |

Failed calls are refunded. **PLANNED:** there are no payments today. In the prototype, credits are granted manually with `agentgrid.cli`, and the monthly free-tier reset is not implemented yet.

## Architecture

```
Agent / SDK / MCP client
        │  REST /v1/*  or  MCP /mcp (Streamable HTTP)  or  stdio proxy
        ▼
One Python process (stdlib ThreadingHTTPServer)
  auth (hashed API keys + scopes) → rate limit (per-key token bucket)
  → capability registry (schemas, price, limits) → reserve credits
  → worker: siteqa.audit (SSRF-guarded fetcher)
  → verification (evidence hash + HMAC signature) → settle / refund
  → execution record + audit log
        ▼
SQLite (default) · Postgres on Neon (PLANNED)
```

| Module | Role |
|---|---|
| `agentgrid/server.py` | HTTP gateway: REST routes, `/mcp`, `/healthz` |
| `agentgrid/service.py` | execution pipeline shared by REST and MCP |
| `agentgrid/registry.py` | capability registry + input validation |
| `agentgrid/siteqa.py` | the audit itself (checks, findings, evidence hash) |
| `agentgrid/fetch.py`, `ssrf.py` | pinned-IP HTTP fetcher and SSRF guard |
| `agentgrid/store.py` | SQLite: accounts, hashed keys, ledger, executions, audit log |
| `agentgrid/ratelimit.py` | in-memory token bucket |
| `agentgrid/mcp.py`, `mcp_stdio.py` | MCP JSON-RPC handler and stdio proxy |
| `agentgrid/cli.py` | local admin: create accounts, grant credits |

Design docs are in [`docs/`](docs): market research, capability selection, [V1 architecture](docs/decision/v1-architecture.md), the [roadmap](docs/roadmap.md) and the [deployment guide](docs/deploy.md).

### Known limitations

- SQLite only. Postgres via `DATABASE_URL` is **PLANNED**, and on Render's free plan SQLite data is ephemeral.
- The rate limiter is in-memory (per process).
- CPU time is measured on the request thread only (link-check threads are not counted).
- No payments, no self-serve signup, no hosted endpoint yet.

## Deployment

A `Dockerfile` and a Render Blueprint (`render.yaml`, free web service, health check `/healthz`) are included. See [docs/deploy.md](docs/deploy.md). **Not deployed yet.**

## Contributing & security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Licensed under the [MIT License](LICENSE) © 2026 SPAL AgentGrid.
