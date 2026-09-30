# Deploying AgentGrid V1 (Render + optional Neon Postgres)

> **Status:** see the README for the live URL once deployed. Neon Postgres is **not connected yet** (PLANNED); without `DATABASE_URL` the service runs in SQLite demo mode, which is ephemeral on the free plan.

## What gets deployed

One Docker web service (`Dockerfile`) running `python -m agentgrid.server`, which serves:

- REST API under `/v1/*`, including self-serve signup (`POST /v1/signup`) and the admin API (`/v1/admin/*`)
- MCP (Streamable HTTP, JSON responses) at `POST /mcp`
- Liveness probe at `GET /healthz` (no DB access) and detailed health at `GET /v1/health` (reports `storage: sqlite|postgres`)

The image installs `requirements.txt` (only `pg8000`, a pure-Python Postgres driver). The core is stdlib-only.

## Environment variables

| Variable | Required | Secret | Default | Purpose |
|---|---|---|---|---|
| `PORT` | set by Render | no | `8787` | Listen port |
| `AGENTGRID_HOST` | yes (in containers) | no | `127.0.0.1` (`0.0.0.0` in the Docker image) | Bind address |
| `AGENTGRID_ENV` | recommended | no | unset | Set to `production`; the server then refuses to start without a signing secret |
| `AGENTGRID_SIGNING_SECRET` | **yes** in production | **yes** | `dev-only-secret` (local only!) | HMAC key used to sign evidence hashes. Rotating it invalidates `/verify` for older executions |
| `AGENTGRID_ADMIN_TOKEN` | to use the admin API | **yes** | unset (admin API disabled, routes return 404) | Bearer token for `/v1/admin/*`; must be ≥ 32 chars (`openssl rand -hex 32`) or the server refuses to start |
| `DATABASE_URL` | no | **yes** | unset | Postgres URL, e.g. Neon `postgresql://…-pooler…/agentgrid?sslmode=require`. When set, SQLite is not used |
| `AGENTGRID_DB` | no | no | `agentgrid.db` (`/data/agentgrid.db` in the image) | SQLite file path (only without `DATABASE_URL`) |
| `AGENTGRID_SIGNUP_CREDITS` | no | no | `100` | Free credits granted on signup |
| `AGENTGRID_SIGNUP_PER_IP_PER_HOUR` | no | no | `5` | Signups allowed per client IP per hour |
| `AGENTGRID_SIGNUP_GLOBAL_PER_HOUR` | no | no | `200` | Global signup cap per hour (backstop against IP spoofing/rotation) |
| `AGENTGRID_SIGNUP_ENABLED` | no | no | `1` | `0` disables `POST /v1/signup` (403) |
| `AGENTGRID_TRUSTED_PROXY_HOPS` | behind a proxy | no | `0` | Use the N-th entry from the right of `X-Forwarded-For` as the client IP. `0` = socket peer. Check with `GET /v1/admin/request-info` |
| `AGENTGRID_ACCESS_LOG` | no | no | unset | Set to any value to print HTTP access logs |
| `AGENTGRID_ALLOW_PRIVATE` | **never in prod** | no | unset | `1` disables the SSRF guard; for local tests only |

Client-side (stdio MCP proxy): `AGENTGRID_BASE_URL` (your service URL) and `AGENTGRID_API_KEY`.

## Render (free web service)

Either use the Blueprint (`render.yaml`: **New → Blueprint**, pick the repo) or create the web service through the dashboard or the Render REST API with the same settings:

- `runtime: docker`, `plan: free`, `region: singapore`, `healthCheckPath: /healthz`, branch `main`, auto-deploy on
- Env: `AGENTGRID_ENV=production`, `AGENTGRID_HOST=0.0.0.0`, and the secrets `AGENTGRID_SIGNING_SECRET` and `AGENTGRID_ADMIN_TOKEN` (generate each with `openssl rand -hex 32`, keep them in a password manager, never commit them)
- `DATABASE_URL`: leave empty until Neon is connected
- Render needs GitHub access to the `spal-agentgrid` org (install the Render GitHub App on the org) to build from the repo

After the deploy, check the service (replace the URL with yours):

```bash
BASE=https://<service>.onrender.com
curl -s $BASE/healthz
curl -s $BASE/v1/health
curl -s -X POST $BASE/v1/signup -H "Content-Type: application/json" -d '{"email":"you@example.com"}'
curl -s -H "Authorization: Bearer $AGENTGRID_ADMIN_TOKEN" $BASE/v1/admin/request-info   # client-IP derivation
```

Update `server.json` → `remotes[0].url` to `$BASE/mcp` if the URL changes.

### Free-plan caveats (important)

- **Ephemeral filesystem.** Free web services have no persistent disk. Without `DATABASE_URL`, the SQLite database (accounts, API keys, ledger, executions) is **lost on every redeploy, restart or spin-down**, so signed-up keys stop working. Treat this as demo mode until Neon is connected.
- **Spin-down** after 15 minutes idle, with a cold start of about 1 minute on the next request. MCP clients may time out on the first call.
- **Account bootstrap:** use `POST /v1/signup`, and the admin API to grant extra credits.

## Neon (Postgres)

Postgres support is implemented (`agentgrid/db.py`, driver `pg8000`) and tested in CI against a Postgres 17 service container. The schema is created automatically on startup (`CREATE TABLE IF NOT EXISTS`, `BIGSERIAL` ids, `DOUBLE PRECISION` metrics). Connecting a Neon database is **PLANNED**:

1. Create a Neon project (Free plan) in AWS `ap-southeast-1` (Singapore, next to Render Singapore).
2. Create a database `agentgrid` and a role with a strong password.
3. Copy the **pooled** connection string (`postgresql://…@…-pooler…/agentgrid?sslmode=require`). TLS is verified with the system CA store; SNI is sent, so Neon endpoint routing works.
4. In Render, set `DATABASE_URL` to that string (dashboard → Environment, or the API). Never commit it.
5. Redeploy and confirm `GET /v1/health` reports `"storage": "postgres"`.

Dropped connections (e.g. Neon scale-to-zero) are re-established automatically on the next query outside a transaction.

To run the test suite against a local Postgres: `AGENTGRID_TEST_DATABASE_URL=postgresql://user:pass@localhost:5432/db python -m unittest discover -s tests`.

## Local Docker check

```bash
docker build -t agentgrid:dev .
docker run --rm -p 8787:8787 -e AGENTGRID_SIGNING_SECRET=local-test agentgrid:dev
curl -s localhost:8787/healthz
```
