# Deploying AgentGrid V1 (Render + Neon)

> **Status: NOT DEPLOYED.** This guide is preparation only. Nothing described here has been created yet: no Render service, no Neon project, no DNS.

## What gets deployed

One Docker web service (`Dockerfile`) running `python -m agentgrid.server`, which serves:

- REST API under `/v1/*`
- MCP (Streamable HTTP, JSON responses) at `POST /mcp`
- Liveness probe at `GET /healthz` (no DB access) and detailed health at `GET /v1/health`

The runtime is stdlib-only, so there is no `pip install` step.

## Environment variables

| Variable | Required | Secret | Default | Purpose |
|---|---|---|---|---|
| `PORT` | set by Render | no | `8787` | Listen port |
| `AGENTGRID_HOST` | yes (in containers) | no | `127.0.0.1` (`0.0.0.0` in the Docker image) | Bind address |
| `AGENTGRID_ENV` | recommended | no | unset | Set to `production`; the server then refuses to start without a signing secret |
| `AGENTGRID_SIGNING_SECRET` | **yes** in production | **yes** | `dev-only-secret` (local only!) | HMAC key used to sign evidence hashes. Rotating it invalidates `/verify` for older executions |
| `AGENTGRID_DB` | no | no | `agentgrid.db` (`/data/agentgrid.db` in the image) | SQLite file path |
| `DATABASE_URL` | no | **yes** | unset | Neon Postgres connection string. **PLANNED:** not read yet; the server logs a warning and keeps using SQLite |
| `AGENTGRID_ACCESS_LOG` | no | no | unset | Set to any value to print HTTP access logs |
| `AGENTGRID_ALLOW_PRIVATE` | **never in prod** | no | unset | `1` disables the SSRF guard; for local tests only |

Client-side (stdio MCP proxy): `AGENTGRID_BASE_URL` (e.g. `https://agentgrid-api.onrender.com`) and `AGENTGRID_API_KEY`.

## Render (free web service)

1. Push this repo to GitHub as `spal-agentgrid/agentgrid` (not done yet).
2. In Render: **New → Blueprint**, connect the GitHub org, and select the repo. Render reads `render.yaml`:
   - `runtime: docker`, `plan: free`, `region: singapore`, `healthCheckPath: /healthz`
   - `autoDeployTrigger: checksPass`, so deploys wait for GitHub Actions CI to pass
3. When prompted for `sync: false` variables:
   - `AGENTGRID_SIGNING_SECRET`: generate one with `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`. Store it in a password manager too.
   - `DATABASE_URL`: leave empty for now (Postgres is PLANNED).
4. After the deploy, check the service:
   ```bash
   curl -s https://agentgrid-api.onrender.com/healthz
   curl -s https://agentgrid-api.onrender.com/v1/capabilities
   ```
   Your service name or URL may differ; update `server.json` → `remotes[0].url` to match.

### Free-plan caveats (important)

- **Ephemeral filesystem.** Free web services have no persistent disk, so the SQLite database (accounts, API keys, ledger, executions) is **lost on every redeploy, restart or spin-down**. Use the free plan for demos only, until Postgres support lands or you move to a paid plan with a persistent disk (Starter + disk mounted at `/data`).
- **Spin-down** after 15 minutes idle, with a cold start of about 1 minute on the next request. MCP clients may time out on the first call.
- **Account bootstrap.** Accounts and keys are created with `python -m agentgrid.cli --db $AGENTGRID_DB create-account <name> --credits 100`. That needs shell access to the instance (not available on the free plan) and does not survive a restart anyway. **PLANNED:** an authenticated admin endpoint or self-serve signup backed by Postgres.

## Neon (Postgres), PLANNED

The schema in `agentgrid/store.py` is written to port cleanly to Postgres, but the prototype is stdlib-only and Python's standard library has no Postgres driver. Adding one (`psycopg`) and a small DB adapter is the next step. It was kept out of V1 to preserve the zero-dependency property and the passing test suite.

Steps once support lands:

1. Create a Neon project (Free plan: 0.5 GB, scale-to-zero, no card) in the region closest to Render Singapore (e.g. AWS `ap-southeast-1`).
2. Create a database `agentgrid` and a role with a strong password.
3. Copy the **pooled** connection string (`postgresql://…@…-pooler…/agentgrid?sslmode=require`).
4. In Render, set `DATABASE_URL` to that string (dashboard → Environment). Never commit it.
5. Run migrations (the `SCHEMA` in `store.py`, translated: `INTEGER PRIMARY KEY AUTOINCREMENT` → `BIGSERIAL PRIMARY KEY`).
6. Redeploy and confirm `/v1/health`.

## Local Docker check

```bash
docker build -t agentgrid:dev .
docker run --rm -p 8787:8787 -e AGENTGRID_SIGNING_SECRET=local-test agentgrid:dev
curl -s localhost:8787/healthz
```
