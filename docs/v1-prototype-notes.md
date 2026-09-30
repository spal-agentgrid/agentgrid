# AgentGrid V1 prototype (local only, not deployed)

> Historical note: these are the original notes from when the prototype lived in `v1/`. In this repo the package sits at the root, so skip the `cd v1` step. See the top-level README for current instructions.

Stdlib-only Python 3.11+. No dependencies, no accounts, no network services except the pages you audit.

```bash
cd v1
python3 -m unittest discover -s tests -t .           # 29 tests
python3 -m agentgrid.cli --db dev.db create-account me --credits 100   # prints api_key
python3 -m agentgrid.server --db dev.db --port 8787
curl -s -X POST localhost:8787/v1/capabilities/siteqa.audit/run \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d '{"url":"https://example.com"}'
```
MCP (stdio): `{"command":"python3","args":["-m","agentgrid.mcp_stdio"],"env":{"AGENTGRID_API_KEY":"…"}}`

Known gaps: SQLite rather than Postgres; CPU time is measured on the request thread only (link-check threads not counted); in-memory rate limiter; no payments.
