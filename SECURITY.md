# Security Policy

## Status

AgentGrid V1 is a **prototype**. It is tested locally but is **not running anywhere as a production service**. Don't rely on it for anything critical yet.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

- Preferred: use GitHub's private vulnerability reporting ("Security" tab → "Report a vulnerability") on `spal-agentgrid/agentgrid`, once it is enabled for the repository.
- We aim to acknowledge reports within 5 working days and to share a fix or mitigation plan within 30 days.

Please include the affected version or commit, reproduction steps, and the impact you expect.

## Scope and areas of interest

- SSRF bypasses in the page fetcher (`agentgrid/ssrf.py`, `agentgrid/fetch.py`), e.g. DNS rebinding, redirects to private ranges, IPv6/IPv4-mapped tricks.
- API key handling (`agentgrid/store.py`): keys are stored as SHA-256 hashes and compared in constant time.
- Credit ledger integrity (double spend, refund abuse).
- Evidence hash / HMAC signature verification (`/v1/executions/{id}/verify`).

## Operational notes

- Set a strong random `AGENTGRID_SIGNING_SECRET` in any shared deployment. The server refuses to start with `AGENTGRID_ENV=production` unless this is set.
- Never commit `.env` files, SQLite databases or keys; `.gitignore` excludes them.
- `AGENTGRID_ALLOW_PRIVATE=1` turns off the SSRF guard and exists **only for tests/local fixtures**. Never set it in a deployment.
