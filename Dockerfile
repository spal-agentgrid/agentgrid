# SPAL AgentGrid V1: Python API (REST + MCP). Stdlib core + pg8000 (pure Python) for optional Postgres.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="SPAL AgentGrid" \
      org.opencontainers.image.description="siteqa.audit: deterministic website QA audits for AI agents (REST + MCP)" \
      org.opencontainers.image.source="https://github.com/spal-agentgrid/agentgrid" \
      org.opencontainers.image.licenses="MIT" \
      io.modelcontextprotocol.server.name="io.github.spal-agentgrid/siteqa"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AGENTGRID_HOST=0.0.0.0 \
    PORT=8787 \
    AGENTGRID_DB=/data/agentgrid.db

RUN useradd --create-home --uid 10001 agentgrid \
 && mkdir -p /data && chown agentgrid:agentgrid /data

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt
COPY agentgrid/ ./agentgrid/
COPY LICENSE README.md ./

USER agentgrid
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8787\")}/healthz', timeout=4)" || exit 1

CMD ["python", "-m", "agentgrid.server"]
