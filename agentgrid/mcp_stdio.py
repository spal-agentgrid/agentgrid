"""stdio MCP server that proxies tool calls to an AgentGrid HTTP API.

Config (env): AGENTGRID_API_KEY, AGENTGRID_BASE_URL (default http://127.0.0.1:8787).
Usage in an MCP client config:  {"command": "python3", "args": ["-m", "agentgrid.mcp_stdio"]}
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

from . import mcp


def _call_remote(capability: str, arguments: dict):
    base = os.environ.get("AGENTGRID_BASE_URL", "http://127.0.0.1:8787").rstrip("/")
    req = urllib.request.Request(f"{base}/v1/capabilities/{capability}/run", data=json.dumps(arguments).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {os.environ.get('AGENTGRID_API_KEY', '')}"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")
    except urllib.error.URLError as e:
        return 502, {"error": {"code": "GATEWAY_UNREACHABLE", "message": str(e.reason), "retryable": True}}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            resp = mcp.handle(msg, _call_remote)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
