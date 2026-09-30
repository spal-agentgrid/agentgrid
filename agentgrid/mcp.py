"""Minimal MCP (Model Context Protocol) JSON-RPC handler, transport-agnostic.
Used by the HTTP endpoint (POST /mcp, JSON responses per Streamable HTTP) and
by the stdio server."""
from __future__ import annotations

import json

from . import __version__, registry

SUPPORTED_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26"]


def tool_name(capability: str) -> str:
    return capability.replace(".", "_")


def tool_definitions() -> list[dict]:
    tools = []
    for cap in registry.CAPABILITIES.values():
        tools.append({
            "name": tool_name(cap["name"]),
            "title": cap["title"],
            "description": cap["description"] + f" Costs {cap['credits_per_call']} credit per successful call; "
                                                "failed calls are refunded.",
            "inputSchema": cap["input_schema"],
            "outputSchema": cap["output_schema"],
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True,
                            "openWorldHint": True},
        })
    return tools


def handle(message: dict, call_tool) -> dict | None:
    """call_tool(capability, arguments) -> (http_status, body). Returns a JSON-RPC
    response, or None for notifications."""
    mid = message.get("id")
    method = message.get("method")
    if mid is None:  # notification (e.g. notifications/initialized)
        return None

    def ok(result):
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def err(code, msg):
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": msg}}

    if method == "initialize":
        requested = (message.get("params") or {}).get("protocolVersion")
        version = requested if requested in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0]
        return ok({"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                   "serverInfo": {"name": "spal-agentgrid", "title": "SPAL AgentGrid", "version": __version__},
                   "instructions": "Deterministic, metered capabilities. Each tool result includes "
                                   "verification.evidence_hash and a server signature."})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": tool_definitions()})
    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name", "")
        cap = next((c for c in registry.CAPABILITIES if tool_name(c) == name), None)
        if cap is None:
            return err(-32602, f"unknown tool '{name}'")
        status, body = call_tool(cap, params.get("arguments") or {})
        text = json.dumps(body)
        if status == 200:
            return ok({"content": [{"type": "text", "text": text}], "structuredContent": body, "isError": False})
        return ok({"content": [{"type": "text", "text": text}], "isError": True})
    return err(-32601, f"method not found: {method}")
