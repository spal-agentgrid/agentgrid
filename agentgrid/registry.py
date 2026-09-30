"""Capability registry: the single source of truth for what can be called,
its schemas, pricing and operational limits. The HTTP API, MCP server and
docs are all generated from these entries."""
from __future__ import annotations

from . import siteqa

SITEQA_INPUT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["url"],
    "properties": {
        "url": {"type": "string", "format": "uri", "maxLength": 2048,
                "description": "Public http(s) URL of the page to audit."},
        "checks": {"type": "array", "uniqueItems": True, "minItems": 1,
                   "items": {"type": "string", "enum": siteqa.ALL_CHECKS},
                   "description": "Subset of checks to run. Default: all."},
        "max_links": {"type": "integer", "minimum": 0, "maximum": 50, "default": 25,
                      "description": "Max links on the page to verify (internal first)."},
        "timeout_ms": {"type": "integer", "minimum": 1000, "maximum": 30000, "default": 15000,
                       "description": "Budget for fetching the main page."},
        "fail_on": {"type": "string", "enum": ["critical", "warning", "never"], "default": "critical",
                    "description": "Lowest severity that makes verdict=fail (for CI gating)."},
    },
}

FINDING_SCHEMA = {
    "type": "object",
    "required": ["id", "check", "severity", "title", "evidence", "recommendation"],
    "properties": {
        "id": {"type": "string", "pattern": "^[a-z0-9]+\\.[a-z0-9_]+$"},
        "check": {"type": "string", "enum": siteqa.ALL_CHECKS},
        "severity": {"type": "string", "enum": ["critical", "warning", "info"]},
        "title": {"type": "string"},
        "evidence": {"type": "object"},
        "recommendation": {"type": "string"},
    },
}

SITEQA_OUTPUT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["request_id", "capability", "version", "url", "final_url", "verdict", "counts",
                 "findings", "checks_run", "checks_skipped", "verification", "usage"],
    "properties": {
        "request_id": {"type": "string"},
        "capability": {"const": "siteqa.audit"},
        "version": {"type": "string"},
        "url": {"type": "string"},
        "final_url": {"type": "string"},
        "verdict": {"type": "string", "enum": ["pass", "fail"]},
        "fail_on": {"type": "string"},
        "counts": {"type": "object", "properties": {"critical": {"type": "integer"},
                                                    "warning": {"type": "integer"},
                                                    "info": {"type": "integer"}}},
        "summary": {"type": ["object", "null"], "properties": {
            "status_code": {"type": "integer"}, "redirects": {"type": "array"},
            "ttfb_ms": {"type": "integer"}, "total_ms": {"type": "integer"}, "bytes": {"type": "integer"},
            "content_type": {"type": ["string", "null"]}, "tls": {"type": ["object", "null"]}}},
        "findings": {"type": "array", "items": FINDING_SCHEMA},
        "checks_run": {"type": "array", "items": {"type": "string"}},
        "checks_skipped": {"type": "array", "items": {"type": "object"}},
        "verification": {"type": "object", "required": ["method", "evidence_hash", "signature"],
                         "properties": {"method": {"type": "string"},
                                        "evidence_hash": {"type": "string"},
                                        "signature": {"type": "string"}}},
        "usage": {"type": "object", "properties": {"billable_units": {"type": "integer"},
                                                   "credits_charged": {"type": "integer"},
                                                   "links_checked": {"type": "integer"},
                                                   "duration_ms": {"type": "integer"}}},
    },
}

CAPABILITIES = {
    "siteqa.audit": {
        "name": "siteqa.audit",
        "title": "Site QA Audit",
        "version": siteqa.VERSION,
        "description": ("Deterministic QA audit of a public web page: HTTP status/redirects/latency, HTTPS "
                        "redirect, TLS certificate, security headers, SEO/meta/JSON-LD validity, broken links, "
                        "mixed content, basic accessibility and robots.txt. Every finding includes evidence. "
                        "No LLM involved; same input and same site state produce the same findings."),
        "input_schema": SITEQA_INPUT_SCHEMA,
        "output_schema": SITEQA_OUTPUT_SCHEMA,
        "credits_per_call": 1,
        "price_usd_per_call": 0.005,
        "timeout_ms": 45000,
        "estimated_execution_ms": {"p50": 2500, "p95": 9000},
        "permissions": ["network:egress:public-http"],
        "scopes": ["capability:siteqa.audit"],
        "retention": {"results_days": 30, "raw_html_stored": False},
        "handler": siteqa.run_audit,
    }
}


def public_view(cap: dict) -> dict:
    return {k: v for k, v in cap.items() if k != "handler"}


class ValidationError(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def validate(schema: dict, data) -> dict:
    """Minimal validator for the subset of JSON Schema used by our input schemas.
    Returns a copy with defaults applied."""
    errors: list[str] = []
    if not isinstance(data, dict):
        raise ValidationError(["input must be a JSON object"])
    props = schema.get("properties", {})
    for req in schema.get("required", []):
        if req not in data:
            errors.append(f"'{req}' is required")
    if schema.get("additionalProperties") is False:
        for k in data:
            if k not in props:
                errors.append(f"unknown property '{k}'")
    out = {}
    for k, spec in props.items():
        if k not in data:
            if "default" in spec:
                out[k] = spec["default"]
            continue
        v = data[k]
        t = spec.get("type")
        if t == "string":
            if not isinstance(v, str):
                errors.append(f"'{k}' must be a string"); continue
            if "maxLength" in spec and len(v) > spec["maxLength"]:
                errors.append(f"'{k}' too long")
            if "enum" in spec and v not in spec["enum"]:
                errors.append(f"'{k}' must be one of {spec['enum']}")
            if spec.get("format") == "uri" and not v.lower().startswith(("http://", "https://")):
                errors.append(f"'{k}' must be an http(s) URL")
        elif t == "integer":
            if not isinstance(v, int) or isinstance(v, bool):
                errors.append(f"'{k}' must be an integer"); continue
            if "minimum" in spec and v < spec["minimum"]:
                errors.append(f"'{k}' must be >= {spec['minimum']}")
            if "maximum" in spec and v > spec["maximum"]:
                errors.append(f"'{k}' must be <= {spec['maximum']}")
        elif t == "array":
            if not isinstance(v, list):
                errors.append(f"'{k}' must be an array"); continue
            if spec.get("minItems") and len(v) < spec["minItems"]:
                errors.append(f"'{k}' must have at least {spec['minItems']} item(s)")
            if spec.get("uniqueItems") and len(set(map(str, v))) != len(v):
                errors.append(f"'{k}' items must be unique")
            enum = spec.get("items", {}).get("enum")
            if enum:
                bad = [x for x in v if x not in enum]
                if bad:
                    errors.append(f"'{k}' has invalid values {bad}; allowed {enum}")
        out[k] = v
    if errors:
        raise ValidationError(errors)
    return out
