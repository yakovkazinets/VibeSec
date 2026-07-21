"""Standard profile coverage model and safe Markdown rendering."""

from __future__ import annotations

import re
from typing import Any

STATES = {"ran", "not_applicable", "not_configured", "tool_error"}
NETWORK = {"none", "advisory_queries", "local_database", "scanner_managed"}
STANDARD_TOOLS = {"opengrep", "osv-scanner", "syft", "checkov", "trivy", "gitleaks", "actionlint", "trivy-image"}
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
MAX_TEXT = 500
MAX_PATHS = 100_000


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_TEXT or CONTROL.search(value):
        raise ValueError(f"coverage {field} must be nonempty bounded text without controls")
    return value


def _paths(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_PATHS:
        raise ValueError(f"coverage {field} must be a bounded array")
    for item in value:
        _text(item, field)
        if item.startswith("/") or ".." in item.split("/") or "\\" in item:
            raise ValueError(f"coverage {field} paths must be repository-relative")
    return value


def validate_coverage(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema_version") != 1 or not isinstance(payload.get("tools"), list):
        raise ValueError("coverage must be a schema-version 1 object with a tools array")
    seen: set[str] = set()
    for item in payload["tools"]:
        if not isinstance(item, dict) or item.get("state") not in STATES:
            raise ValueError("coverage tool entries require a valid state")
        for key in ("tool", "version", "scope", "reason"):
            _text(item.get(key), f"tool.{key}")
        if item["tool"] in seen:
            raise ValueError(f"coverage contains duplicate tool entry {item['tool']}")
        seen.add(item["tool"])
        _paths(item.get("relevant_artifacts"), "relevant_artifacts")
        _paths(item.get("output_files"), "output_files")
        if item.get("network_access") not in NETWORK:
            raise ValueError("coverage tool entries require a valid network_access")
        if not isinstance(item.get("application_code_executed"), bool):
            raise ValueError("coverage tool entries require application_code_executed boolean")
    if payload.get("profile") == "standard" and seen != STANDARD_TOOLS:
        raise ValueError(f"Standard coverage must contain exactly {sorted(STANDARD_TOOLS)}")
    for key in ("limitations", "outside_coverage"):
        values = payload.get(key)
        if not isinstance(values, list) or not values:
            raise ValueError(f"coverage requires a nonempty {key} array")
        for value in values:
            _text(value, key)
    return payload


def _cell(value: str) -> str:
    return (value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("`", "&#96;").replace("|", "\\|").replace("\r", " ").replace("\n", " "))


def markdown(payload: dict[str, Any]) -> str:
    validate_coverage(payload)
    lines = ["## Standard profile coverage", "", "| Tool | Version | Scope | State | Network | Reason |", "|---|---|---|---|---|---|"]
    for item in sorted(payload["tools"], key=lambda value: value["tool"]):
        values = [_cell(str(item[key])) for key in ("tool", "version", "scope", "state", "network_access", "reason")]
        lines.append("| " + " | ".join(values) + " |")
    lines.extend(["", "### Limitations", ""] + [f"- {_cell(value)}" for value in payload["limitations"]])
    lines.extend(["", "### Outside coverage", ""] + [f"- {_cell(value)}" for value in payload["outside_coverage"]])
    return "\n".join(lines) + "\n"
