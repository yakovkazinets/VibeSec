"""Standard profile coverage model and safe Markdown rendering."""

from __future__ import annotations

from typing import Any

STATES = {"ran", "not_applicable", "not_configured", "tool_error"}


def validate_coverage(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema_version") != 1 or not isinstance(payload.get("tools"), list):
        raise ValueError("coverage must be a schema-version 1 object with a tools array")
    for item in payload["tools"]:
        if not isinstance(item, dict) or item.get("state") not in STATES:
            raise ValueError("coverage tool entries require a valid state")
        if not all(isinstance(item.get(key), str) and item[key] for key in ("tool", "scope", "reason")):
            raise ValueError("coverage tool entries require tool, scope, and reason")
    return payload


def markdown(payload: dict[str, Any]) -> str:
    validate_coverage(payload)
    lines = ["## Standard profile coverage", "", "| Tool | Scope | State | Reason |", "|---|---|---|---|"]
    for item in sorted(payload["tools"], key=lambda value: (value["tool"], value["scope"])):
        values = [str(item[key]).replace("|", "\\|").replace("\n", " ") for key in ("tool", "scope", "state", "reason")]
        lines.append("| " + " | ".join(values) + " |")
    return "\n".join(lines) + "\n"
