"""Evaluate normalized findings against baseline and suppression policy."""

from __future__ import annotations

from datetime import date
import json
from pathlib import Path
from typing import Any

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class ConfigurationError(ValueError):
    """Policy or result input is invalid."""


def load_json_yaml(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"invalid configuration in {path}: {exc}") from exc


def active_suppressions(payload: Any, today: date) -> tuple[set[str], list[str]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("suppressions"), list):
        raise ConfigurationError("suppressions must contain a suppressions array")
    active: set[str] = set()
    expired: list[str] = []
    for item in payload["suppressions"]:
        if not isinstance(item, dict):
            raise ConfigurationError("each suppression must be an object")
        required = ("finding_fingerprint", "reason", "owner", "expiration_date")
        if any(not item.get(field) for field in required):
            raise ConfigurationError("suppression requires fingerprint, reason, owner, and expiration date")
        try:
            expiration = date.fromisoformat(str(item["expiration_date"]))
        except ValueError as exc:
            raise ConfigurationError("suppression expiration_date must use YYYY-MM-DD") from exc
        fingerprint = str(item["finding_fingerprint"])
        if expiration < today:
            expired.append(fingerprint)
        else:
            active.add(fingerprint)
    return active, expired


def evaluate(
    results: list[dict[str, Any]], *, minimum_severity: str, enforcement: str,
    baseline: set[str], suppressions: set[str], today: date,
) -> dict[str, Any]:
    del today
    if minimum_severity not in SEVERITY_RANK:
        raise ConfigurationError(f"invalid minimum severity: {minimum_severity}")
    if enforcement not in ("observe", "new", "all"):
        raise ConfigurationError(f"invalid enforcement mode: {enforcement}")
    for item in results:
        if not isinstance(item, dict) or item.get("result_type") not in ("finding", "tool_error", "pass"):
            raise ConfigurationError("each result must be an object with a valid result_type")
        required = ("tool", "category", "rule_id", "description", "confidence", "fingerprint")
        if any(field not in item for field in required):
            raise ConfigurationError("result is missing a required shared-model field")
    tool_errors = [item for item in results if item.get("result_type") == "tool_error"]
    findings = [item for item in results if item.get("result_type") == "finding"]
    for item in findings:
        if item.get("severity") not in SEVERITY_RANK or not item.get("fingerprint"):
            raise ConfigurationError("finding has invalid severity or missing fingerprint")
    considered = [item for item in findings if SEVERITY_RANK[item["severity"]] >= SEVERITY_RANK[minimum_severity]]
    unsuppressed = [item for item in considered if item["fingerprint"] not in suppressions]
    new_findings = [item for item in unsuppressed if item["fingerprint"] not in baseline]
    violations = [] if enforcement == "observe" else (new_findings if enforcement == "new" else unsuppressed)
    return {
        "tool_errors": tool_errors,
        "findings": findings,
        "considered": considered,
        "new_findings": new_findings,
        "violations": violations,
        "status": "tool_error" if tool_errors else ("policy_violation" if violations else "pass"),
    }
