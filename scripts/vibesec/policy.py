"""Evaluate normalized findings against baseline and suppression policy."""

from __future__ import annotations

from datetime import date
import json
from pathlib import Path
from typing import Any

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
PRIORITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


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


def evaluate_priority(groups: list[dict[str, Any]], controls: Any) -> list[dict[str, Any]]:
    """Evaluate optional group controls without changing legacy finding policy."""
    if controls is None:
        return []
    if not isinstance(controls, dict) or set(controls) != {
            "enabled", "minimum_priority", "minimum_independent_scanners", "require_confirmed_runtime"}:
        raise ConfigurationError("finding_intelligence policy controls are malformed")
    if type(controls["enabled"]) is not bool or type(controls["require_confirmed_runtime"]) is not bool:
        raise ConfigurationError("finding_intelligence Boolean controls are malformed")
    minimum = controls["minimum_priority"]
    scanner_minimum = controls["minimum_independent_scanners"]
    if minimum not in PRIORITY_RANK:
        raise ConfigurationError("finding_intelligence minimum_priority is invalid")
    if scanner_minimum is not None and (type(scanner_minimum) is not int or not 1 <= scanner_minimum <= 16):
        raise ConfigurationError("finding_intelligence minimum_independent_scanners is invalid")
    if not controls["enabled"]:
        return []
    violations: list[dict[str, Any]] = []
    for group in groups:
        if (not isinstance(group, dict) or group.get("priority") not in PRIORITY_RANK
                or type(group.get("independent_scanner_count")) is not int
                or type(group.get("confirmed_runtime")) is not bool):
            raise ConfigurationError("prioritized finding group is malformed")
        if PRIORITY_RANK[group["priority"]] < PRIORITY_RANK[minimum]:
            continue
        if scanner_minimum is not None and group["independent_scanner_count"] < scanner_minimum:
            continue
        if controls["require_confirmed_runtime"] and not group["confirmed_runtime"]:
            continue
        violations.append(group)
    return violations
