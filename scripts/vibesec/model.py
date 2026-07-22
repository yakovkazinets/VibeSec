"""Shared result model for scanner findings and execution outcomes."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import PurePosixPath
from typing import Any

SEVERITIES = ("low", "medium", "high", "critical")
RESULT_TYPES = ("finding", "tool_error", "pass")


def normalize_path(value: str | None) -> str:
    path = (value or "").replace("\\", "/").strip()
    while path.startswith("./"):
        path = path[2:]
    return str(PurePosixPath(path)) if path else ""


def normalize_severity(value: str | None) -> str:
    raw = (value or "").strip().lower()
    aliases = {
        "unknown": "low",
        "info": "low",
        "informational": "low",
        "warning": "medium",
        "error": "high",
        "moderate": "medium",
        "important": "high",
        "severe": "critical",
    }
    normalized = aliases.get(raw, raw)
    if normalized not in SEVERITIES:
        raise ValueError(f"unsupported severity: {value!r}")
    return normalized


def fingerprint_for(tool: str, category: str, rule_id: str, file: str, line: int | None, description: str) -> str:
    stable = "\0".join(
        [
            tool.strip().lower(),
            category.strip().lower(),
            rule_id.strip().lower(),
            normalize_path(file).lower(),
            str(line or 0),
            " ".join(description.split()).lower(),
        ]
    )
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Finding:
    tool: str
    category: str
    rule_id: str
    severity: str
    file: str
    line: int | None
    description: str
    confidence: str
    fingerprint: str
    result_type: str = "finding"
    end_line: int | None = None
    cwe: str | None = None
    vulnerability_family: str | None = None
    sink_category: str | None = None
    framework: str | None = None
    package_ecosystem: str | None = None
    package_name: str | None = None
    installed_version: str | None = None
    advisory_id: str | None = None
    direct_dependency: bool | None = None
    reachable_sink: bool | None = None
    known_exploited: bool | None = None

    def __post_init__(self) -> None:
        if self.result_type not in RESULT_TYPES:
            raise ValueError(f"unsupported result type: {self.result_type}")
        if self.result_type == "finding" and self.severity not in SEVERITIES:
            raise ValueError(f"unsupported normalized severity: {self.severity}")
        if self.confidence not in ("confirmed", "possible", "unknown"):
            raise ValueError(f"unsupported confidence: {self.confidence}")

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        required = {"tool", "category", "rule_id", "severity", "file", "line", "description",
                    "confidence", "fingerprint", "result_type"}
        return {key: value for key, value in payload.items() if key in required or value is not None}

    @classmethod
    def create(
        cls,
        *,
        tool: str,
        category: str,
        rule_id: str,
        severity: str,
        file: str = "",
        line: int | None = None,
        description: str,
        confidence: str = "possible",
        result_type: str = "finding",
        end_line: int | None = None,
        cwe: str | None = None,
        vulnerability_family: str | None = None,
        sink_category: str | None = None,
        framework: str | None = None,
        package_ecosystem: str | None = None,
        package_name: str | None = None,
        installed_version: str | None = None,
        advisory_id: str | None = None,
        direct_dependency: bool | None = None,
        reachable_sink: bool | None = None,
        known_exploited: bool | None = None,
    ) -> "Finding":
        normalized_file = normalize_path(file)
        normalized_severity = normalize_severity(severity) if result_type == "finding" else "low"
        fingerprint = fingerprint_for(tool, category, rule_id, normalized_file, line, description)
        return cls(
            tool, category, rule_id, normalized_severity, normalized_file, line,
            description, confidence, fingerprint, result_type, end_line, cwe,
            vulnerability_family, sink_category, framework, package_ecosystem,
            package_name, installed_version, advisory_id, direct_dependency,
            reachable_sink, known_exploited,
        )
