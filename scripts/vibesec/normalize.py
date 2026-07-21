"""Normalize Trivy, Gitleaks, and actionlint output."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .model import Finding


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"malformed scanner output in {path}: {exc}") from exc


def normalize_trivy(path: Path) -> list[Finding]:
    payload = _load_json(path)
    if not isinstance(payload, dict) or not isinstance(payload.get("Results", []), list):
        raise ValueError("malformed Trivy output: expected object with Results array")
    findings: list[Finding] = []
    for result in payload.get("Results", []):
        if not isinstance(result, dict):
            raise ValueError("malformed Trivy output: Results entries must be objects")
        target = str(result.get("Target", ""))
        result_class = str(result.get("Class", result.get("Type", "filesystem")))
        for vulnerability in result.get("Vulnerabilities") or []:
            findings.append(Finding.create(
                tool="trivy", category="dependency", rule_id=str(vulnerability.get("VulnerabilityID", "unknown")),
                severity=str(vulnerability.get("Severity", "unknown")), file=target,
                description=str(vulnerability.get("Title") or vulnerability.get("Description") or "Dependency vulnerability"),
                confidence="confirmed",
            ))
        for item in result.get("Misconfigurations") or []:
            findings.append(Finding.create(
                tool="trivy", category="configuration", rule_id=str(item.get("ID", "unknown")),
                severity=str(item.get("Severity", "unknown")), file=str(item.get("CauseMetadata", {}).get("Resource", target)),
                line=item.get("CauseMetadata", {}).get("StartLine"), description=str(item.get("Title") or item.get("Description") or result_class),
                confidence="possible",
            ))
        for secret in result.get("Secrets") or []:
            findings.append(Finding.create(
                tool="trivy", category="secret", rule_id=str(secret.get("RuleID", "secret")),
                severity=str(secret.get("Severity", "high")), file=target, line=secret.get("StartLine"),
                description=str(secret.get("Title") or "Potential secret detected; value omitted"), confidence="possible",
            ))
    return findings


def normalize_gitleaks(path: Path) -> list[Finding]:
    payload = _load_json(path)
    if not isinstance(payload, list):
        raise ValueError("malformed Gitleaks output: expected an array")
    findings: list[Finding] = []
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("malformed Gitleaks output: entries must be objects")
        findings.append(Finding.create(
            tool="gitleaks", category="secret", rule_id=str(item.get("RuleID", "secret")), severity="high",
            file=str(item.get("File", "")), line=item.get("StartLine"),
            description=str(item.get("Description") or "Potential secret detected; value omitted"), confidence="possible",
        ))
    return findings


ACTIONLINT_PATTERN = re.compile(r"^(?P<file>.*?):(?P<line>\d+):(?P<col>\d+): (?P<message>.*?)(?: \[(?P<rule>[^]]+)\])?$")


def normalize_actionlint(path: Path) -> list[Finding]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"malformed actionlint output: {exc}") from exc
    findings: list[Finding] = []
    for line in lines:
        if not line.strip():
            continue
        match = ACTIONLINT_PATTERN.match(line)
        if not match:
            raise ValueError(f"malformed actionlint output line: {line!r}")
        findings.append(Finding.create(
            tool="actionlint", category="ci", rule_id=match.group("rule") or "workflow-lint",
            severity="medium", file=match.group("file"), line=int(match.group("line")),
            description=match.group("message"), confidence="confirmed",
        ))
    return findings


NORMALIZERS = {"trivy": normalize_trivy, "gitleaks": normalize_gitleaks, "actionlint": normalize_actionlint}


def normalize_file(tool: str, path: Path) -> list[Finding]:
    try:
        normalizer = NORMALIZERS[tool]
    except KeyError as exc:
        raise ValueError(f"unsupported tool: {tool}") from exc
    return normalizer(path)
