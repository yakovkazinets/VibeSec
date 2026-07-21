"""Strictly normalize supported scanner output without retaining source snippets."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .model import Finding

MAX_INPUT_BYTES = 25 * 1024 * 1024
MAX_TEXT = 2_000
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _load_json(path: Path) -> Any:
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError(f"scanner output exceeds {MAX_INPUT_BYTES} bytes")
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"malformed scanner output in {path}: {exc}") from exc


def _text(value: Any, *, field: str, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, (str, int, float)):
        raise ValueError(f"malformed scanner output: {field} must be scalar")
    result = " ".join(str(value).split())[:MAX_TEXT]
    if CONTROL.search(result):
        raise ValueError(f"malformed scanner output: {field} contains control characters")
    if required and not result:
        raise ValueError(f"malformed scanner output: {field} is required")
    return result


def _line(value: Any) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise ValueError("malformed scanner output: line must be a positive integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("malformed scanner output: line must be a positive integer") from exc
    if result < 1 or result > 10_000_000:
        raise ValueError("malformed scanner output: line is outside the accepted range")
    return result


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
                line=_line(item.get("CauseMetadata", {}).get("StartLine")), description=_text(item.get("Title") or item.get("Description") or result_class, field="description"),
                confidence="possible",
            ))
        for secret in result.get("Secrets") or []:
            findings.append(Finding.create(
                tool="trivy", category="secret", rule_id=str(secret.get("RuleID", "secret")),
                severity=str(secret.get("Severity", "high")), file=target, line=_line(secret.get("StartLine")),
                description=_text(secret.get("Title") or "Potential secret detected; value omitted", field="description"), confidence="possible",
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
            file=_text(item.get("File", ""), field="file"), line=_line(item.get("StartLine")),
            description=_text(item.get("Description") or "Potential secret detected; value omitted", field="description"), confidence="possible",
        ))
    return findings


def normalize_opengrep(path: Path) -> list[Finding]:
    payload = _load_json(path)
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("malformed Opengrep output: expected object with results array")
    findings: list[Finding] = []
    for item in payload["results"]:
        if not isinstance(item, dict) or not isinstance(item.get("extra"), dict):
            raise ValueError("malformed Opengrep output: result entries require extra objects")
        extra = item["extra"]
        start = item.get("start") or {}
        if not isinstance(start, dict):
            raise ValueError("malformed Opengrep output: start must be an object")
        findings.append(Finding.create(
            tool="opengrep", category="sast", rule_id=_text(item.get("check_id"), field="check_id", required=True),
            severity=_text(extra.get("severity", "warning"), field="severity"),
            file=_text(item.get("path", ""), field="path"), line=_line(start.get("line")),
            description=_text(extra.get("message") or "Static analysis finding", field="message"), confidence="possible",
        ))
    return findings


def _osv_severity(vulnerability: dict[str, Any]) -> str:
    database = vulnerability.get("database_specific") or {}
    if database and not isinstance(database, dict):
        raise ValueError("malformed OSV output: database_specific must be an object")
    candidate = database.get("severity") if isinstance(database, dict) else None
    return _text(candidate or "unknown", field="severity")


def normalize_osv(path: Path) -> list[Finding]:
    payload = _load_json(path)
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("malformed OSV-Scanner output: expected object with results array")
    findings: list[Finding] = []
    for result in payload["results"]:
        if not isinstance(result, dict) or not isinstance(result.get("packages", []), list):
            raise ValueError("malformed OSV-Scanner output: results entries require packages arrays")
        source = result.get("source") or {}
        if source and not isinstance(source, dict):
            raise ValueError("malformed OSV-Scanner output: source must be an object")
        source_path = _text(source.get("path", "") if isinstance(source, dict) else "", field="source.path")
        for package_result in result.get("packages", []):
            if not isinstance(package_result, dict) or not isinstance(package_result.get("vulnerabilities", []), list):
                raise ValueError("malformed OSV-Scanner output: package entries require vulnerabilities arrays")
            package = package_result.get("package") or {}
            if not isinstance(package, dict):
                raise ValueError("malformed OSV-Scanner output: package must be an object")
            package_name = _text(package.get("name") or "package", field="package.name")
            for vulnerability in package_result.get("vulnerabilities", []):
                if not isinstance(vulnerability, dict):
                    raise ValueError("malformed OSV-Scanner output: vulnerability entries must be objects")
                advisory = _text(vulnerability.get("id"), field="vulnerability.id", required=True)
                summary = _text(vulnerability.get("summary") or f"Vulnerability in {package_name}", field="summary")
                findings.append(Finding.create(
                    tool="osv-scanner", category="dependency", rule_id=advisory,
                    severity=_osv_severity(vulnerability), file=source_path,
                    description=summary, confidence="confirmed",
                ))
    return findings


def _checkov_documents(payload: Any) -> list[dict[str, Any]]:
    documents = payload if isinstance(payload, list) else [payload]
    if not documents or not all(isinstance(item, dict) for item in documents):
        raise ValueError("malformed Checkov output: expected an object or array of objects")
    return documents


def normalize_checkov(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for document in _checkov_documents(_load_json(path)):
        results = document.get("results")
        if not isinstance(results, dict) or not isinstance(results.get("failed_checks", []), list):
            raise ValueError("malformed Checkov output: results.failed_checks must be an array")
        for item in results.get("failed_checks", []):
            if not isinstance(item, dict):
                raise ValueError("malformed Checkov output: failed checks must be objects")
            ranges = item.get("file_line_range") or []
            line = _line(ranges[0]) if isinstance(ranges, list) and ranges else None
            findings.append(Finding.create(
                tool="checkov", category="iac", rule_id=_text(item.get("check_id"), field="check_id", required=True),
                severity=_text(item.get("severity") or "medium", field="severity"),
                file=_text(item.get("file_abs_path") or item.get("file_path") or "", field="file_path"), line=line,
                description=_text(item.get("check_name") or "Infrastructure policy finding", field="check_name"), confidence="possible",
            ))
    return findings


def normalize_trivy_image(path: Path) -> list[Finding]:
    return [Finding.create(
        tool="trivy-image", category="container", rule_id=item.rule_id, severity=item.severity,
        file=item.file, line=item.line, description=item.description, confidence=item.confidence,
    ) for item in normalize_trivy(path)]


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


NORMALIZERS = {
    "trivy": normalize_trivy, "trivy-image": normalize_trivy_image,
    "gitleaks": normalize_gitleaks, "actionlint": normalize_actionlint,
    "opengrep": normalize_opengrep, "osv-scanner": normalize_osv, "checkov": normalize_checkov,
}


def normalize_file(tool: str, path: Path) -> list[Finding]:
    try:
        normalizer = NORMALIZERS[tool]
    except KeyError as exc:
        raise ValueError(f"unsupported tool: {tool}") from exc
    return normalizer(path)
