"""Strictly normalize supported scanner output without retaining source snippets."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .model import Finding
from .strict_json import StrictJSONError, loads_strict

MAX_INPUT_BYTES = 25 * 1024 * 1024
MAX_TEXT = 2_000
MAX_ITEMS = 100_000
MAX_JSON_DEPTH = 64
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _parse_scanner_json(data: bytes, *, source: Path) -> Any:
    try:
        return loads_strict(
            data,
            maximum_bytes=MAX_INPUT_BYTES,
            maximum_depth=MAX_JSON_DEPTH,
            maximum_items=MAX_ITEMS,
            maximum_string=MAX_INPUT_BYTES,
            # Scanner fields can legitimately contain escaped line breaks in
            # source snippets that normalization subsequently discards.
            reject_controls=False,
        )
    except StrictJSONError as exc:
        raise ValueError(f"malformed scanner output in {source}: {exc}") from exc


def _read_scanner_output(path: Path) -> bytes:
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"malformed scanner output in {path}: {exc}") from exc
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(f"scanner output exceeds {MAX_INPUT_BYTES} bytes")
    return data


def load_scanner_json(path: Path) -> Any:
    data = _read_scanner_output(path)
    return _parse_scanner_json(data, source=path)


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


def _items(value: Any, *, field: str, allow_missing: bool = True) -> list[Any]:
    if value is None and allow_missing:
        return []
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise ValueError(f"malformed scanner output: {field} must be a bounded array")
    return value


def _path(value: Any, *, field: str, repository_root: Path | None = None) -> str:
    result = _text(value, field=field).replace("\\", "/")
    if result == "/workspace":
        return ""
    if result.startswith("/workspace/"):
        result = result[len("/workspace/"):]
    elif repository_root is not None:
        trusted_root = repository_root.resolve().as_posix().rstrip("/")
        if result == trusted_root:
            result = ""
        elif result.startswith(trusted_root + "/"):
            result = result[len(trusted_root) + 1:]
        elif result.startswith("/"):
            raise ValueError(
                f"malformed scanner output: {field} contains an absolute path outside the repository"
            )
    else:
        result = result.lstrip("/")
    while result.startswith("./"):
        result = result[2:]
    if ".." in result.split("/"):
        raise ValueError(f"malformed scanner output: {field} contains parent traversal")
    return result


def normalize_trivy(path: Path, repository_root: Path | None = None) -> list[Finding]:
    payload = load_scanner_json(path)
    if not isinstance(payload, dict):
        raise ValueError("malformed Trivy output: expected object with Results array")
    results = payload.get("Results")
    if results is None and isinstance(payload.get("SchemaVersion"), int) and isinstance(payload.get("Trivy"), dict):
        results = []
    if not isinstance(results, list):
        raise ValueError("malformed Trivy output: expected Results array or validated clean report metadata")
    findings: list[Finding] = []
    for result in _items(results, field="Results", allow_missing=False):
        if not isinstance(result, dict):
            raise ValueError("malformed Trivy output: Results entries must be objects")
        target = _path(
            result.get("Target", ""), field="Target", repository_root=repository_root,
        )
        result_class = _text(result.get("Class", result.get("Type", "filesystem")), field="Class")
        for vulnerability in _items(result.get("Vulnerabilities"), field="Vulnerabilities"):
            if not isinstance(vulnerability, dict):
                raise ValueError("malformed Trivy output: vulnerabilities must be objects")
            findings.append(Finding.create(
                tool="trivy", category="dependency", rule_id=_text(vulnerability.get("VulnerabilityID"), field="VulnerabilityID", required=True),
                severity=_text(vulnerability.get("Severity", "unknown"), field="Severity"), file=target,
                description=_text(vulnerability.get("Title") or vulnerability.get("Description") or "Dependency vulnerability", field="description"),
                confidence="confirmed",
                package_ecosystem=_text(result.get("Type"), field="Type") or None,
                package_name=_text(vulnerability.get("PkgName"), field="PkgName") or None,
                installed_version=_text(vulnerability.get("InstalledVersion"), field="InstalledVersion") or None,
                advisory_id=_text(vulnerability.get("VulnerabilityID"), field="VulnerabilityID", required=True),
            ))
        for item in _items(result.get("Misconfigurations"), field="Misconfigurations"):
            if not isinstance(item, dict) or not isinstance(item.get("CauseMetadata", {}), dict):
                raise ValueError("malformed Trivy output: misconfigurations must be objects")
            findings.append(Finding.create(
                tool="trivy", category="configuration", rule_id=_text(item.get("ID"), field="ID", required=True),
                severity=_text(item.get("Severity", "unknown"), field="Severity"), file=_path(
                    item.get("CauseMetadata", {}).get("Resource", target),
                    field="Resource", repository_root=repository_root,
                ),
                line=_line(item.get("CauseMetadata", {}).get("StartLine")), description=_text(item.get("Title") or item.get("Description") or result_class, field="description"),
                confidence="possible",
            ))
        for secret in _items(result.get("Secrets"), field="Secrets"):
            if not isinstance(secret, dict):
                raise ValueError("malformed Trivy output: secrets must be objects")
            findings.append(Finding.create(
                tool="trivy", category="secret", rule_id=_text(secret.get("RuleID", "secret"), field="RuleID"),
                severity=_text(secret.get("Severity", "high"), field="Severity"), file=target, line=_line(secret.get("StartLine")),
                description=_text(secret.get("Title") or "Potential secret detected; value omitted", field="description"), confidence="possible",
            ))
    return findings


def normalize_gitleaks(path: Path, repository_root: Path | None = None) -> list[Finding]:
    payload = load_scanner_json(path)
    if not isinstance(payload, list):
        raise ValueError("malformed Gitleaks output: expected an array")
    findings: list[Finding] = []
    for item in _items(payload, field="Gitleaks results", allow_missing=False):
        if not isinstance(item, dict):
            raise ValueError("malformed Gitleaks output: entries must be objects")
        findings.append(Finding.create(
            tool="gitleaks", category="secret", rule_id=_text(item.get("RuleID", "secret"), field="RuleID"), severity="high",
            file=_path(
                item.get("File", ""), field="file", repository_root=repository_root,
            ), line=_line(item.get("StartLine")),
            description=_text(item.get("Description") or "Potential secret detected; value omitted", field="description"), confidence="possible",
        ))
    return findings


def _opengrep_rule_id(value: Any) -> str:
    rule_id = _text(value, field="check_id", required=True)
    match = re.search(r"(?:^|\.)vibesec\.", rule_id)
    return rule_id[match.start() + (1 if rule_id[match.start()] == "." else 0):] if match else rule_id


def normalize_opengrep(path: Path, repository_root: Path | None = None) -> list[Finding]:
    payload = load_scanner_json(path)
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("malformed Opengrep output: expected object with results array")
    findings: list[Finding] = []
    for item in _items(payload["results"], field="Opengrep results", allow_missing=False):
        if not isinstance(item, dict) or not isinstance(item.get("extra"), dict):
            raise ValueError("malformed Opengrep output: result entries require extra objects")
        extra = item["extra"]
        metadata = extra.get("metadata") or {}
        if not isinstance(metadata, dict):
            raise ValueError("malformed Opengrep output: metadata must be an object")
        start = item.get("start") or {}
        if not isinstance(start, dict):
            raise ValueError("malformed Opengrep output: start must be an object")
        findings.append(Finding.create(
            tool="opengrep", category="sast", rule_id=_opengrep_rule_id(item.get("check_id")),
            severity=_text(extra.get("severity", "warning"), field="severity"),
            file=_path(
                item.get("path", ""), field="path", repository_root=repository_root,
            ), line=_line(start.get("line")),
            end_line=_line((item.get("end") or {}).get("line")) if isinstance(item.get("end") or {}, dict) else None,
            description=_text(extra.get("message") or "Static analysis finding", field="message"),
            confidence={"high": "confirmed", "medium": "possible", "low": "unknown"}.get(
                _text(metadata.get("confidence", "medium"), field="metadata.confidence").lower(), "possible"),
            cwe=_text(metadata.get("cwe"), field="metadata.cwe") or None,
            vulnerability_family=_text(metadata.get("category"), field="metadata.category") or None,
            sink_category=_text(metadata.get("category"), field="metadata.category") or None,
            framework=_text(metadata.get("framework"), field="metadata.framework") or None,
        ))
    return findings


def _osv_severity(vulnerability: dict[str, Any]) -> str:
    database = vulnerability.get("database_specific") or {}
    ecosystem = vulnerability.get("ecosystem_specific") or {}
    if database and not isinstance(database, dict):
        raise ValueError("malformed OSV output: database_specific must be an object")
    if ecosystem and not isinstance(ecosystem, dict):
        raise ValueError("malformed OSV output: ecosystem_specific must be an object")
    candidate = database.get("severity") or ecosystem.get("severity")
    return _text(candidate or "medium", field="severity")


def normalize_osv(path: Path, repository_root: Path | None = None) -> list[Finding]:
    payload = load_scanner_json(path)
    if not isinstance(payload, dict) or "results" not in payload:
        raise ValueError("malformed OSV-Scanner output: expected object with results array")
    results = [] if payload["results"] is None else payload["results"]
    if not isinstance(results, list):
        raise ValueError("malformed OSV-Scanner output: results must be an array or null clean result")
    findings: list[Finding] = []
    for result in _items(results, field="OSV results", allow_missing=False):
        if not isinstance(result, dict) or not isinstance(result.get("packages", []), list):
            raise ValueError("malformed OSV-Scanner output: results entries require packages arrays")
        source = result.get("source") or {}
        if source and not isinstance(source, dict):
            raise ValueError("malformed OSV-Scanner output: source must be an object")
        source_path = _path(
            source.get("path", "") if isinstance(source, dict) else "",
            field="source.path", repository_root=repository_root,
        )
        for package_result in _items(result.get("packages"), field="packages"):
            if not isinstance(package_result, dict) or not isinstance(package_result.get("vulnerabilities", []), list):
                raise ValueError("malformed OSV-Scanner output: package entries require vulnerabilities arrays")
            package = package_result.get("package") or {}
            if not isinstance(package, dict):
                raise ValueError("malformed OSV-Scanner output: package must be an object")
            package_name = _text(package.get("name") or "package", field="package.name")
            ecosystem = _text(package.get("ecosystem"), field="package.ecosystem") or None
            installed_version = _text(package.get("version"), field="package.version") or None
            for vulnerability in _items(package_result.get("vulnerabilities"), field="vulnerabilities"):
                if not isinstance(vulnerability, dict):
                    raise ValueError("malformed OSV-Scanner output: vulnerability entries must be objects")
                advisory = _text(vulnerability.get("id"), field="vulnerability.id", required=True)
                aliases = vulnerability.get("aliases") or []
                if not isinstance(aliases, list) or any(not isinstance(item, str) for item in aliases):
                    raise ValueError("malformed OSV output: vulnerability aliases must be an array of strings")
                correlation_advisory = next((item for item in aliases if item.upper().startswith("CVE-")), advisory)
                summary = _text(vulnerability.get("summary") or f"Vulnerability in {package_name}", field="summary")
                findings.append(Finding.create(
                    tool="osv-scanner", category="dependency", rule_id=advisory,
                    severity=_osv_severity(vulnerability), file=source_path,
                    description=summary, confidence="confirmed",
                    package_ecosystem=ecosystem, package_name=package_name,
                    installed_version=installed_version, advisory_id=correlation_advisory,
                ))
    return findings


def _checkov_documents(payload: Any) -> list[dict[str, Any]]:
    documents = payload if isinstance(payload, list) else [payload]
    if not documents or not all(isinstance(item, dict) for item in documents):
        raise ValueError("malformed Checkov output: expected an object or array of objects")
    return documents


def normalize_checkov(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for document in _checkov_documents(load_scanner_json(path)):
        results = document.get("results")
        if not isinstance(results, dict) or not isinstance(results.get("failed_checks", []), list):
            raise ValueError("malformed Checkov output: results.failed_checks must be an array")
        for item in _items(results.get("failed_checks"), field="failed_checks"):
            if not isinstance(item, dict):
                raise ValueError("malformed Checkov output: failed checks must be objects")
            ranges = item.get("file_line_range") or []
            line = _line(ranges[0]) if isinstance(ranges, list) and ranges else None
            findings.append(Finding.create(
                tool="checkov", category="iac", rule_id=_text(item.get("check_id"), field="check_id", required=True),
                severity=_text(item.get("severity") or "medium", field="severity"),
                file=_path(item.get("file_path") or item.get("file_abs_path") or "", field="file_path"), line=line,
                description=_text(item.get("check_name") or "Infrastructure policy finding", field="check_name"), confidence="possible",
            ))
    return findings


def normalize_trivy_image(path: Path) -> list[Finding]:
    return [Finding.create(
        tool="trivy-image", category="container", rule_id=item.rule_id, severity=item.severity,
        file=item.file, line=item.line, description=item.description, confidence=item.confidence,
    ) for item in normalize_trivy(path)]


ACTIONLINT_PATTERN = re.compile(r"^(?P<file>.*?):(?P<line>\d+):(?P<col>\d+): (?P<message>.*?)(?: \[(?P<rule>[^]]+)\])?$")


def normalize_actionlint(path: Path, repository_root: Path | None = None) -> list[Finding]:
    try:
        data = _read_scanner_output(path)
        text = data.decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise ValueError(f"malformed actionlint output: {exc}") from exc
    findings: list[Finding] = []
    stripped = text.strip()
    if stripped.startswith("["):
        payload = _parse_scanner_json(stripped.encode("utf-8"), source=path)
        if not isinstance(payload, list) or len(payload) > MAX_ITEMS:
            raise ValueError("malformed actionlint JSON output: expected a bounded array")
        for item in payload:
            if not isinstance(item, dict):
                raise ValueError("malformed actionlint JSON output: entries must be objects")
            filepath = _path(
                item.get("filepath"), field="filepath", repository_root=repository_root,
            )
            if not filepath:
                raise ValueError("malformed actionlint JSON output: filepath is required")
            findings.append(Finding.create(
                tool="actionlint", category="ci",
                rule_id=_text(item.get("kind") or "workflow-lint", field="kind"),
                severity="medium", file=filepath,
                line=_line(item.get("line")),
                description=_text(item.get("message"), field="message", required=True),
                confidence="confirmed",
            ))
        return findings
    lines = text.splitlines()
    if len(lines) > MAX_ITEMS:
        raise ValueError("malformed actionlint output: too many lines")
    for line in lines:
        if not line.strip():
            continue
        match = ACTIONLINT_PATTERN.match(line)
        if not match:
            raise ValueError(f"malformed actionlint output line: {line!r}")
        findings.append(Finding.create(
            tool="actionlint", category="ci", rule_id=_text(match.group("rule") or "workflow-lint", field="rule"),
            severity="medium", file=_path(
                match.group("file"), field="file", repository_root=repository_root,
            ), line=_line(match.group("line")),
            description=_text(match.group("message"), field="message", required=True), confidence="confirmed",
        ))
    return findings


NORMALIZERS = {
    "trivy": normalize_trivy, "trivy-image": normalize_trivy_image,
    "gitleaks": normalize_gitleaks, "actionlint": normalize_actionlint,
    "opengrep": normalize_opengrep, "osv-scanner": normalize_osv, "checkov": normalize_checkov,
}


def normalize_file(
    tool: str, path: Path, *, repository_root: Path | None = None,
) -> list[Finding]:
    try:
        normalizer = NORMALIZERS[tool]
    except KeyError as exc:
        raise ValueError(f"unsupported tool: {tool}") from exc
    if repository_root is not None and tool in {
        "trivy", "gitleaks", "actionlint", "opengrep", "osv-scanner",
    }:
        return normalizer(path, repository_root=repository_root)
    return normalizer(path)
