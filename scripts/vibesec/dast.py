"""Strict configuration, normalization, and artifacts for passive baseline DAST."""

from __future__ import annotations

from datetime import date
import hashlib
import html
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Any
from urllib.parse import unquote, urlsplit

from .model import Finding
from .policy import active_suppressions, evaluate
from .strict_json import StrictJSONError, canonical_json, loads_strict

IMAGE = re.compile(r"^[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
METHOD = re.compile(r"^[A-Z]{3,10}$")
CONFIG_FIELDS = {
    "schema_version", "target_hostname", "default_target_port", "default_base_path",
    "startup_timeout_seconds", "spider_duration_minutes", "passive_scan_timeout_minutes",
    "total_scan_timeout_minutes", "maximum_normalized_findings", "maximum_raw_report_bytes",
    "maximum_response_bytes", "container_cpu_limit", "container_memory_megabytes",
    "container_pid_limit", "application_tmpfs_megabytes", "zap_tmpfs_megabytes",
    "rule_disposition_file", "output_schema_version",
}
RISK = {"0": "low", "Informational": "low", "1": "low", "Low": "low", "2": "medium", "Medium": "medium", "3": "high", "High": "high"}
CONFIDENCE = {"0": "unknown", "False Positive": "unknown", "1": "possible", "Low": "possible", "2": "possible", "Medium": "possible", "3": "confirmed", "High": "confirmed", "4": "confirmed", "Confirmed": "confirmed"}
TRUSTED_EVENTS = {"workflow_dispatch", "schedule"}
ZAP_POLICY_FILENAME = "vibesec-zap-baseline.conf"
ZAP_REPORT_FILENAME = "zap-report.json"
ZAP_TRUSTED_OPTIONS = "-silent"
ZAP_RUNTIME_ADDON_OPTIONS = frozenset({"-addonupdate", "-addoninstall", "-addoninstallall", "-addonuninstall"})


class DastError(ValueError):
    """DAST configuration or scanner evidence failed closed."""


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_config(root: Path) -> dict[str, Any]:
    try:
        payload = loads_strict((root / "config/dast-baseline.json").read_bytes())
    except (OSError, StrictJSONError) as exc:
        raise DastError(f"trusted DAST configuration is invalid: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != CONFIG_FIELDS or payload.get("schema_version") != 1 or payload.get("output_schema_version") != 1:
        raise DastError("trusted DAST configuration fields or schema are invalid")
    if payload.get("target_hostname") != "target" or payload.get("rule_disposition_file") != "config/zap-baseline.conf":
        raise DastError("trusted DAST hostname or rule policy differs from the reviewed value")
    bounds = {
        "default_target_port": (1, 65535), "startup_timeout_seconds": (5, 300),
        "spider_duration_minutes": (1, 5), "passive_scan_timeout_minutes": (1, 10),
        "total_scan_timeout_minutes": (2, 20), "maximum_normalized_findings": (1, 5000),
        "maximum_raw_report_bytes": (1024, 25_000_000), "maximum_response_bytes": (1024, 2_000_000),
        "container_cpu_limit": (1, 4), "container_memory_megabytes": (128, 4096),
        "container_pid_limit": (32, 1024), "application_tmpfs_megabytes": (8, 512),
        "zap_tmpfs_megabytes": (64, 2048),
    }
    for field, (minimum, maximum) in bounds.items():
        value = payload.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise DastError(f"trusted DAST {field} is outside its reviewed bound")
    if payload["spider_duration_minutes"] + payload["passive_scan_timeout_minutes"] > payload["total_scan_timeout_minutes"]:
        raise DastError("trusted DAST phase timeouts exceed the total scan timeout")
    validate_base_path(payload.get("default_base_path"))
    policy = root / payload["rule_disposition_file"]
    if policy.is_symlink() or not policy.is_file():
        raise DastError("trusted ZAP rule policy is missing or unsafe")
    lines = [line for line in policy.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]
    if lines != ["10020\tWARN\t(Missing Anti-clickjacking Header)"]:
        raise DastError("trusted ZAP rule policy differs from the reviewed passive rule")
    return payload


def validate_image_reference(value: str) -> str:
    if not isinstance(value, str) or not IMAGE.fullmatch(value):
        raise DastError("application image must be an immutable OCI sha256 reference")
    return value


def image_digest(value: str) -> str:
    return "sha256:" + value.rsplit("@sha256:", 1)[1]


def validate_port(value: Any) -> int:
    if isinstance(value, bool):
        raise DastError("target port must be an integer from 1 through 65535")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise DastError("target port must be an integer from 1 through 65535") from exc
    if str(port) != str(value) or not 1 <= port <= 65535:
        raise DastError("target port must be an integer from 1 through 65535")
    return port


def validate_base_path(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 512 or CONTROL.search(value):
        raise DastError("DAST base path must be a bounded absolute path")
    lowered = value.casefold()
    if any(marker in value for marker in ("\\", "?", "#")) or "://" in lowered or "%2e" in lowered or "%2f" in lowered or "%5c" in lowered:
        raise DastError("DAST base path contains a prohibited URL or encoded traversal component")
    decoded = unquote(value)
    if ".." in decoded.split("/") or CONTROL.search(decoded):
        raise DastError("DAST base path contains traversal or controls")
    return value


def trusted_event(value: str) -> bool:
    if value in TRUSTED_EVENTS:
        return True
    if value in {"pull_request", "pull_request_target"}:
        return False
    raise DastError(f"unsupported DAST event: {value or 'unset'}")


def trusted_zap_baseline_arguments(*, target_url: str, config: dict[str, Any]) -> list[str]:
    """Build the complete reviewed packaged-scan argv; callers cannot extend it."""
    parsed = urlsplit(target_url)
    if (parsed.scheme != "http" or parsed.hostname != "target" or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.port is None):
        raise DastError("ZAP target must use the exact isolated target origin")
    validate_base_path(parsed.path or "/")
    arguments = [
        "zap-baseline.py", "-t", target_url,
        "-c", ZAP_POLICY_FILENAME,
        "-m", str(config["spider_duration_minutes"]),
        "-T", str(config["passive_scan_timeout_minutes"]),
        "-J", ZAP_REPORT_FILENAME,
        "-s", "-i", "-z", ZAP_TRUSTED_OPTIONS, "--autooff",
    ]
    if arguments.count("-z") != 1 or arguments[arguments.index("-z") + 1] != ZAP_TRUSTED_OPTIONS:
        raise DastError("trusted ZAP silent-mode contract is invalid")
    if ZAP_RUNTIME_ADDON_OPTIONS.intersection(arguments):
        raise DastError("trusted ZAP command attempts a runtime add-on change")
    return arguments


def sanitize_url(value: Any, *, port: int) -> str:
    if not isinstance(value, str) or len(value) > 4096 or CONTROL.search(value):
        raise DastError("ZAP URL is missing, oversized, or contains controls")
    parsed = urlsplit(value)
    if parsed.scheme != "http" or parsed.hostname != "target" or parsed.port != port or parsed.username or parsed.password:
        raise DastError("ZAP finding escaped the exact isolated target origin")
    raw_path = parsed.path or "/"
    lowered = raw_path.casefold()
    if "%2e" in lowered or "%2f" in lowered or "%5c" in lowered or "\\" in raw_path:
        raise DastError("ZAP finding path contains encoded traversal or separators")
    path = unquote(raw_path)
    if not path.startswith("/") or len(path) > 1024 or ".." in path.split("/") or CONTROL.search(path):
        raise DastError("ZAP finding path is unsafe")
    return path


def _scalar(value: Any, field: str, limit: int = 300) -> str:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise DastError(f"ZAP {field} must be scalar")
    text = " ".join(html.unescape(str(value)).split())
    if not text or len(text) > limit or CONTROL.search(text):
        raise DastError(f"ZAP {field} is missing, oversized, or unsafe")
    return text


def normalize_zap_payload(payload: Any, *, port: int, maximum_findings: int) -> tuple[list[dict[str, Any]], int]:
    if not isinstance(payload, dict) or not isinstance(payload.get("site"), list) or len(payload["site"]) > 32:
        raise DastError("unsupported ZAP JSON report schema")
    findings: list[dict[str, Any]] = []
    urls: set[str] = set()
    for site in payload["site"]:
        if not isinstance(site, dict) or not isinstance(site.get("alerts", []), list):
            raise DastError("ZAP site entries require alerts arrays")
        for alert in site.get("alerts", []):
            if not isinstance(alert, dict):
                raise DastError("ZAP alert entries must be objects")
            rule_id = _scalar(alert.get("pluginid"), "pluginid", 32)
            if rule_id != "10020":
                continue
            risk_key = str(alert.get("riskcode", alert.get("riskdesc", ""))).split(" ", 1)[0]
            confidence_key = str(alert.get("confidence", ""))
            if risk_key not in RISK:
                raise DastError("ZAP report contains an unknown risk value")
            if confidence_key not in CONFIDENCE:
                raise DastError("ZAP report contains an unknown confidence value")
            instances = alert.get("instances")
            if not isinstance(instances, list) or len(instances) > maximum_findings:
                raise DastError("ZAP alert instances are missing or oversized")
            for instance in instances:
                if not isinstance(instance, dict):
                    raise DastError("ZAP alert instance must be an object")
                path = sanitize_url(instance.get("uri"), port=port)
                method = _scalar(instance.get("method", "GET"), "method", 10).upper()
                if not METHOD.fullmatch(method):
                    raise DastError("ZAP method is unsupported")
                name = _scalar(alert.get("alert"), "alert", 200)
                base = Finding.create(tool="zap-baseline", category="dast", rule_id=rule_id,
                                      severity=RISK[risk_key], file=path, description=name,
                                      confidence=CONFIDENCE[confidence_key]).to_dict()
                base["method"] = method
                base["cwe"] = _scalar(alert["cweid"], "cweid", 16) if alert.get("cweid") not in (None, "", "-1") else None
                base["wasc"] = _scalar(alert["wascid"], "wascid", 16) if alert.get("wascid") not in (None, "", "-1") else None
                base["remediation"] = _scalar(alert.get("solution") or "Add an anti-clickjacking response header.", "solution", 300)
                stable = "\0".join(("zap-baseline", rule_id, path, method)).encode("utf-8")
                base["fingerprint"] = hashlib.sha256(stable).hexdigest()
                findings.append(base)
                urls.add(path)
                if len(findings) > maximum_findings:
                    raise DastError("normalized DAST findings exceed the configured maximum")
    findings.sort(key=lambda item: (item["file"], item["method"], item["rule_id"], item["fingerprint"]))
    return findings, len(urls)


def normalize_zap_report(path: Path, *, port: int, maximum_bytes: int, maximum_findings: int) -> tuple[list[dict[str, Any]], int]:
    if path.is_symlink() or not path.is_file():
        raise DastError("ZAP raw report is missing or not a regular file")
    try:
        size = path.stat().st_size
        if not 1 <= size <= maximum_bytes:
            raise DastError("ZAP raw report is empty or oversized")
        payload = loads_strict(path.read_bytes(), maximum_bytes=maximum_bytes)
    except (OSError, StrictJSONError) as exc:
        raise DastError(f"ZAP raw report is malformed: {exc}") from exc
    return normalize_zap_payload(payload, port=port, maximum_findings=maximum_findings)


def tool_error(reason: str) -> dict[str, Any]:
    return Finding.create(tool="zap-baseline", category="execution", rule_id="tool-error",
                          severity="low", description=reason, confidence="confirmed",
                          result_type="tool_error").to_dict()


def write_artifacts(results: Path, *, root: Path, state: str, reason: str, event: str,
                    digest: str | None, port: int, base_path: str, findings: list[dict[str, Any]],
                    duration_seconds: int, url_count: int, exit_code: int,
                    enforcement: str, minimum_severity: str) -> None:
    if state not in {"ran", "not_configured", "not_applicable", "tool_error"}:
        raise DastError("DAST coverage state is invalid")
    payload_results = {"schema_version": 1, "profile": "dast-baseline", "results": findings}
    baseline = loads_strict((root / "policy/dast-baseline.json").read_bytes())
    suppressions_payload = loads_strict((root / "policy/dast-suppressions.json").read_bytes())
    if not isinstance(baseline, dict) or baseline.get("profile") != "dast-baseline" or not isinstance(baseline.get("fingerprints"), list):
        raise DastError("DAST baseline is malformed or has the wrong profile")
    if not isinstance(suppressions_payload, dict) or suppressions_payload.get("profile") != "dast-baseline":
        raise DastError("DAST suppressions are malformed or have the wrong profile")
    suppressions, expired = active_suppressions(suppressions_payload, date.today())
    evaluation = evaluate(findings, minimum_severity=minimum_severity, enforcement=enforcement,
                          baseline=set(baseline["fingerprints"]), suppressions=suppressions, today=date.today())
    category = {0: "pass", 1: "policy_violation", 2: "tool_error", 3: "invalid_input"}.get(exit_code)
    if category is None:
        raise DastError("DAST exit code is outside the reviewed contract")
    tools = loads_strict((root / "config/tools.json").read_bytes())
    scanner = tools["zap-baseline"]
    coverage = {
        "schema_version": 1, "profile": "dast-baseline", "tool": "zap-baseline",
        "scanner_version": scanner["version"], "scanner_image_digest": scanner["digest"],
        "target_type": "isolated_immutable_container", "target_digest": digest,
        "target_port": port, "base_path": base_path, "trusted_event": event,
        "network_mode": "internal_only", "active_scanning": False, "traditional_spider": True,
        "ajax_spider": False, "authentication": False, "external_egress": False,
        "application_code_executed": state in {"ran", "tool_error"} and digest is not None,
        "application_source_built": False, "project_dependencies_installed": False,
        "state": state, "reason": reason, "output_artifacts": ["normalized.json", "report.md", "coverage.json", "policy-result.json"],
        "limitations": ["Passive unauthenticated crawling cannot prove an application is secure or assess authorization, business logic, or injection resistance."],
        "scan_duration_seconds": max(0, duration_seconds), "url_count": max(0, url_count),
        "normalized_finding_count": len([item for item in findings if item.get("result_type") == "finding"]),
    }
    policy_result = {"schema_version": 1, "profile": "dast-baseline", "exit_code": exit_code,
                     "exit_category": category, "clean": exit_code == 0, "security_guarantee": False,
                     "findings": len(evaluation["findings"]), "violations": len(evaluation["violations"]),
                     "tool_errors": len(evaluation["tool_errors"]), "expired_suppressions": len(expired)}
    lines = ["# VibeSec DAST baseline", "", f"Status: **{category}**", "",
             f"- Coverage: {state}", f"- Passive findings: {len(evaluation['findings'])}",
             f"- Policy violations: {len(evaluation['violations'])}", "- Active scanning: false", "- External egress: false", "",
             "A passing passive scan does not prove the application is secure."]
    if evaluation["findings"]:
        lines += ["", "## Findings", "", "| Severity | Rule | Path | Method | Description |", "|---|---|---|---|---|"]
        for item in evaluation["findings"]:
            safe = lambda value: str(value or "").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")[:300]
            lines.append("| " + " | ".join(safe(value) for value in (item["severity"], item["rule_id"], item["file"], item.get("method"), item["description"])) + " |")
    atomic_write(results / "normalized.json", canonical_json(payload_results))
    atomic_write(results / "coverage.json", canonical_json(coverage))
    atomic_write(results / "policy-result.json", canonical_json(policy_result))
    atomic_write(results / "report.md", ("\n".join(lines) + "\n").encode("utf-8"))
