"""Strict configuration, evidence normalization, and artifacts for active API testing."""

from __future__ import annotations

from datetime import date
import hashlib
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .api_security import atomic_write, sanitize_path_template
from .authenticated import authentication_evidence, validate_publishable_bytes
from .finding_intelligence import FindingIntelligenceError, SourceDocument, build as build_finding_intelligence
from .model import Finding
from .policy import active_suppressions, evaluate
from .strict_json import StrictJSONError, canonical_json, loads_strict

PROFILE = "api-fuzzing"
INSTALLED_CONFIG_PATH = ".vibesec/api-fuzzing.json"
RAW_REPORT_FILENAME = "fuzzing-events.ndjson"
MODES = ("contract", "fuzz", "injection", "combined")
LOCATIONS = ("body", "header", "path", "query")
PARAMETER_LOCATIONS = set(LOCATIONS) | {"none"}
FAMILY_DETAILS = {
    "command-marker": ("command-injection", "Potential command injection handling weakness", "CWE-78"),
    "header-marker": ("header-injection", "Header injection input handling weakness", "CWE-113"),
    "path-marker": ("path-traversal", "Path traversal input handling weakness", "CWE-22"),
    "sql-marker": ("sql-injection", "Potential SQL injection handling weakness", "CWE-89"),
    "template-marker": ("template-injection", "Template injection input handling weakness", "CWE-1336"),
}
DETECTION_REASONS = {
    "controlled_5xx", "response_schema_violation", "status_code_violation", "reflected_marker",
    "framework_error_pattern", "request_timeout", "target_process_termination",
    "unexpected_connection_closure", "semantic_mismatch",
}
RUNTIME_FAILURE_REASONS = {"request_timeout", "target_process_termination", "unexpected_connection_closure"}
CHECK_IDS = {
    "not_a_server_error", "status_code_conformance", "response_schema_conformance", "reflected_marker",
    "framework_error_pattern", "request_timeout", "target_process_termination",
    "unexpected_connection_closure", "semantic_mismatch",
}
FRAMEWORK_PATTERN_IDS = {
    "database-error-shape", "process-error-shape", "template-error-shape", "path-error-shape",
}
CONFIG_FIELDS = {
    "schema_version", "workers", "max_examples_per_operation", "max_failures",
    "request_timeout_seconds", "total_timeout_minutes", "maximum_operations",
    "maximum_request_body_bytes", "maximum_response_body_bytes_read",
    "maximum_normalized_findings", "maximum_diagnostic_bytes", "maximum_raw_report_bytes",
    "fixed_seed", "safe_methods", "allowed_methods", "supported_modes", "default_mode",
    "default_payload_profile",
}
INSTALLED_FIELDS = {
    "schema_version", "mode", "fuzzing_enabled", "injection_testing_enabled", "safe_methods_only",
    "mutating_methods_enabled", "max_examples_per_operation", "max_failures",
    "request_timeout_seconds", "total_timeout_minutes", "payload_profile", "stateful_testing",
    "auth_header_fuzzing", "custom_payload_path", "external_target_url", "raw_body_artifacts",
}
EVENT_FIELDS = {
    "event", "operation_id", "method", "path_template", "parameter_location",
    "payload_family_id", "payload_marker_id", "detection_reason", "response_status",
    "scanner_check_id", "framework_pattern_id", "authenticated_context", "replay_seed",
}
SUMMARY_FIELDS = {"event", "completed", "mode", "operation_count"}
OPERATION_ID = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
MARKER_ID = re.compile(r"^VIBESEC_[A-Z0-9_]{1,64}$")


class ApiFuzzingError(ValueError):
    """Active API testing input or evidence failed closed."""


def parse_config(data: bytes) -> dict[str, Any]:
    try:
        payload = loads_strict(data, maximum_bytes=32_768)
    except StrictJSONError as exc:
        raise ApiFuzzingError(f"trusted fuzzing configuration is invalid: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != CONFIG_FIELDS or payload.get("schema_version") != 1:
        raise ApiFuzzingError("trusted fuzzing configuration fields are invalid")
    exact = {
        "workers": 1, "max_examples_per_operation": 25, "max_failures": 25,
        "request_timeout_seconds": 5, "total_timeout_minutes": 15, "maximum_operations": 200,
        "maximum_request_body_bytes": 65_536, "maximum_response_body_bytes_read": 262_144,
        "maximum_normalized_findings": 1000, "maximum_diagnostic_bytes": 65_536,
        "maximum_raw_report_bytes": 10_485_760,
    }
    for field, expected in exact.items():
        if type(payload.get(field)) is not int or payload[field] != expected:
            raise ApiFuzzingError(f"trusted fuzzing {field} differs from its reviewed bound")
    if payload.get("fixed_seed") != 20260722:
        raise ApiFuzzingError("trusted fuzzing seed differs from its reviewed value")
    if payload.get("safe_methods") != ["GET", "HEAD", "OPTIONS"]:
        raise ApiFuzzingError("trusted fuzzing safe-method allowlist differs")
    if payload.get("allowed_methods") != ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]:
        raise ApiFuzzingError("trusted fuzzing method allowlist differs")
    if payload.get("supported_modes") != list(MODES) or payload.get("default_mode") != "contract":
        raise ApiFuzzingError("trusted fuzzing modes differ")
    if payload.get("default_payload_profile") != "safe-v1":
        raise ApiFuzzingError("trusted fuzzing payload profile differs")
    return payload


def load_config(root: Path) -> dict[str, Any]:
    try:
        return parse_config((root / "config/api-fuzzing.json").read_bytes())
    except OSError as exc:
        raise ApiFuzzingError("trusted fuzzing configuration is unavailable") from exc


def default_installed_config() -> dict[str, Any]:
    return {
        "schema_version": 1, "mode": "contract", "fuzzing_enabled": False,
        "injection_testing_enabled": False, "safe_methods_only": True,
        "mutating_methods_enabled": False, "max_examples_per_operation": 25,
        "max_failures": 25, "request_timeout_seconds": 5, "total_timeout_minutes": 15,
        "payload_profile": "safe-v1", "stateful_testing": False,
        "auth_header_fuzzing": False, "custom_payload_path": None,
        "external_target_url": None, "raw_body_artifacts": False,
    }


def validate_installed_config(payload: Any, trusted: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != INSTALLED_FIELDS or payload.get("schema_version") != 1:
        raise ApiFuzzingError("installed fuzzing configuration fields are invalid")
    mode = payload.get("mode")
    if mode not in MODES:
        raise ApiFuzzingError("installed fuzzing mode is unsupported")
    booleans = (
        "fuzzing_enabled", "injection_testing_enabled", "safe_methods_only",
        "mutating_methods_enabled", "stateful_testing", "auth_header_fuzzing", "raw_body_artifacts",
    )
    if any(type(payload.get(field)) is not bool for field in booleans):
        raise ApiFuzzingError("installed fuzzing Boolean setting is invalid")
    if payload["stateful_testing"] or payload["auth_header_fuzzing"] or payload["raw_body_artifacts"]:
        raise ApiFuzzingError("stateful testing, authentication-header fuzzing, and raw-body artifacts are prohibited")
    if payload.get("custom_payload_path") is not None:
        raise ApiFuzzingError("custom payload paths are prohibited")
    if payload.get("external_target_url") is not None:
        raise ApiFuzzingError("public and remote fuzzing targets are prohibited")
    if payload.get("payload_profile") != trusted["default_payload_profile"]:
        raise ApiFuzzingError("unknown injection payload profile")
    ceilings = {
        "max_examples_per_operation": trusted["max_examples_per_operation"],
        "max_failures": trusted["max_failures"],
        "request_timeout_seconds": trusted["request_timeout_seconds"],
        "total_timeout_minutes": trusted["total_timeout_minutes"],
    }
    for field, ceiling in ceilings.items():
        value = payload.get(field)
        if type(value) is not int or not 1 <= value <= ceiling:
            raise ApiFuzzingError(f"installed fuzzing {field} exceeds its hard ceiling")
    if payload["mutating_methods_enabled"] and payload["safe_methods_only"]:
        raise ApiFuzzingError("mutating methods require safe_methods_only=false")
    if not payload["safe_methods_only"] and not payload["mutating_methods_enabled"]:
        raise ApiFuzzingError("unsafe method selection requires explicit mutating-method opt-in")
    if mode in {"fuzz", "combined"} and not payload["fuzzing_enabled"]:
        raise ApiFuzzingError("fuzz mode requires fuzzing_enabled=true")
    if mode in {"injection", "combined"} and not payload["injection_testing_enabled"]:
        raise ApiFuzzingError("injection mode requires injection_testing_enabled=true")
    if mode == "contract" and (payload["fuzzing_enabled"] or payload["injection_testing_enabled"]):
        raise ApiFuzzingError("contract mode cannot silently enable active fuzzing or injection testing")
    return {field: payload[field] for field in sorted(INSTALLED_FIELDS)}


def installed_config_bytes(payload: Any) -> bytes:
    return canonical_json(validate_installed_config(payload, load_config(Path(__file__).resolve().parents[2])))


def load_installed_config(repository: Path, trusted: dict[str, Any]) -> dict[str, Any]:
    path = repository / INSTALLED_CONFIG_PATH
    if path.is_symlink() or not path.is_file():
        raise ApiFuzzingError("installed fuzzing configuration is missing or unsafe")
    try:
        return validate_installed_config(loads_strict(path.read_bytes(), maximum_bytes=16_384), trusted)
    except (OSError, StrictJSONError) as exc:
        raise ApiFuzzingError("installed fuzzing configuration is malformed") from exc


def validate_payload_registry(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "profile", "families"}:
        raise ApiFuzzingError("injection payload registry fields are invalid")
    if payload.get("schema_version") != 1 or payload.get("profile") != "safe-v1":
        raise ApiFuzzingError("injection payload registry profile is unsupported")
    families = payload.get("families")
    if not isinstance(families, list) or len(families) != len(FAMILY_DETAILS):
        raise ApiFuzzingError("injection payload registry family count is invalid")
    required = {"family_id", "payload", "marker_id", "locations", "expected_safe_handling", "severity", "limitation"}
    observed: set[str] = set()
    normalized: list[dict[str, Any]] = []
    prohibited = re.compile(r"(?i)(https?://|curl\b|wget\b|/bin/(?:sh|bash)|powershell|cmd\.exe|drop\s+table|delete\s+from|authorization|bearer|callback|webhook)")
    for family in families:
        if not isinstance(family, dict) or set(family) != required:
            raise ApiFuzzingError("injection payload family fields are invalid")
        family_id = family.get("family_id")
        if family_id not in FAMILY_DETAILS or family_id in observed:
            raise ApiFuzzingError("unknown or duplicate injection payload family")
        observed.add(family_id)
        payload_value, marker = family.get("payload"), family.get("marker_id")
        if (not isinstance(payload_value, str) or not 1 <= len(payload_value.encode("utf-8")) <= 256
                or prohibited.search(payload_value)):
            raise ApiFuzzingError("injection payload is unsafe or oversized")
        if not isinstance(marker, str) or not MARKER_ID.fullmatch(marker) or marker not in payload_value:
            raise ApiFuzzingError("injection marker identity is invalid")
        locations = family.get("locations")
        if (not isinstance(locations, list) or not locations or locations != sorted(set(locations))
                or not set(locations) <= set(LOCATIONS)):
            raise ApiFuzzingError("injection payload locations are invalid")
        if family_id != "header-marker" and "header" in locations:
            raise ApiFuzzingError("only the reviewed header family may mutate non-authentication headers")
        if family.get("severity") not in {"medium", "high"}:
            raise ApiFuzzingError("injection payload severity is invalid")
        for field in ("expected_safe_handling", "limitation"):
            value = family.get(field)
            if not isinstance(value, str) or not 1 <= len(value) <= 300 or any(ord(char) < 32 for char in value):
                raise ApiFuzzingError("injection payload explanation is invalid")
        normalized.append({field: family[field] for field in sorted(required)})
    if observed != set(FAMILY_DETAILS):
        raise ApiFuzzingError("injection payload registry is incomplete")
    return {"schema_version": 1, "profile": "safe-v1", "families": sorted(normalized, key=lambda item: item["family_id"])}


def load_payload_registry(root: Path) -> dict[str, Any]:
    try:
        return validate_payload_registry(loads_strict((root / "config/injection-payloads.json").read_bytes(), maximum_bytes=32_768))
    except (OSError, StrictJSONError) as exc:
        raise ApiFuzzingError("injection payload registry is malformed") from exc


def normalize_events(path: Path, *, schema_source: str, mode: str, registry: dict[str, Any],
                     maximum_bytes: int, maximum_findings: int) -> tuple[list[dict[str, Any]], int, bool]:
    if path.is_symlink() or not path.is_file() or not 1 <= path.stat().st_size <= maximum_bytes:
        raise ApiFuzzingError("active API raw report is missing, unsafe, empty, or oversized")
    families = {item["family_id"]: item for item in registry["families"]}
    results: dict[str, dict[str, Any]] = {}
    summary: dict[str, Any] | None = None
    runtime_failure = False
    for raw_line in path.read_bytes().splitlines():
        try:
            event = loads_strict(raw_line, maximum_bytes=maximum_bytes)
        except StrictJSONError as exc:
            raise ApiFuzzingError("active API NDJSON is malformed") from exc
        if not isinstance(event, dict) or event.get("event") not in {"finding", "summary"}:
            raise ApiFuzzingError("active API event is malformed")
        if event["event"] == "summary":
            if set(event) != SUMMARY_FIELDS or summary is not None or event.get("completed") is not True:
                raise ApiFuzzingError("active API summary is malformed or duplicated")
            if event.get("mode") != mode or type(event.get("operation_count")) is not int or not 0 <= event["operation_count"] <= 200:
                raise ApiFuzzingError("active API summary differs from the reviewed run")
            summary = event
            continue
        if set(event) != EVENT_FIELDS:
            raise ApiFuzzingError("active API finding contains missing, unknown, or raw evidence fields")
        operation_id = event.get("operation_id")
        method = event.get("method")
        path_template = sanitize_path_template(event.get("path_template"))
        if not isinstance(operation_id, str) or not OPERATION_ID.fullmatch(operation_id):
            raise ApiFuzzingError("active API operation identity is unsafe")
        if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            raise ApiFuzzingError("active API method is unsupported")
        location = event.get("parameter_location")
        if location not in PARAMETER_LOCATIONS:
            raise ApiFuzzingError("active API parameter location is unsupported")
        family_id = event.get("payload_family_id")
        marker_id = event.get("payload_marker_id")
        if family_id is not None:
            if family_id not in families or marker_id != families[family_id]["marker_id"] or location not in families[family_id]["locations"]:
                raise ApiFuzzingError("active API payload evidence does not match the reviewed registry")
        elif marker_id is not None:
            raise ApiFuzzingError("active API marker lacks a reviewed payload family")
        reason = event.get("detection_reason")
        check_id = event.get("scanner_check_id")
        if reason not in DETECTION_REASONS or check_id not in CHECK_IDS:
            raise ApiFuzzingError("active API detection evidence is unreviewed")
        pattern = event.get("framework_pattern_id")
        if (reason == "framework_error_pattern") != (pattern in FRAMEWORK_PATTERN_IDS):
            raise ApiFuzzingError("active API framework error evidence is unreviewed")
        status = event.get("response_status")
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            raise ApiFuzzingError("active API response status is invalid")
        if type(event.get("authenticated_context")) is not bool or type(event.get("replay_seed")) is not int:
            raise ApiFuzzingError("active API authentication or replay metadata is invalid")
        if not 0 <= event["replay_seed"] <= 2**63 - 1:
            raise ApiFuzzingError("active API replay seed is out of bounds")
        if reason in RUNTIME_FAILURE_REASONS:
            runtime_failure = True
            continue
        if family_id is None:
            category, title, cwe, severity, limitation = "api", "API fuzzing contract weakness", None, "high", "A contract mismatch is not proof of exploitability."
        else:
            category, title, cwe = FAMILY_DETAILS[family_id]
            severity = families[family_id]["severity"]
            limitation = families[family_id]["limitation"]
        description = f"{title} for {method} {path_template}; evidence: {reason}."
        finding = Finding.create(tool="schemathesis", category=category, rule_id=f"api-fuzzing.{reason}",
                                 severity=severity, file=schema_source, description=description,
                                 confidence="confirmed").to_dict()
        identity = ("api-fuzzing", mode, operation_id, method, path_template, location, family_id or "none",
                    marker_id or "none", reason, check_id, str(event["authenticated_context"]), str(event["replay_seed"]))
        finding.update({
            "fingerprint": hashlib.sha256("\0".join(identity).encode()).hexdigest(),
            "operation_id": operation_id, "method": method, "path_template": path_template,
            "parameter_location": location, "payload_family_id": family_id,
            "payload_marker_id": marker_id, "detection_reason": reason,
            "response_status": status, "timeout_or_crash": False,
            "scanner_check_id": check_id, "framework_pattern_id": pattern,
            "authenticated_context": event["authenticated_context"],
            "authentication_context": "authenticated" if event["authenticated_context"] else "unauthenticated",
            "replay_seed": event["replay_seed"], "title": title, "limitations": limitation,
            "vulnerability_family": category if category != "api" else None,
            "cwe": cwe, "confirmed_runtime": True,
        })
        results[finding["fingerprint"]] = finding
        if len(results) > maximum_findings:
            raise ApiFuzzingError("normalized active API findings exceed the configured maximum")
    if summary is None:
        raise ApiFuzzingError("active API report does not contain a completed summary")
    return sorted(results.values(), key=lambda item: (item["operation_id"], item["rule_id"], item["fingerprint"])), summary["operation_count"], runtime_failure


def build_injection_plan(schema: dict[str, Any], *, maximum_operations: int) -> dict[str, Any]:
    """Build a bounded plan containing identities and locations, never schema examples or secrets."""
    paths = schema.get("paths")
    if not isinstance(paths, dict):
        raise ApiFuzzingError("validated OpenAPI paths are unavailable")
    operations: list[dict[str, Any]] = []
    for path_template in sorted(paths):
        path_item = paths[path_template]
        if not isinstance(path_item, dict):
            continue
        common = path_item.get("parameters", [])
        if not isinstance(common, list):
            raise ApiFuzzingError("OpenAPI path parameters are malformed")
        for method in ("get", "head", "options", "post", "put", "patch", "delete"):
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or not OPERATION_ID.fullmatch(operation_id):
                raise ApiFuzzingError("OpenAPI operation identity is invalid")
            parameters = [*common, *operation.get("parameters", [])]
            locations: list[dict[str, str]] = []
            for parameter in parameters:
                if not isinstance(parameter, dict) or "$ref" in parameter:
                    continue
                name, location = parameter.get("name"), parameter.get("in")
                schema_node = parameter.get("schema", {})
                if (isinstance(name, str) and 1 <= len(name) <= 128 and isinstance(schema_node, dict)
                        and schema_node.get("type") in {"string", None} and location in {"path", "query", "header"}
                        and name.casefold() not in {"authorization", "proxy-authorization", "cookie", "set-cookie"}):
                    locations.append({"name": name, "location": location})
            request_body = operation.get("requestBody")
            body_fields: list[str] = []
            if isinstance(request_body, dict) and "$ref" not in request_body:
                content = request_body.get("content", {})
                media = content.get("application/json", {}) if isinstance(content, dict) else {}
                body_schema = media.get("schema", {}) if isinstance(media, dict) else {}
                properties = body_schema.get("properties", {}) if isinstance(body_schema, dict) else {}
                if isinstance(properties, dict):
                    body_fields = sorted(
                        name for name, node in properties.items()
                        if isinstance(name, str) and 1 <= len(name) <= 128 and isinstance(node, dict)
                        and node.get("type") in {"string", None}
                    )[:32]
            operations.append({
                "operation_id": operation_id, "method": method.upper(),
                "path_template": sanitize_path_template(path_template),
                "parameters": sorted(locations, key=lambda item: (item["location"], item["name"])),
                "body_fields": body_fields,
            })
            if len(operations) > maximum_operations:
                raise ApiFuzzingError("active API operation plan exceeds its hard ceiling")
    return {"schema_version": 1, "operations": operations}


def adapt_contract_findings(findings: list[dict[str, Any]], *, mode: str,
                            authenticated: bool, replay_seed: int) -> list[dict[str, Any]]:
    reason_by_check = {
        "not_a_server_error": "controlled_5xx",
        "status_code_conformance": "status_code_violation",
        "response_schema_conformance": "response_schema_violation",
        "content_type_conformance": "semantic_mismatch",
        "negative_data_rejection": "semantic_mismatch",
        "positive_data_acceptance": "semantic_mismatch",
    }
    output: list[dict[str, Any]] = []
    for source in findings:
        check = source.get("rule_id")
        if check not in reason_by_check:
            raise ApiFuzzingError("Schemathesis contract result contains an unreviewed check")
        reason = reason_by_check[check]
        identity = ("api-fuzzing", mode, str(source.get("operation_id")), str(source.get("method")),
                    str(source.get("path_template")), "none", "none", reason, str(check),
                    str(authenticated), str(replay_seed))
        finding = dict(source)
        finding.update({
            "fingerprint": hashlib.sha256("\0".join(identity).encode()).hexdigest(),
            "category": "api", "rule_id": f"api-fuzzing.{reason}",
            "parameter_location": "none", "payload_family_id": None, "payload_marker_id": None,
            "detection_reason": reason, "timeout_or_crash": False, "scanner_check_id": check,
            "framework_pattern_id": None, "authenticated_context": authenticated,
            "authentication_context": "authenticated" if authenticated else "unauthenticated",
            "replay_seed": replay_seed, "limitations": "Contract evidence does not prove exploitability.",
            "vulnerability_family": None, "cwe": None, "confirmed_runtime": True,
        })
        output.append(finding)
    return sorted(output, key=lambda item: (item.get("operation_id", ""), item["rule_id"], item["fingerprint"]))


def tool_error(reason: str) -> dict[str, Any]:
    return Finding.create(tool="schemathesis", category="execution", rule_id="tool-error", severity="low",
                          description=reason, confidence="confirmed", result_type="tool_error").to_dict()


def write_artifacts(results: Path, *, root: Path, state: str, reason: str, mode: str,
                    findings: list[dict[str, Any]], operation_count: int, exit_code: int,
                    enforcement: str, minimum_severity: str, authenticated: bool,
                    authentication_applied: bool, schema_source: str | None,
                    target_digest: str | None, event: str, safe_methods_only: bool,
                    config: dict[str, Any]) -> None:
    if state not in {"ran", "not_applicable", "not_configured", "tool_error"}:
        raise ApiFuzzingError("active API coverage state is invalid")
    baseline = loads_strict((root / "policy/api-fuzzing-baseline.json").read_bytes())
    suppressions = loads_strict((root / "policy/api-fuzzing-suppressions.json").read_bytes())
    if (not isinstance(baseline, dict)
            or set(baseline) != {"schema_version", "profile", "fingerprints"}
            or baseline.get("schema_version") != 1
            or baseline.get("profile") != PROFILE
            or not isinstance(baseline.get("fingerprints"), list)
            or not all(isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item)
                       for item in baseline["fingerprints"])):
        raise ApiFuzzingError("active API baseline is malformed")
    if not isinstance(suppressions, dict) or set(suppressions) != {"schema_version", "profile", "suppressions"} or suppressions.get("schema_version") != 1 or suppressions.get("profile") != PROFILE:
        raise ApiFuzzingError("active API suppressions are malformed")
    active, expired = active_suppressions(suppressions, date.today())
    evaluation = evaluate(findings, minimum_severity=minimum_severity, enforcement=enforcement,
                          baseline=set(baseline["fingerprints"]), suppressions=active, today=date.today())
    category = {0: "pass", 1: "policy_violation", 2: "tool_error", 3: "invalid_input"}.get(exit_code)
    if category is None:
        raise ApiFuzzingError("active API exit code is outside the reviewed contract")
    normalized = {"schema_version": 1, "profile": PROFILE, "results": findings}
    try:
        groups, priorities = build_finding_intelligence([
            SourceDocument(PROFILE, "fuzzing-findings.json", normalized,
                           "authenticated" if authenticated else "unauthenticated"),
        ], baseline=set(baseline["fingerprints"]), suppressions=active)
    except FindingIntelligenceError as exc:
        raise ApiFuzzingError(f"active API finding intelligence failed: {exc}") from exc
    coverage = {
        "schema_version": 1, "profile": PROFILE, "tool": "schemathesis", "state": state,
        "reason": reason, "mode": mode, "schema_source": schema_source,
        "target_type": "isolated_immutable_container", "target_digest": target_digest,
        "trusted_event": event, "network_mode": "internal_only", "external_egress": False,
        "safe_methods_only": safe_methods_only,
        "allowed_methods": config["safe_methods"] if safe_methods_only else config["allowed_methods"],
        "workers": 1, "operation_count": operation_count,
        "normalized_finding_count": len([item for item in findings if item.get("result_type") == "finding"]),
        "raw_request_bodies_published": False, "raw_response_bodies_published": False,
        "authorization_header_fuzzed": False, "stateful_testing": False,
        "payload_profile": config["default_payload_profile"],
        "replay_metadata_contains_raw_values": False,
        "output_artifacts": ["fuzzing-coverage.json", "fuzzing-findings.json", "fuzzing-policy-result.json", "fuzzing-report.md", "finding-groups.json", "prioritized-findings.json"],
        "limitations": ["Active input handling evidence does not prove exploitability or that an API is free from injection flaws."],
        **authentication_evidence(authenticated, authentication_applied),
    }
    policy = {
        "schema_version": 1, "profile": PROFILE, "exit_code": exit_code, "exit_category": category,
        "clean": state == "ran" and exit_code == 0, "security_guarantee": False,
        "findings": len(evaluation["findings"]), "violations": len(evaluation["violations"]),
        "tool_errors": len(evaluation["tool_errors"]), "expired_suppressions": len(expired),
        "enforcement": enforcement,
    }
    lines = ["# VibeSec Guardian API Fuzzing and Injection Testing", "", f"Status: **{category}**", "",
             f"- Coverage: {state}", f"- Mode: {mode}", f"- Findings: {len(evaluation['findings'])}",
             f"- Policy violations: {len(evaluation['violations'])}",
             f"- Safe methods only: {str(safe_methods_only).lower()}",
             f"- Authentication: {'bearer' if authenticated else 'none'}", "- External egress: false", "",
             "Passing does not prove injection safety and this profile does not attempt exploitation."]
    artifacts = {
        "fuzzing-findings.json": canonical_json(normalized),
        "fuzzing-coverage.json": canonical_json(coverage),
        "fuzzing-policy-result.json": canonical_json(policy),
        "fuzzing-report.md": ("\n".join(lines) + "\n").encode(),
        "finding-groups.json": canonical_json(groups),
        "prioritized-findings.json": canonical_json(priorities),
    }
    if authenticated:
        for data in artifacts.values():
            validate_publishable_bytes(data)
    for name, data in artifacts.items():
        atomic_write(results / name, data)
