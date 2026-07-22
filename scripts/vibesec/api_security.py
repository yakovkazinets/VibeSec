"""Strict OpenAPI input, Schemathesis normalization, and API artifacts."""

from __future__ import annotations

from datetime import date
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml

from .model import Finding
from .policy import active_suppressions, evaluate
from .strict_json import StrictJSONError, canonical_json, loads_strict

IMAGE = re.compile(r"^[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$")
METHOD = re.compile(r"^(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)$")
OPERATION_ID = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
HTTP_METHODS = {"get", "head", "options", "post", "put", "patch", "delete", "trace"}
CHECKS = {
    "not_a_server_error": ("high", "Unexpected server error", "Prevent the operation from returning a 5xx response."),
    "status_code_conformance": ("medium", "Undocumented response status", "Document the status code or return a documented response."),
    "content_type_conformance": ("medium", "Response content type mismatch", "Return a response using a documented media type."),
    "response_schema_conformance": ("high", "Response schema mismatch", "Make the response conform to the OpenAPI response schema."),
    "negative_data_rejection": ("medium", "Invalid input was accepted", "Reject inputs that violate the OpenAPI contract."),
    "positive_data_acceptance": ("medium", "Valid input was rejected", "Accept inputs that satisfy the OpenAPI contract."),
}
CONFIG_FIELDS = {
    "schema_version", "target_hostname", "startup_timeout_seconds", "request_timeout_seconds",
    "total_scan_timeout_minutes", "workers", "max_examples_per_operation", "max_failures",
    "fixed_seed", "maximum_operations", "maximum_schema_bytes", "maximum_report_bytes",
    "maximum_normalized_findings", "maximum_nesting_depth", "maximum_collection_items",
    "maximum_string_bytes", "maximum_parameters", "maximum_schemas", "container_cpu_limit",
    "container_memory_megabytes", "container_pid_limit", "target_tmpfs_megabytes",
    "scanner_tmpfs_megabytes", "safe_methods_only_default", "allowed_methods", "safe_methods",
    "output_schema_version",
}
TRUSTED_EVENTS = {"workflow_dispatch", "schedule"}


class ApiSecurityError(ValueError):
    """API baseline configuration, schema, or scanner evidence failed closed."""


class _NoAliasSafeLoader(yaml.SafeLoader):
    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise ApiSecurityError("OpenAPI YAML aliases are prohibited")
        return super().compose_node(parent, index)


def _mapping(loader: yaml.Loader, node: yaml.Node, deep: bool = False) -> dict[Any, Any]:
    pairs = loader.construct_pairs(node, deep=deep)
    result: dict[Any, Any] = {}
    for key, value in pairs:
        if not isinstance(key, (str, int, float, bool, type(None))):
            raise ApiSecurityError("OpenAPI YAML mapping keys must be scalar")
        if key in result:
            raise ApiSecurityError(f"duplicate OpenAPI YAML key: {key}")
        result[key] = value
    return result


_NoAliasSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


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


def parse_config(data: bytes) -> dict[str, Any]:
    try:
        payload = loads_strict(data)
    except StrictJSONError as exc:
        raise ApiSecurityError(f"trusted API configuration is invalid: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != CONFIG_FIELDS or payload.get("schema_version") != 1 or payload.get("output_schema_version") != 1:
        raise ApiSecurityError("trusted API configuration fields or schema are invalid")
    if payload["target_hostname"] != "api-target" or payload["workers"] != 1 or payload["safe_methods_only_default"] is not True:
        raise ApiSecurityError("trusted API execution defaults differ from reviewed values")
    exact = {
        "request_timeout_seconds": 5, "total_scan_timeout_minutes": 10,
        "max_examples_per_operation": 20, "max_failures": 20,
        "maximum_operations": 200, "maximum_schema_bytes": 2 * 1024 * 1024,
        "maximum_report_bytes": 10 * 1024 * 1024, "maximum_normalized_findings": 1000,
    }
    for name, wanted in exact.items():
        if payload.get(name) != wanted or isinstance(payload.get(name), bool):
            raise ApiSecurityError(f"trusted API {name} differs from its reviewed bound")
    if payload["allowed_methods"] != ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"] or payload["safe_methods"] != ["GET", "HEAD", "OPTIONS"]:
        raise ApiSecurityError("trusted API method allowlists differ")
    for name in ("startup_timeout_seconds", "fixed_seed", "maximum_nesting_depth", "maximum_collection_items", "maximum_string_bytes", "maximum_parameters", "maximum_schemas", "container_cpu_limit", "container_memory_megabytes", "container_pid_limit", "target_tmpfs_megabytes", "scanner_tmpfs_megabytes"):
        if isinstance(payload.get(name), bool) or not isinstance(payload.get(name), int) or payload[name] <= 0:
            raise ApiSecurityError(f"trusted API {name} is invalid")
    return payload


def load_config(root: Path) -> dict[str, Any]:
    try:
        return parse_config((root / "config/api-security-baseline.json").read_bytes())
    except OSError as exc:
        raise ApiSecurityError(f"trusted API configuration is invalid: {exc}") from exc


def load_target_configuration(repository: Path) -> dict[str, Any]:
    path = repository / ".vibesec/api-security-baseline.json"
    if path.is_symlink() or not path.is_file():
        raise ApiSecurityError("installed API target configuration is missing or unsafe")
    try:
        payload = loads_strict(path.read_bytes(), maximum_bytes=16_384)
    except (OSError, StrictJSONError) as exc:
        raise ApiSecurityError("installed API target configuration is malformed") from exc
    fields = {"schema_version", "schema_path", "image_variable_name", "container_port", "base_path",
              "safe_methods_only", "authentication", "custom_headers", "external_target_url"}
    if not isinstance(payload, dict) or set(payload) != fields or payload.get("schema_version") != 1:
        raise ApiSecurityError("installed API target configuration fields are invalid")
    if payload.get("authentication") is not False or payload.get("custom_headers") is not False or payload.get("external_target_url") is not None:
        raise ApiSecurityError("authentication, custom headers, and external targets are unsupported")
    if type(payload.get("safe_methods_only")) is not bool:
        raise ApiSecurityError("installed safe-methods-only setting must be Boolean")
    validate_port(payload.get("container_port"))
    validate_base_path(payload.get("base_path"))
    if not isinstance(payload.get("schema_path"), str) or not payload["schema_path"]:
        raise ApiSecurityError("installed schema path is missing")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", str(payload.get("image_variable_name", ""))):
        raise ApiSecurityError("installed image variable name is invalid")
    return payload


def validate_image_reference(value: str) -> str:
    if not isinstance(value, str) or not IMAGE.fullmatch(value):
        raise ApiSecurityError("target image must be an immutable OCI sha256 reference")
    return value


def image_digest(value: str) -> str:
    return "sha256:" + validate_image_reference(value).rsplit("@sha256:", 1)[1]


def validate_port(value: Any) -> int:
    if isinstance(value, bool):
        raise ApiSecurityError("API target port must be an integer from 1 through 65535")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ApiSecurityError("API target port must be an integer from 1 through 65535") from exc
    if str(port) != str(value) or not 1 <= port <= 65535:
        raise ApiSecurityError("API target port must be an integer from 1 through 65535")
    return port


def validate_base_path(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 512 or CONTROL.search(value):
        raise ApiSecurityError("API base path must be a bounded absolute path")
    lowered = value.casefold()
    if any(marker in value for marker in ("\\", "?", "#")) or "://" in lowered or any(marker in lowered for marker in ("%2e", "%2f", "%5c")):
        raise ApiSecurityError("API base path contains a prohibited URL or traversal component")
    if ".." in unquote(value).split("/"):
        raise ApiSecurityError("API base path contains traversal")
    return value


def trusted_event(value: str) -> bool:
    if value in TRUSTED_EVENTS:
        return True
    if value in {"pull_request", "pull_request_target", "push"}:
        return False
    raise ApiSecurityError(f"unsupported API security event: {value or 'unset'}")


def _bounded(value: Any, config: dict[str, Any], *, depth: int = 0, counters: dict[str, int] | None = None) -> None:
    counters = counters if counters is not None else {"items": 0}
    if depth > config["maximum_nesting_depth"]:
        raise ApiSecurityError("OpenAPI nesting exceeds the reviewed maximum")
    if isinstance(value, str):
        if len(value.encode("utf-8")) > config["maximum_string_bytes"] or CONTROL.search(value):
            raise ApiSecurityError("OpenAPI string is oversized or contains controls")
    elif isinstance(value, list):
        counters["items"] += len(value)
        if counters["items"] > config["maximum_collection_items"]:
            raise ApiSecurityError("OpenAPI collections exceed the reviewed maximum")
        for item in value:
            _bounded(item, config, depth=depth + 1, counters=counters)
    elif isinstance(value, dict):
        counters["items"] += len(value)
        if counters["items"] > config["maximum_collection_items"]:
            raise ApiSecurityError("OpenAPI collections exceed the reviewed maximum")
        for key, item in value.items():
            if not isinstance(key, str):
                raise ApiSecurityError("OpenAPI object keys must be strings")
            _bounded(key, config, depth=depth + 1, counters=counters)
            _bounded(item, config, depth=depth + 1, counters=counters)
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise ApiSecurityError("OpenAPI contains an unsupported value")


def _walk(value: Any) -> Any:
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _valid_local_ref(value: str) -> bool:
    if not value.startswith("#/") or len(value) > 2048 or CONTROL.search(value):
        return False
    return not any(marker in value.casefold() for marker in ("http://", "https://", "file://", "\\", "../", "%2e", "%2f", "%5c"))


def _validate_server(value: Any, *, port: int, base_path: str) -> None:
    if not isinstance(value, dict) or set(value) - {"url", "description", "variables"} or not isinstance(value.get("url"), str):
        raise ApiSecurityError("OpenAPI server entry is unsupported")
    url = value["url"]
    parsed = urlsplit(url)
    expected = f"http://api-target:{port}{base_path}".rstrip("/")
    if "{" in url or "}" in url or parsed.query or parsed.fragment or url.rstrip("/") != expected:
        raise ApiSecurityError("OpenAPI server may not redirect the fixed internal origin")


def validate_openapi_schema(repository: Path, relative: str, *, config: dict[str, Any], port: int, base_path: str) -> tuple[Path, dict[str, Any], int]:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts or "\\" in relative:
        raise ApiSecurityError("OpenAPI schema path must be repository-relative")
    repository = repository.resolve(strict=True)
    path = repository / relative
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(repository)
        details = path.stat(follow_symlinks=False)
    except (OSError, ValueError) as exc:
        raise ApiSecurityError("OpenAPI schema is unavailable or escapes the repository") from exc
    if path.is_symlink() or not stat.S_ISREG(details.st_mode) or not 1 <= details.st_size <= config["maximum_schema_bytes"]:
        raise ApiSecurityError("OpenAPI schema must be a bounded regular non-symlink file")
    data = path.read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        raise ApiSecurityError("OpenAPI schema must be strict UTF-8 without a BOM")
    try:
        if path.suffix.casefold() == ".json":
            payload = loads_strict(data, maximum_bytes=config["maximum_schema_bytes"])
        elif path.suffix.casefold() in {".yaml", ".yml"}:
            text = data.decode("utf-8")
            payload = yaml.load(text, Loader=_NoAliasSafeLoader)
        else:
            raise ApiSecurityError("OpenAPI schema must use .json, .yaml, or .yml")
    except (UnicodeError, yaml.YAMLError, StrictJSONError) as exc:
        raise ApiSecurityError(f"OpenAPI schema is malformed: {type(exc).__name__}") from exc
    if not isinstance(payload, dict):
        raise ApiSecurityError("OpenAPI schema must be an object")
    _bounded(payload, config)
    version = payload.get("openapi")
    if not isinstance(version, str) or not re.fullmatch(r"3\.(?:0|1)\.\d+", version):
        raise ApiSecurityError("only OpenAPI 3.0.x and 3.1.x are supported")
    if "swagger" in payload or "webhooks" in payload or "externalDocs" in payload:
        raise ApiSecurityError("Swagger, webhooks, and external documentation are unsupported")
    if not isinstance(payload.get("paths"), dict):
        raise ApiSecurityError("OpenAPI paths must be an object")
    operations = parameters = 0
    identifiers: set[str] = set()
    for node in _walk(payload):
        if any(key in node for key in ("callbacks", "links", "externalDocs", "webhooks")):
            raise ApiSecurityError("callbacks, links, webhooks, and external documentation are unsupported")
        if any(key in node for key in ("$dynamicRef", "$recursiveRef", "$id", "externalValue")):
            raise ApiSecurityError("dynamic, recursive, identified, and external OpenAPI references are unsupported")
        if "$ref" in node and (not isinstance(node["$ref"], str) or not _valid_local_ref(node["$ref"])):
            raise ApiSecurityError("only local in-document OpenAPI references are permitted")
        if "servers" in node:
            if not isinstance(node["servers"], list) or len(node["servers"]) > 4:
                raise ApiSecurityError("OpenAPI servers must be a bounded array")
            for server in node["servers"]:
                _validate_server(server, port=port, base_path=base_path)
        if "parameters" in node:
            if not isinstance(node["parameters"], list):
                raise ApiSecurityError("OpenAPI parameters must be arrays")
            parameters += len(node["parameters"])
    for path_template, path_item in payload["paths"].items():
        sanitize_path_template(path_template)
        if not isinstance(path_item, dict):
            raise ApiSecurityError("OpenAPI path items must be objects")
        for method, operation in path_item.items():
            if method.casefold() not in HTTP_METHODS:
                continue
            if method.casefold() == "trace":
                raise ApiSecurityError("TRACE operations are unsupported")
            if not isinstance(operation, dict):
                raise ApiSecurityError("OpenAPI operations must be objects")
            operations += 1
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or not OPERATION_ID.fullmatch(operation_id) or operation_id in identifiers:
                raise ApiSecurityError("each operation requires a unique bounded operationId")
            identifiers.add(operation_id)
    schemas = payload.get("components", {}).get("schemas", {}) if isinstance(payload.get("components", {}), dict) else {}
    if not isinstance(schemas, dict) or len(schemas) > config["maximum_schemas"]:
        raise ApiSecurityError("OpenAPI schemas exceed the reviewed maximum")
    if not 1 <= operations <= config["maximum_operations"] or parameters > config["maximum_parameters"]:
        raise ApiSecurityError("OpenAPI operations or parameters exceed the reviewed maximum")
    return resolved, payload, operations


def sanitize_path_template(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 1024 or CONTROL.search(value):
        raise ApiSecurityError("OpenAPI path template is unsafe")
    lowered = value.casefold()
    if any(marker in value for marker in ("\\", "?", "#")) or any(marker in lowered for marker in ("%2e", "%2f", "%5c")) or ".." in unquote(value).split("/"):
        raise ApiSecurityError("OpenAPI path template contains traversal or URL data")
    return value


def operation_index(payload: dict[str, Any]) -> dict[tuple[str, str], str]:
    result: dict[tuple[str, str], str] = {}
    paths = payload.get("paths")
    if not isinstance(paths, dict):
        raise ApiSecurityError("OpenAPI paths are unavailable for operation identity")
    for path_template, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.casefold() in HTTP_METHODS - {"trace"} and isinstance(operation, dict):
                identifier = operation.get("operationId")
                if not isinstance(identifier, str) or not OPERATION_ID.fullmatch(identifier):
                    raise ApiSecurityError("OpenAPI operation identity is unsafe")
                result[(method.upper(), sanitize_path_template(path_template))] = identifier
    return result


def _case_value(node: Any) -> dict[str, Any]:
    if not isinstance(node, dict):
        raise ApiSecurityError("Schemathesis case node is malformed")
    value = node.get("value", node)
    if not isinstance(value, dict):
        raise ApiSecurityError("Schemathesis case value is malformed")
    return value


def normalize_schemathesis_report(path: Path, *, schema_source: str,
                                  operations: dict[tuple[str, str], str],
                                  maximum_bytes: int, maximum_findings: int) -> tuple[list[dict[str, Any]], int]:
    if path.is_symlink() or not path.is_file() or not 1 <= path.stat().st_size <= maximum_bytes:
        raise ApiSecurityError("Schemathesis raw report is missing, unsafe, empty, or oversized")
    findings_by_fingerprint: dict[str, dict[str, Any]] = {}
    operation_ids: set[str] = set()
    try:
        lines = path.read_bytes().splitlines()
    except OSError as exc:
        raise ApiSecurityError("Schemathesis raw report cannot be read") from exc
    if not lines:
        raise ApiSecurityError("Schemathesis raw report is empty")
    finished = False
    for raw_line in lines:
        try:
            event = loads_strict(raw_line, maximum_bytes=maximum_bytes)
        except StrictJSONError as exc:
            raise ApiSecurityError("Schemathesis NDJSON is malformed") from exc
        if not isinstance(event, dict) or len(event) != 1 or not isinstance(next(iter(event)), str):
            raise ApiSecurityError("Schemathesis NDJSON event is malformed")
        event_type, event_payload = next(iter(event.items()))
        if event_type in {"FatalError", "NonFatalError", "Interrupted"}:
            raise ApiSecurityError("Schemathesis reported an execution error")
        if event_type == "EngineFinished":
            if not isinstance(event_payload, dict):
                raise ApiSecurityError("Schemathesis completion event is malformed")
            if event_payload.get("stop_reason") not in {"completed", "failure_limit"}:
                raise ApiSecurityError("Schemathesis did not reach a reviewed terminal state")
            if event_payload.get("failures", []) not in ([], None):
                raise ApiSecurityError("Schemathesis reported an unnormalized after-run failure")
            finished = True
        if event_type != "ScenarioFinished":
            continue
        if not isinstance(event_payload, dict):
            raise ApiSecurityError("Schemathesis scenario event is malformed")
        recorder = event_payload.get("recorder")
        if not isinstance(recorder, dict) or not isinstance(recorder.get("cases"), dict) or not isinstance(recorder.get("checks"), dict):
            raise ApiSecurityError("Schemathesis scenario recorder is malformed")
        interactions = recorder.get("interactions", {})
        if not isinstance(interactions, dict):
            raise ApiSecurityError("Schemathesis interactions are malformed")
        for case_id, checks in recorder["checks"].items():
            if case_id not in recorder["cases"] or not isinstance(checks, list):
                raise ApiSecurityError("Schemathesis check references an unknown case")
            case = _case_value(recorder["cases"][case_id])
            method = case.get("method")
            path_template = case.get("path", case.get("path_template"))
            if not isinstance(method, str) or not METHOD.fullmatch(method.upper()):
                raise ApiSecurityError("Schemathesis method is unsupported")
            path_template = sanitize_path_template(path_template)
            operation_id = operations.get((method.upper(), path_template))
            if operation_id is None:
                raise ApiSecurityError("Schemathesis case does not map to a validated OpenAPI operation")
            operation_ids.add(operation_id)
            interaction = interactions.get(case_id, {})
            response = interaction.get("response", {}) if isinstance(interaction, dict) else {}
            status = response.get("status_code") if isinstance(response, dict) else None
            if status is not None and (isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599):
                raise ApiSecurityError("Schemathesis response status is invalid")
            for check in checks:
                if not isinstance(check, dict) or check.get("status") not in {"success", "failure", "skip"} or not isinstance(check.get("name"), str):
                    raise ApiSecurityError("Schemathesis check record is malformed")
                if check["status"] != "failure":
                    continue
                check_id = check["name"]
                if check_id not in CHECKS:
                    raise ApiSecurityError(f"unreviewed Schemathesis check ID: {check_id}")
                severity, title, remediation = CHECKS[check_id]
                description = f"{title} for {method.upper()} {path_template}."
                finding = Finding.create(tool="schemathesis", category="api", rule_id=check_id, severity=severity,
                                         file=schema_source, description=description, confidence="confirmed").to_dict()
                finding.update({"operation_id": operation_id, "method": method.upper(), "path_template": path_template,
                                "title": title, "remediation": remediation, "response_status": status})
                stable = "\0".join(("schemathesis", check_id, operation_id, method.upper(), path_template, schema_source)).encode()
                finding["fingerprint"] = hashlib.sha256(stable).hexdigest()
                findings_by_fingerprint[finding["fingerprint"]] = finding
                if len(findings_by_fingerprint) > maximum_findings:
                    raise ApiSecurityError("normalized API findings exceed the configured maximum")
    if not finished:
        raise ApiSecurityError("Schemathesis report does not contain a completed engine event")
    findings = sorted(findings_by_fingerprint.values(),
                      key=lambda item: (item["operation_id"], item["rule_id"], item["fingerprint"]))
    return findings, len(operation_ids)


def tool_error(reason: str) -> dict[str, Any]:
    return Finding.create(tool="schemathesis", category="execution", rule_id="tool-error", severity="low",
                          description=reason, confidence="confirmed", result_type="tool_error").to_dict()


def write_artifacts(results: Path, *, root: Path, state: str, reason: str, event: str, digest: str | None,
                    schema_source: str | None, port: int, base_path: str, safe_methods_only: bool,
                    findings: list[dict[str, Any]], duration_seconds: int, operation_count: int,
                    exit_code: int, enforcement: str, minimum_severity: str) -> None:
    if state not in {"ran", "not_applicable", "not_configured", "tool_error"}:
        raise ApiSecurityError("API coverage state is invalid")
    baseline = loads_strict((root / "policy/api-security-baseline.json").read_bytes())
    suppression_payload = loads_strict((root / "policy/api-security-suppressions.json").read_bytes())
    if not isinstance(baseline, dict) or baseline.get("profile") != "api-security-baseline" or not isinstance(baseline.get("fingerprints"), list):
        raise ApiSecurityError("API baseline is malformed")
    if not isinstance(suppression_payload, dict) or suppression_payload.get("profile") != "api-security-baseline":
        raise ApiSecurityError("API suppressions are malformed")
    active, expired = active_suppressions(suppression_payload, date.today())
    evaluation = evaluate(findings, minimum_severity=minimum_severity, enforcement=enforcement,
                          baseline=set(baseline["fingerprints"]), suppressions=active, today=date.today())
    category = {0: "pass", 1: "policy_violation", 2: "tool_error", 3: "invalid_input"}.get(exit_code)
    if category is None:
        raise ApiSecurityError("API exit code is outside the reviewed contract")
    scanner = loads_strict((root / "config/tools.json").read_bytes())["schemathesis"]
    config = load_config(root)
    normalized = {"schema_version": 1, "profile": "api-security-baseline", "results": findings}
    coverage = {
        "schema_version": 1, "profile": "api-security-baseline", "tool": "schemathesis",
        "scanner_version": scanner["version"], "scanner_image_digest": scanner["digest"],
        "target_type": "isolated_immutable_container", "target_digest": digest,
        "schema_source": schema_source, "target_port": port, "base_path": base_path,
        "trusted_event": event, "network_mode": "internal_only", "external_egress": False,
        "authentication": False, "custom_headers": False, "stateful_testing": False,
        "phases": ["examples", "coverage", "fuzzing"], "generation_mode": "all",
        "safe_methods_only": safe_methods_only,
        "allowed_methods": config["safe_methods"] if safe_methods_only else config["allowed_methods"],
        "state": state, "reason": reason, "operation_count": operation_count,
        "normalized_finding_count": len([item for item in findings if item.get("result_type") == "finding"]),
        "scan_duration_seconds": max(duration_seconds, 0),
        "output_artifacts": ["normalized.json", "coverage.json", "policy-result.json", "report.md"],
        "limitations": ["Contract-driven unauthenticated testing does not prove that an API is secure."],
    }
    policy = {"schema_version": 1, "profile": "api-security-baseline", "exit_code": exit_code,
              "exit_category": category, "clean": state == "ran" and exit_code == 0, "security_guarantee": False,
              "findings": len(evaluation["findings"]), "violations": len(evaluation["violations"]),
              "tool_errors": len(evaluation["tool_errors"]), "expired_suppressions": len(expired)}
    lines = ["# VibeSec API Security Baseline", "", f"Status: **{category}**", "",
             f"- Coverage: {state}", f"- Findings: {len(evaluation['findings'])}",
             f"- Policy violations: {len(evaluation['violations'])}", f"- Safe methods only: {str(safe_methods_only).lower()}",
             "- Authentication: false", "- External egress: false", "", "A passing contract test does not prove the API is secure."]
    if evaluation["findings"]:
        lines += ["", "## Findings", "", "| Severity | Check | Operation | Method | Path |", "|---|---|---|---|---|"]
        for item in evaluation["findings"]:
            safe = lambda value: str(value or "").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")[:200]
            lines.append("| " + " | ".join(safe(value) for value in (item["severity"], item["rule_id"], item.get("operation_id"), item.get("method"), item.get("path_template"))) + " |")
    atomic_write(results / "normalized.json", canonical_json(normalized))
    atomic_write(results / "coverage.json", canonical_json(coverage))
    atomic_write(results / "policy-result.json", canonical_json(policy))
    atomic_write(results / "report.md", ("\n".join(lines) + "\n").encode())
