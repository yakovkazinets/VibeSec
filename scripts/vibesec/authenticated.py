"""Bearer-only authenticated runtime testing controls.

This module deliberately handles opaque bearer values only in memory.  It does
not parse JWTs, derive token metadata, or serialize a token or derivative.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .finding_intelligence import FindingIntelligenceError, SourceDocument, build as build_finding_intelligence
from .strict_json import StrictJSONError, canonical_json, loads_strict

AUTH_ENVIRONMENT_VARIABLE = "VIBESEC_AUTH_BEARER_TOKEN"
CONFIG_PATH = ".vibesec/authenticated-security-testing.json"
SECRET_NAME = re.compile(r"^(?!GITHUB_)[A-Z_][A-Z0-9_]{0,99}$")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
BEARER = re.compile(rb"(?i)authorization\s*:\s*bearer\s+[^\s\"'<>]{1,16384}")
LIKELY_JWT = re.compile(rb"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])")
MAX_TOKEN_BYTES = 16_384
MAX_DIAGNOSTIC_BYTES = 2_000
CONFIG_FIELDS = {"schema_version", "secret_name", "header_name", "scheme"}


class AuthenticatedSecurityError(ValueError):
    """Authenticated testing configuration or evidence failed closed."""


def validate_secret_name(value: Any) -> str:
    if not isinstance(value, str) or not SECRET_NAME.fullmatch(value):
        raise AuthenticatedSecurityError("GitHub Actions secret name is invalid")
    return value


def configuration(secret_name: str) -> dict[str, Any]:
    return validate_configuration({
        "schema_version": 1,
        "secret_name": secret_name,
        "header_name": "Authorization",
        "scheme": "Bearer",
    })


def validate_configuration(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != CONFIG_FIELDS or payload.get("schema_version") != 1:
        raise AuthenticatedSecurityError("authenticated testing configuration fields are invalid")
    if payload.get("header_name") != "Authorization" or payload.get("scheme") != "Bearer":
        raise AuthenticatedSecurityError("only the Authorization: Bearer authentication model is supported")
    validate_secret_name(payload.get("secret_name"))
    return {name: payload[name] for name in ("schema_version", "secret_name", "header_name", "scheme")}


def configuration_bytes(secret_name: str) -> bytes:
    return canonical_json(configuration(secret_name))


def load_configuration(repository: Path) -> dict[str, Any]:
    path = repository / CONFIG_PATH
    if path.is_symlink() or not path.is_file():
        raise AuthenticatedSecurityError("authenticated testing configuration is missing or unsafe")
    try:
        return validate_configuration(loads_strict(path.read_bytes(), maximum_bytes=4096))
    except (OSError, StrictJSONError) as exc:
        raise AuthenticatedSecurityError("authenticated testing configuration is malformed") from exc


def consume_bearer_token(environment: dict[str, str] | os._Environ[str] = os.environ) -> str | None:
    """Remove and validate the scanner-step token without deriving metadata."""
    value = environment.pop(AUTH_ENVIRONMENT_VARIABLE, None)
    if value is None or value == "":
        return None
    encoded = value.encode("utf-8", errors="strict")
    if len(encoded) > MAX_TOKEN_BYTES or CONTROL.search(value):
        raise AuthenticatedSecurityError("bearer token is empty, oversized, or contains controls")
    return value


def redact_bytes(data: bytes, token: str) -> bytes:
    """Redact the exact opaque token and any bearer header entirely in memory."""
    token_bytes = token.encode("utf-8")
    redacted = data.replace(token_bytes, b"[REDACTED]")
    redacted = BEARER.sub(b"[REDACTED AUTHORIZATION]", redacted)
    if token_bytes in redacted or BEARER.search(redacted):
        raise AuthenticatedSecurityError("authenticated scanner output could not be fully redacted")
    return redacted


def sanitize_diagnostic(value: str, token: str | None = None) -> str:
    data = value.encode("utf-8", errors="replace")[:MAX_DIAGNOSTIC_BYTES]
    if token:
        data = redact_bytes(data, token)
    else:
        data = BEARER.sub(b"[REDACTED AUTHORIZATION]", data)
    text = data.decode("utf-8", errors="replace")
    return " ".join(text.split())[:MAX_DIAGNOSTIC_BYTES]


def validate_publishable_bytes(data: bytes, token: str | None = None) -> None:
    if token and token.encode("utf-8") in data:
        raise AuthenticatedSecurityError("authenticated artifact contains the bearer token")
    if BEARER.search(data):
        raise AuthenticatedSecurityError("authenticated artifact contains a bearer credential")
    if LIKELY_JWT.search(data):
        raise AuthenticatedSecurityError("authenticated artifact contains likely JWT material")


def atomic_publish(path: Path, data: bytes, token: str | None = None) -> None:
    validate_publishable_bytes(data, token)
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


def authentication_evidence(requested: bool, applied: bool) -> dict[str, Any]:
    return {
        "authentication_mode": "bearer" if requested else "none",
        "authentication_applied": bool(applied),
        "secret_source": "github_actions_secret" if requested else None,
    }


def annotate_findings(findings: list[dict[str, Any]], *, authenticated: bool) -> list[dict[str, Any]]:
    result = copy.deepcopy(findings)
    for finding in result:
        if finding.get("result_type") == "finding":
            finding["observed_unauthenticated"] = not authenticated
            finding["observed_authenticated"] = authenticated
    return result


def _correlation_key(finding: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    path = finding.get("path_template", finding.get("file", ""))
    status = finding.get("status_class", "unknown")
    contract = finding.get("contract_class", "unknown")
    values = (finding.get("tool"), finding.get("rule_id"), finding.get("method"), path, status, contract)
    if not all(isinstance(value, str) and value for value in values):
        raise AuthenticatedSecurityError("finding lacks the exact fields required for authenticated correlation")
    return values  # type: ignore[return-value]


def correlate_findings(unauthenticated: list[dict[str, Any]], authenticated: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Correlate only identical findings from the same scanner and contract class."""
    correlated: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}
    passthrough: list[dict[str, Any]] = []
    for is_authenticated, collection in ((False, unauthenticated), (True, authenticated)):
        for original in collection:
            finding = copy.deepcopy(original)
            if finding.get("result_type") != "finding":
                passthrough.append(finding)
                continue
            key = _correlation_key(finding)
            existing = correlated.get(key)
            if existing is None:
                finding["observed_unauthenticated"] = not is_authenticated
                finding["observed_authenticated"] = is_authenticated
                correlated[key] = finding
            else:
                existing["observed_unauthenticated"] = True
                existing["observed_authenticated"] = True
    findings = list(correlated.values()) + passthrough
    findings.sort(key=lambda item: (
        str(item.get("tool", "")), str(item.get("rule_id", "")),
        str(item.get("method", "")), str(item.get("path_template", item.get("file", ""))),
        str(item.get("fingerprint", "")),
    ))
    return findings


def _validate_child_exit_contract(label: str, coverage: dict[str, Any], policy: dict[str, Any],
                                  process_exit_code: int) -> None:
    if type(process_exit_code) is not int or process_exit_code not in {0, 1, 2, 3}:
        raise AuthenticatedSecurityError(f"{label} comparison process exit is outside the reviewed contract")
    policy_exit_code = policy.get("exit_code")
    if type(policy_exit_code) is not int or policy_exit_code != process_exit_code:
        raise AuthenticatedSecurityError(f"{label} comparison process and policy exits differ")
    state = coverage.get("state")
    valid_pairs = {
        "ran": {0, 1},
        "not_applicable": {0},
        "not_configured": {0},
        "tool_error": {2, 3},
    }
    if state not in valid_pairs or process_exit_code not in valid_pairs[state]:
        raise AuthenticatedSecurityError(f"{label} comparison coverage and process exit differ")
    if policy.get("clean") is not (state == "ran" and process_exit_code == 0):
        raise AuthenticatedSecurityError(f"{label} comparison clean state is inconsistent")


def combine_result_directories(unauthenticated: Path, authenticated: Path, output: Path, *,
                               unauthenticated_exit_code: int, authenticated_exit_code: int) -> int:
    """Publish one sanitized comparison from two completed same-scanner runs."""
    required = {"normalized.json", "coverage.json", "policy-result.json", "report.md"}
    documents: dict[str, dict[str, Any]] = {}
    for label, directory in (("unauthenticated", unauthenticated), ("authenticated", authenticated)):
        observed = {item.name for item in directory.iterdir() if item.is_file()}
        if not required <= observed:
            raise AuthenticatedSecurityError(f"{label} comparison artifacts are incomplete")
        for name in required:
            validate_publishable_bytes((directory / name).read_bytes())
        normalized = loads_strict((directory / "normalized.json").read_bytes())
        coverage = loads_strict((directory / "coverage.json").read_bytes())
        policy = loads_strict((directory / "policy-result.json").read_bytes())
        if (not isinstance(normalized, dict) or not isinstance(normalized.get("results"), list)
                or not isinstance(coverage, dict) or not isinstance(policy, dict)
                or normalized.get("profile") != coverage.get("profile")
                or normalized.get("profile") != policy.get("profile")):
            raise AuthenticatedSecurityError(f"{label} comparison artifacts are malformed")
        documents[label] = {"normalized": normalized, "coverage": coverage, "policy": policy}
    unauth = documents["unauthenticated"]
    auth = documents["authenticated"]
    if unauth["normalized"]["profile"] != auth["normalized"]["profile"]:
        raise AuthenticatedSecurityError("authenticated comparison profiles differ")
    try:
        finding_groups, prioritized_findings = build_finding_intelligence([
            SourceDocument(unauth["normalized"]["profile"], "unauthenticated/normalized.json",
                           unauth["normalized"], "unauthenticated"),
            SourceDocument(auth["normalized"]["profile"], "authenticated/normalized.json",
                           auth["normalized"], "authenticated"),
        ])
    except FindingIntelligenceError as exc:
        raise AuthenticatedSecurityError(f"authenticated finding intelligence failed: {exc}") from exc
    _validate_child_exit_contract(
        "unauthenticated", unauth["coverage"], unauth["policy"], unauthenticated_exit_code,
    )
    _validate_child_exit_contract(
        "authenticated", auth["coverage"], auth["policy"], authenticated_exit_code,
    )
    auth_state = auth["coverage"].get("state")
    unauth_state = unauth["coverage"].get("state")
    if auth_state == "ran" and unauth_state == "ran":
        results = correlate_findings(unauth["normalized"]["results"], auth["normalized"]["results"])
        state = "ran"
        code = max(unauthenticated_exit_code, authenticated_exit_code)
    elif "tool_error" in {auth_state, unauth_state}:
        results = copy.deepcopy(unauth["normalized"]["results"] + auth["normalized"]["results"])
        state = "tool_error"
        child_codes = {unauthenticated_exit_code, authenticated_exit_code}
        code = 3 if 3 in child_codes else 2 if 2 in child_codes else 3
    elif auth_state == "ran":
        results = copy.deepcopy(unauth["normalized"]["results"] + auth["normalized"]["results"])
        state = "tool_error"
        code = 3
    else:
        results = copy.deepcopy(auth["normalized"]["results"])
        state = auth_state if auth_state in {"not_applicable", "not_configured", "tool_error"} else "tool_error"
        code = authenticated_exit_code
        if state in {"not_applicable", "not_configured"}:
            code = 0
    normalized = {"schema_version": 1, "profile": auth["normalized"]["profile"], "results": results}
    coverage = copy.deepcopy(auth["coverage"])
    coverage.update({
        "state": state,
        "comparison_mode": "authenticated_and_unauthenticated",
        "unauthenticated_state": unauth_state,
        "authenticated_state": auth_state,
        "normalized_finding_count": len([item for item in results if item.get("result_type") == "finding"]),
    })
    policy = copy.deepcopy(auth["policy"])
    policy.update({
        "exit_code": code,
        "exit_category": {0: "pass", 1: "policy_violation", 2: "tool_error", 3: "invalid_input"}[code],
        "clean": state == "ran" and code == 0,
        "findings": len([item for item in results if item.get("result_type") == "finding"]),
        "tool_errors": len([item for item in results if item.get("result_type") == "tool_error"]),
    })
    report = ("# VibeSec authenticated security comparison\n\n"
              f"- Coverage: {state}\n- Authenticated scan: {auth_state}\n"
              f"- Unauthenticated scan: {unauth_state}\n"
              f"- Correlated findings: {policy['findings']}\n\n"
              f"- Finding intelligence groups: {len(finding_groups['groups'])}\n\n"
              "One bearer identity cannot prove authorization correctness.\n").encode()
    output.mkdir(parents=True, exist_ok=True)
    for name, data in {
        "normalized.json": canonical_json(normalized), "coverage.json": canonical_json(coverage),
        "policy-result.json": canonical_json(policy), "report.md": report,
        "finding-groups.json": canonical_json(finding_groups),
        "prioritized-findings.json": canonical_json(prioritized_findings),
    }.items():
        atomic_publish(output / name, data)
    return code
