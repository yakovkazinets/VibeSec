#!/usr/bin/env python3
"""Validate the security accountability matrix, fixtures, CI references, and rendered documentation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.paths import UnsafePath, safe_posix_path  # noqa: E402
from vibesec.strict_json import StrictJSONError, loads_strict  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "config/security-capabilities.json"
DOCUMENT_PATH = ROOT / "docs/security-capability-matrix.md"
MATRIX_FIELDS = {"schema_version", "claimed_scanners", "capabilities"}
CAPABILITY_FIELDS = {
    "id", "profile", "category", "component", "tool", "tool_version_source",
    "positive_fixture", "negative_fixture", "expected_metadata", "expected_coverage",
    "expected_finding_ids", "expected_artifacts", "network_behavior", "trusted_event_only",
    "self_repository_scan", "limitations_document", "ci_enforcement", "status", "status_reason",
}
EXPECTED_FIELDS = {
    "schema_version", "capability_id", "expected_tool", "positive", "negative",
    "required_normalized_fields", "failure_modes", "privacy_classification", "fake_secret_pattern",
}
CASE_FIELDS = {"expected_findings", "expected_finding_ids", "expected_count", "expected_coverage", "expected_exit_category"}
FINDING_EXPECTATION_FIELDS = {"id", "path", "severity"}
PROFILES = {"minimal", "standard", "dast-baseline", "api-security-baseline", "authenticated-security-testing"}
CATEGORIES = {"secret_configuration", "secret", "ci", "policy", "sast", "sca", "sbom", "iac", "container", "inventory", "coverage", "trust_boundary", "dast", "api", "authentication"}
STATUSES = {"enforced", "conditionally_enforced", "documented_only", "deferred"}
COVERAGE = {"ran", "not_applicable", "not_configured", "tool_error"}
NON_SCANNER_TOOLS = {"cosign", "dast-fixture-python"}
IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$")


class CapabilityError(ValueError):
    """Trusted accountability configuration is invalid or inconsistent."""


def _load(path: Path) -> Any:
    try:
        return loads_strict(path.read_bytes())
    except (OSError, StrictJSONError) as exc:
        try:
            label = path.relative_to(ROOT).as_posix()
        except ValueError:
            label = path.name
        raise CapabilityError(f"invalid strict JSON in {label}: {exc}") from exc


def _strings(value: Any, field: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value) or len(value) > 256:
        raise CapabilityError(f"{field} must be a bounded string array")
    if any(not isinstance(item, str) or not item or len(item) > 500 for item in value):
        raise CapabilityError(f"{field} contains invalid text")
    return value


def _path(value: Any, field: str, *, directory: bool = False) -> Path:
    try:
        relative = safe_posix_path(value)
    except UnsafePath as exc:
        raise CapabilityError(f"{field} is unsafe: {exc}") from exc
    path = ROOT / relative
    if directory and not path.is_dir():
        raise CapabilityError(f"{field} directory is missing: {relative}")
    if not directory and not path.is_file():
        raise CapabilityError(f"{field} file is missing: {relative}")
    return path


def _validate_expected(path: Path, capability: dict[str, Any]) -> None:
    payload = _load(path)
    if not isinstance(payload, dict) or set(payload) != EXPECTED_FIELDS or payload.get("schema_version") != 1:
        raise CapabilityError(f"fixture expected metadata schema is invalid: {path.relative_to(ROOT)}")
    expected_tool = "trivy-image" if capability["id"] == "standard.trivy-image" else capability["tool"]
    if payload["capability_id"] != capability["id"] or payload["expected_tool"] != expected_tool:
        raise CapabilityError(f"fixture metadata identity differs from capability: {capability['id']}")
    for case_name in ("positive", "negative"):
        case = payload[case_name]
        if not isinstance(case, dict) or set(case) != CASE_FIELDS:
            raise CapabilityError(f"fixture {case_name} metadata fields are invalid: {capability['id']}")
        identifiers = _strings(case["expected_finding_ids"], f"{capability['id']}.{case_name}.expected_finding_ids", allow_empty=True)
        finding_expectations = case["expected_findings"]
        if not isinstance(finding_expectations, list) or any(
            not isinstance(item, dict) or set(item) != FINDING_EXPECTATION_FIELDS
            or not all(isinstance(item[field], str) and item[field] for field in FINDING_EXPECTATION_FIELDS)
            for item in finding_expectations
        ):
            raise CapabilityError(f"fixture {case_name} finding expectations are invalid: {capability['id']}")
        for item in finding_expectations:
            if capability["tool"] == "zap-baseline":
                if not item["path"].startswith("/") or ".." in item["path"].split("/") or "\\" in item["path"]:
                    raise CapabilityError(f"fixture expected DAST path is unsafe: {capability['id']}")
            else:
                try:
                    safe_posix_path(item["path"])
                except UnsafePath as exc:
                    raise CapabilityError(f"fixture expected finding path is unsafe: {capability['id']}: {exc}") from exc
        detailed_ids = sorted(item["id"] for item in finding_expectations)
        count = case["expected_count"]
        if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= 1000 or count != len(identifiers) or detailed_ids != sorted(identifiers):
            raise CapabilityError(f"fixture {case_name} count and identifiers differ: {capability['id']}")
        if case["expected_coverage"] not in COVERAGE or not isinstance(case["expected_exit_category"], str):
            raise CapabilityError(f"fixture {case_name} coverage or exit category is invalid: {capability['id']}")
    if payload["positive"]["expected_finding_ids"] != capability["expected_finding_ids"]:
        raise CapabilityError(f"matrix and fixture finding identifiers differ: {capability['id']}")
    _strings(payload["required_normalized_fields"], "required_normalized_fields", allow_empty=True)
    _strings(payload["failure_modes"], "failure_modes")
    if not isinstance(payload["privacy_classification"], str) or not payload["privacy_classification"]:
        raise CapabilityError(f"fixture privacy classification is missing: {capability['id']}")
    if payload["fake_secret_pattern"] is not None and not isinstance(payload["fake_secret_pattern"], str):
        raise CapabilityError(f"fixture fake-secret declaration is invalid: {capability['id']}")


def validate_matrix() -> dict[str, Any]:
    payload = _load(MATRIX_PATH)
    if not isinstance(payload, dict) or set(payload) != MATRIX_FIELDS or payload.get("schema_version") != 1:
        raise CapabilityError("security capability matrix schema or fields are invalid")
    claimed = _strings(payload["claimed_scanners"], "claimed_scanners")
    if claimed != sorted(set(claimed)):
        raise CapabilityError("claimed scanners must be unique and sorted")
    tools = _load(ROOT / "config/tools.json")
    if not isinstance(tools, dict) or set(claimed) != set(tools) - NON_SCANNER_TOOLS:
        raise CapabilityError("claimed scanners and configured scanner tools differ")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    marker = re.search(r"<!-- claimed-scanners: ([a-z0-9,.-]+) -->", readme)
    if marker is None or marker.group(1).split(",") != claimed:
        raise CapabilityError("README claimed-scanners marker and capability matrix differ")
    capabilities = payload["capabilities"]
    if not isinstance(capabilities, list) or not capabilities or len(capabilities) > 128:
        raise CapabilityError("capabilities must be a bounded nonempty array")
    identifiers: set[str] = set()
    matrix_tools: set[str] = set()
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for capability in capabilities:
        if not isinstance(capability, dict) or set(capability) != CAPABILITY_FIELDS:
            raise CapabilityError("capability contains missing or unknown fields")
        identifier = capability["id"]
        if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier) or identifier in identifiers:
            raise CapabilityError(f"capability ID is invalid or duplicated: {identifier!r}")
        identifiers.add(identifier)
        if capability["profile"] not in PROFILES or capability["category"] not in CATEGORIES or capability["status"] not in STATUSES:
            raise CapabilityError(f"capability enum is unsupported: {identifier}")
        if capability["expected_coverage"] not in COVERAGE or capability["self_repository_scan"] not in COVERAGE | {"conditional"}:
            raise CapabilityError(f"capability coverage state is unsupported: {identifier}")
        tool = capability["tool"]
        if tool is not None:
            if tool not in tools:
                raise CapabilityError(f"capability references unconfigured tool: {identifier}")
            matrix_tools.add(tool)
            if capability["tool_version_source"] != f"config/tools.json#{tool}.version":
                raise CapabilityError(f"tool version source is inconsistent: {identifier}")
        elif capability["tool_version_source"] != "VERSION":
            raise CapabilityError(f"internal capability version source is invalid: {identifier}")
        positive = _path(capability["positive_fixture"], f"{identifier}.positive_fixture", directory=True)
        negative = _path(capability["negative_fixture"], f"{identifier}.negative_fixture", directory=True)
        if not any(path.is_file() for path in positive.rglob("*")) or not any(path.is_file() for path in negative.rglob("*")):
            raise CapabilityError(f"capability fixtures must contain files: {identifier}")
        metadata = _path(capability["expected_metadata"], f"{identifier}.expected_metadata")
        _path(capability["limitations_document"], f"{identifier}.limitations_document")
        findings = _strings(capability["expected_finding_ids"], f"{identifier}.expected_finding_ids", allow_empty=True)
        if findings != sorted(set(findings)):
            raise CapabilityError(f"expected finding identifiers must be unique and sorted: {identifier}")
        _strings(capability["expected_artifacts"], f"{identifier}.expected_artifacts")
        enforcement = _strings(capability["ci_enforcement"], f"{identifier}.ci_enforcement")
        for reference in enforcement:
            if "/" in reference:
                _path(reference, f"{identifier}.ci_enforcement")
            elif not re.search(rf"(?m)^  {re.escape(reference)}:\s*$", workflow):
                raise CapabilityError(f"capability CI job reference is missing: {identifier}: {reference}")
        if capability["status"] in {"enforced", "conditionally_enforced"} and not enforcement:
            raise CapabilityError(f"enforced capability lacks CI evidence: {identifier}")
        if capability["status"] in {"documented_only", "deferred"} and not capability["status_reason"]:
            raise CapabilityError(f"non-enforced capability lacks rationale: {identifier}")
        if not isinstance(capability["trusted_event_only"], bool) or not isinstance(capability["status_reason"], str) or not capability["status_reason"]:
            raise CapabilityError(f"capability trust or rationale field is invalid: {identifier}")
        _validate_expected(metadata, capability)
    if matrix_tools != set(claimed):
        raise CapabilityError(f"claimed scanners lack capability coverage: {sorted(set(claimed) - matrix_tools)}")
    return payload


def render_matrix(payload: dict[str, Any]) -> str:
    lines = [
        "# Security capability matrix", "",
        "This document is generated from `config/security-capabilities.json`. Run `python3 scripts/validate_security_capabilities.py --write-matrix` after an approved matrix change.", "",
        "A capability is not complete merely because integration code exists. See [security validation policy](security-validation-policy.md).", "",
        "| Capability | Profile | Component/tool | Status | Fixtures | Self-scan | Expected state | Artifacts | Network/trust | Limitations | CI enforcement |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for item in payload["capabilities"]:
        def cell(value: Any) -> str:
            return str(value).replace("|", "\\|").replace("\n", " ")
        fixture = f"positive + negative ({item['expected_metadata']})"
        trust = item["network_behavior"] + ("; trusted events only" if item["trusted_event_only"] else "")
        lines.append("| " + " | ".join(cell(value) for value in (
            item["id"], item["profile"], item["tool"] or item["component"], item["status"], fixture,
            item["self_repository_scan"], item["expected_coverage"], ", ".join(item["expected_artifacts"]),
            trust, item["limitations_document"], ", ".join(item["ci_enforcement"]),
        )) + " |")
    lines.extend([
        "", "## Interpretation", "",
        "`enforced` means implementation, controlled fixtures, normalization or artifact checks, failure paths, documentation, and CI evidence are all linked. `conditionally_enforced` means the safe routing and controlled evidence are enforced but live execution needs an explicit trusted condition. No passing row is a claim that VibeSec or a scanned application is secure.", "",
    ])
    return "\n".join(lines)


def validate_evidence(path: Path, matrix: dict[str, Any]) -> None:
    payload = _load(path)
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "evidence_type", "capabilities"} or payload.get("schema_version") != 1:
        raise CapabilityError("accountability evidence schema is invalid")
    if payload["evidence_type"] != "controlled_security_accountability" or not isinstance(payload["capabilities"], list):
        raise CapabilityError("accountability evidence type or capability list is invalid")
    expected = {item["id"]: item for item in matrix["capabilities"]}
    observed: dict[str, dict[str, Any]] = {}
    for item in payload["capabilities"]:
        if not isinstance(item, dict) or set(item) != {"capability_id", "tool", "status", "positive", "negative", "failure_modes", "expected_artifacts", "trusted_event_only"}:
            raise CapabilityError("accountability evidence entry fields are invalid")
        identifier = item["capability_id"]
        if identifier in observed or identifier not in expected:
            raise CapabilityError(f"accountability evidence capability is duplicate or unknown: {identifier}")
        observed[identifier] = item
        capability = expected[identifier]
        fixture = _load(ROOT / capability["expected_metadata"])
        if item["tool"] != capability["tool"] or item["status"] != capability["status"] or item["failure_modes"] != fixture["failure_modes"]:
            raise CapabilityError(f"accountability evidence identity differs: {identifier}")
        for case in ("positive", "negative"):
            value = item[case]
            fields = {"fixture_ran", "coverage_state", "finding_ids", "finding_count", "exit_category"}
            wanted = fixture[case]
            if not isinstance(value, dict) or set(value) != fields or value["fixture_ran"] is not True:
                raise CapabilityError(f"accountability {case} evidence is malformed: {identifier}")
            if value["coverage_state"] != wanted["expected_coverage"] or value["finding_ids"] != sorted(wanted["expected_finding_ids"]) or value["finding_count"] != wanted["expected_count"] or value["exit_category"] != wanted["expected_exit_category"]:
                raise CapabilityError(f"accountability {case} evidence differs: {identifier}")
    if set(observed) != set(expected):
        raise CapabilityError(f"accountability evidence omits capabilities: {sorted(set(expected) - set(observed))}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-matrix", action="store_true")
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    try:
        payload = validate_matrix()
        rendered = render_matrix(payload)
        if args.write_matrix:
            DOCUMENT_PATH.write_text(rendered, encoding="utf-8", newline="\n")
        elif not DOCUMENT_PATH.is_file() or DOCUMENT_PATH.read_text(encoding="utf-8") != rendered:
            raise CapabilityError("docs/security-capability-matrix.md differs from machine-readable configuration")
        if args.evidence:
            validate_evidence(args.evidence, payload)
    except (CapabilityError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 3
    print(f"validated {len(payload['capabilities'])} security capabilities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
