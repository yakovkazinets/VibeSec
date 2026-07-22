#!/usr/bin/env python3
"""Exercise deterministic positive/negative accountability fixtures and emit sanitized evidence."""

from __future__ import annotations

import argparse
from datetime import date
import json
import os
from pathlib import Path
import tempfile
from typing import Any
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.detection import inventory  # noqa: E402
from vibesec.dast import normalize_zap_report  # noqa: E402
from vibesec.api_security import CHECKS, load_config as load_api_config, normalize_schemathesis_report, operation_index, validate_openapi_schema  # noqa: E402
from vibesec.normalize import normalize_file  # noqa: E402
from vibesec.policy import evaluate  # noqa: E402
from vibesec.results import _validate_document  # noqa: E402
from vibesec.sbom import validate_cyclonedx, validate_spdx  # noqa: E402
from vibesec.strict_json import loads_strict  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "config/security-capabilities.json"
SCANNER_NORMALIZERS = {
    "minimal.trivy-filesystem": ("trivy", "raw.json"),
    "minimal.gitleaks": ("gitleaks", "raw.json"),
    "minimal.actionlint": ("actionlint", "raw.txt"),
    "standard.opengrep-sast": ("opengrep", "raw.json"),
    "standard.osv-dependencies": ("osv-scanner", "raw.json"),
    "standard.checkov-iac": ("checkov", "raw.json"),
    "standard.trivy-image": ("trivy-image", "raw.json"),
    "dast.zap-passive-baseline": ("zap-baseline", "raw.json"),
    "api.response-schema-conformance": ("schemathesis", "raw.ndjson"),
}
PROHIBITED_OUTPUT = ("VIBESEC_" + "FAKE_SECRET_DO_NOT_USE_", "/home/runner/", "/Users/", "RUNNER_TOKEN", "registry credential")


class AccountabilityError(ValueError):
    """Fixture evidence is missing, unsafe, or differs from expected behavior."""


def load_json(path: Path) -> Any:
    try:
        return loads_strict(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise AccountabilityError(f"invalid accountability JSON {path.relative_to(ROOT)}: {exc}") from exc


def atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def scanner_evidence(capability: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    tool, raw_name = SCANNER_NORMALIZERS[capability["id"]]
    observed: dict[str, Any] = {}
    for case in ("positive", "negative"):
        raw = ROOT / capability[f"{case}_fixture"] / raw_name
        try:
            if tool == "zap-baseline":
                findings, _ = normalize_zap_report(raw, port=8080, maximum_bytes=5_000_000, maximum_findings=1000)
            elif tool == "schemathesis":
                _, schema_payload, _ = validate_openapi_schema(ROOT / "tests/security-fixtures/api-security", "openapi.yaml", config=load_api_config(ROOT), port=8080, base_path="/")
                findings, _ = normalize_schemathesis_report(raw, schema_source="openapi.yaml", operations=operation_index(schema_payload), maximum_bytes=10_485_760, maximum_findings=1000)
            else:
                findings = [item.to_dict() for item in normalize_file(tool, raw)]
        except ValueError as exc:
            raise AccountabilityError(f"{capability['id']} {case} normalization failed: {exc}") from exc
        identifiers = sorted(item["rule_id"] for item in findings)
        details = sorted(
            ({"id": item["rule_id"], "path": item["file"], "severity": item["severity"]} for item in findings),
            key=lambda item: (item["id"], item["path"], item["severity"]),
        )
        wanted = expected[case]
        wanted_details = sorted(wanted["expected_findings"], key=lambda item: (item["id"], item["path"], item["severity"]))
        if len(findings) != wanted["expected_count"] or identifiers != sorted(wanted["expected_finding_ids"]) or details != wanted_details:
            raise AccountabilityError(f"{capability['id']} {case} expected {wanted['expected_finding_ids']} but observed {identifiers}")
        required = set(expected["required_normalized_fields"])
        for finding in findings:
            if not required <= set(finding) or finding["tool"] != tool or finding["result_type"] != "finding":
                raise AccountabilityError(f"{capability['id']} normalized fields or identity differ")
            if (tool not in {"zap-baseline"} and finding["file"].startswith("/")) or ".." in finding["file"].split("/"):
                raise AccountabilityError(f"{capability['id']} produced an unsafe normalized path")
        serialized = json.dumps(findings, sort_keys=True)
        if any(marker in serialized for marker in PROHIBITED_OUTPUT):
            raise AccountabilityError(f"{capability['id']} normalized evidence contains prohibited sensitive or host data")
        observed[case] = {
            "fixture_ran": True, "coverage_state": wanted["expected_coverage"],
            "finding_ids": identifiers, "finding_count": len(findings),
            "exit_category": wanted["expected_exit_category"],
        }
    return observed


def internal_evidence(capability: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    identifier = capability["id"]
    positive = ROOT / capability["positive_fixture"]
    negative = ROOT / capability["negative_fixture"]
    if identifier == "standard.syft-sbom":
        cdx = validate_cyclonedx(positive / "sbom.cyclonedx.json")
        spdx = validate_spdx(positive / "sbom.spdx.json")
        if [item.get("name") for item in cdx["components"]] != ["vibesec-synthetic-package"]:
            raise AccountabilityError("CycloneDX fixture package identity differs")
        if [item.get("name") for item in spdx["packages"]] != ["vibesec-synthetic-package"]:
            raise AccountabilityError("SPDX fixture package identity differs")
        if (negative / "package.json").exists():
            raise AccountabilityError("negative Syft fixture unexpectedly has a package manifest")
    elif identifier == "minimal.result-policy":
        document = _validate_document(load_json(positive / "scenario.json"))
        clean = _validate_document(load_json(negative / "scenario.json"))
        violation = evaluate(document["results"], minimum_severity="high", enforcement="all", baseline=set(), suppressions=set(), today=date.today())
        if len(violation["violations"]) != 1 or clean["results"]:
            raise AccountabilityError("policy fixture result distinction failed")
    elif identifier == "standard.repository-inventory":
        present = inventory(positive)
        absent = inventory(negative)
        if not present["source_files"] or not present["manifests"] or absent["source_files"] or absent["manifests"]:
            raise AccountabilityError("repository inventory fixture routing differs")
    elif identifier == "standard.coverage-report":
        states = load_json(positive / "scenario.json").get("states")
        missing = load_json(negative / "scenario.json").get("states")
        if set(states or []) != {"ran", "not_applicable", "not_configured", "tool_error"} or set(missing or []) == set(states or []):
            raise AccountabilityError("coverage-state fixture distinction failed")
    elif identifier == "standard.trusted-harness":
        scenario = load_json(positive / "scenario.json")
        if scenario != {"schema_version": 1, "harness_source": "trusted_base_revision", "target_authority": False}:
            raise AccountabilityError("trusted harness fixture is malformed")
        required = {"scripts/run_standard_profile.py", "config/security-capabilities.json", "policy/standard-baseline.json"}
        observed = {path.relative_to(negative).as_posix() for path in negative.rglob("*") if path.is_file()}
        if not required <= observed:
            raise AccountabilityError("trusted harness replacement fixture is incomplete")
    elif identifier == "standard.profile-baselines":
        good = load_json(positive / "scenario.json")
        bad = load_json(negative / "scenario.json")
        if good.get("minimal_profile") != "minimal" or good.get("standard_profile") != "standard" or bad.get("minimal_profile") != "standard":
            raise AccountabilityError("profile baseline fixture distinction failed")
    elif identifier.startswith("dast."):
        good = load_json(positive / "scenario.json")
        bad = load_json(negative / "scenario.json")
        if good != {"schema_version": 1, "safe": True, "event": "workflow_dispatch", "network": "internal_only", "active_scanning": False}:
            raise AccountabilityError(f"{identifier} positive DAST scenario is malformed")
        if bad.get("safe") is not False or bad.get("event") != "pull_request" or bad.get("active_scanning") is not True:
            raise AccountabilityError(f"{identifier} negative DAST scenario is malformed")
    elif identifier.startswith("api."):
        fixture = ROOT / "tests/security-fixtures/api-security"
        if identifier == "api.openapi-schema-validation":
            _, _, operations = validate_openapi_schema(fixture, "openapi.yaml", config=load_api_config(ROOT), port=8080, base_path="/")
            if operations != 2:
                raise AccountabilityError("API schema fixture operation count differs")
        else:
            _, schema_payload, _ = validate_openapi_schema(fixture, "openapi.yaml", config=load_api_config(ROOT), port=8080, base_path="/")
            index = operation_index(schema_payload)
            findings, _ = normalize_schemathesis_report(fixture / "positive/raw.ndjson", schema_source="openapi.yaml", operations=index, maximum_bytes=10_485_760, maximum_findings=1000)
            clean, _ = normalize_schemathesis_report(fixture / "negative/raw.ndjson", schema_source="openapi.yaml", operations=index, maximum_bytes=10_485_760, maximum_findings=1000)
            if [item["rule_id"] for item in findings] != ["response_schema_conformance"] or clean:
                raise AccountabilityError(f"{identifier} API structured fixture distinction failed")
            check = identifier.removeprefix("api.").replace("server-error-detection", "not_a_server_error").replace("status-code-conformance", "status_code_conformance").replace("content-type-conformance", "content_type_conformance").replace("response-schema-conformance", "response_schema_conformance").replace("negative-data-rejection", "negative_data_rejection").replace("positive-data-acceptance", "positive_data_acceptance")
            if identifier in {"api.server-error-detection", "api.status-code-conformance", "api.content-type-conformance", "api.response-schema-conformance", "api.negative-data-rejection", "api.positive-data-acceptance"} and check not in CHECKS:
                raise AccountabilityError(f"{identifier} reviewed check mapping is absent")
    else:
        raise AccountabilityError(f"no fixture handler exists for {identifier}")
    return {
        "positive": {"fixture_ran": True, "coverage_state": expected["positive"]["expected_coverage"], "finding_ids": expected["positive"]["expected_finding_ids"], "finding_count": expected["positive"]["expected_count"], "exit_category": expected["positive"]["expected_exit_category"]},
        "negative": {"fixture_ran": True, "coverage_state": expected["negative"]["expected_coverage"], "finding_ids": expected["negative"]["expected_finding_ids"], "finding_count": expected["negative"]["expected_count"], "exit_category": expected["negative"]["expected_exit_category"]},
    }


def run() -> dict[str, Any]:
    matrix = load_json(MATRIX)
    evidence: list[dict[str, Any]] = []
    for capability in matrix["capabilities"]:
        expected = load_json(ROOT / capability["expected_metadata"])
        cases = scanner_evidence(capability, expected) if capability["id"] in SCANNER_NORMALIZERS else internal_evidence(capability, expected)
        evidence.append({
            "capability_id": capability["id"], "tool": capability["tool"],
            "status": capability["status"], "positive": cases["positive"], "negative": cases["negative"],
            "failure_modes": expected["failure_modes"], "expected_artifacts": capability["expected_artifacts"],
            "trusted_event_only": capability["trusted_event_only"],
        })
    return {"schema_version": 1, "evidence_type": "controlled_security_accountability", "capabilities": evidence}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        payload = run()
        atomic_json(args.output, payload)
    except (AccountabilityError, OSError, ValueError) as exc:
        print(f"security accountability failed: {exc}", file=sys.stderr)
        return 2
    print(f"validated {len(payload['capabilities'])} positive and negative capability fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
