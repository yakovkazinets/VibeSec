#!/usr/bin/env python3
"""Validate the exact sanitized API Security Baseline artifact contract."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.api_security import ApiSecurityError, CHECKS, IMAGE, sanitize_path_template  # noqa: E402
from vibesec.authenticated import validate_publishable_bytes  # noqa: E402
from vibesec.finding_intelligence import FindingIntelligenceError, validate_documents  # noqa: E402
from vibesec.strict_json import StrictJSONError, loads_strict  # noqa: E402

REQUIRED = {"normalized.json", "coverage.json", "report.md", "policy-result.json", "finding-groups.json", "prioritized-findings.json"}
PROHIBITED = ("schemathesis.ndjson", "request_body", "response_body", "request_headers", "response_headers", "cookies", "curl ",
              "authorization", "/home/runner", "/users/", "container-id", "registry.example")


def validate(results: Path, expected_state: str) -> None:
    if results.is_symlink() or not results.is_dir():
        raise ApiSecurityError("API results directory is missing or unsafe")
    observed = {path.name for path in results.iterdir() if path.is_file()}
    if not REQUIRED <= observed or observed - REQUIRED - {"scan-exit-code.txt"}:
        raise ApiSecurityError("API result file set is missing or contains unapproved artifacts")
    normalized = loads_strict((results / "normalized.json").read_bytes())
    coverage = loads_strict((results / "coverage.json").read_bytes())
    policy = loads_strict((results / "policy-result.json").read_bytes())
    validate_documents(
        loads_strict((results / "finding-groups.json").read_bytes()),
        loads_strict((results / "prioritized-findings.json").read_bytes()),
    )
    if not isinstance(normalized, dict) or normalized.get("profile") != "api-security-baseline" or not isinstance(normalized.get("results"), list):
        raise ApiSecurityError("normalized API artifact is malformed")
    authenticated = coverage.get("authentication_mode") == "bearer"
    fixed = {"network_mode": "internal_only", "external_egress": False, "authentication": authenticated,
             "custom_headers": authenticated, "stateful_testing": False, "phases": ["examples", "coverage", "fuzzing"],
             "generation_mode": "all"}
    if not isinstance(coverage, dict) or coverage.get("profile") != "api-security-baseline" or coverage.get("state") != expected_state or any(coverage.get(key) != value for key, value in fixed.items()):
        raise ApiSecurityError("API coverage profile, state, or isolation declarations differ")
    if coverage.get("target_digest") is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", coverage["target_digest"]):
        raise ApiSecurityError("API target digest is malformed")
    if not isinstance(policy, dict) or policy.get("profile") != "api-security-baseline" or policy.get("exit_code") not in {0, 1, 2, 3}:
        raise ApiSecurityError("API policy artifact is malformed")
    allowed_fields = {"tool", "category", "rule_id", "severity", "file", "line", "description", "confidence", "fingerprint", "result_type",
                      "operation_id", "method", "path_template", "title", "remediation", "response_status",
                      "status_class", "contract_class", "observed_unauthenticated", "observed_authenticated"}
    for item in normalized["results"]:
        if not isinstance(item, dict) or set(item) - allowed_fields or item.get("result_type") not in {"finding", "tool_error"}:
            raise ApiSecurityError("API normalized result contains unapproved fields")
        if item["result_type"] == "finding":
            if item.get("rule_id") not in CHECKS:
                raise ApiSecurityError("API normalized result contains an unreviewed check")
            sanitize_path_template(item.get("path_template"))
    raw_artifacts = b"".join((results / name).read_bytes() for name in REQUIRED)
    validate_publishable_bytes(raw_artifacts)
    serialized = raw_artifacts.decode("utf-8").casefold()
    if any(marker.casefold() in serialized for marker in PROHIBITED) or re.search(r"https?://", serialized):
        raise ApiSecurityError("API artifacts contain prohibited raw, sensitive, or origin material")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--expect-state", required=True, choices=("ran", "not_applicable", "not_configured", "tool_error"))
    args = parser.parse_args()
    try:
        validate(args.results, args.expect_state)
    except (ApiSecurityError, FindingIntelligenceError, OSError, StrictJSONError, UnicodeError) as exc:
        print(f"API artifact validation failed: {exc}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
