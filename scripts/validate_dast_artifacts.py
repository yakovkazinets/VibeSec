#!/usr/bin/env python3
"""Validate the exact sanitized DAST baseline artifact contract."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.dast import DastError, DIGEST, sanitize_url  # noqa: E402
from vibesec.authenticated import validate_publishable_bytes  # noqa: E402
from vibesec.finding_intelligence import FindingIntelligenceError, validate_documents  # noqa: E402
from vibesec.strict_json import StrictJSONError, loads_strict  # noqa: E402

REQUIRED = {"normalized.json", "coverage.json", "report.md", "policy-result.json", "finding-groups.json", "prioritized-findings.json"}
PROHIBITED = ("zap-report.json", "?", "cookie", "request body", "response body", "registry.example", "/home/runner", "/Users/")


def validate(results: Path, expected_state: str) -> None:
    if results.is_symlink() or not results.is_dir():
        raise DastError("DAST results directory is missing or unsafe")
    observed = {path.name for path in results.iterdir() if path.is_file()}
    if not REQUIRED <= observed or observed - REQUIRED - {"scan-exit-code.txt"}:
        raise DastError("DAST result file set is missing or contains unapproved artifacts")
    normalized = loads_strict((results / "normalized.json").read_bytes())
    coverage = loads_strict((results / "coverage.json").read_bytes())
    policy = loads_strict((results / "policy-result.json").read_bytes())
    validate_documents(
        loads_strict((results / "finding-groups.json").read_bytes()),
        loads_strict((results / "prioritized-findings.json").read_bytes()),
    )
    if not isinstance(normalized, dict) or normalized.get("profile") != "dast-baseline" or not isinstance(normalized.get("results"), list):
        raise DastError("normalized DAST artifact is malformed")
    if not isinstance(coverage, dict) or coverage.get("profile") != "dast-baseline" or coverage.get("state") != expected_state:
        raise DastError("DAST coverage profile or exact state differs")
    authenticated = coverage.get("authentication_mode") == "bearer"
    fixed = {"network_mode": "internal_only", "active_scanning": False, "traditional_spider": True,
             "ajax_spider": False, "authentication": authenticated, "external_egress": False,
             "application_source_built": False, "project_dependencies_installed": False,
             "scanner_mode": "automation_framework", "report_template": "traditional-json",
             "runtime_addon_updates": False,
             "zap_home_mode": "ephemeral_tmpfs", "zap_home_path": "/zap/vibesec-home",
             "zap_home_tmpfs_megabytes": 256,
             "automation_plan_jobs": ["spider", "passiveScan-wait", "report", "exitStatus"]}
    if any(coverage.get(key) != value for key, value in fixed.items()):
        raise DastError("DAST coverage isolation declarations differ")
    if coverage.get("target_digest") is not None and (not isinstance(coverage["target_digest"], str) or not DIGEST.fullmatch(coverage["target_digest"])):
        raise DastError("DAST coverage target digest is malformed")
    if not isinstance(policy, dict) or policy.get("profile") != "dast-baseline" or policy.get("exit_code") not in {0, 1, 2, 3}:
        raise DastError("DAST policy artifact is malformed")
    for item in normalized["results"]:
        if not isinstance(item, dict) or item.get("result_type") not in {"finding", "tool_error"}:
            raise DastError("DAST normalized result is malformed")
        if item["result_type"] == "finding":
            sanitize_url(f"http://target:{coverage['target_port']}{item.get('file', '')}", port=coverage["target_port"])
    raw_artifacts = b"".join((results / name).read_bytes() for name in REQUIRED)
    validate_publishable_bytes(raw_artifacts)
    serialized = raw_artifacts.decode("utf-8").casefold()
    if any(marker.casefold() in serialized for marker in PROHIBITED):
        raise DastError("DAST artifacts contain prohibited raw or sensitive material")
    if re.search(r"https?://", serialized):
        raise DastError("DAST artifacts contain an unapproved full URL")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--expect-state", required=True, choices=("ran", "not_configured", "not_applicable", "tool_error"))
    args = parser.parse_args()
    try:
        validate(args.results, args.expect_state)
    except (DastError, FindingIntelligenceError, OSError, StrictJSONError, UnicodeError) as exc:
        print(f"DAST artifact validation failed: {exc}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
