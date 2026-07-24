#!/usr/bin/env python3
"""Validate the complete publishable API fuzzing artifact contract."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from vibesec.authenticated import validate_publishable_bytes  # noqa: E402
from vibesec.finding_intelligence import validate_documents  # noqa: E402
from vibesec.strict_json import loads_strict  # noqa: E402

FILES = {
    "fuzzing-findings.json", "fuzzing-coverage.json", "fuzzing-policy-result.json",
    "fuzzing-report.md", "finding-groups.json", "prioritized-findings.json",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--expect-state", choices=("ran", "not_applicable", "not_configured", "tool_error"))
    args = parser.parse_args()
    try:
        if args.results.is_symlink() or not args.results.is_dir():
            raise ValueError("results directory is unsafe or missing")
        observed = {path.name for path in args.results.iterdir()}
        if observed != FILES:
            raise ValueError("active API artifact inventory is incomplete or contains raw output")
        documents = {name: loads_strict((args.results / name).read_bytes(), maximum_bytes=5_000_000)
                     for name in FILES if name.endswith(".json")}
        normalized = documents["fuzzing-findings.json"]
        coverage = documents["fuzzing-coverage.json"]
        policy = documents["fuzzing-policy-result.json"]
        if normalized.get("schema_version") != 1 or normalized.get("profile") != "api-fuzzing" or not isinstance(normalized.get("results"), list):
            raise ValueError("active API normalized findings are malformed")
        if coverage.get("profile") != "api-fuzzing" or coverage.get("state") not in {"ran", "not_applicable", "not_configured", "tool_error"}:
            raise ValueError("active API coverage is malformed")
        if args.expect_state and coverage["state"] != args.expect_state:
            raise ValueError("active API coverage state differs from expectation")
        if policy.get("profile") != "api-fuzzing" or policy.get("exit_code") not in {0, 1, 2, 3}:
            raise ValueError("active API policy result is malformed")
        if policy.get("clean") is not (coverage["state"] == "ran" and policy["exit_code"] == 0):
            raise ValueError("active API clean state contradicts coverage or exit status")
        if any(coverage.get(field) is not False for field in ("external_egress", "raw_request_bodies_published", "raw_response_bodies_published", "authorization_header_fuzzed", "stateful_testing", "replay_metadata_contains_raw_values")):
            raise ValueError("active API trust boundary is not preserved")
        validate_documents(documents["finding-groups.json"], documents["prioritized-findings.json"])
        published = b"\n".join((args.results / name).read_bytes() for name in sorted(FILES))
        validate_publishable_bytes(published)
        if b"request_body" in published or b"response_body" in published or b"Authorization: Bearer" in published:
            raise ValueError("raw or authentication material reached active API artifacts")
        return 0
    except Exception as exc:
        print(f"API fuzzing artifact validation failed: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
