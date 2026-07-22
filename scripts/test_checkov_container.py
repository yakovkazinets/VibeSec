#!/usr/bin/env python3
"""Smoke-test the immutable Checkov container through production orchestration."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile

SCRIPT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_ROOT))
from run_standard_profile import run_checkov_files
from vibesec.model import Finding


ROOT = SCRIPT_ROOT.parent
FIXTURE_ROOT = ROOT / "tests/security-fixtures/checkov-iac"
CHECK_ID = "CKV_AWS_24"


def fail(reason: str) -> int:
    print(f"component=checkov-smoke category=tool_error reason={reason} docs=docs/self-hosted-validation.md", file=sys.stderr)
    return 2


def scan_files(target: Path, files: list[str]) -> tuple[bool, list[dict[str, object]]] | None:
    manifest = json.loads((ROOT / "config/tools.json").read_text(encoding="utf-8"))["checkov"]
    image = f'{manifest["image"]}@{manifest["digest"]}'
    config = ROOT / "config/checkov-standard.yaml"
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "checkov.json"
        findings, error, invalid_input = run_checkov_files(
            target, config, image, files, output,
            cwd=ROOT, env=dict(__import__("os").environ), extra_arguments=("--check", CHECK_ID),
        )
        if error == "Docker is unavailable":
            return None
        if error or invalid_input:
            return False, []
        normalized = [finding.to_dict() for finding in findings]
        try:
            payload = json.loads(output.read_text(encoding="utf-8"))
            raw_paths = [item["file_path"] for item in payload["results"]["failed_checks"]]
        except (OSError, KeyError, TypeError, json.JSONDecodeError):
            return False, []
        if raw_paths != [item["file"] for item in normalized]:
            return False, []
        return True, normalized


def scan(fixture: str, expected_exit: int) -> tuple[bool, list[str]] | None:
    """Compatibility helper used by focused failure-path tests."""
    result = scan_files(FIXTURE_ROOT / fixture, ["main.tf"])
    if result is None:
        return None
    valid, findings = result
    expected_findings = [CHECK_ID] if expected_exit == 1 else []
    return valid and [item["rule_id"] for item in findings] == expected_findings, [
        str(item["rule_id"]) for item in findings
    ]


def main() -> int:
    positive = scan_files(FIXTURE_ROOT / "positive", ["main.tf"])
    if positive is None:
        return fail("Docker is unavailable")
    if not positive[0] or [item["rule_id"] for item in positive[1]] != [CHECK_ID]:
        return fail("positive fixture did not produce the expected pinned Checkov finding")

    negative = scan_files(FIXTURE_ROOT / "negative", ["main.tf"])
    if negative != (True, []):
        return fail("negative fixture was not a clean valid pinned Checkov scan")

    multi = scan_files(FIXTURE_ROOT, ["positive/main.tf", "negative/main.tf"])
    if multi is None or not multi[0]:
        return fail("multi-file fixture did not complete through production orchestration")
    findings = multi[1]
    if [item["rule_id"] for item in findings] != [CHECK_ID]:
        return fail("multi-file fixture did not produce one deterministic finding")
    serialized = json.dumps(findings)
    if (findings[0]["file"] != "positive/main.tf" or str(FIXTURE_ROOT) in serialized
            or "/workspace/" in serialized or "\\" in serialized or ".." in findings[0]["file"]):
        return fail("multi-file fixture exposed a non-relative path")
    expected = Finding.create(
        tool="checkov", category="iac", rule_id=str(findings[0]["rule_id"]),
        severity=str(findings[0]["severity"]), file="positive/main.tf",
        line=findings[0]["line"] if isinstance(findings[0]["line"], int) else None,
        description=str(findings[0]["description"]), confidence=str(findings[0]["confidence"]),
    )
    if findings[0]["fingerprint"] != expected.fingerprint:
        return fail("multi-file fixture fingerprint did not use the canonical relative path")
    if len({item["fingerprint"] for item in findings}) != len(findings):
        return fail("multi-file fixture produced duplicate findings")

    print("validated pinned Checkov positive, negative, and production multi-file orchestration")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
