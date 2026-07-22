#!/usr/bin/env python3
"""Smoke-test the immutable Checkov container against inert IaC fixtures."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile

SCRIPT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_ROOT))
from run_standard_profile import checkov_command
from vibesec.normalize import normalize_file


ROOT = SCRIPT_ROOT.parent
CHECK_ID = "CKV_AWS_24"


def fail(reason: str) -> int:
    print(f"component=checkov-smoke category=tool_error reason={reason} docs=docs/self-hosted-validation.md", file=sys.stderr)
    return 2


def scan(fixture: str, expected_exit: int) -> tuple[bool, list[str]] | None:
    manifest = json.loads((ROOT / "config/tools.json").read_text(encoding="utf-8"))["checkov"]
    image = f'{manifest["image"]}@{manifest["digest"]}'
    config = ROOT / "config/checkov-standard.yaml"
    target = ROOT / f"tests/security-fixtures/checkov-iac/{fixture}"
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "checkov.json"
        try:
            with output.open("xb") as stream:
                completed = subprocess.run(
                    checkov_command(target, config, image, ["main.tf"], "--check", CHECK_ID),
                    cwd=ROOT, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.DEVNULL,
                    timeout=300, check=False,
                )
        except FileNotFoundError:
            return None
        except (OSError, subprocess.TimeoutExpired):
            return False, []
        if completed.returncode != expected_exit:
            return False, []
        try:
            return True, [finding.rule_id for finding in normalize_file("checkov", output)]
        except ValueError:
            return False, []


def main() -> int:
    positive = scan("positive", 1)
    if positive is None:
        return fail("Docker is unavailable")
    if positive != (True, [CHECK_ID]):
        return fail("positive fixture did not produce the expected pinned Checkov finding")
    negative = scan("negative", 0)
    if negative != (True, []):
        return fail("negative fixture was not a clean valid pinned Checkov scan")
    print("validated pinned Checkov positive and negative fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
