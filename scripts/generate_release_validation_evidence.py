#!/usr/bin/env python3
"""Record successful same-job validation evidence for an exact source commit."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from vibesec.strict_json import canonical_json  # noqa: E402
from vibesec.v1_contract import (  # noqa: E402
    V1ContractError, validate_release_validation_evidence,
)

MAX_LOG_BYTES = 5 * 1024 * 1024
TEST_COMMAND = "python3 -m unittest discover -s tests -v"
REPOSITORY_COMMAND = "python3 scripts/validate_repository.py"


def _read_log(path: Path) -> str:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_LOG_BYTES:
            raise V1ContractError(f"validation log is missing, unsafe, or oversized: {path.name}")
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise V1ContractError(f"validation log cannot be read: {path.name}") from exc


def build_evidence(*, source_commit: str, test_log: str,
                   repository_validation_log: str) -> dict[str, object]:
    matches = re.findall(r"(?m)^Ran ([1-9][0-9]*) tests? in [0-9.]+s$", test_log)
    if len(matches) != 1:
        raise V1ContractError("test log does not contain one complete unittest total")
    lines = [line.strip() for line in test_log.splitlines() if line.strip()]
    ok_lines = [line for line in lines if re.fullmatch(r"OK(?: \(skipped=[1-9][0-9]*\))?", line)]
    if len(ok_lines) != 1 or any(
            marker in test_log for marker in ("\nFAILED (", "\nFAILED\n", "\nERROR\n")):
        raise V1ContractError("test log does not record one successful full-suite result")
    repository_lines = [
        line.strip() for line in repository_validation_log.splitlines() if line.strip()
    ]
    if repository_lines != ["repository configuration is valid"]:
        raise V1ContractError("repository validation log is not the exact successful result")
    value: dict[str, object] = {
        "schema_version": 1,
        "stable_id": "vibesec.release-validation-evidence.v1",
        "status": "passed",
        "source_commit": source_commit,
        "test_command": TEST_COMMAND,
        "test_total": int(matches[0]),
        "test_result": "passed",
        "repository_validation_command": REPOSITORY_COMMAND,
        "repository_validation_result": "passed",
    }
    return validate_release_validation_evidence(value, source_commit=source_commit)


def _current_commit() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10,
        check=False,
    )
    if completed.returncode != 0:
        raise V1ContractError("current source commit cannot be determined")
    return completed.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--test-log", required=True, type=Path)
    parser.add_argument("--repository-validation-log", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
            raise V1ContractError("validation-evidence output must be a new file in an existing directory")
        if _current_commit() != args.source_commit:
            raise V1ContractError("requested source commit is not the checked-out exact commit")
        value = build_evidence(
            source_commit=args.source_commit,
            test_log=_read_log(args.test_log),
            repository_validation_log=_read_log(args.repository_validation_log),
        )
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{args.output.name}.", dir=args.output.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(canonical_json(value))
                stream.flush()
                os.fsync(stream.fileno())
            temporary.chmod(0o644)
            os.rename(temporary, args.output)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        print(f"generated {args.output}")
        return 0
    except (OSError, ValueError, V1ContractError) as exc:
        print(f"release validation evidence generation failed: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
