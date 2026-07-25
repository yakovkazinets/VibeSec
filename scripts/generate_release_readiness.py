#!/usr/bin/env python3
"""Generate a deterministic exact-main VibeSec release-readiness report."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from vibesec.strict_json import loads_strict  # noqa: E402
from vibesec.v1_contract import (  # noqa: E402
    V1ContractError, build_readiness, canonical_readiness, validate_readiness,
)


def _test_total(args: argparse.Namespace) -> int:
    if args.test_total is not None:
        return args.test_total
    value = loads_strict(args.test_total_file.read_bytes())
    validate_readiness(value)
    total = value["test_totals"].get("automated_tests")
    if not isinstance(total, int) or isinstance(total, bool):
        raise V1ContractError("test-total file has no integer automated_tests count")
    return total


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--main-commit", required=True)
    totals = parser.add_mutually_exclusive_group(required=True)
    totals.add_argument("--test-total", type=int)
    totals.add_argument("--test-total-file", type=Path)
    parser.add_argument("--test-evidence", required=True)
    args = parser.parse_args()
    try:
        if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
            raise V1ContractError("readiness output must be a new file in an existing directory")
        value = build_readiness(
            ROOT, main_commit=args.main_commit, test_total=_test_total(args),
            test_evidence=args.test_evidence,
        )
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{args.output.name}.", dir=args.output.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(canonical_readiness(value))
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
        print(f"release readiness generation failed: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
