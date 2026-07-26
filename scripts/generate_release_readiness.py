#!/usr/bin/env python3
"""Generate a deterministic exact-main VibeSec Guardian release-readiness report."""

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
    V1ContractError, build_readiness, canonical_readiness,
    validate_release_validation_evidence,
)


def _validation_evidence(path: Path, source_commit: str) -> dict[str, object]:
    value = loads_strict(path.read_bytes())
    return validate_release_validation_evidence(value, source_commit=source_commit)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--main-commit", required=True)
    parser.add_argument("--validation-evidence", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
            raise V1ContractError("readiness output must be a new file in an existing directory")
        value = build_readiness(
            ROOT, main_commit=args.main_commit,
            validation_evidence=_validation_evidence(
                args.validation_evidence, args.main_commit,
            ),
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
