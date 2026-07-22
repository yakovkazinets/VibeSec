#!/usr/bin/env python3
"""Build a deterministic, unsigned VibeSec consumer ZIP from reviewed files."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.bundle import BundleError, write_bundle  # noqa: E402
from vibesec.exit_codes import INFRASTRUCTURE_FAILURE, INVALID_INPUT, SUCCESS  # noqa: E402
from vibesec.output import emit, envelope  # noqa: E402
from vibesec.version import VersionError, read_version  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        version = read_version(ROOT)
        digest, manifest = write_bundle(ROOT, args.output, args.source_commit)
        payload = envelope("build_consumer_bundle", version, "success", result={
            "output": str(args.output), "sha256": digest,
            "file_count": manifest["total_file_count"],
            "uncompressed_size": manifest["total_uncompressed_size"],
            "signed": False,
        }, information=["Built deterministic unsigned development bundle; verify before use."])
        emit(payload, as_json=args.json)
        return SUCCESS
    except (BundleError, VersionError, ValueError) as exc:
        version = "unknown"
        try:
            version = read_version(ROOT)
        except VersionError:
            pass
        emit(envelope("build_consumer_bundle", version, "invalid", errors=[str(exc)]), as_json=args.json)
        return INVALID_INPUT
    except OSError as exc:
        emit(envelope("build_consumer_bundle", "unknown", "infrastructure_failure", errors=[str(exc)]), as_json=args.json)
        return INFRASTRUCTURE_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
