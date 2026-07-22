#!/usr/bin/env python3
"""Strictly verify an untrusted local VibeSec consumer ZIP without extraction."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.bundle import BundleError, verify_bundle  # noqa: E402
from vibesec.exit_codes import INFRASTRUCTURE_FAILURE, SUCCESS, VERIFICATION_FAILED  # noqa: E402
from vibesec.output import emit, envelope  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        bundle = verify_bundle(args.bundle)
        emit(envelope("verify_consumer_bundle", bundle.version, "valid", result={
            "bundle_manifest_sha256": bundle.manifest_sha256,
            "source_commit": bundle.source_commit,
            "file_count": bundle.manifest["total_file_count"],
            "signed": False,
        }, information=["Bundle structure and hashes are valid; this does not prove application security."]), as_json=args.json)
        return SUCCESS
    except BundleError as exc:
        emit(envelope("verify_consumer_bundle", "unknown", "invalid", errors=[str(exc)]), as_json=args.json)
        return VERIFICATION_FAILED
    except OSError as exc:
        emit(envelope("verify_consumer_bundle", "unknown", "infrastructure_failure", errors=[str(exc)]), as_json=args.json)
        return INFRASTRUCTURE_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
