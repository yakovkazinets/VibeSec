#!/usr/bin/env python3
"""Verify an installed VibeSec configuration without modifying the target."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.exit_codes import INFRASTRUCTURE_FAILURE, INVALID_INPUT, SUCCESS, VERIFICATION_FAILED, WARNINGS  # noqa: E402
from vibesec.installation import InstallationError, verify_installation  # noqa: E402
from vibesec.output import emit, envelope  # noqa: E402
from vibesec.version import VersionError, read_version  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        tool_version = read_version(ROOT)
    except VersionError:
        tool_version = "unknown"
    try:
        state = verify_installation(args.target)
        payload = envelope(
            "verify_installation", tool_version, state.status, result=state.result(),
            errors=state.errors, warnings=state.warnings, information=state.information,
        )
        emit(payload, as_json=args.json)
        if state.status == "valid":
            return SUCCESS
        if state.status in {"valid_with_local_changes", "unverifiable_legacy_installation"}:
            return WARNINGS
        return VERIFICATION_FAILED
    except InstallationError as exc:
        emit(envelope("verify_installation", tool_version, "invalid", errors=[str(exc)]), as_json=args.json)
        return INVALID_INPUT
    except OSError as exc:
        emit(envelope("verify_installation", tool_version, "infrastructure_failure", errors=[str(exc)]), as_json=args.json)
        return INFRASTRUCTURE_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
