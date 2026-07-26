#!/usr/bin/env python3
"""Verify an installed VibeSec Guardian configuration without modifying the target."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.exit_codes import INFRASTRUCTURE_FAILURE, INVALID_INPUT, SUCCESS, VERIFICATION_FAILED, WARNINGS  # noqa: E402
from vibesec.agents import AgentGuidanceError, verify_adapters  # noqa: E402
from vibesec.extensions import ExtensionError, verify_extensions  # noqa: E402
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
        extension_state = verify_extensions(state.target)
        agent_state = verify_adapters(ROOT, state.target)
        result = state.result()
        result["extension_verification"] = extension_state
        result["agent_verification"] = agent_state
        status = "invalid" if extension_state["status"] != "valid" or agent_state["status"] != "valid" else state.status
        errors = [*state.errors, *extension_state["errors"]]
        errors.extend(
            f"{item['adapter_id']}: {item['detail']}"
            for item in agent_state["adapters"] if item["state"] not in {"valid", "disabled"}
        )
        payload = envelope(
            "verify_installation", tool_version, status, result=result,
            errors=errors, warnings=state.warnings, information=state.information,
        )
        emit(payload, as_json=args.json)
        if status == "valid":
            return SUCCESS
        if status in {"valid_with_local_changes", "unverifiable_legacy_installation"}:
            return WARNINGS
        return VERIFICATION_FAILED
    except (AgentGuidanceError, ExtensionError, InstallationError) as exc:
        emit(envelope("verify_installation", tool_version, "invalid", errors=[str(exc)]), as_json=args.json)
        return INVALID_INPUT
    except OSError as exc:
        emit(envelope("verify_installation", tool_version, "infrastructure_failure", errors=[str(exc)]), as_json=args.json)
        return INFRASTRUCTURE_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
