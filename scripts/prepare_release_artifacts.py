#!/usr/bin/env python3
"""Prepare, but do not publish or sign, a strict VibeSec release artifact set."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.exit_codes import INFRASTRUCTURE_FAILURE, INVALID_INPUT, SUCCESS  # noqa: E402
from vibesec.output import emit, envelope  # noqa: E402
from vibesec.strict_json import StrictJSONError, loads_strict  # noqa: E402
from vibesec.supply_chain import SupplyChainError, prepare_release  # noqa: E402
from vibesec.version import VersionError, read_version  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--cyclonedx", required=True, type=Path)
    parser.add_argument("--spdx", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--creation-mode", choices=("local-preparation", "trusted-github-workflow"), default="local-preparation")
    parser.add_argument("--invocation-id", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        version = read_version(ROOT)
        tools = loads_strict((ROOT / "config/tools.json").read_bytes())
        if not isinstance(tools, dict):
            raise SupplyChainError("tool inventory must be an object")
        tool_versions = {
            name: str(tools[name]["version"])
            for name in ("cosign", "syft")
            if isinstance(tools.get(name), dict) and isinstance(tools[name].get("version"), str)
        }
        if set(tool_versions) != {"cosign", "syft"}:
            raise SupplyChainError("release tool versions are unavailable")
        manifest = prepare_release(
            args.output, bundle=args.bundle, cyclonedx=args.cyclonedx, spdx=args.spdx,
            version=version, source_commit=args.source_commit, tool_versions=tool_versions,
            creation_mode=args.creation_mode, invocation_id=args.invocation_id,
        )
        emit(envelope("prepare_release_artifacts", version, "prepared", result={
            "output": str(args.output), "source_commit": manifest["source"]["commit"],
            "signed": False, "published": False,
        }, information=["Prepared artifacts are unsigned and were not published."]), as_json=args.json)
        return SUCCESS
    except (OSError, StrictJSONError, SupplyChainError, VersionError, ValueError) as exc:
        emit(envelope("prepare_release_artifacts", "unknown", "invalid", errors=[str(exc)]), as_json=args.json)
        return INVALID_INPUT
    except Exception as exc:  # defensive CLI boundary
        emit(envelope("prepare_release_artifacts", "unknown", "infrastructure_failure", errors=[type(exc).__name__]), as_json=args.json)
        return INFRASTRUCTURE_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
