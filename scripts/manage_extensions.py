#!/usr/bin/env python3
"""Manage verified local VibeSec extensions; mutations are dry-run by default."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.exit_codes import INFRASTRUCTURE_FAILURE, INVALID_INPUT, SUCCESS, VERIFICATION_FAILED  # noqa: E402
from vibesec.extensions import (  # noqa: E402
    ExtensionError, describe_extension, install_extension, list_extensions, plan_extension_upgrade,
    remove_extension, set_enabled, verify_extensions,
)
from vibesec.output import emit, envelope  # noqa: E402
from vibesec.version import VersionError, read_version  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="operation", required=True)
    for name in ("list", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--target", type=Path, default=Path("."))
        command.add_argument("--json", action="store_true")
    describe = commands.add_parser("describe")
    describe.add_argument("extension_id")
    describe.add_argument("--target", type=Path, default=Path("."))
    describe.add_argument("--json", action="store_true")
    install = commands.add_parser("install")
    install.add_argument("source", type=Path)
    install.add_argument("--target", type=Path, default=Path("."))
    install.add_argument("--write", action="store_true")
    install.add_argument("--json", action="store_true")
    for name in ("disable", "enable", "remove"):
        command = commands.add_parser(name)
        command.add_argument("extension_id")
        command.add_argument("--target", type=Path, default=Path("."))
        command.add_argument("--write", action="store_true")
        command.add_argument("--json", action="store_true")
    upgrade = commands.add_parser("upgrade-plan")
    upgrade.add_argument("source", type=Path)
    upgrade.add_argument("--target", type=Path, default=Path("."))
    upgrade.add_argument("--json", action="store_true")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        version = read_version(ROOT)
    except VersionError:
        version = "unknown"
    try:
        if args.operation == "list":
            value = {"extensions": list_extensions(args.target)}
        elif args.operation == "verify":
            value = verify_extensions(args.target)
        elif args.operation == "describe":
            value = {"extension": describe_extension(args.target, args.extension_id)}
        elif args.operation == "install":
            value = install_extension(args.target, args.source, write=args.write)
        elif args.operation in {"disable", "enable"}:
            value = set_enabled(args.target, args.extension_id, enabled=args.operation == "enable", write=args.write)
        elif args.operation == "remove":
            value = remove_extension(args.target, args.extension_id, write=args.write)
        else:
            value = plan_extension_upgrade(args.target, args.source)
        status = value.get("status", "success") if isinstance(value, dict) else "success"
        emit(envelope(f"extensions_{args.operation.replace('-', '_')}", version, status, result=value), as_json=args.json)
        return VERIFICATION_FAILED if status == "invalid" else SUCCESS
    except (ExtensionError, OSError, ValueError) as exc:
        emit(envelope(f"extensions_{args.operation.replace('-', '_')}", version, "invalid", errors=[str(exc)]), as_json=getattr(args, "json", False))
        return INVALID_INPUT
    except KeyboardInterrupt:
        emit(envelope("extensions", version, "infrastructure_failure", errors=["interrupted"]), as_json=getattr(args, "json", False))
        return INFRASTRUCTURE_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
