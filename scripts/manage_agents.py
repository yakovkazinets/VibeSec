#!/usr/bin/env python3
"""Manage deterministic VibeSec agent guidance; all mutations are dry-run by default."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.agents import (  # noqa: E402
    AgentGuidanceError, clean_empty_agent_storage, describe_adapter, doctor, install_adapter,
    list_adapters, plan_install, plan_upgrade, remove_adapter, render_task, set_enabled, verify_adapters,
)
from vibesec.exit_codes import INFRASTRUCTURE_FAILURE, INVALID_INPUT, SUCCESS, WARNINGS  # noqa: E402
from vibesec.output import emit, envelope  # noqa: E402
from vibesec.version import VersionError, read_version  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="operation", required=True)
    for name in ("list", "doctor"):
        command = commands.add_parser(name)
        command.add_argument("--target", type=Path, default=Path("."))
        command.add_argument("--json", action="store_true")
    for name in ("describe", "plan", "verify", "upgrade-plan"):
        command = commands.add_parser(name)
        command.add_argument("adapter")
        command.add_argument("--target", type=Path, default=Path("."))
        command.add_argument("--json", action="store_true")
    install = commands.add_parser("install")
    install.add_argument("adapter")
    install.add_argument("--target", type=Path, default=Path("."))
    install.add_argument("--write", action="store_true")
    install.add_argument("--json", action="store_true")
    for name in ("disable", "enable", "remove"):
        command = commands.add_parser(name)
        command.add_argument("adapter")
        command.add_argument("--target", type=Path, default=Path("."))
        command.add_argument("--write", action="store_true")
        command.add_argument("--json", action="store_true")
    render = commands.add_parser("render-task")
    render.add_argument("adapter")
    render.add_argument("task_id")
    render.add_argument("--target", type=Path, default=Path("."))
    render.add_argument("--json", action="store_true")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        version = read_version(ROOT)
    except VersionError:
        version = "unknown"
    try:
        exit_code = SUCCESS
        if args.operation == "list":
            value = {"adapters": list_adapters(ROOT, args.target)}
        elif args.operation == "describe":
            value = describe_adapter(ROOT, args.target, args.adapter)
        elif args.operation == "plan":
            value = plan_install(ROOT, args.target, args.adapter)
        elif args.operation == "install":
            value = install_adapter(ROOT, args.target, args.adapter, write=args.write)
        elif args.operation == "verify":
            complete = verify_adapters(ROOT, args.target)
            selected = [item for item in complete["adapters"] if item["adapter_id"] == args.adapter]
            if not selected:
                raise AgentGuidanceError(f"agent adapter is not installed: {args.adapter}")
            value = {**complete, "adapters": selected}
        elif args.operation == "doctor":
            value = doctor(ROOT, args.target)
        elif args.operation in {"disable", "enable"}:
            value = set_enabled(
                ROOT, args.target, args.adapter, enabled=args.operation == "enable", write=args.write,
            )
        elif args.operation == "remove":
            value = remove_adapter(ROOT, args.target, args.adapter, write=args.write)
            if args.write:
                clean_empty_agent_storage(args.target.resolve(strict=True))
        elif args.operation == "upgrade-plan":
            value = plan_upgrade(ROOT, args.target, args.adapter)
        else:
            rendered = render_task(ROOT, args.target, args.adapter, args.task_id)
            value = {"adapter_id": args.adapter, "task_id": args.task_id, "rendered": rendered}
        status = value.get("status", "success")
        if status in {"invalid", "conflicting", "review_required"}:
            exit_code = WARNINGS
        emit(
            envelope(f"agents_{args.operation.replace('-', '_')}", version, status, result=value),
            as_json=args.json,
        )
        return exit_code
    except (AgentGuidanceError, OSError, ValueError) as exc:
        emit(
            envelope(f"agents_{args.operation.replace('-', '_')}", version, "invalid", errors=[str(exc)]),
            as_json=getattr(args, "json", False),
        )
        return INVALID_INPUT
    except KeyboardInterrupt:
        emit(
            envelope("agents", version, "infrastructure_failure", errors=["interrupted"]),
            as_json=getattr(args, "json", False),
        )
        return INFRASTRUCTURE_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
