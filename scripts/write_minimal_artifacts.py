#!/usr/bin/env python3
"""Write deterministic Minimal coverage and policy-status artifacts."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.coverage import validate_coverage  # noqa: E402


def atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def coverage(args: argparse.Namespace) -> None:
    tools = json.loads((args.vibesec_root / "config/tools.json").read_text(encoding="utf-8"))
    entries = []
    output_names = {"trivy": "trivy.json", "gitleaks": "gitleaks.json", "actionlint": "actionlint.txt"}
    for tool, state in (("trivy", args.trivy_state), ("gitleaks", args.gitleaks_state), ("actionlint", args.actionlint_state)):
        if args.normalization_failed and state == "ran":
            state = "tool_error"
        reason = "scanner completed and output normalized" if state == "ran" else "scanner execution or output validation failed"
        entries.append({
            "tool": tool, "version": tools[tool]["version"], "scope": "Minimal repository scan",
            "state": state, "reason": reason, "relevant_artifacts": ["."],
            "output_files": [] if state == "tool_error" else [output_names[tool]],
            "network_access": "none", "application_code_executed": False,
        })
    payload = validate_coverage({
        "schema_version": 1, "profile": "minimal", "tools": entries,
        "limitations": ["A completed Minimal scan is not proof that the repository is secure."],
        "outside_coverage": ["SAST, advisory-specific dependency analysis, SBOM, IaC, image, runtime, DAST, and business logic are outside Minimal."],
    })
    atomic_json(args.output, payload)


def policy(args: argparse.Namespace) -> None:
    categories = {0: "pass", 1: "policy_violation", 2: "tool_error", 3: "invalid_input"}
    if args.exit_code not in categories:
        raise ValueError("policy exit code is outside the reviewed contract")
    atomic_json(args.output, {
        "schema_version": 1, "profile": args.profile, "exit_code": args.exit_code,
        "exit_category": categories[args.exit_code], "clean": args.exit_code == 0,
        "security_guarantee": False,
    })


def report(args: argparse.Namespace) -> None:
    categories = {2: "tool_error", 3: "invalid_input"}
    if args.exit_code not in categories:
        raise ValueError("failure report requires exit code 2 or 3")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    content = (
        "# VibeSec Minimal report\n\n"
        f"Status: **{categories[args.exit_code]}**\n\n"
        "The scan did not complete with structurally valid evidence. Review coverage.json and "
        "policy-result.json for the failed component. No clean result is asserted.\n\n"
        "A VibeSec report is not a security guarantee.\n"
    )
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{args.output.name}.", dir=args.output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, args.output)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    coverage_parser = subparsers.add_parser("coverage")
    coverage_parser.add_argument("--vibesec-root", required=True, type=Path)
    coverage_parser.add_argument("--output", required=True, type=Path)
    for tool in ("trivy", "gitleaks", "actionlint"):
        coverage_parser.add_argument(f"--{tool}-state", required=True, choices=("ran", "tool_error"))
    coverage_parser.add_argument("--normalization-failed", action="store_true")
    policy_parser = subparsers.add_parser("policy")
    policy_parser.add_argument("--profile", required=True, choices=("minimal", "standard"))
    policy_parser.add_argument("--exit-code", required=True, type=int)
    policy_parser.add_argument("--output", required=True, type=Path)
    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("--profile", required=True, choices=("minimal",))
    report_parser.add_argument("--exit-code", required=True, type=int)
    report_parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "coverage":
            coverage(args)
        elif args.command == "policy":
            policy(args)
        else:
            report(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"could not write profile artifact: {exc}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
