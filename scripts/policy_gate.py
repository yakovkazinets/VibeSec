#!/usr/bin/env python3
"""Apply VibeSec policy. Exit: 0 pass, 1 violation, 2 tool failure, 3 invalid input."""

import argparse
from datetime import date
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.policy import ConfigurationError, active_suppressions, evaluate, load_json_yaml  # noqa: E402


def safe_markdown_cell(value: object, limit: int = 240) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(value or ""))
    text = " ".join(text.split())[:limit]
    return text.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("`", "'")


def write_markdown(path: Path, evaluation: dict, expired: list[str]) -> None:
    lines = ["# VibeSec minimal profile", "", f"Status: **{evaluation['status']}**", ""]
    lines += [
        f"- Findings: {len(evaluation['findings'])}",
        f"- New findings: {len(evaluation['new_findings'])}",
        f"- Policy violations: {len(evaluation['violations'])}",
        f"- Tool errors: {len(evaluation['tool_errors'])}",
        f"- Expired suppressions: {len(expired)}",
        "",
        "A pass means only that configured scanners completed without a policy violation. It is not a security guarantee.",
    ]
    if evaluation["findings"]:
        lines += ["", "## Findings", "", "| Tool | Severity | Rule | Location | Confidence | Description |", "|---|---|---|---|---|---|"]
        for item in evaluation["findings"]:
            location = f"{item.get('file', '')}:{item.get('line') or ''}".rstrip(":")
            lines.append("| " + " | ".join(safe_markdown_cell(value) for value in (
                item.get("tool"), item.get("severity"), item.get("rule_id"), location,
                item.get("confidence"), item.get("description"),
            )) + " |")
    if evaluation["tool_errors"]:
        lines += ["", "## Tool errors", ""]
        for item in evaluation["tool_errors"]:
            lines.append(f"- **{safe_markdown_cell(item.get('tool'))}:** {safe_markdown_cell(item.get('description'))}")
    if expired:
        lines += ["", "## Expired suppressions", ""]
        lines.extend(f"- `{safe_markdown_cell(fingerprint, 64)}`" for fingerprint in expired)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--suppressions", type=Path, required=True)
    parser.add_argument("--minimum-severity")
    parser.add_argument("--enforcement")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        result_payload = load_json_yaml(args.results)
        policy = load_json_yaml(args.policy)
        baseline_payload = load_json_yaml(args.baseline)
        suppression_payload = load_json_yaml(args.suppressions)
        if not isinstance(result_payload, dict) or not isinstance(result_payload.get("results"), list):
            raise ConfigurationError("results input must contain a results array")
        baseline = baseline_payload.get("fingerprints")
        if not isinstance(baseline, list) or not all(isinstance(item, str) for item in baseline):
            raise ConfigurationError("baseline fingerprints must be an array of strings")
        suppressions, expired = active_suppressions(suppression_payload, date.today())
        evaluation = evaluate(
            result_payload["results"], minimum_severity=args.minimum_severity or policy.get("default_minimum_severity", "high"),
            enforcement=args.enforcement or policy.get("enforcement", "observe"), baseline=set(baseline),
            suppressions=suppressions, today=date.today(),
        )
        write_markdown(args.report, evaluation, expired)
    except ConfigurationError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    if evaluation["tool_errors"]:
        return 2
    return 1 if evaluation["violations"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
