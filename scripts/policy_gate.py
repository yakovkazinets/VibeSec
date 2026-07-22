#!/usr/bin/env python3
"""Apply VibeSec policy. Exit: 0 pass, 1 violation, 2 tool failure, 3 invalid input."""

import argparse
from datetime import date
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.finding_intelligence import FindingIntelligenceError, validate_documents  # noqa: E402
from vibesec.policy import ConfigurationError, active_suppressions, evaluate, evaluate_priority, load_json_yaml  # noqa: E402


def safe_markdown_cell(value: object, limit: int = 240) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(value or ""))
    text = " ".join(text.split())[:limit]
    return text.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("`", "'")


def write_markdown(path: Path, evaluation: dict, expired: list[str], profile: str = "minimal",
                   finding_groups: dict | None = None, prioritized: dict | None = None) -> None:
    lines = [f"# VibeSec {profile} profile", "", f"Status: **{evaluation['status']}**", ""]
    lines += [
        f"- Findings: {len(evaluation['findings'])}",
        f"- New findings: {len(evaluation['new_findings'])}",
        f"- Policy violations: {len(evaluation['violations'])}",
        f"- Tool errors: {len(evaluation['tool_errors'])}",
        f"- Priority policy violations: {len(evaluation.get('priority_violations', []))}",
        f"- Expired suppressions: {len(expired)}",
        "",
        "A pass means only that configured scanners completed without a policy violation. It is not a security guarantee.",
    ]
    if finding_groups is not None and prioritized is not None:
        group_index = {item["correlation_key"]: item for item in finding_groups["groups"]}
        lines += ["", "## Prioritized finding groups", ""]
        if not prioritized["groups"]:
            lines.append("No finding groups were produced.")
        for item in prioritized["groups"]:
            group = group_index[item["correlation_key"]]
            reasons = ", ".join(
                f"{reason.get('factor')}: {reason.get('evidence')}" for reason in item["priority_reasons"]
            )
            references = ", ".join(reference[:12] for reference in item["member_references"])
            lines += [
                f"### {safe_markdown_cell(item['priority']).title()} `{safe_markdown_cell(item['correlation_key'], 64)}`",
                "",
                f"- Correlation: {safe_markdown_cell(group['correlation_classification'])}",
                f"- Underlying findings: {item['member_count']}",
                f"- Contributing scanners: {safe_markdown_cell(', '.join(item['contributing_scanners']))}",
                f"- Evidence reasons: {safe_markdown_cell(reasons, 500)}",
                f"- Original finding references: {safe_markdown_cell(references, 500)}",
                "",
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
    parser.add_argument("--profile", choices=("minimal", "standard"), default="minimal")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--finding-groups", type=Path)
    parser.add_argument("--prioritized-findings", type=Path)
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
        if baseline_payload.get("profile", "minimal") != args.profile:
            raise ConfigurationError(f"baseline profile does not match requested {args.profile} profile")
        if result_payload.get("profile", args.profile) != args.profile:
            raise ConfigurationError(f"results profile does not match requested {args.profile} profile")
        suppressions, expired = active_suppressions(suppression_payload, date.today())
        evaluation = evaluate(
            result_payload["results"], minimum_severity=args.minimum_severity or policy.get("default_minimum_severity", "high"),
            enforcement=args.enforcement or policy.get("enforcement", "observe"), baseline=set(baseline),
            suppressions=suppressions, today=date.today(),
        )
        finding_groups = prioritized = None
        if bool(args.finding_groups) != bool(args.prioritized_findings):
            raise ConfigurationError("both finding intelligence artifacts are required together")
        if args.finding_groups:
            finding_groups = load_json_yaml(args.finding_groups)
            prioritized = load_json_yaml(args.prioritized_findings)
            validate_documents(finding_groups, prioritized)
            evaluation["priority_violations"] = evaluate_priority(
                prioritized["groups"], policy.get("finding_intelligence")
            )
            if evaluation["priority_violations"] and evaluation["status"] == "pass":
                evaluation["status"] = "policy_violation"
        else:
            evaluation["priority_violations"] = []
        write_markdown(args.report, evaluation, expired, args.profile, finding_groups, prioritized)
    except (ConfigurationError, FindingIntelligenceError) as exc:
        print(str(exc), file=sys.stderr)
        return 3
    if evaluation["tool_errors"]:
        return 2
    return 1 if evaluation["violations"] or evaluation["priority_violations"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
