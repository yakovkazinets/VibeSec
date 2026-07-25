#!/usr/bin/env python3
"""Generate deterministic human v1 reference tables from machine catalogs."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from vibesec.v1_contract import CATALOGS, validate_catalogs, validate_examples  # noqa: E402

REFERENCE = ROOT / "docs/v1-interface-reference.md"
EXAMPLES = ROOT / "docs/examples.md"
REFERENCE_BEGIN = "<!-- BEGIN GENERATED V1 REFERENCE -->"
REFERENCE_END = "<!-- END GENERATED V1 REFERENCE -->"
EXAMPLES_BEGIN = "<!-- BEGIN GENERATED EXAMPLES -->"
EXAMPLES_END = "<!-- END GENERATED EXAMPLES -->"


def _replace(path: Path, begin: str, end: str, body: str) -> str:
    text = path.read_text(encoding="utf-8")
    if text.count(begin) != 1 or text.count(end) != 1 or text.index(begin) > text.index(end):
        raise ValueError(f"{path.relative_to(ROOT)} has invalid generated markers")
    prefix, remainder = text.split(begin, 1)
    _, suffix = remainder.split(end, 1)
    return prefix + begin + "\n" + body.rstrip() + "\n" + end + suffix


def _reference() -> str:
    inventory, catalogs = validate_catalogs(ROOT)
    lines = [
        "| Stable ID | Status | Owner | Summary |",
        "|---|---|---|---|",
    ]
    for item in sorted(inventory["interfaces"], key=lambda record: record["stable_id"]):
        lines.append(
            f"| `{item['stable_id']}` | `{item['status']}` | "
            f"{item['owning_component']} | {item['summary']} |"
        )
    lines.extend(["", "## Domain members", ""])
    for name in CATALOGS:
        catalog = catalogs[name]
        lines.extend([
            f"### {name.replace('-', ' ').title()}",
            "",
            f"Source: `{catalog['source']}`",
            "",
            "| Member | Status |",
            "|---|---|",
        ])
        for member in sorted(catalog["members"]):
            lines.append(f"| `{member}` | `{catalog['statuses'][member]}` |")
        lines.append("")
    return "\n".join(lines)


def _examples() -> str:
    value = validate_examples(ROOT)
    lines = ["| Pattern | Fixture | Validated commands |", "|---|---|---|"]
    for item in value["examples"]:
        commands = "<br>".join(f"`{command.replace('|', '&#124;')}`" for command in item["commands"])
        lines.append(f"| `{item['stable_id']}` — {item['summary']} | `{item['fixture']}` | {commands} |")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected_reference = _replace(
        REFERENCE, REFERENCE_BEGIN, REFERENCE_END, _reference(),
    )
    expected_examples = _replace(EXAMPLES, EXAMPLES_BEGIN, EXAMPLES_END, _examples())
    stale = []
    for path, expected in ((REFERENCE, expected_reference), (EXAMPLES, expected_examples)):
        current = path.read_text(encoding="utf-8")
        if current != expected:
            stale.append(str(path.relative_to(ROOT)))
            if not args.check:
                path.write_text(expected, encoding="utf-8", newline="\n")
    if args.check and stale:
        print(f"generated documentation is stale: {', '.join(stale)}", file=sys.stderr)
        return 3
    print("generated documentation is current" if args.check else "generated documentation updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
