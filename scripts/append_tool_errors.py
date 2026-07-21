#!/usr/bin/env python3
"""Append scanner execution errors to a normalized VibeSec result document."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.model import Finding  # noqa: E402
from vibesec.results import ResultDocumentError, append_tool_errors_atomic  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--tool-error", action="append", nargs=2, default=[], metavar=("TOOL", "MESSAGE"))
    args = parser.parse_args()
    errors = [
        Finding.create(
            tool=tool,
            category="execution",
            rule_id="tool-error",
            severity="low",
            description=message,
            confidence="unknown",
            result_type="tool_error",
        ).to_dict()
        for tool, message in args.tool_error
    ]
    try:
        append_tool_errors_atomic(args.results, errors)
    except ResultDocumentError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
