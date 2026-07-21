#!/usr/bin/env python3
"""Normalize one or more raw scanner outputs into the VibeSec result schema."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.normalize import normalize_file  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", nargs=2, metavar=("TOOL", "PATH"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    findings = []
    try:
        for tool, path in args.input:
            findings.extend(item.to_dict() for item in normalize_file(tool, Path(path)))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({"schema_version": 1, "results": findings}, indent=2) + "\n", encoding="utf-8")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
