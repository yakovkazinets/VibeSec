#!/usr/bin/env python3
"""Validate an imported skill without executing or following its instructions."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.skill_validation import SkillValidationError, validate_skill  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("skill_root", type=Path)
    parser.add_argument("--canonical-output", type=Path)
    args = parser.parse_args()
    try:
        result = validate_skill(args.skill_root)
        if args.canonical_output:
            args.canonical_output.write_text(result.canonical + "\n", encoding="utf-8")
        print(json.dumps(result.to_dict(), sort_keys=True))
        return 0
    except SkillValidationError as exc:
        print(json.dumps({"status": "validation_error", "description": str(exc)}, sort_keys=True))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
