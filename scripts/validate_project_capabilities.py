#!/usr/bin/env python3
"""Validate a project capability manifest and report scanner applicability."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.capabilities import CapabilityError, load_capabilities_file, scanner_applicability  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?", type=Path, default=Path(".vibesec/project-capabilities.json"))
    args = parser.parse_args()
    try:
        payload = load_capabilities_file(args.manifest)
    except CapabilityError as exc:
        print(json.dumps({"schema_version": 1, "status": "invalid", "errors": [str(exc)]}, indent=2, sort_keys=True))
        return 3
    print(json.dumps({
        "schema_version": 1,
        "status": "valid",
        "manifest": payload,
        "scanner_applicability": scanner_applicability(payload),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
