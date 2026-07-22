#!/usr/bin/env python3
"""Exit with a strictly validated scanner result recorded by an earlier CI step."""

from __future__ import annotations

import argparse
from pathlib import Path


VALID_EXIT_FILES = {f"{code}\n".encode(): code for code in range(4)}


def read_scan_exit(path: Path) -> int:
    try:
        payload = path.read_bytes()
    except OSError:
        return 3
    return VALID_EXIT_FILES.get(payload, 3)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    return read_scan_exit(args.path)


if __name__ == "__main__":
    raise SystemExit(main())
