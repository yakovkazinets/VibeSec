#!/usr/bin/env python3
"""Validate the strict public v1 interface inventory and domain projections."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from vibesec.v1_contract import V1ContractError, validate_catalogs  # noqa: E402


def main() -> int:
    try:
        inventory, catalogs = validate_catalogs(ROOT)
        print(
            f"validated {len(inventory['interfaces'])} public interfaces "
            f"across {len(catalogs)} machine catalogs"
        )
        return 0
    except V1ContractError as exc:
        print(f"v1 interface contract invalid: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
