#!/usr/bin/env python3
"""Run Standard against a fixed product-only view of this VibeSec checkout."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import tempfile

SCRIPT_ROOT = Path(__file__).resolve().parent
ROOT = SCRIPT_ROOT.parent
sys.path.insert(0, str(SCRIPT_ROOT))
from vibesec.self_scan import (  # noqa: E402
    SelfScanError, build_product_view, initialize_snapshot_repository,
    load_scope, make_read_only, make_removable,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    parser.add_argument("--tool-dir", type=Path, default=ROOT / ".tools/bin")
    args = parser.parse_args()
    results = args.results.resolve()
    try:
        results.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        print("VibeSec self-scan results must be outside the source checkout", file=sys.stderr)
        return 3
    try:
        _, exclusions = load_scope(ROOT)
        with tempfile.TemporaryDirectory(prefix="vibesec-product-scan-") as temporary:
            view = Path(temporary) / "repository"
            try:
                build_product_view(ROOT, view, exclusions)
                initialize_snapshot_repository(view)
                make_read_only(view)
                completed = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/run_standard_profile.py"), str(view), str(results),
                     "--vibesec-root", str(ROOT), "--tool-dir", str(args.tool_dir.resolve())],
                    cwd=ROOT, stdin=subprocess.DEVNULL, check=False,
                )
                return completed.returncode if completed.returncode in {0, 1, 2, 3} else 3
            finally:
                make_removable(view)
    except (OSError, SelfScanError) as exc:
        print(f"VibeSec self-scan scope failed closed: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
