#!/usr/bin/env python3
"""Compute self-scan coverage expectations without reading scan results."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import tempfile

SCRIPT_ROOT = Path(__file__).resolve().parent
ROOT = SCRIPT_ROOT.parent
sys.path.insert(0, str(SCRIPT_ROOT))
from vibesec.coverage import STATES  # noqa: E402
from vibesec.detection import DetectionError, ImageStateError, derive_image_expectation, inventory  # noqa: E402
from vibesec.self_scan import (  # noqa: E402
    SelfScanError, build_product_view, load_scope, make_removable,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--github-event", required=True)
    parser.add_argument("--image-reference", default="")
    parser.add_argument("--format", choices=("shell",), default="shell")
    args = parser.parse_args()
    try:
        _, exclusions = load_scope(ROOT)
        with tempfile.TemporaryDirectory(prefix="vibesec-expectation-") as temporary:
            view = Path(temporary) / "repository"
            try:
                build_product_view(ROOT, view, exclusions)
                repository = inventory(view)
                expectation = derive_image_expectation(
                    github_actions=True,
                    github_event=args.github_event,
                    image_reference=args.image_reference,
                    has_dockerfile=bool(repository["dockerfiles"]),
                    strict_event=True,
                )
                if expectation.state not in STATES:
                    raise ImageStateError("derived state is outside the supported coverage vocabulary")
            finally:
                make_removable(view)
    except (DetectionError, ImageStateError, OSError, SelfScanError) as exc:
        print(f"VibeSec self-scan expectation failed closed: {exc}", file=sys.stderr)
        return 3
    print(f"TRIVY_IMAGE_STATE={expectation.state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
