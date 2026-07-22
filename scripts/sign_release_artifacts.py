#!/usr/bin/env python3
"""Keyless-sign prepared checksums only in the reviewed trusted workflow."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.strict_json import StrictJSONError, loads_strict  # noqa: E402
from vibesec.supply_chain import (  # noqa: E402
    CHECKSUMS_NAME, SIGNATURE_NAME, SupplyChainError, verify_release,
)


def trusted_environment(manifest: dict) -> None:
    expected = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": "yakovkazinets/VibeSec",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": manifest["source"]["commit"],
    }
    if any(os.getenv(name) != value for name, value in expected.items()):
        raise SupplyChainError("release signing is restricted to the reviewed main-branch workflow context")
    if manifest["creation_mode"] != "trusted-github-workflow":
        raise SupplyChainError("local-preparation artifacts cannot be signed as official release candidates")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--cosign", required=True, type=Path)
    args = parser.parse_args()
    temporary: Path | None = None
    try:
        release = verify_release(args.directory)
        trusted_environment(release.manifest)
        if args.cosign.is_symlink() or not args.cosign.is_file() or not os.access(args.cosign, os.X_OK):
            raise SupplyChainError("trusted Cosign executable is unavailable")
        destination = release.directory / SIGNATURE_NAME
        if destination.exists() or destination.is_symlink():
            raise SupplyChainError("signature bundle already exists")
        temporary = Path(tempfile.mkdtemp(prefix=".vibesec-signature-")) / SIGNATURE_NAME
        completed = subprocess.run(
            [str(args.cosign), "sign-blob", "--yes", "--bundle", str(temporary),
             str(release.directory / CHECKSUMS_NAME)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, timeout=120, check=False,
        )
        if completed.returncode != 0:
            print("release signing tool failed", file=sys.stderr)
            return 2
        if temporary.is_symlink() or not temporary.is_file() or temporary.stat().st_size > 2 * 1024 * 1024:
            raise SupplyChainError("Cosign produced a missing, unsafe, or oversized signature bundle")
        value = loads_strict(temporary.read_bytes(), maximum_bytes=2 * 1024 * 1024)
        if not isinstance(value, dict):
            raise SupplyChainError("Cosign signature bundle must contain a JSON object")
        os.link(temporary, destination, follow_symlinks=False)
        return 0
    except (OSError, StrictJSONError, SupplyChainError, subprocess.TimeoutExpired) as exc:
        print(str(exc), file=sys.stderr)
        return 3
    finally:
        if temporary is not None:
            shutil.rmtree(temporary.parent, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
