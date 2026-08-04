#!/usr/bin/env python3
"""Install one complete verified VibeSec Guardian scanner profile."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

SCRIPT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_ROOT))
from vibesec.portable import platform_id  # noqa: E402
from vibesec.toolchain import (  # noqa: E402
    ToolchainError, default_cache_home, inspect_profile_cache, install_profile_tools,
    managed_toolchain_disclosure,
)
from vibesec.version import VersionError, read_version  # noqa: E402


def publish_compatibility_directory(source: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    for executable in sorted(source.iterdir()):
        temporary = destination / f".{executable.name}.new"
        try:
            shutil.copyfile(executable, temporary, follow_symlinks=False)
            temporary.chmod(0o755)
            os.replace(temporary, destination / executable.name)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise


def progress(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("minimal", "standard"), required=True)
    parser.add_argument("--vibesec-root", type=Path, default=SCRIPT_ROOT.parent)
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--platform")
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        root = args.vibesec_root.resolve(strict=True)
        cache = (args.cache_dir or default_cache_home()).expanduser().resolve()
        version = read_version(root)
        selected_platform = args.platform or platform_id()
        reusable = inspect_profile_cache(
            metadata_path=root / "config/tools.json", cache_home=cache,
            version=version, platform_name=selected_platform, profile=args.profile,
        )
        for line in managed_toolchain_disclosure(
            profile=args.profile, platform_name=selected_platform, cache_home=cache,
            cache_reused=reusable, network_mode="online",
        ):
            progress(line)
        tool_dir, reused = install_profile_tools(
            metadata_path=root / "config/tools.json",
            cache_home=cache,
            version=version,
            platform_name=selected_platform,
            profile=args.profile,
            progress=progress,
        )
        if args.destination:
            publish_compatibility_directory(tool_dir, args.destination.resolve())
        payload = {
            "schema_version": 1,
            "profile": args.profile,
            "platform": selected_platform,
            "development_version": version,
            "cache_reused": reused,
            "tool_dir": str(tool_dir),
        }
        print(json.dumps(payload, sort_keys=True) if args.json else str(tool_dir))
        return 0
    except (OSError, ToolchainError, VersionError, ValueError) as exc:
        message = " ".join(str(exc).split())[:300]
        if args.json:
            print(json.dumps({
                "schema_version": 1, "status": "tool_error", "errors": [message],
            }, sort_keys=True))
        else:
            print(f"component=tool-installer result=tool_error cause={message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
