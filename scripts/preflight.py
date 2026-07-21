#!/usr/bin/env python3
"""Read-only consumer diagnostics for an installed VibeSec profile."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil

IMAGE_DIGEST = re.compile(r"^[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, choices=("minimal", "standard"))
    parser.add_argument("--target", type=Path, default=Path("."), help="installed consumer repository")
    args = parser.parse_args()
    report = {"schema_version": 1, "profile": args.profile, "ready": False, "check": [], "warning": [], "error": []}
    if args.target.is_symlink():
        report["error"].append("target root is a symbolic link; use a canonical repository directory")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 3
    try:
        root = args.target.resolve(strict=True)
    except OSError as exc:
        report["error"].append(f"target unavailable: {exc}")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 3
    if not root.is_dir():
        report["error"].append("target is not a directory")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 3
    try:
        catalog = json.loads((root / "config/adoption-files.json").read_text(encoding="utf-8"))
        config = catalog["profiles"][args.profile]
        required = [*catalog["common"], *config["support"]]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        report["error"].append(f"installation catalog missing or malformed: {exc}; rerun the initializer dry run")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 2
    for relative in required:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            report["error"].append(f"required file missing or unsafe: {relative}")
    workflow = root / config["workflow_destination"]
    if args.profile == "minimal" and (workflow.is_symlink() or not workflow.is_file()):
        report["error"].append(f"Minimal workflow missing: {config['workflow_destination']}")
    elif args.profile == "standard" and not workflow.exists():
        report["warning"].append("Standard support stage is present but workflow stage is not; merge support, then initialize --stage workflow")
    elif workflow.is_symlink() or not workflow.is_file():
        report["error"].append(f"workflow path is unsafe: {config['workflow_destination']}")
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        report["warning"].append("scanner installers support Linux x86_64 runners; local installation is unavailable on this platform")
    for relative in ("config/tools.json", "policy/severity-thresholds.yml", "policy/suppressions.yml"):
        try:
            payload = json.loads((root / relative).read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("top level is not an object")
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            report["error"].append(f"configuration malformed: {relative}: {exc}")
    image = os.getenv("VIBESEC_IMAGE_REFERENCE", "")
    if image and not IMAGE_DIGEST.fullmatch(image):
        report["error"].append("prebuilt image reference is tag-only or malformed; use registry/name@sha256:<64 lowercase hex>")
    if args.profile == "standard":
        if shutil.which("docker") is None:
            report["warning"].append("Docker runtime unavailable; Checkov cannot run when supported IaC is detected")
        if os.getenv("VIBESEC_NETWORK_MODE", "online") == "offline":
            missing = [name for name in ("VIBESEC_OSV_DATABASE_DIR", "VIBESEC_OSV_DATABASE_DATE") if not os.getenv(name)]
            if missing:
                report["error"].append("offline OSV configuration missing: " + ", ".join(missing))
    report["check"].append(f"checked {len(required)} required support files without executing them")
    report["ready"] = not report["error"]
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
