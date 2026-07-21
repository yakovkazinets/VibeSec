#!/usr/bin/env python3
"""Validate static VibeSec configuration without third-party Python packages."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_TOOLS = {"trivy", "gitleaks", "actionlint"}


def load_object(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path.relative_to(ROOT)} is not valid JSON-compatible YAML: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain an object")
    return value


def validate_tools() -> None:
    tools = load_object(ROOT / "config/tools.json")
    if set(tools) != EXPECTED_TOOLS:
        raise ValueError(f"config/tools.json must define exactly {sorted(EXPECTED_TOOLS)}")
    for name, config in tools.items():
        if not isinstance(config, dict):
            raise ValueError(f"tool {name} configuration must be an object")
        if not all(isinstance(config.get(field), str) and config[field] for field in ("archive", "sha256", "url", "version")):
            raise ValueError(f"tool {name} is missing archive, sha256, url, or version")
        if not SHA256.fullmatch(config["sha256"]):
            raise ValueError(f"tool {name} has an invalid SHA-256 checksum")
        parsed = urlparse(config["url"])
        if parsed.scheme != "https" or parsed.hostname != "github.com" or "/releases/download/" not in parsed.path:
            raise ValueError(f"tool {name} must use an official versioned GitHub release URL")
        if config["archive"] not in parsed.path or config["version"] not in parsed.path:
            raise ValueError(f"tool {name} URL, archive, and version are inconsistent")


def validate_policy() -> None:
    thresholds = load_object(ROOT / "policy/severity-thresholds.yml")
    if thresholds.get("default_minimum_severity") not in ("low", "medium", "high", "critical"):
        raise ValueError("policy threshold is invalid")
    if thresholds.get("enforcement") not in ("observe", "new", "all"):
        raise ValueError("policy enforcement mode is invalid")
    suppressions = load_object(ROOT / "policy/suppressions.yml")
    if not isinstance(suppressions.get("suppressions"), list):
        raise ValueError("policy/suppressions.yml must contain a suppressions array")
    baseline = load_object(ROOT / "policy/baseline.json")
    if not isinstance(baseline.get("fingerprints"), list):
        raise ValueError("policy/baseline.json must contain a fingerprints array")


def validate_references() -> None:
    required = (
        ".github/workflows/ci.yml", "templates/github-actions/security-baseline.yml",
        "scripts/install_tools.sh", "scripts/run_minimal_profile.sh", "scripts/normalize_results.py",
        "scripts/append_tool_errors.py", "scripts/policy_gate.py", "scripts/validate_skill.py",
        "skills/appsec-guardian/SKILL.md",
    )
    missing = [path for path in required if not (ROOT / path).is_file()]
    if missing:
        raise ValueError(f"required files are missing: {', '.join(missing)}")
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    if requirements != ["PyYAML==6.0.3"]:
        raise ValueError("requirements.txt must contain the reviewed PyYAML pin")


def main() -> int:
    try:
        validate_tools()
        validate_policy()
        validate_references()
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 3
    print("repository configuration is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
