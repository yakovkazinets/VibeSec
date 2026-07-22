#!/usr/bin/env python3
"""Fail closed on missing, malformed, stale-looking, or sensitive self-scan artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.coverage import validate_coverage  # noqa: E402
from vibesec.results import REQUIRED_RESULT_FIELDS  # noqa: E402
from vibesec.sbom import validate_cyclonedx, validate_spdx  # noqa: E402
from vibesec.strict_json import StrictJSONError, loads_strict  # noqa: E402

PROHIBITED = re.compile(
    r"VIBESEC_" + r"FAKE_SECRET_DO_NOT_USE_|/home/runner/|/Users/|[A-Za-z]:\\|RUNNER_TOKEN|GITHUB_TOKEN|registry[_ -]?password",
    re.IGNORECASE,
)
STATES = {"ran", "not_applicable", "not_configured", "tool_error"}
PROFILE_TOOLS = {
    "minimal": {"trivy", "gitleaks", "actionlint"},
    "standard": {"opengrep", "osv-scanner", "syft", "checkov", "trivy", "gitleaks", "actionlint", "trivy-image"},
}


class ArtifactError(ValueError):
    """A mandatory artifact is unsafe or inconsistent with this run."""


def load(path: Path) -> Any:
    if not path.is_file() or path.stat().st_size == 0:
        raise ArtifactError(f"mandatory artifact is missing or empty: {path.name}")
    try:
        data = path.read_bytes()
        payload = loads_strict(data)
    except (OSError, StrictJSONError) as exc:
        raise ArtifactError(f"artifact is invalid JSON: {path.name}: {exc}") from exc
    if PROHIBITED.search(data.decode("utf-8")):
        raise ArtifactError(f"artifact contains a raw fixture marker, credential name, or absolute host path: {path.name}")
    return payload


def validate_normalized(payload: Any, profile: str) -> None:
    if not isinstance(payload, dict) or payload.get("schema_version") != 1 or not isinstance(payload.get("results"), list):
        raise ArtifactError("normalized results schema is invalid")
    if payload.get("profile", profile) != profile:
        raise ArtifactError("normalized results profile differs")
    for item in payload["results"]:
        if not isinstance(item, dict) or not REQUIRED_RESULT_FIELDS <= set(item):
            raise ArtifactError("normalized result is missing required fields")
        if item.get("result_type") not in {"finding", "tool_error", "pass"}:
            raise ArtifactError("normalized result type is invalid")
        path = item.get("file")
        if not isinstance(path, str) or path.startswith("/") or ".." in path.replace("\\", "/").split("/"):
            raise ArtifactError("normalized result path is not repository-relative")
        if not re.fullmatch(r"[0-9a-f]{64}", str(item.get("fingerprint", ""))):
            raise ArtifactError("normalized result fingerprint is invalid")


def validate_policy(payload: Any, profile: str, has_tool_error: bool) -> None:
    required = {"schema_version", "profile", "exit_code", "exit_category", "clean", "security_guarantee"}
    if not isinstance(payload, dict) or set(payload) != required or payload.get("schema_version") != 1 or payload.get("profile") != profile:
        raise ArtifactError("policy result schema or profile is invalid")
    if payload["security_guarantee"] is not False or not isinstance(payload["clean"], bool):
        raise ArtifactError("policy result security declaration is invalid")
    categories = {0: "pass", 1: "policy_violation", 2: "tool_error", 3: "invalid_input"}
    if payload["exit_code"] not in categories or payload["exit_category"] != categories[payload["exit_code"]]:
        raise ArtifactError("policy result exit code and category differ")
    if has_tool_error and (payload["clean"] or payload["exit_category"] not in {"tool_error", "invalid_input"}):
        raise ArtifactError("tool or parser error was represented as a clean policy result")
    if payload["clean"] != (payload["exit_code"] == 0):
        raise ArtifactError("policy clean flag and exit code differ")


def validate_inventory(payload: Any) -> None:
    required = {"schema_version", "files_inspected", "languages", "source_files", "package_managers", "manifests", "lockfiles", "monorepo", "dockerfiles", "iac", "workflows", "ci_configs"}
    if not isinstance(payload, dict) or set(payload) != required or payload.get("schema_version") != 1:
        raise ArtifactError("repository inventory schema is invalid")
    for field in ("source_files", "manifests", "lockfiles", "dockerfiles", "workflows", "ci_configs"):
        values = payload[field]
        if not isinstance(values, list) or any(not isinstance(path, str) or path.startswith("/") or ".." in path.split("/") for path in values):
            raise ArtifactError(f"inventory {field} paths are unsafe")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--profile", required=True, choices=("minimal", "standard"))
    parser.add_argument("--expect-state", action="append", default=[], metavar="TOOL=STATE")
    args = parser.parse_args()
    try:
        normalized = load(args.results / "normalized.json")
        validate_normalized(normalized, args.profile)
        report = args.results / "report.md"
        if not report.is_file() or report.stat().st_size == 0:
            raise ArtifactError("Markdown report is missing or empty")
        report_text = report.read_text(encoding="utf-8")
        if PROHIBITED.search(report_text) or "not a security guarantee" not in report_text:
            raise ArtifactError("Markdown report is unsafe or omits the security limitation")
        coverage = load(args.results / "coverage.json")
        try:
            validate_coverage(coverage)
        except ValueError as exc:
            raise ArtifactError(str(exc)) from exc
        states = {item["tool"]: item["state"] for item in coverage["tools"]}
        if coverage.get("profile") != args.profile or set(states) != PROFILE_TOOLS[args.profile]:
            raise ArtifactError(f"coverage profile or scanner set differs: expected {sorted(PROFILE_TOOLS[args.profile])}, observed {sorted(states)}")
        for expectation in args.expect_state:
            tool, separator, state = expectation.partition("=")
            if not separator or state not in STATES or states.get(tool) != state:
                raise ArtifactError(f"coverage state differs: {tool}: expected {state}, observed {states.get(tool)}")
        has_tool_error = any(item.get("result_type") == "tool_error" for item in normalized["results"])
        validate_policy(load(args.results / "policy-result.json"), args.profile, has_tool_error)
        if args.profile == "standard":
            validate_inventory(load(args.results / "inventory.json"))
            syft_state = states.get("syft")
            if syft_state == "ran":
                validate_cyclonedx(args.results / "sbom.cyclonedx.json")
                validate_spdx(args.results / "sbom.spdx.json")
                for path in (args.results / "sbom.cyclonedx.json", args.results / "sbom.spdx.json"):
                    if PROHIBITED.search(path.read_text(encoding="utf-8")):
                        raise ArtifactError(f"SBOM contains a prohibited host path: {path.name}")
            elif (args.results / "sbom.cyclonedx.json").exists() or (args.results / "sbom.spdx.json").exists():
                raise ArtifactError("stale SBOM survived a non-ran Syft state")
    except (ArtifactError, OSError, UnicodeError, ValueError) as exc:
        print(f"security artifact validation failed: {exc}", file=sys.stderr)
        return 2
    print(f"validated {args.profile} security artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
