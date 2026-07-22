#!/usr/bin/env python3
"""Offline read-only diagnostics for a VibeSec consumer installation."""

from __future__ import annotations

import argparse
from datetime import date
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.exit_codes import INFRASTRUCTURE_FAILURE, INVALID_INPUT, SUCCESS, VERIFICATION_FAILED, WARNINGS  # noqa: E402
from vibesec.installation import InstallationError, verify_installation  # noqa: E402
from vibesec.output import emit, envelope, safe_text  # noqa: E402
from vibesec.strict_json import StrictJSONError, loads_strict  # noqa: E402
from vibesec.version import VersionError, read_version  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
IMAGE = re.compile(r"^[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$")
SUPPORTED_SOURCE = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".java", ".go"}
MANIFESTS = {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock", "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "go.sum"}
DIAGNOSTIC_FIELDS = {"component", "code", "severity", "explanation", "next_action", "documentation"}
DIAGNOSTIC_SEVERITIES = {"error", "warning", "informational", "not_applicable"}


def diagnostic(component: str, code: str, severity: str, explanation: str,
               action: str, documentation: str) -> dict[str, str]:
    value = {
        "component": safe_text(component), "code": safe_text(code), "severity": severity,
        "explanation": safe_text(explanation), "next_action": safe_text(action),
        "documentation": documentation,
    }
    if (set(value) != DIAGNOSTIC_FIELDS or severity not in DIAGNOSTIC_SEVERITIES
            or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", value["code"])
            or not documentation.startswith("docs/") or ".." in Path(documentation).parts):
        raise ValueError("doctor diagnostic schema is invalid")
    return value


def _safe_inventory(root: Path) -> tuple[bool, bool, bool]:
    source = manifest = iac = False
    count = 0
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        names[:] = sorted(name for name in names if name not in {".git", "node_modules", "vendor", ".tools", "results"} and not (base / name).is_symlink())
        for name in files:
            path = base / name
            if path.is_symlink():
                continue
            count += 1
            if count > 100_000:
                return source, manifest, iac
            source |= path.suffix.casefold() in SUPPORTED_SOURCE
            manifest |= name in MANIFESTS or name.casefold().startswith("requirements") and name.casefold().endswith(".txt")
            iac |= path.suffix.casefold() in {".tf", ".bicep"} or name in {"Chart.yaml", "kustomization.yaml", "kustomization.yml"}
    return source, manifest, iac


def _overlap(root: Path) -> list[str]:
    workflow_root = root / ".github/workflows"
    markers = {"codeql", "semgrep", "snyk", "dependabot", "renovate", "trivy", "gitleaks", "checkov"}
    found: set[str] = set()
    if workflow_root.is_dir() and not workflow_root.is_symlink():
        for path in workflow_root.glob("*.y*ml"):
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= 1_000_000:
                text = path.read_text(encoding="utf-8", errors="replace").casefold()
                found.update(marker for marker in markers if marker in text and "vibesec" not in path.name.casefold())
    return sorted(found)


def run_doctor(target: Path, requested_profile: str | None) -> tuple[str, list[dict[str, str]], dict[str, Any]]:
    state = verify_installation(target)
    diagnostics: list[dict[str, str]] = []
    severity = "informational" if state.status == "valid" else "warning"
    diagnostics.append(diagnostic("installation", f"INSTALLATION_{state.status.upper()}", severity,
                                  f"Installation verification status is {state.status}.",
                                  "Review installation verification details before scanner diagnosis.", "docs/installation-verification.md"))
    for message in state.errors:
        diagnostics.append(diagnostic("installation", "INSTALLATION_BLOCKING", "error", message,
                                      "Restore the matching versioned file set; do not overwrite local policy blindly.", "docs/installation-verification.md"))
    for message in state.warnings:
        diagnostics.append(diagnostic("installation", "INSTALLATION_DRIFT", "warning", message,
                                      "Compare the local file with its installation manifest.", "docs/installation-verification.md"))
    diagnostics.append(diagnostic("runtime", "PYTHON_VERSION", "informational", f"Python {platform.python_version()} is running.",
                                  "Use Python 3.11 or newer for distribution tooling.", "docs/doctor.md"))
    if sys.version_info < (3, 11):
        diagnostics.append(diagnostic("runtime", "PYTHON_UNSUPPORTED", "error", "Python is older than the supported 3.11 minimum.",
                                      "Use Python 3.11 or newer.", "docs/compatibility.md"))
    if shutil.which("bash") is None:
        diagnostics.append(diagnostic("runtime", "BASH_MISSING", "error", "The required Bash shell is unavailable.",
                                      "Use a supported Linux x86_64 GitHub runner.", "docs/doctor.md"))
    else:
        diagnostics.append(diagnostic("runtime", "BASH_AVAILABLE", "informational", "Bash is available.",
                                      "No action required.", "docs/doctor.md"))
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        diagnostics.append(diagnostic("runtime", "SCANNER_PLATFORM_LOCAL_UNSUPPORTED", "warning",
                                      f"Local platform {platform.system()} {platform.machine()} is not supported by scanner installers.",
                                      "Run scanners on Linux x86_64; offline diagnostics remain safe locally.", "docs/troubleshooting.md"))
    profiles = state.profiles
    profile = requested_profile or (profiles[0] if len(profiles) == 1 else None)
    if requested_profile and profiles and requested_profile not in profiles:
        diagnostics.append(diagnostic("profile", "PROFILE_MISMATCH", "error", "Requested profile differs from installed manifests.",
                                      "Select the installed profile or repair the manifest conflict.", "docs/installation-verification.md"))
    stages = {manifest["stage"] for manifest in state.manifests}
    if profile == "standard" and "support" in stages and "workflow" not in stages:
        diagnostics.append(diagnostic("profile", "STANDARD_WORKFLOW_PENDING", "warning", "Standard support is installed without the workflow stage.",
                                      "After support is reviewed on the default branch, initialize the workflow stage.", "docs/quickstart.md"))
    for relative in ("config/tools.json", "policy/severity-thresholds.yml", "policy/suppressions.yml"):
        path = state.target / relative
        if path.is_file() and not path.is_symlink():
            try:
                payload = loads_strict(path.read_bytes())
                if not isinstance(payload, dict):
                    raise StrictJSONError("top level must be an object")
            except (OSError, StrictJSONError) as exc:
                diagnostics.append(diagnostic("configuration", "CONFIG_MALFORMED", "error", f"{relative} is malformed: {type(exc).__name__}.",
                                              "Restore or manually repair reviewed JSON-compatible configuration.", "docs/troubleshooting.md"))
    allowed = {
        "VIBESEC_ENFORCEMENT": {"observe", "new", "all"},
        "VIBESEC_MIN_SEVERITY": {"low", "medium", "high", "critical"},
        "VIBESEC_NETWORK_MODE": {"online", "offline"},
    }
    for name, values in allowed.items():
        if name in os.environ and os.environ[name] not in values:
            diagnostics.append(diagnostic("environment", "ENV_VALUE_UNSUPPORTED", "error", f"{name} has an unsupported value; the value was redacted.",
                                          "Use a documented accepted value.", "docs/configuration.md"))
    if os.getenv("VIBESEC_NETWORK_MODE", "online") == "offline":
        missing = [name for name in ("VIBESEC_OSV_DATABASE_DIR", "VIBESEC_OSV_DATABASE_DATE") if not os.getenv(name)]
        if missing:
            diagnostics.append(diagnostic("osv", "OSV_OFFLINE_INCOMPLETE", "error", "Offline OSV configuration is incomplete: " + ", ".join(missing),
                                          "Provide a local database path and declared date.", "docs/configuration.md"))
        else:
            try:
                declared = date.fromisoformat(os.environ["VIBESEC_OSV_DATABASE_DATE"])
                maximum = int(os.getenv("VIBESEC_OSV_MAX_DATABASE_AGE_DAYS", "7"))
                if maximum < 0:
                    raise ValueError("negative maximum age")
                if (date.today() - declared).days > maximum:
                    diagnostics.append(diagnostic("osv", "OSV_DATABASE_STALE", "error", "Declared offline OSV database date exceeds the maximum age.",
                                                  "Provision reviewed fresh offline data.", "docs/troubleshooting.md"))
                if not Path(os.environ["VIBESEC_OSV_DATABASE_DIR"]).is_dir():
                    diagnostics.append(diagnostic("osv", "OSV_DATABASE_UNAVAILABLE", "error", "Configured offline OSV database directory is unavailable.",
                                                  "Provision the local database without printing its path.", "docs/troubleshooting.md"))
            except (ValueError, OverflowError):
                diagnostics.append(diagnostic("osv", "OSV_DATE_INVALID", "error", "Offline OSV date or maximum age is invalid.",
                                              "Use YYYY-MM-DD and a non-negative integer age.", "docs/configuration.md"))
    image = os.getenv("VIBESEC_IMAGE_REFERENCE", "")
    if image and not IMAGE.fullmatch(image):
        diagnostics.append(diagnostic("image", "IMAGE_REFERENCE_INVALID", "error", "Prebuilt image reference is tag-only or malformed; value redacted.",
                                      "Use an immutable registry/name@sha256 digest.", "docs/configuration.md"))
    if os.getenv("GITHUB_ACTIONS", "").casefold() == "true" and os.getenv("GITHUB_EVENT_NAME", "") == "pull_request":
        diagnostics.append(diagnostic("fork", "FORK_RESTRICTIONS_ACTIVE", "not_applicable", "Pull-request image/private-registry scanning remains disabled and receives no secrets.",
                                      "Review coverage state; do not weaken the trust boundary.", "docs/security-model.md"))
    source, manifests, iac = _safe_inventory(state.target)
    if profile == "standard" and iac and shutil.which("docker") is None:
        diagnostics.append(diagnostic("checkov", "DOCKER_OPTIONAL_UNAVAILABLE", "warning", "Docker is unavailable while IaC evidence exists.",
                                      "Use a trusted runner with Docker or document missing Checkov coverage.", "docs/troubleshooting.md"))
    elif profile == "standard" and not iac:
        diagnostics.append(diagnostic("checkov", "CHECKOV_NOT_APPLICABLE", "not_applicable", "No simple IaC evidence was found for the optional Docker check.",
                                      "No action unless deterministic inventory identifies supported IaC.", "docs/compatibility.md"))
    if not source and not manifests and not iac:
        diagnostics.append(diagnostic("coverage", "REPOSITORY_UNSUPPORTED", "warning", "No supported source, package, or IaC evidence was found.",
                                      "Report outside-coverage areas; do not call the repository clean.", "docs/compatibility.md"))
    overlap = _overlap(state.target)
    if overlap:
        diagnostics.append(diagnostic("overlap", "SECURITY_TOOL_OVERLAP", "warning", "Existing security workflow markers detected: " + ", ".join(overlap),
                                      "Review scope before adding duplicate scanners.", "docs/profile-selection.md"))
    if state.version and state.version != read_version(ROOT):
        diagnostics.append(diagnostic("version", "DEVELOPMENT_VERSION_DRIFT", "warning", "Installed development version differs from this doctor version.",
                                      "Use a verified local bundle and generate an upgrade plan.", "docs/upgrading.md"))
    if any(item["severity"] == "error" for item in diagnostics):
        status = "error"
    elif any(item["severity"] == "warning" for item in diagnostics):
        status = "warning"
    else:
        status = "healthy"
    return status, diagnostics, {"profile": profile, "stage": sorted({manifest["stage"] for manifest in state.manifests}), "installation_status": state.status}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--profile", choices=("minimal", "standard"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        version = read_version(ROOT)
    except VersionError:
        version = "unknown"
    try:
        status, diagnostics, context = run_doctor(args.target, args.profile)
        errors = [item["explanation"] for item in diagnostics if item["severity"] == "error"]
        warnings = [item["explanation"] for item in diagnostics if item["severity"] == "warning"]
        payload = envelope("vibesec_doctor", version, status, result={"context": context, "diagnostics": diagnostics}, errors=errors, warnings=warnings,
                           information=["Diagnostics are offline and do not assess application security."])
        emit(payload, as_json=args.json)
        return VERIFICATION_FAILED if status == "error" else WARNINGS if status == "warning" else SUCCESS
    except InstallationError as exc:
        emit(envelope("vibesec_doctor", version, "invalid", errors=[str(exc)]), as_json=args.json)
        return INVALID_INPUT
    except OSError as exc:
        emit(envelope("vibesec_doctor", version, "infrastructure_failure", errors=[type(exc).__name__]), as_json=args.json)
        return INFRASTRUCTURE_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
