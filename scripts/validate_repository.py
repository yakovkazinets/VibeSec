#!/usr/bin/env python3
"""Validate static VibeSec configuration without third-party Python packages."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from vibesec.bundle import validate_catalog  # noqa: E402
from vibesec.strict_json import loads_strict  # noqa: E402
from vibesec.version import read_version  # noqa: E402
from validate_security_capabilities import validate_matrix  # noqa: E402
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_TOOLS = {"trivy", "gitleaks", "actionlint", "opengrep", "osv-scanner", "syft", "cosign", "checkov", "zap-baseline", "dast-fixture-python"}
EXPECTED_VIBESEC_VARIABLES = {
    "VIBESEC_ENFORCEMENT", "VIBESEC_MIN_SEVERITY", "VIBESEC_TOOL_DIR", "VIBESEC_NETWORK_MODE",
    "VIBESEC_OSV_DATABASE_DIR", "VIBESEC_OSV_DATABASE_DATE", "VIBESEC_OSV_MAX_DATABASE_AGE_DAYS",
    "VIBESEC_IMAGE_REFERENCE", "VIBESEC_DAST_IMAGE_REFERENCE", "VIBESEC_DAST_CONTAINER_PORT",
    "VIBESEC_DAST_BASE_PATH", "VIBESEC_DAST_ENFORCEMENT", "VIBESEC_DAST_MIN_SEVERITY",
}


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
        if not all(isinstance(config.get(field), str) and config[field] for field in ("version", "license", "official_repository", "verification_date")):
            raise ValueError(f"tool {name} is missing version, license, official_repository, or verification_date")
        if config["verification_date"] != "2026-07-21":
            raise ValueError(f"tool {name} pin must record the current review date")
        official = urlparse(config["official_repository"])
        if official.scheme != "https" or official.hostname != "github.com":
            raise ValueError(f"tool {name} must identify its official GitHub repository")
        if config.get("kind") == "container":
            if not isinstance(config.get("image"), str) or not config["image"] or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(config.get("digest", ""))):
                raise ValueError(f"container tool {name} must use an immutable SHA-256 digest")
            continue
        if not all(isinstance(config.get(field), str) and config[field] for field in ("archive", "sha256", "url")):
            raise ValueError(f"tool {name} is missing archive, sha256, url, or version")
        if not SHA256.fullmatch(config["sha256"]):
            raise ValueError(f"tool {name} has an invalid SHA-256 checksum")
        parsed = urlparse(config["url"])
        if parsed.scheme != "https" or parsed.hostname != "github.com" or "/releases/download/" not in parsed.path:
            raise ValueError(f"tool {name} must use an official versioned GitHub release URL")
        if config["archive"] not in parsed.path or config["version"] not in parsed.path:
            raise ValueError(f"tool {name} URL, archive, and version are inconsistent")
        if name == "opengrep":
            for field in ("signature_url", "certificate_url", "certificate_identity", "certificate_oidc_issuer"):
                if not isinstance(config.get(field), str) or not config[field]:
                    raise ValueError(f"Opengrep is missing Sigstore field {field}")


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
    standard_baseline = load_object(ROOT / "policy/standard-baseline.json")
    if standard_baseline.get("profile") != "standard" or not isinstance(standard_baseline.get("fingerprints"), list):
        raise ValueError("policy/standard-baseline.json must contain a Standard fingerprints array")
    dast_baseline = load_object(ROOT / "policy/dast-baseline.json")
    if dast_baseline.get("profile") != "dast-baseline" or not isinstance(dast_baseline.get("fingerprints"), list):
        raise ValueError("policy/dast-baseline.json must contain a DAST Baseline fingerprints array")
    dast_suppressions = load_object(ROOT / "policy/dast-suppressions.json")
    if dast_suppressions.get("profile") != "dast-baseline" or not isinstance(dast_suppressions.get("suppressions"), list):
        raise ValueError("policy/dast-suppressions.json must contain a DAST Baseline suppressions array")


def validate_references() -> None:
    required = (
        ".github/workflows/ci.yml", "templates/github-actions/security-baseline.yml",
        "templates/github-actions/security-standard.yml", "templates/github-actions/dast-baseline.yml",
        "scripts/install_tools.sh", "scripts/run_minimal_profile.sh", "scripts/normalize_results.py",
        "scripts/install_standard_tools.sh", "scripts/run_standard_profile.py", "scripts/detect_repository.py",
        "scripts/validate_sbom.py", "scripts/validate_opengrep_rules.py",
        "scripts/test_opengrep_rules.py", "scripts/test_checkov_container.py",
        "scripts/preserve_scan_exit.py", "scripts/run_vibesec_self_scan.py", "scripts/expected_self_scan_states.py",
        "scripts/vibesec/self_scan.py",
        "scripts/append_tool_errors.py", "scripts/policy_gate.py", "scripts/validate_skill.py",
        "scripts/init_vibesec.py", "scripts/preflight.py", "config/adoption-files.json",
        "VERSION", "scripts/build_consumer_bundle.py", "scripts/verify_consumer_bundle.py",
        "scripts/verify_installation.py", "scripts/vibesec_doctor.py", "scripts/plan_vibesec_upgrade.py",
        "scripts/validate_security_capabilities.py", "scripts/run_security_accountability.py",
        "scripts/validate_security_artifacts.py", "config/security-capabilities.json", "config/self-scan-scope.json",
        "scripts/run_dast_baseline.py", "scripts/test_dast_container.py", "scripts/validate_dast_artifacts.py", "scripts/vibesec/dast.py",
        "config/environment-variables.json", "docs/quickstart.md", "docs/profile-selection.md",
        "docs/compatibility.md", "docs/configuration.md", "docs/upgrading.md", "docs/distribution.md",
        "docs/installation-verification.md", "docs/doctor.md", "docs/dast-baseline.md", "docs/dast-threat-model.md",
        "docs/security-validation-policy.md", "docs/security-capability-matrix.md", "docs/self-hosted-validation.md",
        "examples/reports/README.md",
        "skills/appsec-guardian/SKILL.md",
    )
    missing = [path for path in required if not (ROOT / path).is_file()]
    if missing:
        raise ValueError(f"required files are missing: {', '.join(missing)}")
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    if requirements != ["PyYAML==6.0.3"]:
        raise ValueError("requirements.txt must contain the reviewed PyYAML pin")


def validate_adoption_metadata() -> None:
    version = read_version(ROOT)
    if version != "0.3.0-dev":
        raise ValueError("VERSION must declare the reviewed unreleased 0.3.0-dev development version")
    adoption = validate_catalog(loads_strict((ROOT / "config/adoption-files.json").read_bytes()))
    common = adoption.get("common")
    profiles = adoption.get("profiles")
    addons = adoption.get("addons")
    if not isinstance(common, list) or not isinstance(profiles, dict) or set(profiles) != {"minimal", "standard"} or not isinstance(addons, dict) or set(addons) != {"dast-baseline"}:
        raise ValueError("adoption catalog must define common, Minimal, Standard, and the DAST Baseline add-on")
    for profile, config in profiles.items():
        if not isinstance(config, dict) or not isinstance(config.get("support"), list):
            raise ValueError(f"adoption catalog profile {profile} is malformed")
        for relative in [*common, *adoption["bundle_additional"], *config["support"], config.get("workflow_source")]:
            if not isinstance(relative, str) or not relative or relative.startswith("/") or ".." in Path(relative).parts:
                raise ValueError(f"adoption catalog contains unsafe path {relative!r}")
            if not (ROOT / relative).is_file():
                raise ValueError(f"adoption catalog references missing file {relative}")
    for addon, config in addons.items():
        for relative in [*config["support"], config["workflow_source"]]:
            if not isinstance(relative, str) or not relative or relative.startswith("/") or ".." in Path(relative).parts or not (ROOT / relative).is_file():
                raise ValueError(f"adoption catalog add-on {addon} references invalid file {relative!r}")
    executable = set(adoption["executable_files"])
    selected = set(common) | set(adoption["bundle_additional"])
    for config in profiles.values():
        selected.update(config["support"])
        selected.add(config["workflow_source"])
    for config in addons.values():
        selected.update(config["support"])
        selected.add(config["workflow_source"])
    if not executable <= selected:
        raise ValueError("executable allowlist must be contained in the consumer file set")
    environment = load_object(ROOT / "config/environment-variables.json")
    variables = environment.get("variables")
    if environment.get("schema_version") != 1 or not isinstance(variables, list):
        raise ValueError("environment variable catalog is malformed")
    names = {item.get("name") for item in variables if isinstance(item, dict)}
    if names != EXPECTED_VIBESEC_VARIABLES:
        raise ValueError(f"environment variable catalog must define exactly {sorted(EXPECTED_VIBESEC_VARIABLES)}")
    configuration = (ROOT / "docs/configuration.md").read_text(encoding="utf-8")
    if any(name not in configuration for name in names):
        raise ValueError("configuration documentation is missing a supported VIBESEC variable")


def main() -> int:
    try:
        validate_tools()
        validate_policy()
        validate_references()
        validate_adoption_metadata()
        validate_matrix()
    except (OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 3
    print("repository configuration is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
