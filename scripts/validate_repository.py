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
from vibesec.api_security import load_config as load_api_config  # noqa: E402
from vibesec.dast import load_config  # noqa: E402
from vibesec.github_actions import (  # noqa: E402
    GitHubActionsError, audit_tracked_files, load_inventory,
)
from vibesec.strict_json import loads_strict  # noqa: E402
from vibesec.schemathesis_runtime import trusted_schemathesis_command  # noqa: E402
from vibesec.version import read_version  # noqa: E402
from vibesec.zap_automation import (  # noqa: E402
    CONTAINER_ZAP_HOME, JOB_TYPES, REPORT_FILENAME, REPORT_TEMPLATE,
    RUNTIME_ADDON_OPTIONS, build_passive_plan, trusted_zap_command,
    validate_passive_plan,
)
from validate_security_capabilities import validate_matrix  # noqa: E402
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_TOOLS = {"trivy", "gitleaks", "actionlint", "opengrep", "osv-scanner", "syft", "cosign", "checkov", "zap-baseline", "dast-fixture-python", "schemathesis"}
EXPECTED_VIBESEC_VARIABLES = {
    "VIBESEC_ENFORCEMENT", "VIBESEC_MIN_SEVERITY", "VIBESEC_TOOL_DIR", "VIBESEC_NETWORK_MODE",
    "VIBESEC_OSV_DATABASE_DIR", "VIBESEC_OSV_DATABASE_DATE", "VIBESEC_OSV_MAX_DATABASE_AGE_DAYS",
    "VIBESEC_IMAGE_REFERENCE", "VIBESEC_DAST_IMAGE_REFERENCE", "VIBESEC_DAST_CONTAINER_PORT",
    "VIBESEC_DAST_BASE_PATH", "VIBESEC_DAST_ENFORCEMENT", "VIBESEC_DAST_MIN_SEVERITY",
    "VIBESEC_API_IMAGE_REFERENCE", "VIBESEC_API_SCHEMA_PATH", "VIBESEC_API_CONTAINER_PORT",
    "VIBESEC_API_BASE_PATH", "VIBESEC_API_SAFE_METHODS_ONLY", "VIBESEC_API_ENFORCEMENT",
    "VIBESEC_API_MIN_SEVERITY", "VIBESEC_AUTH_MODE",
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
        expected_date = "2026-07-22" if name in {"cosign", "schemathesis"} else "2026-07-21"
        if config["verification_date"] != expected_date:
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
    api_baseline = load_object(ROOT / "policy/api-security-baseline.json")
    if api_baseline.get("profile") != "api-security-baseline" or not isinstance(api_baseline.get("fingerprints"), list):
        raise ValueError("policy/api-security-baseline.json must contain API fingerprints")
    api_suppressions = load_object(ROOT / "policy/api-security-suppressions.json")
    if api_suppressions.get("profile") != "api-security-baseline" or not isinstance(api_suppressions.get("suppressions"), list):
        raise ValueError("policy/api-security-suppressions.json must contain API suppressions")


def validate_references() -> None:
    required = (
        ".github/workflows/ci.yml", ".github/workflows/dast-integration.yml", ".github/workflows/api-security-integration.yml",
        ".github/workflows/authenticated-dast-integration.yml", ".github/workflows/authenticated-api-integration.yml", ".github/workflows/release-candidate.yml", "templates/github-actions/security-baseline.yml",
        "templates/github-actions/security-standard.yml", "templates/github-actions/dast-baseline.yml", "templates/github-actions/api-security-baseline.yml",
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
        "scripts/run_dast_baseline.py", "scripts/test_dast_container.py", "scripts/validate_dast_artifacts.py",
        "scripts/vibesec/dast.py", "scripts/vibesec/zap_automation.py", "scripts/vibesec/zap_diagnostics.py",
        "scripts/run_api_security_baseline.py", "scripts/validate_api_security_artifacts.py",
        "scripts/vibesec/api_security.py", "scripts/vibesec/schemathesis_runtime.py",
        "scripts/vibesec/authenticated.py", "tests/test_authenticated_security_testing.py",
        "config/api-security-result-schema.json",
        "config/github-actions.json", "scripts/vibesec/github_actions.py",
        "config/zap-passive-plan-schema.json",
        "config/environment-variables.json", "docs/quickstart.md", "docs/profile-selection.md",
        "docs/github-actions-runtime.md",
        "docs/compatibility.md", "docs/configuration.md", "docs/upgrading.md", "docs/distribution.md",
        "docs/installation-verification.md", "docs/doctor.md", "docs/dast-baseline.md", "docs/dast-threat-model.md",
        "docs/api-security-baseline.md", "docs/api-security-threat-model.md", "scripts/test_api_security_container.py",
        "docs/authenticated-security-testing.md", "docs/authenticated-security-threat-model.md",
        "docs/software-supply-chain-assurance.md", "docs/release-signing.md", "docs/provenance.md", "docs/release-threat-model.md",
        "scripts/install_release_tools.sh", "scripts/prepare_release_artifacts.py", "scripts/sign_release_artifacts.py", "scripts/verify_release_artifacts.py", "scripts/validate_supply_chain_posture.py",
        "scripts/vibesec/supply_chain.py", "config/release-manifest-schema.json", "config/provenance-schema.json", "config/supply-chain-policy.json",
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


def validate_dast_command_contract() -> None:
    config = load_config(ROOT)
    command = trusted_zap_command()
    if command != ["zap.sh", "-cmd", "-silent", "-dir", CONTAINER_ZAP_HOME,
                   "-autorun", "/zap/wrk/vibesec-zap-plan.yaml"]:
        raise ValueError("DAST command must contain only the reviewed Automation Framework arguments")
    if command.count("-dir") != 1 or command[command.index("-dir") + 1] != "/zap/vibesec-home":
        raise ValueError("DAST command must use exactly one explicit ephemeral ZAP home")
    if RUNTIME_ADDON_OPTIONS.intersection(command) or any("proxy" in item.casefold() for item in command):
        raise ValueError("DAST command must not update add-ons or configure a proxy")
    plan = build_passive_plan(
        port=8080, base_path="/", spider_minutes=config["spider_duration_minutes"],
        passive_wait_minutes=config["passive_scan_timeout_minutes"],
    )
    validate_passive_plan(
        plan, port=8080, base_path="/", spider_minutes=config["spider_duration_minutes"],
        passive_wait_minutes=config["passive_scan_timeout_minutes"],
    )
    if tuple(job["type"] for job in plan["jobs"]) != JOB_TYPES:
        raise ValueError("DAST plan job order differs from the reviewed passive sequence")
    report = plan["jobs"][2]
    if report["parameters"]["template"] != REPORT_TEMPLATE or report["parameters"]["reportFile"] != REPORT_FILENAME:
        raise ValueError("DAST plan must use only the traditional JSON private report")
    schema = load_object(ROOT / "config/zap-passive-plan-schema.json")
    if schema.get("additionalProperties") is not False or schema.get("properties", {}).get("jobs", {}).get("maxItems") != 4:
        raise ValueError("trusted ZAP plan schema does not preserve the closed four-job contract")
    for relative in ("scripts/run_dast_baseline.py", "scripts/test_dast_container.py"):
        source = (ROOT / relative).read_text(encoding="utf-8")
        if "trusted_zap_container_command(" not in source or "zap-baseline.py" in source or "zap-full-scan.py" in source:
            raise ValueError(f"{relative} must use only the shared trusted ZAP Automation Framework builder")
        if "PLAN_FILENAME" not in source and relative.endswith("run_dast_baseline.py"):
            raise ValueError("production DAST runner must create and delete the trusted plan")


def validate_api_command_contract() -> None:
    config = load_api_config(ROOT)
    command = trusted_schemathesis_command(port=8080, base_path="/", config=config, safe_methods_only=True)
    flattened = " ".join(command)
    required = ("--phases examples,coverage,fuzzing", "--mode all", "--workers 1", "--max-examples 20",
                "--max-failures 20", "--request-timeout 5", "--generation-deterministic",
                "--generation-database none", "--report ndjson")
    prohibited = ("stateful", "--header", "--auth", "--hooks", "--config", "--proxy", "--report-junit")
    if any(item not in flattened for item in required) or any(item in flattened for item in prohibited):
        raise ValueError("API command differs from the reviewed bounded stateless contract")
    methods = [command[index + 1] for index, item in enumerate(command) if item == "--include-method"]
    if methods != ["GET", "HEAD", "OPTIONS"]:
        raise ValueError("API safe-method default differs from the reviewed set")
    for relative in ("scripts/run_api_security_baseline.py", "tests/test_api_security_baseline.py"):
        if "trusted_scanner_container_command(" not in (ROOT / relative).read_text(encoding="utf-8"):
            raise ValueError(f"{relative} must use the shared Schemathesis command builder")


def validate_adoption_metadata() -> None:
    version = read_version(ROOT)
    if version != "0.3.0-dev":
        raise ValueError("VERSION must declare the reviewed unreleased 0.3.0-dev development version")
    adoption = validate_catalog(loads_strict((ROOT / "config/adoption-files.json").read_bytes()))
    common = adoption.get("common")
    profiles = adoption.get("profiles")
    addons = adoption.get("addons")
    if not isinstance(common, list) or not isinstance(profiles, dict) or set(profiles) != {"minimal", "standard"} or not isinstance(addons, dict) or set(addons) != {"dast-baseline", "api-security-baseline"}:
        raise ValueError("adoption catalog must define common, Minimal, Standard, and both runtime add-ons")
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


def validate_github_actions_documentation() -> None:
    required = (
        "README.md", "CHANGELOG.md", "docs/quickstart.md", "docs/configuration.md",
        "docs/distribution.md", "docs/installation-verification.md", "docs/doctor.md",
        "docs/upgrading.md", "docs/self-hosted-validation.md", "docs/github-actions-runtime.md",
        "skills/appsec-guardian/SKILL.md",
    )
    for relative in required:
        text = (ROOT / relative).read_text(encoding="utf-8")
        if "Node 24" not in text:
            raise ValueError(f"Node 24 action runtime documentation is missing from {relative}")
    runtime = (ROOT / "docs/github-actions-runtime.md").read_text(encoding="utf-8")
    markers = (
        "2.327.1", "Node 20", "Node 26", "GitHub.com", "GHES",
        "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION=true",
    )
    if any(marker not in runtime for marker in markers):
        raise ValueError("GitHub Actions runtime documentation is incomplete")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    expected = "  validate:\n    needs: [self-scan-minimal, self-scan-standard, scanner-accountability, security-artifacts, dast-artifacts, api-security-artifacts, authenticated-security-artifacts, supply-chain-artifacts]"
    if expected not in ci or ci.count("\n  validate:\n") != 1:
        raise ValueError("validate must remain the single required aggregate CI job")


def validate_supply_chain_configuration() -> None:
    policy = load_object(ROOT / "config/supply-chain-policy.json")
    if set(policy) != {
        "schema_version", "source_repository", "release_branch", "workflow_identity",
        "certificate_oidc_issuer", "signature_subject", "signature_bundle",
        "required_artifacts", "normal_scans_require_network_signing", "claimed_slsa_level",
    }:
        raise ValueError("supply-chain policy fields are invalid")
    if (policy["schema_version"] != 1
            or policy["source_repository"] != "https://github.com/yakovkazinets/VibeSec"
            or policy["release_branch"] != "refs/heads/main"
            or policy["certificate_oidc_issuer"] != "https://token.actions.githubusercontent.com"
            or policy["signature_subject"] != "SHA256SUMS"
            or policy["signature_bundle"] != "SHA256SUMS.sigstore.json"
            or policy["normal_scans_require_network_signing"] is not False
            or policy["claimed_slsa_level"] is not None):
        raise ValueError("supply-chain policy values are invalid")
    expected = [
        "vibesec-consumer-bundle.zip", "sbom.cyclonedx.json", "sbom.spdx.json",
        "provenance.intoto.jsonl", "release-manifest.json", "SHA256SUMS",
        "SHA256SUMS.sigstore.json",
    ]
    if policy["required_artifacts"] != expected:
        raise ValueError("release artifact set is invalid")
    for relative in ("config/release-manifest-schema.json", "config/provenance-schema.json"):
        schema = load_object(ROOT / relative)
        if schema.get("additionalProperties") is not False or schema.get("type") != "object":
            raise ValueError(f"{relative} must be a closed object schema")


def main() -> int:
    try:
        validate_tools()
        validate_policy()
        validate_references()
        validate_dast_command_contract()
        validate_api_command_contract()
        validate_adoption_metadata()
        validate_github_actions_documentation()
        validate_supply_chain_configuration()
        inventory = load_inventory(ROOT / "config/github-actions.json")
        action_errors = audit_tracked_files(ROOT, inventory)
        if action_errors:
            raise ValueError("; ".join(action_errors))
        validate_matrix()
    except (GitHubActionsError, OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 3
    print("repository configuration is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
