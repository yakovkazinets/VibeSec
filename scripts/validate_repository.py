#!/usr/bin/env python3
"""Validate static VibeSec Guardian configuration without third-party Python packages."""

from __future__ import annotations

from pathlib import Path
import re
import sys
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from vibesec.bundle import validate_catalog  # noqa: E402
from vibesec.agents import ADAPTER_IDS, TASK_IDS, load_catalog, render_adapter  # noqa: E402
from vibesec.api_security import load_config as load_api_config  # noqa: E402
from vibesec.api_fuzzing import load_config as load_fuzzing_config, load_payload_registry  # noqa: E402
from vibesec.dast import load_config  # noqa: E402
from vibesec.github_actions import (  # noqa: E402
    GitHubActionsError, audit_tracked_files, load_inventory as load_action_inventory,
)
from vibesec.extensions import collect_source  # noqa: E402
from vibesec.portable import load_support  # noqa: E402
from vibesec.toolchain import load_tool_metadata  # noqa: E402
from vibesec.strict_json import loads_strict  # noqa: E402
from vibesec.schemathesis_runtime import trusted_active_schemathesis_command, trusted_schemathesis_command  # noqa: E402
from vibesec.version import read_version  # noqa: E402
from vibesec.v1_contract import validate_catalogs, validate_examples, validate_migrations, load_readiness  # noqa: E402
from vibesec.zap_automation import (  # noqa: E402
    CONTAINER_ZAP_HOME, JOB_TYPES, REPORT_FILENAME, REPORT_TEMPLATE,
    RUNTIME_ADDON_OPTIONS, build_passive_plan, trusted_zap_command,
    validate_passive_plan,
)
from validate_security_capabilities import validate_matrix  # noqa: E402
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_TOOLS = {"trivy", "gitleaks", "actionlint", "opengrep", "osv-scanner", "syft", "cosign", "checkov", "zap-baseline", "dast-fixture-python", "schemathesis"}
EXPECTED_VIBESEC_VARIABLES = {
    "VIBESEC_ENFORCEMENT", "VIBESEC_MIN_SEVERITY", "VIBESEC_TOOL_DIR", "VIBESEC_CACHE_HOME", "VIBESEC_NETWORK_MODE",
    "VIBESEC_OSV_DATABASE_DIR", "VIBESEC_OSV_DATABASE_DATE", "VIBESEC_OSV_MAX_DATABASE_AGE_DAYS",
    "VIBESEC_IMAGE_REFERENCE", "VIBESEC_DAST_IMAGE_REFERENCE", "VIBESEC_DAST_CONTAINER_PORT",
    "VIBESEC_DAST_BASE_PATH", "VIBESEC_DAST_ENFORCEMENT", "VIBESEC_DAST_MIN_SEVERITY",
    "VIBESEC_API_IMAGE_REFERENCE", "VIBESEC_API_SCHEMA_PATH", "VIBESEC_API_CONTAINER_PORT",
    "VIBESEC_API_BASE_PATH", "VIBESEC_API_SAFE_METHODS_ONLY", "VIBESEC_API_ENFORCEMENT",
    "VIBESEC_API_MIN_SEVERITY", "VIBESEC_AUTH_MODE",
    "VIBESEC_API_FUZZING_ENFORCEMENT", "VIBESEC_API_FUZZING_MIN_SEVERITY",
}


def load_object(path: Path) -> dict:
    try:
        value = loads_strict(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ValueError(f"{path.relative_to(ROOT)} is not valid JSON-compatible YAML: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain an object")
    return value


def validate_tools() -> None:
    metadata = load_tool_metadata(ROOT / "config/tools.json")
    tools = metadata["tools"]
    if set(tools) != EXPECTED_TOOLS:
        raise ValueError(f"config/tools.json must define exactly {sorted(EXPECTED_TOOLS)}")
    for name, config in tools.items():
        if not isinstance(config, dict):
            raise ValueError(f"tool {name} configuration must be an object")
        if not all(isinstance(config.get(field), str) and config[field] for field in ("version", "license", "official_repository", "verification_date")):
            raise ValueError(f"tool {name} is missing version, license, official_repository, or verification_date")
        if config["verification_date"] != "2026-08-03":
            raise ValueError(f"tool {name} pin must record the current review date")
        official = urlparse(config["official_repository"])
        if official.scheme != "https" or official.hostname != "github.com":
            raise ValueError(f"tool {name} must identify its official GitHub repository")
        if config.get("kind") == "container":
            if not isinstance(config.get("image"), str) or not config["image"] or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(config.get("digest", ""))):
                raise ValueError(f"container tool {name} must use an immutable SHA-256 digest")
            continue
        platforms = config.get("platforms")
        if not isinstance(platforms, dict) or set(platforms) != {"linux-amd64", "macos-amd64", "macos-arm64"}:
            raise ValueError(f"native tool {name} must pin all supported release platforms")
        for platform_name, asset in platforms.items():
            if not SHA256.fullmatch(asset["sha256"]):
                raise ValueError(f"tool {name} has an invalid SHA-256 checksum on {platform_name}")
            parsed = urlparse(asset["url"])
            if parsed.scheme != "https" or parsed.hostname != "github.com" or "/releases/download/" not in parsed.path:
                raise ValueError(f"tool {name} must use an official versioned GitHub release URL")
            if asset["asset_name"] not in parsed.path or config["version"] not in parsed.path:
                raise ValueError(f"tool {name} URL, asset, and version are inconsistent")
        if name == "opengrep":
            for platform_name, asset in platforms.items():
                for field in ("signature_url", "certificate_url", "certificate_identity", "certificate_oidc_issuer"):
                    if not isinstance(asset.get(field), str) or not asset[field]:
                        raise ValueError(f"Opengrep is missing Sigstore field {field} on {platform_name}")


def validate_policy() -> None:
    thresholds = load_object(ROOT / "policy/severity-thresholds.yml")
    if thresholds.get("default_minimum_severity") not in ("low", "medium", "high", "critical"):
        raise ValueError("policy threshold is invalid")
    if thresholds.get("enforcement") not in ("observe", "new", "all"):
        raise ValueError("policy enforcement mode is invalid")
    intelligence = thresholds.get("finding_intelligence")
    if (not isinstance(intelligence, dict) or set(intelligence) != {
            "enabled", "minimum_priority", "minimum_independent_scanners", "require_confirmed_runtime"}
            or type(intelligence["enabled"]) is not bool
            or intelligence["minimum_priority"] not in {"informational", "low", "medium", "high", "critical"}
            or intelligence["minimum_independent_scanners"] is not None
            or type(intelligence["require_confirmed_runtime"]) is not bool):
        raise ValueError("default finding intelligence policy controls must be present and disabled")
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
    fuzzing_baseline = load_object(ROOT / "policy/api-fuzzing-baseline.json")
    if fuzzing_baseline.get("profile") != "api-fuzzing" or not isinstance(fuzzing_baseline.get("fingerprints"), list):
        raise ValueError("policy/api-fuzzing-baseline.json must contain active API fingerprints")
    fuzzing_suppressions = load_object(ROOT / "policy/api-fuzzing-suppressions.json")
    if fuzzing_suppressions.get("profile") != "api-fuzzing" or not isinstance(fuzzing_suppressions.get("suppressions"), list):
        raise ValueError("policy/api-fuzzing-suppressions.json must contain active API suppressions")


def validate_references() -> None:
    required = (
        ".github/workflows/ci.yml", ".github/workflows/dast-integration.yml", ".github/workflows/api-security-integration.yml", ".github/workflows/api-fuzzing-integration.yml",
        ".github/workflows/authenticated-dast-integration.yml", ".github/workflows/authenticated-api-integration.yml", ".github/workflows/release-candidate.yml", "templates/github-actions/security-baseline.yml",
        "templates/github-actions/security-standard.yml", "templates/github-actions/dast-baseline.yml", "templates/github-actions/api-security-baseline.yml", "templates/github-actions/api-fuzzing.yml",
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
        "scripts/run_api_fuzzing.py", "scripts/validate_api_fuzzing_artifacts.py", "scripts/test_api_fuzzing_container.py",
        "scripts/vibesec/api_fuzzing.py", "scripts/vibesec/api_fuzzing_launcher.py", "config/api-fuzzing.json",
        "config/api-fuzzing-result-schema.json", "config/injection-payloads.json",
        "scripts/vibesec/authenticated.py", "tests/test_authenticated_security_testing.py",
        "scripts/generate_finding_intelligence.py", "scripts/vibesec/finding_intelligence.py",
        "config/finding-groups-schema.json", "config/prioritized-findings-schema.json",
        "config/api-security-result-schema.json",
        "config/github-actions.json", "scripts/vibesec/github_actions.py",
        "config/zap-passive-plan-schema.json",
        "config/environment-variables.json", "docs/quickstart.md", "docs/profile-selection.md",
        "docs/github-actions-runtime.md",
        "docs/compatibility.md", "docs/configuration.md", "docs/upgrading.md", "docs/distribution.md",
        "docs/installation-verification.md", "docs/doctor.md", "docs/dast-baseline.md", "docs/dast-threat-model.md",
        "docs/api-security-baseline.md", "docs/api-security-threat-model.md", "scripts/test_api_security_container.py",
        "docs/api-fuzzing.md", "docs/injection-testing.md", "docs/fuzzing-threat-model.md",
        "docs/authenticated-security-testing.md", "docs/authenticated-security-threat-model.md",
        "docs/software-supply-chain-assurance.md", "docs/release-signing.md", "docs/provenance.md", "docs/release-threat-model.md",
        "scripts/install_release_tools.sh", "scripts/generate_release_validation_evidence.py",
        "scripts/prepare_release_artifacts.py", "scripts/sign_release_artifacts.py",
        "scripts/verify_release_artifacts.py", "scripts/validate_supply_chain_posture.py",
        "scripts/vibesec/supply_chain.py", "config/release-manifest-schema.json", "config/provenance-schema.json", "config/supply-chain-policy.json",
        "vibesec", "scripts/manage_extensions.py", "scripts/vibesec/portable.py", "scripts/vibesec/extensions.py",
        "scripts/manage_agents.py", "scripts/vibesec/agents.py",
        "config/portable-execution.json", "config/extension-manifest-schema.json",
        "extensions/examples/repository-metadata/vibesec-extension.json", "extensions/examples/repository-metadata/adapter.py",
        "docs/local-execution.md", "docs/platform-support.md", "docs/extensions.md", "docs/extension-security-model.md", "docs/extension-authoring.md",
        "docs/multi-agent-support.md", "docs/agent-contract.md", "docs/agent-adapters.md",
        "docs/agent-task-pack.md", "docs/agent-safety-model.md", "docs/agent-installation.md", "docs/agent-upgrades.md",
        "docs/v1-final-review.md", "machine/v1-final-review.json",
        "machine/agents/contract.json", "machine/agents/safety-rules.json",
        "machine/agents/capabilities.json", "machine/agents/documentation-map.json",
        "machine/schemas/agent-contract.schema.json", "machine/schemas/agent-adapter.schema.json",
        "machine/schemas/agent-task.schema.json",
        "docs/finding-intelligence.md", "docs/framework-sast-coverage.md",
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
    fuzzing_config = load_fuzzing_config(ROOT)
    load_payload_registry(ROOT)
    active = trusted_active_schemathesis_command(port=8080, base_path="/", config=fuzzing_config,
                                                  mode="combined", safe_methods_only=True)
    active_flattened = " ".join(active)
    active_required = ("--phases examples,coverage,fuzzing", "--workers 1", "--max-examples 25",
                       "--max-failures 25", "--request-timeout 5", "--generation-allow-x00 false")
    if any(item not in active_flattened for item in active_required) or any(item in active_flattened for item in prohibited):
        raise ValueError("active API command differs from its reviewed deterministic contract")
    for relative in ("scripts/run_api_fuzzing.py", "tests/test_api_fuzzing.py"):
        source = (ROOT / relative).read_text(encoding="utf-8")
        if "trusted_active_scanner_container_command(" not in source or "trusted_injection_container_command(" not in source:
            raise ValueError(f"{relative} must use both trusted active API command builders")


def validate_adoption_metadata() -> None:
    version = read_version(ROOT)
    if version != "1.1.1":
        raise ValueError("VERSION must declare the reviewed v1.1.1 release-preparation version")
    adoption = validate_catalog(loads_strict((ROOT / "config/adoption-files.json").read_bytes()))
    common = adoption.get("common")
    profiles = adoption.get("profiles")
    addons = adoption.get("addons")
    if not isinstance(common, list) or not isinstance(profiles, dict) or set(profiles) != {"minimal", "standard"} or not isinstance(addons, dict) or set(addons) != {"dast-baseline", "api-security-baseline", "api-fuzzing"}:
        raise ValueError("adoption catalog must define common, Minimal, Standard, and all reviewed runtime add-ons")
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
    expected = "  validate:\n    needs: [self-scan-minimal, self-scan-standard, scanner-accountability, finding-intelligence-artifacts, security-artifacts, dast-artifacts, api-security-artifacts, authenticated-security-artifacts, fuzzing-artifacts, supply-chain-artifacts, portable-execution-artifacts, extension-platform-artifacts, agent-documentation-contract, documentation-contract, v1-interface-contract, migration-artifacts, release-readiness-artifacts]"
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
        "release-readiness.json",
        "provenance.intoto.jsonl", "release-manifest.json", "SHA256SUMS",
        "SHA256SUMS.sigstore.json",
    ]
    if policy["required_artifacts"] != expected:
        raise ValueError("release artifact set is invalid")
    for relative in ("config/release-manifest-schema.json", "config/provenance-schema.json"):
        schema = load_object(ROOT / relative)
        if schema.get("additionalProperties") is not False or schema.get("type") != "object":
            raise ValueError(f"{relative} must be a closed object schema")


def validate_portable_extension_platform() -> None:
    support = load_support(ROOT / "config/portable-execution.json")
    if support["platforms"]["linux-amd64"]["native_profiles"] != ["minimal", "standard"]:
        raise ValueError("portable execution must retain complete Linux amd64 native profiles")
    if any(support["platforms"][name]["container_profiles"] for name in support["platforms"]):
        raise ValueError("portable metadata must not claim an undistributed complete profile container")
    source = collect_source(ROOT / "extensions/examples/repository-metadata")
    if source.manifest["extension_id"] != "vibesec.repository-metadata-example":
        raise ValueError("reference extension identity is invalid")
    schema = load_object(ROOT / "config/extension-manifest-schema.json")
    if (schema.get("additionalProperties") is not False or schema.get("type") != "object"
            or set(schema.get("required", [])) != set(source.manifest)):
        raise ValueError("extension manifest JSON schema differs from the strict runtime fields")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for job in ("portable-execution-artifacts", "extension-platform-artifacts"):
        if ci.count(f"\n  {job}:\n") != 1:
            raise ValueError(f"required portable accountability job is missing or duplicated: {job}")


def validate_agent_documentation_contract() -> None:
    catalog = load_catalog(ROOT)
    if tuple(catalog["adapters"]) != ADAPTER_IDS or tuple(catalog["tasks"]) != TASK_IDS:
        raise ValueError("agent adapter or task IDs differ from the stable v1 inventory")
    schemas = {
        "machine/schemas/agent-contract.schema.json": set(catalog["contract"]),
        "machine/schemas/agent-adapter.schema.json": set(next(iter(catalog["adapters"].values()))),
        "machine/schemas/agent-task.schema.json": set(next(iter(catalog["tasks"].values()))),
    }
    for relative, fields in schemas.items():
        schema = load_object(ROOT / relative)
        if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
            raise ValueError(f"{relative} must be a closed object schema")
        if set(schema.get("required", [])) != fields:
            raise ValueError(f"{relative} required fields differ from the runtime object")
    documentation_map = load_object(ROOT / "machine/agents/documentation-map.json")
    expected_mapping = {
        catalog["contract"]["contract_id"]: catalog["contract"]["human_documentation"],
        **{item["object_id"]: item["human_documentation"] for item in catalog["adapters"].values()},
    }
    mapped_objects = documentation_map.get("objects")
    if not isinstance(mapped_objects, dict) or any(mapped_objects.get(key) != value for key, value in expected_mapping.items()):
        raise ValueError("agent machine-to-human documentation map is incomplete")
    for object_id, relative in mapped_objects.items():
        path = ROOT / relative
        if not path.is_file() or object_id not in path.read_text(encoding="utf-8"):
            raise ValueError(f"agent human documentation does not link back to {object_id}")
    for adapter_id in ADAPTER_IDS:
        rendered = render_adapter(ROOT, ROOT, adapter_id).decode("utf-8")
        for marker in (
            "explicit_human_authorization_only", "Do not weaken, delete, skip, or rewrite tests",
            "Report the manual push command", "Do not invoke an external agent CLI",
        ):
            if marker not in rendered:
                raise ValueError(f"agent adapter lost required safety semantics: {adapter_id}")
        for task_id in TASK_IDS:
            if f"`{task_id}`" not in rendered:
                raise ValueError(f"agent adapter lost a task: {adapter_id}: {task_id}")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    if ci.count("\n  agent-documentation-contract:\n") != 1:
        raise ValueError("agent documentation accountability job is missing or duplicated")
    job = ci.split("\n  agent-documentation-contract:\n", 1)[1].split("\n  validate:\n", 1)[0]
    prohibited = ("gh auth", "docker ", "curl ", "wget ", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY")
    if any(value.casefold() in job.casefold() for value in prohibited):
        raise ValueError("agent documentation accountability job requests network, Docker, or credentials")


def validate_v1_release_contract() -> None:
    validate_catalogs(ROOT)
    validate_examples(ROOT)
    validate_migrations(ROOT)
    load_readiness(
        ROOT / "machine/release-readiness.json",
        source_commit="1203e5a700b7485287e34028d204cb0711f8ea9f",
    )
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for job in (
        "documentation-contract", "v1-interface-contract",
        "migration-artifacts", "release-readiness-artifacts",
    ):
        if ci.count(f"\n  {job}:\n") != 1:
            raise ValueError(f"required v1 accountability job is missing or duplicated: {job}")


def validate_v1_final_review() -> None:
    review = load_object(ROOT / "machine/v1-final-review.json")
    required = {
        "schema_version", "stable_id", "reviewed_main_commit", "review_date",
        "review_branch", "reviewer_scopes", "findings", "fixes",
        "accepted_limitations", "deferred_items", "false_positives", "tests",
        "platform_limits", "local_checks", "github_only_checks",
        "remaining_blockers", "release_candidate", "recommendation",
    }
    if set(review) != required:
        raise ValueError("v1 final-review record has unknown or missing fields")
    if (review["schema_version"] != 1
            or review["stable_id"] != "vibesec.v1-final-review"
            or review["reviewed_main_commit"] != "f19d5dcf29dc13b6b716d39bf11da1e31ca94234"
            or review["review_date"] != "2026-07-25"
            or review["review_branch"] != "fix/v1-final-review"
            or review["recommendation"] != "ready_with_documented_limitations"
            or review["remaining_blockers"] != []):
        raise ValueError("v1 final-review identity, recommendation, or blocker state is invalid")
    if set(review["reviewer_scopes"]) != {"A", "B", "C", "D", "E"}:
        raise ValueError("v1 final-review reviewer scopes are incomplete")
    if (not isinstance(review["findings"], list) or len(review["findings"]) != 15
            or any(item.get("resolution") != "fixed" for item in review["findings"])):
        raise ValueError("v1 final-review findings are incomplete or unresolved")
    tests = review["tests"]
    if tests != {
        "reviewed_main_automated_tests": 406,
        "post_fix_automated_tests": 436,
        "post_fix_skipped": 2,
        "required_ci_job_equivalents": 18,
        "representative_migrations_executed": 11,
        "adoption_examples_executed": 11,
    }:
        raise ValueError("v1 final-review test totals differ from reviewed evidence")
    candidate = review["release_candidate"]
    if (candidate.get("source_commit") is not None
            or not isinstance(candidate.get("sha256"), str)
            or not SHA256.fullmatch(candidate["sha256"])
            or not isinstance(candidate.get("bytes"), int)
            or isinstance(candidate.get("bytes"), bool)
            or candidate["bytes"] < 1
            or candidate.get("file_count") != 204
            or candidate.get("byte_comparison") != "identical"
            or candidate.get("verification") != "valid"):
        raise ValueError("v1 final-review candidate evidence differs from local verification")
    documentation = (ROOT / "docs/v1-final-review.md").read_text(encoding="utf-8")
    for marker in (
        review["reviewed_main_commit"], review["review_date"],
        review["recommendation"], candidate["sha256"], "436 automated tests",
        "18 required CI job-equivalent", "No tag or release was created",
    ):
        if marker not in documentation:
            raise ValueError(f"v1 final-review human record is missing: {marker}")


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
        validate_portable_extension_platform()
        validate_agent_documentation_contract()
        validate_v1_release_contract()
        validate_v1_final_review()
        inventory = load_action_inventory(ROOT / "config/github-actions.json")
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
