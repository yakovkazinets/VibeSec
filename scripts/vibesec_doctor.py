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
import subprocess
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.exit_codes import INFRASTRUCTURE_FAILURE, INVALID_INPUT, SUCCESS, VERIFICATION_FAILED, WARNINGS  # noqa: E402
from vibesec.capabilities import CapabilityError, load_capabilities_file, scanner_applicability  # noqa: E402
from vibesec.authenticated import (  # noqa: E402
    AUTH_ENVIRONMENT_VARIABLE, AuthenticatedSecurityError, BEARER, LIKELY_JWT,
    load_configuration as load_auth_configuration,
)
from vibesec.installation import InstallationError, verify_installation  # noqa: E402
from vibesec.github_actions import KNOWN_NODE20_PINS, MAX_AUDIT_FILE_BYTES  # noqa: E402
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
    markers = {"codeql", "semgrep", "snyk", "dependabot", "renovate", "trivy", "gitleaks", "checkov", "schemathesis", "dredd"}
    found: set[str] = set()
    if workflow_root.is_dir() and not workflow_root.is_symlink():
        for path in workflow_root.glob("*.y*ml"):
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= 1_000_000:
                text = path.read_text(encoding="utf-8", errors="replace").casefold()
                found.update(marker for marker in markers if marker in text and "vibesec" not in path.name.casefold())
    return sorted(found)


def _known_node20_workflows(root: Path) -> list[str]:
    workflow_root = root / ".github/workflows"
    found: list[str] = []
    if not workflow_root.is_dir() or workflow_root.is_symlink():
        return found
    for path in sorted(workflow_root.glob("*.y*ml")):
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_AUDIT_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        labels = sorted({label for commit, label in KNOWN_NODE20_PINS.items() if commit in text})
        if labels:
            found.append(f"{path.name}: {', '.join(labels)}")
    return found


def _auth_workflow_problems(text: str, *, secret_name: str | None, enabled: bool) -> list[str]:
    problems: list[str] = []
    lowered = text.casefold()
    secret_references = re.findall(r"\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}", text)
    if "${{ secrets[" in lowered or "${{ fromjson" in lowered:
        problems.append("unsafe dynamic secret expression")
    if any(marker in lowered for marker in ("pull_request:", "pull_request_target:", "push:", "workflow_call:")):
        problems.append("untrusted workflow trigger")
    if "authorization: bearer" in lowered:
        problems.append("literal Authorization bearer value")
    if "schemathesis.ndjson\n" in lowered or "zap-report.json\n" in lowered or "results/raw" in lowered:
        problems.append("raw scanner report upload")
    if enabled:
        if secret_name is None or secret_references != [secret_name]:
            problems.append("missing, duplicate, or incorrect static secret reference")
        expected = f"{AUTH_ENVIRONMENT_VARIABLE}: ${{{{ secrets.{secret_name} }}}}" if secret_name else ""
        if expected and expected not in text:
            problems.append("secret is not assigned to the reviewed scanner variable")
        if secret_references:
            lines = text.splitlines()
            scanner_step_names = {
                "Run isolated passive baseline",
                "Run isolated contract-driven API baseline",
            }
            secret_lines = {index for index, line in enumerate(lines) if "secrets." in line}
            allowed_lines: set[int] = set()
            for index, line in enumerate(lines):
                match = re.match(r"^(\s*)-\s+name:\s*(.*?)\s*$", line)
                if match is None or match.group(2) not in scanner_step_names:
                    continue
                indentation = len(match.group(1))
                end = len(lines)
                for candidate in range(index + 1, len(lines)):
                    if re.match(rf"^\s{{{indentation}}}-\s+name:\s*", lines[candidate]):
                        end = candidate
                        break
                allowed_lines.update(range(index, end))
            if not secret_lines or not secret_lines <= allowed_lines:
                problems.append("secret reference exists outside the reviewed scanner step")
    elif secret_references or AUTH_ENVIRONMENT_VARIABLE in text:
        problems.append("authenticated workflow material exists while capability is false")
    return sorted(set(problems))


def run_doctor(target: Path, requested_profile: str | None) -> tuple[str, list[dict[str, str]], dict[str, Any]]:
    state = verify_installation(target)
    diagnostics: list[dict[str, str]] = []
    project_capabilities = None
    applicability: dict[str, dict[str, str]] = {}
    try:
        project_capabilities = load_capabilities_file(state.target / ".vibesec/project-capabilities.json")
        applicability = scanner_applicability(project_capabilities)
    except CapabilityError as exc:
        diagnostics.append(diagnostic("capabilities", "CAPABILITY_MANIFEST_INVALID", "error", str(exc),
                                      "Create or repair the strict project capability manifest.", "docs/configuration.md"))
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
    old_action_pins = _known_node20_workflows(state.target)
    if old_action_pins:
        diagnostics.append(diagnostic(
            "github_actions", "GITHUB_ACTION_NODE20_PIN", "error",
            "Known Node 20 action pins remain in installed workflows: " + "; ".join(old_action_pins),
            "Generate a read-only upgrade plan and migrate to the approved Node 24 pins.",
            "docs/upgrading.md",
        ))
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
    base_profiles = [item for item in profiles if item in {"minimal", "standard"}]
    profile = requested_profile or (base_profiles[0] if len(base_profiles) == 1 else None)
    if requested_profile and base_profiles and requested_profile not in base_profiles:
        diagnostics.append(diagnostic("profile", "PROFILE_MISMATCH", "error", "Requested profile differs from installed manifests.",
                                      "Select the installed profile or repair the manifest conflict.", "docs/installation-verification.md"))
    stages = {manifest["stage"] for manifest in state.manifests}
    if project_capabilities is not None:
        dast_enabled = project_capabilities["capabilities"]["dast_target"]
        dast_installed = "dast-baseline" in profiles
        if dast_installed and not dast_enabled:
            diagnostics.append(diagnostic("dast", "DAST_INSTALLED_NOT_APPLICABLE", "error",
                                          "DAST is installed while dast_target=false.",
                                          "Remove the add-on or explicitly review and enable the capability.", "docs/dast-baseline.md"))
        if dast_enabled and not dast_installed:
            diagnostics.append(diagnostic("dast", "DAST_SUPPORT_MISSING", "error",
                                          "dast_target=true but DAST support is not installed.",
                                          "Install the DAST add-on after reviewing its trust boundary.", "docs/dast-baseline.md"))
        if not dast_enabled:
            diagnostics.append(diagnostic("dast", "DAST_NOT_APPLICABLE", "not_applicable",
                                          "Project capability manifest declares no runnable web application target.",
                                          "No action unless the project later gains an eligible runtime target.", "docs/dast-baseline.md"))
        api_enabled = project_capabilities["capabilities"]["api_security_target"]
        api_installed = "api-security-baseline" in profiles
        if api_installed and not api_enabled:
            diagnostics.append(diagnostic("api_security", "API_SECURITY_INSTALLED_NOT_APPLICABLE", "error",
                                          "API Security Baseline is installed while api_security_target=false.",
                                          "Remove the add-on or explicitly review and enable the capability.", "docs/api-security-baseline.md"))
        if api_enabled and not api_installed:
            diagnostics.append(diagnostic("api_security", "API_SECURITY_SUPPORT_MISSING", "error",
                                          "api_security_target=true but API Security Baseline is not installed.",
                                          "Install the add-on after reviewing its active-request boundary.", "docs/api-security-baseline.md"))
        if not api_enabled:
            diagnostics.append(diagnostic("api_security", "API_SECURITY_NOT_APPLICABLE", "not_applicable",
                                          "Project capability manifest declares no runnable OpenAPI API target.",
                                          "No action unless the project later gains an eligible API target.", "docs/api-security-baseline.md"))
        auth_enabled = project_capabilities["capabilities"]["authenticated_security_testing"]
        auth_config = None
        try:
            auth_config = load_auth_configuration(state.target)
        except AuthenticatedSecurityError:
            if auth_enabled:
                diagnostics.append(diagnostic("authenticated_testing", "AUTH_CONFIG_INVALID", "error",
                                              "Authenticated testing is enabled but its bearer secret-name configuration is missing or invalid.",
                                              "Restore the generated bearer-only configuration; never store the secret value.",
                                              "docs/authenticated-security-testing.md"))
        if not auth_enabled:
            diagnostics.append(diagnostic("authenticated_testing", "AUTHENTICATED_TESTING_NOT_APPLICABLE", "not_applicable",
                                          "Project capability manifest excludes authenticated runtime security testing.",
                                          "No action unless the project later gains an eligible authenticated target.",
                                          "docs/authenticated-security-testing.md"))
        for workflow_name in ("vibesec-dast-baseline.yml", "vibesec-api-security-baseline.yml"):
            workflow = state.target / ".github/workflows" / workflow_name
            if not workflow.is_file() or workflow.is_symlink():
                continue
            text = workflow.read_text(encoding="utf-8", errors="replace")
            problems = _auth_workflow_problems(text, secret_name=auth_config["secret_name"] if auth_config else None,
                                               enabled=auth_enabled)
            if problems:
                diagnostics.append(diagnostic("authenticated_testing", "AUTH_WORKFLOW_UNSAFE", "error",
                                              f"{workflow_name} violates authenticated secret handling: " + "; ".join(problems) + ".",
                                              "Restore the atomically generated workflow and keep the secret on the exact scanner step.",
                                              "docs/authenticated-security-threat-model.md"))
        generated = [state.target / ".vibesec/project-capabilities.json",
                     state.target / ".vibesec/authenticated-security-testing.json"]
        for path in generated:
            if path.is_file() and not path.is_symlink():
                data = path.read_bytes()
                if BEARER.search(data) or LIKELY_JWT.search(data):
                    diagnostics.append(diagnostic("authenticated_testing", "AUTH_LITERAL_SECRET_DETECTED", "error",
                                                  "Generated authenticated configuration contains credential-like material; value redacted.",
                                                  "Remove the literal immediately and retain only the GitHub secret name.",
                                                  "docs/authenticated-security-threat-model.md"))
    if any("project-capabilities.json" in message for message in state.warnings):
        diagnostics.append(diagnostic("capabilities", "CAPABILITY_MANIFEST_CHANGED", "warning",
                                      "The project capability manifest changed after installation.",
                                      "Validate the answers and review scanner applicability before accepting the change.", "docs/installation-verification.md"))
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
        "VIBESEC_DAST_ENFORCEMENT": {"observe", "new", "all"},
        "VIBESEC_DAST_MIN_SEVERITY": {"low", "medium", "high", "critical"},
        "VIBESEC_API_ENFORCEMENT": {"observe", "new", "all"},
        "VIBESEC_API_MIN_SEVERITY": {"low", "medium", "high", "critical"},
        "VIBESEC_API_SAFE_METHODS_ONLY": {"true", "false"},
        "VIBESEC_AUTH_MODE": {"none", "bearer"},
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
    if "dast-baseline" in profiles:
        dast_image = os.getenv("VIBESEC_DAST_IMAGE_REFERENCE", "")
        if dast_image and not IMAGE.fullmatch(dast_image):
            diagnostics.append(diagnostic("dast", "DAST_IMAGE_REFERENCE_INVALID", "error", "DAST image reference is mutable or malformed; value redacted.",
                                          "Use an immutable registry/name@sha256 digest.", "docs/dast-baseline.md"))
        port = os.getenv("VIBESEC_DAST_CONTAINER_PORT", "8080")
        if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
            diagnostics.append(diagnostic("dast", "DAST_PORT_INVALID", "error", "DAST container port is invalid; value redacted.",
                                          "Use an integer from 1 through 65535.", "docs/configuration.md"))
        path = os.getenv("VIBESEC_DAST_BASE_PATH", "/")
        if not path.startswith("/") or any(marker in path for marker in ("..", "\\", "?", "#")):
            diagnostics.append(diagnostic("dast", "DAST_BASE_PATH_INVALID", "error", "DAST base path is invalid; value redacted.",
                                          "Use a bounded absolute path without traversal, query, or fragment.", "docs/configuration.md"))
        if shutil.which("docker") is None:
            diagnostics.append(diagnostic("dast", "DAST_DOCKER_UNAVAILABLE", "warning", "Docker is unavailable for the installed DAST Baseline add-on.",
                                          "Run the add-on only on a disposable trusted runner with Docker.", "docs/dast-baseline.md"))
    if "api-security-baseline" in profiles:
        api_image = ""
        target_config = state.target / ".vibesec/api-security-baseline.json"
        try:
            payload = loads_strict(target_config.read_bytes())
            required = {"schema_version", "schema_path", "image_variable_name", "container_port", "base_path",
                        "safe_methods_only", "authentication", "custom_headers", "external_target_url"}
            if not isinstance(payload, dict) or set(payload) != required or payload.get("schema_version") != 1:
                raise ValueError("unsupported fields")
            if payload.get("authentication") is not False or payload.get("custom_headers") is not False or payload.get("external_target_url") is not None:
                diagnostics.append(diagnostic("api_security", "API_UNSUPPORTED_AUTH_OR_TARGET", "error",
                                              "API configuration requests authentication, custom headers, or an external target.",
                                              "Remove unsupported active-test configuration.", "docs/api-security-baseline.md"))
            image_variable = payload.get("image_variable_name")
            if isinstance(image_variable, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", image_variable):
                api_image = os.getenv(image_variable, "")
            if not api_image:
                diagnostics.append(diagnostic("api_security", "API_IMAGE_NOT_CONFIGURED", "informational",
                                              "The configured immutable API image variable is absent; value and variable name redacted.",
                                              "Set the reviewed repository variable before a trusted manual or scheduled run.", "docs/api-security-baseline.md"))
            elif not IMAGE.fullmatch(api_image):
                diagnostics.append(diagnostic("api_security", "API_IMAGE_REFERENCE_INVALID", "error",
                                              "API target image is mutable or malformed; value redacted.",
                                              "Use an immutable registry/name@sha256 digest.", "docs/api-security-baseline.md"))
            schema_value = payload.get("schema_path")
            if not isinstance(schema_value, str) or not schema_value or schema_value.startswith(("http://", "https://", "file://", "/")) or ".." in Path(schema_value).parts:
                diagnostics.append(diagnostic("api_security", "API_SCHEMA_PATH_INVALID", "error", "API schema path is remote or unsafe; value redacted.",
                                              "Use a repository-relative local OpenAPI JSON or YAML file.", "docs/api-security-baseline.md"))
            else:
                schema_path = state.target / schema_value
                if schema_path.is_symlink() or not schema_path.is_file():
                    diagnostics.append(diagnostic("api_security", "API_SCHEMA_MISSING", "error", "Configured local OpenAPI schema is missing or unsafe.",
                                                  "Restore the regular repository schema file.", "docs/api-security-baseline.md"))
                else:
                    try:
                        from vibesec.api_security import load_config as load_api_config, validate_openapi_schema
                        validate_openapi_schema(state.target, schema_value, config=load_api_config(ROOT),
                                                port=payload.get("container_port"), base_path=payload.get("base_path"))
                    except (ImportError, OSError, ValueError) as exc:
                        diagnostics.append(diagnostic("api_security", "API_SCHEMA_INVALID", "error",
                                                      "The configured OpenAPI schema violates a reviewed structural or trust-boundary rule; details redacted.",
                                                      "Review local references, servers, unsupported constructs, and schema bounds.", "docs/api-security-baseline.md"))
        except (OSError, StrictJSONError, ValueError):
            diagnostics.append(diagnostic("api_security", "API_TARGET_CONFIG_INVALID", "error", "Installed API target configuration is missing or malformed.",
                                          "Reinstall the add-on from a verified bundle without overwriting conflicts.", "docs/api-security-baseline.md"))
        workflow = state.target / ".github/workflows/vibesec-api-security-baseline.yml"
        if workflow.is_file() and not workflow.is_symlink():
            text = workflow.read_text(encoding="utf-8", errors="replace").casefold()
            unsafe = any(marker in text for marker in ("pull_request:", "pull_request_target:", "push:", "--network host", "--publish", "raw.ndjson", "schemathesis.ndjson\n"))
            if unsafe:
                diagnostics.append(diagnostic("api_security", "API_WORKFLOW_TRUST_BOUNDARY_INVALID", "error",
                                              "Installed API workflow contains an unsafe trigger, network option, authentication, or raw upload marker.",
                                              "Restore the reviewed manual/scheduled sanitized workflow.", "docs/api-security-threat-model.md"))
        docker = shutil.which("docker")
        if docker is None:
            diagnostics.append(diagnostic("api_security", "API_DOCKER_UNAVAILABLE", "warning", "Docker is unavailable for the installed API Security Baseline.",
                                          "Run only on a disposable trusted runner with Docker.", "docs/api-security-baseline.md"))
        elif api_image and IMAGE.fullmatch(api_image):
            inspected = subprocess.run(
                [docker, "image", "inspect", "--format", "{{json .Config.User}}", api_image],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, timeout=30, check=False,
            )
            if inspected.returncode != 0:
                diagnostics.append(diagnostic("api_security", "API_TARGET_USER_NOT_LOCALLY_VERIFIED", "informational",
                                              "The immutable target image is not locally available, so its declared user was not inspected.",
                                              "The runtime will pull and reject root or unspecified users before starting the target.", "docs/api-security-baseline.md"))
            else:
                try:
                    declared_user = json.loads(inspected.stdout.strip())
                except json.JSONDecodeError:
                    declared_user = None
                principal = declared_user.split(":", 1)[0].casefold() if isinstance(declared_user, str) else ""
                if not declared_user or principal in {"root", "0"}:
                    diagnostics.append(diagnostic("api_security", "API_TARGET_USER_UNSAFE", "error",
                                                  "The locally available target image declares a root or unspecified user.",
                                                  "Publish an immutable target image with an explicit non-root user.", "docs/api-security-baseline.md"))
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
    return status, diagnostics, {"profile": profile, "stage": sorted({manifest["stage"] for manifest in state.manifests}),
                                 "installation_status": state.status, "scanner_applicability": applicability}


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
