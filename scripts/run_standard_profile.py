#!/usr/bin/env python3
"""Run Standard scanners from a trusted VibeSec harness against an untrusted tree."""

from __future__ import annotations

import argparse
from datetime import date
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
from typing import Any

SCRIPT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_ROOT))
from vibesec.coverage import markdown as coverage_markdown, validate_coverage  # noqa: E402
from vibesec.capabilities import CapabilityError, all_capabilities, load_capabilities_file  # noqa: E402
from vibesec.detection import (  # noqa: E402
    IMAGE_DIGEST, DetectionError, ImageStateError, derive_image_expectation, inventory,
)
from vibesec.model import Finding  # noqa: E402
from vibesec.finding_intelligence import FindingIntelligenceError, SourceDocument, build as build_finding_intelligence  # noqa: E402
from vibesec.normalize import normalize_file  # noqa: E402
from vibesec.policy import active_suppressions  # noqa: E402
from vibesec.osv_database import validate_offline_database  # noqa: E402
from vibesec.sbom import sanitize_repository_paths, validate_cyclonedx, validate_spdx  # noqa: E402

ACTIONLINT_JSON_FORMAT = "{{json .}}"
DIAGNOSTIC_DOCS = "docs/self-hosted-validation.md"
CHECKOV_CONTAINER_CONFIG = "/vibesec/checkov-standard.yaml"
KNOWN_OUTPUTS = (
    "normalized.json", "coverage.json", "inventory.json", "report.md", "policy-result.json",
    "finding-groups.json", "prioritized-findings.json",
    "sbom.cyclonedx.json", "sbom.spdx.json",
    "raw/opengrep.json", "raw/osv.json", "raw/checkov.json", "raw/trivy.json",
    "raw/gitleaks.json", "raw/actionlint.txt", "raw/trivy-image.json",
)


def atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def command(binary: Path | str, *arguments: str | Path) -> list[str]:
    return [str(binary), *map(str, arguments)]


def checkov_command(root: Path, config: Path, image: str, relative_file: str,
                    *extra_arguments: str) -> list[str]:
    """Build an isolated pinned Checkov command for exactly one repository file."""
    return command(
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m", "--workdir", "/tmp",
        "--env", "HOME=/tmp/vibesec-home", "--env", "XDG_CACHE_HOME=/tmp/vibesec-cache",
        "--volume", f"{root}:/workspace:ro", "--volume", f"{config}:{CHECKOV_CONTAINER_CONFIG}:ro",
        image, "--config-file", CHECKOV_CONTAINER_CONFIG, "--file", f"/workspace/{relative_file}",
        "--output", "json", "--compact", "--quiet", "--download-external-modules", "false",
        *extra_arguments,
    )


def diagnostic(component: str, category: str, reason: str, artifact: str | None = None) -> None:
    """Emit one bounded diagnostic containing only harness-controlled text."""
    fields = [
        f"component={component}", f"category={category}",
        f"reason={' '.join(reason.split())[:240]}",
    ]
    if artifact:
        fields.append(f"artifact={artifact}")
    fields.append(f"docs={DIAGNOSTIC_DOCS}")
    print(" ".join(fields), file=sys.stderr)


def run(scanner: str, argv: list[str], raw_path: Path | None, *, cwd: Path,
        env: dict[str, str], stdout_output: bool = False) -> str | None:
    if raw_path is not None:
        try:
            raw_path.unlink(missing_ok=True)
        except OSError as exc:
            return f"{scanner} could not clear its output: {type(exc).__name__}"
    try:
        if stdout_output and raw_path is not None:
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            with raw_path.open("xb") as stdout_stream:
                completed = subprocess.run(
                    argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                    stdout=stdout_stream, stderr=subprocess.DEVNULL, timeout=900, check=False,
                )
        else:
            completed = subprocess.run(
                argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900, check=False,
            )
    except FileNotFoundError:
        if scanner == "checkov":
            return "Docker is unavailable"
        return f"{scanner} executable is unavailable"
    except subprocess.TimeoutExpired:
        return f"{scanner} timed out"
    except OSError as exc:
        return f"{scanner} could not complete: {type(exc).__name__}"
    accepted = {0, 1} if scanner in {"gitleaks", "actionlint", "checkov", "osv-scanner"} else {0}
    if completed.returncode not in accepted:
        if scanner == "checkov" and completed.returncode == 2:
            return "Checkov CLI or image execution exited with status 2"
        return f"{scanner} exited with status {completed.returncode}"
    if raw_path is not None and (not raw_path.is_file() or raw_path.is_symlink()):
        return f"{scanner} did not produce a regular expected output"
    return None


def validate_checkov_relative_file(root: Path, relative_file: str) -> tuple[str, Path]:
    """Validate one trusted inventory path and resolve its exact regular file."""
    try:
        relative_file.encode("utf-8")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise ValueError("Checkov input path must be a UTF-8 string") from exc
    if (not relative_file or "\\" in relative_file
            or any(ord(character) < 32 or ord(character) == 127 for character in relative_file)
            or re.match(r"^/?[A-Za-z]:", relative_file)):
        raise ValueError("Checkov input path is not a canonical repository-relative path")
    pure = PurePosixPath(relative_file)
    if pure.is_absolute() or ".." in pure.parts or pure.as_posix() != relative_file:
        raise ValueError("Checkov input path is not a canonical repository-relative path")
    try:
        resolved_root = root.resolve(strict=True)
        candidate = resolved_root.joinpath(*pure.parts)
        if candidate.is_symlink():
            raise ValueError("Checkov input path must not be a symlink")
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise ValueError("Checkov input path does not resolve beneath the scan root") from exc
    if not resolved.is_file():
        raise ValueError("Checkov input path must identify a regular file")
    return relative_file, resolved


def _checkov_reported_paths(path: Path) -> list[tuple[str | None, str | None]]:
    """Extract only scanner path claims after the main normalizer validates the report."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Checkov path metadata is malformed") from exc
    documents = payload if isinstance(payload, list) else [payload]
    reported: list[tuple[str | None, str | None]] = []
    for document in documents:
        if not isinstance(document, dict) or not isinstance(document.get("results"), dict):
            raise ValueError("Checkov path metadata is malformed")
        failed_checks = document["results"].get("failed_checks", [])
        if not isinstance(failed_checks, list):
            raise ValueError("Checkov path metadata is malformed")
        for item in failed_checks:
            if not isinstance(item, dict):
                raise ValueError("Checkov path metadata is malformed")
            file_path = item.get("file_path")
            absolute_path = item.get("file_abs_path")
            if file_path is not None and not isinstance(file_path, str):
                raise ValueError("Checkov file_path must be a string")
            if absolute_path is not None and not isinstance(absolute_path, str):
                raise ValueError("Checkov file_abs_path must be a string")
            reported.append((file_path or None, absolute_path or None))
    return reported


def _validate_scanner_path(value: str) -> None:
    if ("\\" in value or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or re.match(r"^/?[A-Za-z]:", value)):
        raise ValueError("Checkov reported a non-canonical path")
    pure = PurePosixPath(value)
    if ".." in pure.parts or pure.as_posix() != value:
        raise ValueError("Checkov reported a non-canonical path")


def canonicalize_checkov_findings(relative_file: str, resolved_file: Path,
                                  findings: list[Finding], raw_path: Path) -> list[Finding]:
    """Verify scanner path claims and replace them with the trusted invocation path."""
    reported = _checkov_reported_paths(raw_path)
    if len(reported) != len(findings):
        raise ValueError("Checkov finding and path counts differ")
    full_equivalents = {
        relative_file,
        f"/{relative_file}",
        f"/workspace/{relative_file}",
        resolved_file.as_posix(),
    }
    basename_equivalents = {PurePosixPath(relative_file).name, f"/{PurePosixPath(relative_file).name}"}
    canonical: list[Finding] = []
    for finding, (file_path, absolute_path) in zip(findings, reported, strict=True):
        if not file_path and not absolute_path:
            raise ValueError("Checkov finding omitted its path")
        if file_path:
            _validate_scanner_path(file_path)
        if absolute_path:
            _validate_scanner_path(absolute_path)
        absolute_matches = absolute_path in full_equivalents if absolute_path else False
        if absolute_path and not absolute_matches:
            raise ValueError("Checkov reported a path for a different file")
        if file_path and file_path not in full_equivalents:
            if file_path not in basename_equivalents or not absolute_matches:
                raise ValueError("Checkov reported a path for a different file")
        canonical.append(Finding.create(
            tool=finding.tool, category=finding.category, rule_id=finding.rule_id,
            severity=finding.severity, file=relative_file, line=finding.line,
            description=finding.description, confidence=finding.confidence,
            result_type=finding.result_type,
        ))
    return canonical


def checkov_file_failure(relative_file: str, reason: str) -> str:
    """Create a bounded diagnostic from an already validated trusted path."""
    return f"file={relative_file[:180]} {' '.join(reason.split())}"[:240]


def run_checkov_files(root: Path, config: Path, image: str, files: list[str],
                      raw_path: Path, *, cwd: Path, env: dict[str, str],
                      extra_arguments: tuple[str, ...] = ()) -> tuple[list[Finding], str | None, bool]:
    """Scan deterministic files independently and publish one validated canonical result.

    The final boolean distinguishes malformed scanner output (invalid input) from
    an execution failure (tool error). No partial result is published on either.
    """
    try:
        raw_path.unlink(missing_ok=True)
        raw_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return [], f"checkov could not clear its output: {type(exc).__name__}", False

    findings: list[Finding] = []
    if not all(isinstance(item, str) for item in files):
        return [], "checkov invocation path failed validation", True
    ordered_files = sorted(set(files))
    try:
        with tempfile.TemporaryDirectory(prefix=".checkov-", dir=raw_path.parent) as temporary:
            temporary_root = Path(temporary)
            for index, relative_file in enumerate(ordered_files):
                try:
                    relative_file, resolved_file = validate_checkov_relative_file(root, relative_file)
                except ValueError:
                    return [], "checkov invocation path failed validation", True
                output = temporary_root / f"{index:06d}.json"
                error = run(
                    "checkov",
                    checkov_command(root, config, image, relative_file, *extra_arguments),
                    output, cwd=cwd, env=env, stdout_output=True,
                )
                if error:
                    return [], checkov_file_failure(relative_file, error), False
                try:
                    per_file_findings = normalize_file("checkov", output)
                    findings.extend(canonicalize_checkov_findings(
                        relative_file, resolved_file, per_file_findings, output,
                    ))
                except ValueError:
                    return [], checkov_file_failure(
                        relative_file, "checkov output failed structural validation",
                    ), True
    except OSError as exc:
        return [], f"checkov could not manage private output: {type(exc).__name__}", False

    unique = {finding.fingerprint: finding for finding in findings}
    ordered_findings = sorted(
        unique.values(),
        key=lambda item: (item.file, item.line or 0, item.rule_id, item.fingerprint),
    )
    failed_checks: list[dict[str, Any]] = []
    for finding in ordered_findings:
        item: dict[str, Any] = {
            "check_id": finding.rule_id,
            "check_name": finding.description,
            "file_path": finding.file,
            "severity": finding.severity,
        }
        if finding.line is not None:
            item["file_line_range"] = [finding.line, finding.line]
        failed_checks.append(item)
    try:
        atomic_json(raw_path, {"results": {"failed_checks": failed_checks}})
        canonical = normalize_file("checkov", raw_path)
    except (OSError, ValueError):
        raw_path.unlink(missing_ok=True)
        return [], "checkov aggregate failed structural validation", True
    return canonical, None, False


def tool_error(tool: str, message: str) -> dict[str, Any]:
    return Finding.create(
        tool=tool, category="execution", rule_id="tool-error", severity="low",
        description=message, confidence="confirmed", result_type="tool_error",
    ).to_dict()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path("."), help="untrusted repository to scan")
    parser.add_argument("results", nargs="?", type=Path, default=Path("results"))
    parser.add_argument("--vibesec-root", type=Path, default=SCRIPT_ROOT.parent, help="trusted VibeSec harness root")
    parser.add_argument("--tool-dir", type=Path)
    parser.add_argument("--network-mode", choices=("online", "offline"), default=os.getenv("VIBESEC_NETWORK_MODE", "online"))
    parser.add_argument("--minimum-severity", choices=("low", "medium", "high", "critical"), default=os.getenv("VIBESEC_MIN_SEVERITY", "high"))
    parser.add_argument("--enforcement", choices=("observe", "new", "all"), default=os.getenv("VIBESEC_ENFORCEMENT", "observe"))
    parser.add_argument("--image-reference", default=os.getenv("VIBESEC_IMAGE_REFERENCE", ""))
    parser.add_argument("--capabilities-file", type=Path, help="strict project capability manifest")
    args = parser.parse_args()
    root = args.root.resolve()
    results = args.results.resolve()
    vibesec_root = args.vibesec_root.resolve()
    tools = (args.tool_dir or vibesec_root / ".tools/bin").resolve()
    if not root.is_dir() or not vibesec_root.is_dir() or (args.image_reference and not IMAGE_DIGEST.fullmatch(args.image_reference)):
        print("invalid repository, trusted harness, or image reference; images require an immutable sha256 digest", file=sys.stderr)
        return 3
    capability_path = args.capabilities_file or (root / ".vibesec/project-capabilities.json")
    try:
        project_capabilities = (load_capabilities_file(capability_path)
                                if capability_path.exists() or capability_path.is_symlink()
                                else all_capabilities())
    except CapabilityError as exc:
        print(f"invalid project capability manifest: {exc}", file=sys.stderr)
        return 3
    declared = project_capabilities["capabilities"]
    try:
        tool_manifest = json.loads((vibesec_root / "config/tools.json").read_text(encoding="utf-8"))
        if not isinstance(tool_manifest, dict):
            raise ValueError("tool manifest must be an object")
        for required_tool in ("opengrep", "osv-scanner", "syft", "checkov", "trivy", "gitleaks", "actionlint"):
            if not isinstance(tool_manifest.get(required_tool), dict) or not isinstance(tool_manifest[required_tool].get("version"), str):
                raise ValueError(f"tool manifest is missing {required_tool} version metadata")
        checkov_manifest = tool_manifest["checkov"]
        if not isinstance(checkov_manifest.get("image"), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(checkov_manifest.get("digest", ""))):
            raise ValueError("Checkov must use an immutable SHA-256 image digest")
        checkov_config = vibesec_root / "config/checkov-standard.yaml"
        if checkov_config.is_symlink() or checkov_config.read_bytes() != b"{}\n":
            raise ValueError("trusted Checkov configuration must be the reviewed empty mapping")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"invalid tool manifest: {exc}", file=sys.stderr)
        return 3

    osv_database: dict[str, object] | None = None
    if args.network_mode == "offline":
        try:
            maximum_age = int(os.getenv("VIBESEC_OSV_MAX_DATABASE_AGE_DAYS", "7"))
            osv_database = validate_offline_database(
                Path(os.environ["VIBESEC_OSV_DATABASE_DIR"]),
                os.environ["VIBESEC_OSV_DATABASE_DATE"], maximum_age,
            )
        except (KeyError, ValueError) as exc:
            print(f"offline mode configuration error: {exc}", file=sys.stderr)
            return 3

    results.mkdir(parents=True, exist_ok=True)
    raw = results / "raw"
    raw.mkdir(exist_ok=True)
    for relative in KNOWN_OUTPUTS:
        try:
            (results / relative).unlink(missing_ok=True)
        except OSError as exc:
            print(f"could not clear stale output {relative}: {exc}", file=sys.stderr)
            return 3
    try:
        repo_inventory = inventory(root)
    except DetectionError as exc:
        print(f"repository detection failed closed: {exc}", file=sys.stderr)
        return 3
    atomic_json(results / "inventory.json", repo_inventory)

    coverage: list[dict[str, Any]] = []
    normalized: list[dict[str, Any]] = []
    input_failure = False
    environment = {key: value for key, value in os.environ.items() if not key.startswith(
        ("SYFT_", "OPENGREP_", "SEMGREP_", "OSV_SCANNER_", "GITLEAKS_", "TRIVY_", "CHECKOV_"))}
    scanner_home = results / ".scanner-home"
    scanner_home.mkdir(exist_ok=True)
    environment.update({
        "HOME": str(scanner_home),
        "SYFT_CHECK_FOR_APP_UPDATE": "false", "SYFT_ENRICH": "",
        "SYFT_JAVA_USE_NETWORK": "false", "SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES": "false",
        "SYFT_PYTHON_SEARCH_REMOTE_LICENSES": "false", "OPENGREP_ENABLE_VERSION_CHECK": "0",
        "SEMGREP_SEND_METRICS": "off", "TRIVY_DISABLE_TELEMETRY": "true",
        "XDG_CACHE_HOME": str(results / ".cache"),
    })
    if osv_database:
        environment["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = str(osv_database["path"])

    def record(tool: str, scope: str, state: str, reason: str, artifacts: list[str],
               outputs: list[str], network: str) -> None:
        manifest_name = "trivy" if tool == "trivy-image" else tool
        coverage.append({
            "tool": tool, "version": str(tool_manifest[manifest_name]["version"]),
            "scope": scope, "state": state, "reason": reason,
            "relevant_artifacts": sorted(artifacts), "output_files": outputs,
            "network_access": network, "application_code_executed": False,
        })

    def execute(tool: str, scope: str, argv: list[str], output: Path, *, artifacts: list[str],
                normalizer: str | None = None, stdout: bool = False, network: str = "none",
                reason: str = "configured scanner completed") -> None:
        nonlocal input_failure
        output_rel = output.relative_to(results).as_posix()
        error = run(tool, argv, output, cwd=root, env=environment, stdout_output=stdout)
        if error:
            diagnostic(tool, "tool_error", error, output_rel)
            normalized.append(tool_error(tool, error))
            record(tool, scope, "tool_error", error, artifacts, [], network)
            return
        try:
            if normalizer:
                normalized.extend(item.to_dict() for item in normalize_file(normalizer, output))
        except ValueError:
            input_failure = True
            message = f"{tool} output failed structural validation"
            diagnostic(tool, "invalid_input", message, output_rel)
            normalized.append(tool_error(tool, message))
            record(tool, scope, "tool_error", message, artifacts, [output_rel], network)
            return
        record(tool, scope, "ran", reason, artifacts, [output_rel], network)

    source_files = repo_inventory["source_files"]
    opengrep_output = raw / "opengrep.json"
    if source_files:
        execute("opengrep", "supported first-party source", command(
            tools / "opengrep", "scan", "--legacy", "--config", vibesec_root / "rules/opengrep",
            "--x-ignore-semgrepignore-files",
            "--no-git-ignore", "--json-output", opengrep_output, "--disable-version-check", "."),
            opengrep_output, artifacts=source_files, normalizer="opengrep")
    else:
        record("opengrep", "supported first-party source", "not_applicable", "no supported language files detected", [], [], "none")

    osv_output = raw / "osv.json"
    manifests = repo_inventory["manifests"]
    if manifests:
        osv_args: list[str | Path] = [
            "scan", "source", "--config", "/dev/null", "--recursive", "--format", "json",
            "--output-file", osv_output, "--allow-no-lockfiles", "--no-call-analysis=go",
            "--no-call-analysis=rust", "--no-resolve",
        ]
        if osv_database:
            osv_args += ["--offline", "--offline-vulnerabilities", "--local-db-path", str(osv_database["path"])]
        osv_args.append(".")
        if osv_database:
            reason = f"offline database scan completed; database age {osv_database['age_days']} days across {len(osv_database['ecosystems'])} ecosystems"
            network = "local_database"
        else:
            reason = "online lookup completed; package metadata and file hashes may have been sent to OSV.dev or deps.dev"
            network = "advisory_queries"
        execute("osv-scanner", "source dependencies", command(tools / "osv-scanner", *osv_args),
                osv_output, artifacts=manifests, normalizer="osv-scanner", network=network, reason=reason)
    else:
        record("osv-scanner", "source dependencies", "not_applicable", "no supported manifests detected", [], [], "none")

    cyclonedx = results / "sbom.cyclonedx.json"
    spdx = results / "sbom.spdx.json"
    sbom_formats: list[str] = []
    if manifests:
        sbom_input_failure = False
        error = run("syft", command(
            tools / "syft", "dir:.", "--config", vibesec_root / "config/syft-standard.yaml",
            "--base-path", ".", "--output", f"cyclonedx-json={cyclonedx}",
            "--output", f"spdx-json={spdx}", "--quiet"), None, cwd=root, env=environment)
        if not error:
            try:
                sanitize_repository_paths(cyclonedx, root)
                sanitize_repository_paths(spdx, root)
                cdx_payload = validate_cyclonedx(cyclonedx)
                spdx_payload = validate_spdx(spdx)
                sbom_formats = [f"CycloneDX {cdx_payload['specVersion']}", str(spdx_payload["spdxVersion"])]
            except ValueError:
                input_failure = True
                sbom_input_failure = True
                error = "Syft SBOM failed structural validation"
        if error:
            diagnostic("syft", "invalid_input" if sbom_input_failure else "tool_error", error, "sbom.cyclonedx.json,sbom.spdx.json")
            cyclonedx.unlink(missing_ok=True)
            spdx.unlink(missing_ok=True)
            normalized.append(tool_error("syft", error))
            record("syft", "filesystem SBOM", "tool_error", error, manifests, [], "none")
        else:
            record("syft", "filesystem SBOM", "ran", "validated CycloneDX and SPDX generated without enrichment", manifests,
                   ["sbom.cyclonedx.json", "sbom.spdx.json"], "none")
    else:
        record("syft", "filesystem SBOM", "not_applicable", "no supported package manifests detected", [], [], "none")

    iac_files = sorted({path for values in repo_inventory["iac"].values() for path in values} | set(repo_inventory["dockerfiles"]) | set(repo_inventory["workflows"]))
    checkov_output = raw / "checkov.json"
    if not declared["infrastructure_as_code"]:
        record("checkov", "detected infrastructure as code", "not_applicable",
               "project capability manifest declares infrastructure_as_code=false", [], [], "none")
    elif iac_files:
        image = f'{checkov_manifest["image"]}@{checkov_manifest["digest"]}'
        checkov_findings, checkov_error, checkov_input_failure = run_checkov_files(
            root, checkov_config, image, iac_files, checkov_output,
            cwd=root, env=environment,
        )
        if checkov_error:
            input_failure = input_failure or checkov_input_failure
            category = "invalid_input" if checkov_input_failure else "tool_error"
            diagnostic("checkov", category, checkov_error, "raw/checkov.json")
            normalized.append(tool_error("checkov", checkov_error))
            record("checkov", "detected infrastructure as code", "tool_error", checkov_error,
                   iac_files, [], "none")
        else:
            normalized.extend(item.to_dict() for item in checkov_findings)
            record("checkov", "detected infrastructure as code", "ran",
                   "immutable Checkov container scanned each detected IaC file in an isolated runtime",
                   iac_files, ["raw/checkov.json"], "none")
    else:
        record("checkov", "detected infrastructure as code", "not_applicable", "no supported IaC files detected", [], [], "none")

    trivy_artifacts = sorted(set(repo_inventory["dockerfiles"] + repo_inventory["workflows"] + iac_files + source_files))
    trivy_output = raw / "trivy.json"
    execute("trivy", "secrets and configuration", command(
        tools / "trivy", "--config", vibesec_root / "config/trivy-standard.yaml", "filesystem",
        "--scanners", "misconfig,secret", "--skip-check-update", "--format", "json", "--output",
        trivy_output, "--exit-code", "0", "--no-progress", "."), trivy_output,
        artifacts=trivy_artifacts, normalizer="trivy")

    gitleaks_output = raw / "gitleaks.json"
    execute("gitleaks", "Git history secrets", command(
        tools / "gitleaks", "git", "--no-banner", "--redact", "--config", vibesec_root / "config/gitleaks-standard.toml",
        "--gitleaks-ignore-path", vibesec_root / "config/gitleaks-standard-ignore.txt", "--report-format", "json",
        "--report-path", gitleaks_output, "."), gitleaks_output, artifacts=[".git"], normalizer="gitleaks")

    actionlint_output = raw / "actionlint.txt"
    workflows = repo_inventory["workflows"]
    if not declared["github_actions"]:
        record("actionlint", "GitHub Actions", "not_applicable",
               "project capability manifest declares github_actions=false", [], [], "none")
    elif workflows:
        execute("actionlint", "GitHub Actions", command(
            tools / "actionlint", "-no-color", "-format", ACTIONLINT_JSON_FORMAT,
            "-config-file", vibesec_root / "config/actionlint-standard.yaml",
            "-shellcheck", "", "-pyflakes", "", *workflows), actionlint_output,
            artifacts=workflows, normalizer="actionlint", stdout=True)
    else:
        record("actionlint", "GitHub Actions", "not_applicable", "no workflow files detected", [], [], "none")

    github_event = os.getenv("GITHUB_EVENT_NAME", "")
    github_actions = os.getenv("GITHUB_ACTIONS", "").lower() == "true"
    if not declared["container_image"]:
        image_expectation = None
    else:
        try:
            image_expectation = derive_image_expectation(
                github_actions=github_actions,
                github_event=github_event,
                image_reference=args.image_reference,
                has_dockerfile=bool(repo_inventory["dockerfiles"]),
            )
        except ImageStateError as exc:
            print(f"invalid image coverage configuration: {exc}", file=sys.stderr)
            return 3
    if image_expectation is None:
        record("trivy-image", "prebuilt container image", "not_applicable",
               "project capability manifest declares container_image=false", [], [], "none")
    elif image_expectation.state != "ran":
        record("trivy-image", "prebuilt container image", image_expectation.state,
               image_expectation.reason, repo_inventory["dockerfiles"], [], "none")
    else:
        image_output = raw / "trivy-image.json"
        execute("trivy-image", "prebuilt container image", command(
            tools / "trivy", "--config", vibesec_root / "config/trivy-standard.yaml", "image",
            "--scanners", "vuln", "--format", "json", "--output", image_output,
            "--exit-code", "0", "--no-progress", args.image_reference), image_output,
            artifacts=[], normalizer="trivy-image", network="scanner_managed")

    normalized_payload = {"schema_version": 1, "profile": "standard", "results": normalized}
    coverage_payload: dict[str, Any] = {
        "schema_version": 1, "profile": "standard", "inventory": repo_inventory,
        "network_mode": args.network_mode, "osv_database": osv_database,
        "sbom_formats": sbom_formats, "tools": coverage,
        "limitations": [
            "Scanner findings can be false positives or false negatives; a completed scan is not proof of security.",
            "SBOM artifacts can expose internal package names and versions and should receive restricted retention.",
        ],
        "outside_coverage": [
            "Application builds, tests, lifecycle scripts, runtime behavior, business logic, authorization, and DAST are not executed or assessed.",
            "Unrecognized languages, package formats, IaC layouts, generated files, and skipped directories are outside deterministic routing.",
        ],
    }
    try:
        coverage_payload = validate_coverage(coverage_payload)
    except ValueError as exc:
        diagnostic("coverage", "invalid_input", f"coverage output failed validation: {exc}", "coverage.json")
        return 3
    try:
        baseline_payload = json.loads((vibesec_root / "policy/standard-baseline.json").read_text(encoding="utf-8"))
        suppression_payload = json.loads((vibesec_root / "policy/suppressions.yml").read_text(encoding="utf-8"))
        baseline_values = baseline_payload.get("fingerprints")
        if not isinstance(baseline_values, list) or not all(isinstance(item, str) for item in baseline_values):
            raise FindingIntelligenceError("Standard baseline fingerprints are malformed")
        active, _ = active_suppressions(suppression_payload, date.today())
        finding_groups, prioritized_findings = build_finding_intelligence([
            SourceDocument("standard", "normalized.json", normalized_payload),
        ], baseline=set(baseline_values), suppressions=active)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        diagnostic("finding-intelligence", "invalid_input", f"finding intelligence failed validation: {exc}", "finding-groups.json,prioritized-findings.json")
        return 3
    atomic_json(results / "normalized.json", normalized_payload)
    atomic_json(results / "coverage.json", coverage_payload)
    atomic_json(results / "finding-groups.json", finding_groups)
    atomic_json(results / "prioritized-findings.json", prioritized_findings)
    policy = command(
        sys.executable, vibesec_root / "scripts/policy_gate.py", "--results", results / "normalized.json",
        "--policy", vibesec_root / "policy/severity-thresholds.yml", "--baseline", vibesec_root / "policy/standard-baseline.json",
        "--suppressions", vibesec_root / "policy/suppressions.yml", "--minimum-severity", args.minimum_severity,
        "--enforcement", args.enforcement, "--profile", "standard", "--report", results / "report.md")
    policy.extend([
        "--finding-groups", str(results / "finding-groups.json"),
        "--prioritized-findings", str(results / "prioritized-findings.json"),
    ])
    try:
        completed = subprocess.run(policy, cwd=root, stdin=subprocess.DEVNULL, check=False)
    except OSError as exc:
        diagnostic("policy", "invalid_input", f"policy evaluation could not run: {type(exc).__name__}", "policy-result.json")
        return 3
    if (results / "report.md").is_file():
        with (results / "report.md").open("a", encoding="utf-8", newline="\n") as stream:
            stream.write("\n" + coverage_markdown(coverage_payload))
    final_status = 3 if input_failure else completed.returncode
    categories = {0: "pass", 1: "policy_violation", 2: "tool_error", 3: "invalid_input"}
    atomic_json(results / "policy-result.json", {
        "schema_version": 1, "profile": "standard", "exit_code": final_status,
        "exit_category": categories.get(final_status, "invalid_input"),
        "clean": final_status == 0, "security_guarantee": False,
    })
    return final_status


if __name__ == "__main__":
    raise SystemExit(main())
