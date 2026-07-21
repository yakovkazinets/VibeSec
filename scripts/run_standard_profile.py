#!/usr/bin/env python3
"""Run Standard scanners from a trusted VibeSec harness against an untrusted tree."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any

SCRIPT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_ROOT))
from vibesec.coverage import markdown as coverage_markdown, validate_coverage  # noqa: E402
from vibesec.detection import DetectionError, inventory  # noqa: E402
from vibesec.model import Finding  # noqa: E402
from vibesec.normalize import normalize_file  # noqa: E402
from vibesec.osv_database import validate_offline_database  # noqa: E402
from vibesec.sbom import sanitize_repository_paths, validate_cyclonedx, validate_spdx  # noqa: E402

IMAGE_DIGEST = re.compile(r"^[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$")
TRUSTED_GITHUB_EVENTS = {"push", "schedule", "workflow_dispatch"}
KNOWN_OUTPUTS = (
    "normalized.json", "coverage.json", "inventory.json", "report.md",
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
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"{scanner} could not complete: {type(exc).__name__}"
    accepted = {0, 1} if scanner in {"gitleaks", "actionlint", "checkov", "osv-scanner"} else {0}
    if completed.returncode not in accepted:
        return f"{scanner} exited with status {completed.returncode}"
    if raw_path is not None and (not raw_path.is_file() or raw_path.is_symlink()):
        return f"{scanner} did not produce a regular expected output"
    return None


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
    args = parser.parse_args()
    root = args.root.resolve()
    results = args.results.resolve()
    vibesec_root = args.vibesec_root.resolve()
    tools = (args.tool_dir or vibesec_root / ".tools/bin").resolve()
    if not root.is_dir() or not vibesec_root.is_dir() or (args.image_reference and not IMAGE_DIGEST.fullmatch(args.image_reference)):
        print("invalid repository, trusted harness, or image reference; images require an immutable sha256 digest", file=sys.stderr)
        return 3
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
    environment.update({
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
            normalized.append(tool_error(tool, error))
            record(tool, scope, "tool_error", error, artifacts, [], network)
            return
        try:
            if normalizer:
                normalized.extend(item.to_dict() for item in normalize_file(normalizer, output))
        except ValueError as exc:
            input_failure = True
            message = f"{tool} output failed structural validation: {exc}"
            normalized.append(tool_error(tool, message))
            record(tool, scope, "tool_error", message, artifacts, [output_rel], network)
            return
        record(tool, scope, "ran", reason, artifacts, [output_rel], network)

    source_files = repo_inventory["source_files"]
    opengrep_output = raw / "opengrep.json"
    if source_files:
        execute("opengrep", "supported first-party source", command(
            tools / "opengrep", "scan", "--config", vibesec_root / "rules/opengrep",
            "--semgrepignore-filename", vibesec_root / "config/opengrep-standard.ignore",
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
            except ValueError as exc:
                input_failure = True
                error = f"Syft SBOM failed structural validation: {exc}"
        if error:
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
    if iac_files:
        image = f'{checkov_manifest["image"]}@{checkov_manifest["digest"]}'
        execute("checkov", "detected infrastructure as code", command(
            "docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
            "--volume", f"{root}:/workspace:ro", image, "--config-file", "/dev/null",
            "--directory", "/workspace", "--output", "json", "--compact", "--quiet",
            "--download-external-modules", "false"), checkov_output, artifacts=iac_files,
            normalizer="checkov", stdout=True, reason="immutable Checkov container scanned detected IaC in an isolated runtime")
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
    if workflows:
        execute("actionlint", "GitHub Actions", command(
            tools / "actionlint", "-no-color", "-config-file", vibesec_root / "config/actionlint-standard.yaml",
            "-shellcheck", "", "-pyflakes", "", *workflows), actionlint_output,
            artifacts=workflows, normalizer="actionlint", stdout=True)
    else:
        record("actionlint", "GitHub Actions", "not_applicable", "no workflow files detected", [], [], "none")

    github_event = os.getenv("GITHUB_EVENT_NAME", "")
    github_actions = os.getenv("GITHUB_ACTIONS", "").lower() == "true"
    image_allowed = not github_actions or github_event in TRUSTED_GITHUB_EVENTS
    if not image_allowed:
        record("trivy-image", "prebuilt container image", "not_configured", f"disabled on untrusted or unknown GitHub event {github_event or 'unset'}", [], [], "none")
    elif not args.image_reference:
        state = "not_configured" if repo_inventory["dockerfiles"] else "not_applicable"
        reason = "no immutable prebuilt image reference configured" if repo_inventory["dockerfiles"] else "no Dockerfile or immutable prebuilt image reference detected"
        record("trivy-image", "prebuilt container image", state, reason, repo_inventory["dockerfiles"], [], "none")
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
        print(f"invalid coverage output: {exc}", file=sys.stderr)
        return 3
    atomic_json(results / "normalized.json", normalized_payload)
    atomic_json(results / "coverage.json", coverage_payload)
    policy = command(
        sys.executable, vibesec_root / "scripts/policy_gate.py", "--results", results / "normalized.json",
        "--policy", vibesec_root / "policy/severity-thresholds.yml", "--baseline", vibesec_root / "policy/standard-baseline.json",
        "--suppressions", vibesec_root / "policy/suppressions.yml", "--minimum-severity", args.minimum_severity,
        "--enforcement", args.enforcement, "--profile", "standard", "--report", results / "report.md")
    try:
        completed = subprocess.run(policy, cwd=root, stdin=subprocess.DEVNULL, check=False)
    except OSError as exc:
        print(f"policy evaluation could not run: {exc}", file=sys.stderr)
        return 3
    if (results / "report.md").is_file():
        with (results / "report.md").open("a", encoding="utf-8", newline="\n") as stream:
            stream.write("\n" + coverage_markdown(coverage_payload))
    return 3 if input_failure else completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
