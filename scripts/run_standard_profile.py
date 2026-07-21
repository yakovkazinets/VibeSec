#!/usr/bin/env python3
"""Run the VibeSec Standard profile without building or installing target code."""

from __future__ import annotations

import argparse
from datetime import date
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.coverage import markdown as coverage_markdown, validate_coverage  # noqa: E402
from vibesec.detection import inventory  # noqa: E402
from vibesec.model import Finding  # noqa: E402
from vibesec.normalize import normalize_file  # noqa: E402
from vibesec.sbom import validate_cyclonedx, validate_spdx  # noqa: E402

IMAGE_DIGEST = re.compile(r"^[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$")


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


def command(binary: Path | str, *arguments: str) -> list[str]:
    return [str(binary), *map(str, arguments)]


def run(scanner: str, argv: list[str], raw_path: Path | None, *, cwd: Path, env: dict[str, str], stdout_output: bool = False) -> str | None:
    try:
        completed = subprocess.run(
            argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if stdout_output else subprocess.DEVNULL,
            stderr=subprocess.PIPE, timeout=900, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"{scanner} could not complete: {type(exc).__name__}"
    if stdout_output and raw_path is not None:
        raw_path.write_bytes(completed.stdout)
    # Finding exits are scanner-specific; these values mean the scanner completed.
    accepted = {0, 1} if scanner in {"gitleaks", "actionlint", "checkov"} else {0}
    if completed.returncode not in accepted:
        return f"{scanner} exited with status {completed.returncode}"
    if raw_path is not None and not raw_path.is_file():
        return f"{scanner} did not produce its expected output"
    return None


def tool_error(tool: str, message: str) -> dict[str, Any]:
    return Finding.create(
        tool=tool, category="execution", rule_id="tool-error", severity="low",
        description=message, confidence="confirmed", result_type="tool_error",
    ).to_dict()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path("."))
    parser.add_argument("results", nargs="?", type=Path, default=Path("results"))
    parser.add_argument("--tool-dir", type=Path)
    parser.add_argument("--network-mode", choices=("online", "offline"), default=os.getenv("VIBESEC_NETWORK_MODE", "online"))
    parser.add_argument("--minimum-severity", choices=("low", "medium", "high", "critical"), default=os.getenv("VIBESEC_MIN_SEVERITY", "high"))
    parser.add_argument("--enforcement", choices=("observe", "new", "all"), default=os.getenv("VIBESEC_ENFORCEMENT", "observe"))
    parser.add_argument("--image-reference", default=os.getenv("VIBESEC_IMAGE_REFERENCE", ""))
    args = parser.parse_args()
    root = args.root.resolve()
    results = args.results.resolve()
    tools = (args.tool_dir or root / ".tools/bin").resolve()
    if not root.is_dir() or (args.image_reference and not IMAGE_DIGEST.fullmatch(args.image_reference)):
        print("invalid repository root or image reference; images require an immutable sha256 digest", file=sys.stderr)
        return 3
    database_date = os.getenv("VIBESEC_OSV_DATABASE_DATE", "")
    if args.network_mode == "offline":
        try:
            date.fromisoformat(database_date)
        except ValueError:
            print("offline mode requires VIBESEC_OSV_DATABASE_DATE in YYYY-MM-DD form", file=sys.stderr)
            return 3
    results.mkdir(parents=True, exist_ok=True)
    raw = results / "raw"
    raw.mkdir(exist_ok=True)
    repo_inventory = inventory(root)
    atomic_json(results / "inventory.json", repo_inventory)
    coverage: list[dict[str, str]] = []
    normalized: list[dict[str, Any]] = []
    input_failure = False
    environment = os.environ.copy()
    environment.update({
        "SYFT_CHECK_FOR_APP_UPDATE": "false", "OPENGREP_ENABLE_VERSION_CHECK": "0",
        "SEMGREP_SEND_METRICS": "off", "XDG_CACHE_HOME": str(results / ".cache"),
    })

    def execute(tool: str, scope: str, argv: list[str], output: Path, *, normalizer: str | None = None, stdout: bool = False, reason: str = "configured scanner completed") -> None:
        nonlocal input_failure
        error = run(tool, argv, output, cwd=root, env=environment, stdout_output=stdout)
        if error:
            normalized.append(tool_error(tool, error))
            coverage.append({"tool": tool, "scope": scope, "state": "tool_error", "reason": error})
            return
        try:
            if normalizer:
                normalized.extend(item.to_dict() for item in normalize_file(normalizer, output))
        except ValueError as exc:
            input_failure = True
            message = f"{tool} output failed structural validation: {exc}"
            normalized.append(tool_error(tool, message))
            coverage.append({"tool": tool, "scope": scope, "state": "tool_error", "reason": message})
            return
        coverage.append({"tool": tool, "scope": scope, "state": "ran", "reason": reason})

    opengrep_output = raw / "opengrep.json"
    if set(repo_inventory["languages"]) & {"javascript", "typescript", "python", "java", "go"}:
        execute("opengrep", "first-party source", command(tools / "opengrep", "scan", "--config", str(root / "rules/opengrep"), "--json-output", str(opengrep_output), "--disable-version-check", "--metrics=off", str(root)), opengrep_output, normalizer="opengrep")
    else:
        coverage.append({"tool": "opengrep", "scope": "first-party source", "state": "not_applicable", "reason": "no supported language files detected"})

    osv_output = raw / "osv.json"
    if repo_inventory["manifests"]:
        osv_args = ["scan", "source", "--recursive", "--format", "json", "--output", str(osv_output), "--allow-no-lockfiles"]
        if args.network_mode == "offline":
            osv_args += ["--offline", "--offline-vulnerabilities"]
        osv_args.append(str(root))
        reason = "online advisory lookup completed; package identifiers and versions may have been sent to OSV.dev and deps.dev" if args.network_mode == "online" else f"offline database scan completed; declared database date {database_date}"
        execute("osv-scanner", "source dependencies", command(tools / "osv-scanner", *osv_args), osv_output, normalizer="osv-scanner", reason=reason)
    else:
        coverage.append({"tool": "osv-scanner", "scope": "source dependencies", "state": "not_applicable", "reason": "no supported manifests detected"})

    cyclonedx = results / "sbom.cyclonedx.json"
    spdx = results / "sbom.spdx.json"
    if repo_inventory["manifests"]:
        error = run("syft", command(tools / "syft", f"dir:{root}", "--output", f"cyclonedx-json={cyclonedx}", "--output", f"spdx-json={spdx}", "--quiet"), None, cwd=root, env=environment)
        if not error:
            try:
                validate_cyclonedx(cyclonedx)
                validate_spdx(spdx)
            except ValueError as exc:
                input_failure = True
                error = f"Syft SBOM failed structural validation: {exc}"
        if error:
            normalized.append(tool_error("syft", error))
            coverage.append({"tool": "syft", "scope": "filesystem SBOM", "state": "tool_error", "reason": error})
        else:
            coverage.append({"tool": "syft", "scope": "filesystem SBOM", "state": "ran", "reason": "CycloneDX JSON and SPDX JSON generated without enrichment"})
    else:
        coverage.append({"tool": "syft", "scope": "filesystem SBOM", "state": "not_applicable", "reason": "no supported package manifests detected"})

    iac_files = [path for values in repo_inventory["iac"].values() for path in values] + repo_inventory["dockerfiles"] + repo_inventory["workflows"]
    checkov_output = raw / "checkov.json"
    if iac_files:
        manifest = json.loads((root / "config/tools.json").read_text(encoding="utf-8"))["checkov"]
        image = f'{manifest["image"]}@{manifest["digest"]}'
        execute("checkov", "infrastructure as code", command("docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m", "--volume", f"{root}:/workspace:ro", image, "--directory", "/workspace", "--output", "json", "--compact", "--quiet", "--download-external-modules", "false"), checkov_output, normalizer="checkov", stdout=True, reason="immutable Checkov container scanned detected IaC with network disabled")
    else:
        coverage.append({"tool": "checkov", "scope": "infrastructure as code", "state": "not_applicable", "reason": "no supported IaC files detected"})

    trivy_output = raw / "trivy.json"
    execute("trivy", "secrets and configuration", command(tools / "trivy", "filesystem", "--scanners", "misconfig,secret", "--format", "json", "--output", str(trivy_output), "--exit-code", "0", "--no-progress", str(root)), trivy_output, normalizer="trivy")
    gitleaks_output = raw / "gitleaks.json"
    execute("gitleaks", "Git history secrets", command(tools / "gitleaks", "git", "--no-banner", "--redact", "--report-format", "json", "--report-path", str(gitleaks_output), str(root)), gitleaks_output, normalizer="gitleaks")

    actionlint_output = raw / "actionlint.txt"
    if repo_inventory["workflows"]:
        execute("actionlint", "GitHub Actions", command(tools / "actionlint", "-no-color", *repo_inventory["workflows"]), actionlint_output, normalizer="actionlint", stdout=True)
    else:
        coverage.append({"tool": "actionlint", "scope": "GitHub Actions", "state": "not_applicable", "reason": "no workflow files detected"})

    if os.getenv("GITHUB_EVENT_NAME") == "pull_request":
        coverage.append({"tool": "trivy-image", "scope": "prebuilt container image", "state": "not_configured", "reason": "disabled on untrusted pull_request events"})
    elif not args.image_reference:
        coverage.append({"tool": "trivy-image", "scope": "prebuilt container image", "state": "not_configured", "reason": "no immutable prebuilt image reference configured"})
    else:
        image_output = raw / "trivy-image.json"
        execute("trivy-image", "prebuilt container image", command(tools / "trivy", "image", "--scanners", "vuln", "--format", "json", "--output", str(image_output), "--exit-code", "0", "--no-progress", args.image_reference), image_output, normalizer="trivy-image")

    normalized_payload = {"schema_version": 1, "profile": "standard", "results": normalized}
    coverage_payload = validate_coverage({"schema_version": 1, "profile": "standard", "inventory": repo_inventory, "tools": coverage})
    atomic_json(results / "normalized.json", normalized_payload)
    atomic_json(results / "coverage.json", coverage_payload)
    policy = command(sys.executable, root / "scripts/policy_gate.py", "--results", results / "normalized.json", "--policy", root / "policy/severity-thresholds.yml", "--baseline", root / "policy/standard-baseline.json", "--suppressions", root / "policy/suppressions.yml", "--minimum-severity", args.minimum_severity, "--enforcement", args.enforcement, "--profile", "standard", "--report", results / "report.md")
    completed = subprocess.run(policy, cwd=root, check=False)
    if (results / "report.md").is_file():
        with (results / "report.md").open("a", encoding="utf-8", newline="\n") as stream:
            stream.write("\n" + coverage_markdown(coverage_payload))
    return 3 if input_failure else completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
