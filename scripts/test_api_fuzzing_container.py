#!/usr/bin/env python3
"""Exercise the trusted inert injection launcher against a controlled internal API fixture."""

from __future__ import annotations

import argparse
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from vibesec.api_fuzzing import build_injection_plan, load_config, load_payload_registry, normalize_events  # noqa: E402
from vibesec.api_security import load_config as load_api_config, validate_openapi_schema  # noqa: E402
from vibesec.authenticated import consume_bearer_token  # noqa: E402
from vibesec.schemathesis_runtime import (  # noqa: E402
    render_accountability_diagnostic, trusted_injection_container_command,
)
from vibesec.strict_json import canonical_json, loads_strict  # noqa: E402

READY = "import urllib.request; urllib.request.urlopen('http://api-target:8080/compliant',timeout=5).read(1024)"


def run(command: list[str], timeout: int, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, input=input_text, stdin=subprocess.DEVNULL if input_text is None else None,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-unavailable", action="store_true")
    parser.add_argument("--authenticated", action="store_true")
    args = parser.parse_args()
    token = consume_bearer_token() if args.authenticated else None
    if args.authenticated and token is None:
        print("authenticated active API fixture secret is unavailable", file=sys.stderr)
        return 2
    docker = shutil.which("docker")
    if docker is None or run([docker, "info", "--format", "{{json .ServerVersion}}"], 30).returncode != 0:
        print("SKIP: Docker daemon is unavailable; live active API evidence was not produced.")
        return 0 if args.allow_unavailable else 2
    config = load_config(ROOT)
    api_config = load_api_config(ROOT)
    tools = loads_strict((ROOT / "config/tools.json").read_bytes())
    scanner_image = f"{tools['schemathesis']['image']}@{tools['schemathesis']['digest']}"
    fixture_image = f"{tools['dast-fixture-python']['image']}@{tools['dast-fixture-python']['digest']}"
    for image in (scanner_image, fixture_image):
        if run([docker, "pull", image], 300).returncode != 0:
            print("live active API fixture image pull failed", file=sys.stderr)
            return 2
    fixture = ROOT / "tests/security-fixtures/api-fuzzing"
    _, schema, _ = validate_openapi_schema(fixture, "openapi.yaml", config=api_config, port=8080, base_path="/")
    plan = build_injection_plan(schema, maximum_operations=config["maximum_operations"])
    registry = load_payload_registry(ROOT)
    suffix = secrets.token_hex(8)
    network, target, scanner = (f"vibesec-fuzz-live-net-{suffix}", f"vibesec-fuzz-live-target-{suffix}",
                                f"vibesec-fuzz-live-scanner-{suffix}")
    network_created = target_created = scanner_attempted = False
    result = 2
    try:
        if run([docker, "network", "create", "--internal", "--label", "org.vibesec.scope=fuzzing-live-test", network], 30).returncode != 0:
            raise RuntimeError("internal network creation failed")
        network_created = True
        target_command = [
            docker, "run", "--detach", "--name", target, "--network", network, "--network-alias", "api-target",
            "--restart", "no", "--user", "65532:65532", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--read-only", "--cpus", "1", "--memory", "1024m", "--pids-limit", "256",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--mount", f"type=bind,src={fixture / 'server.py'},dst=/fixture/server.py,readonly",
            fixture_image, "python3", "/fixture/server.py",
        ]
        if run(target_command, 60).returncode != 0:
            raise RuntimeError("controlled target failed to start")
        target_created = True
        deadline = time.monotonic() + 60
        while run([docker, "run", "--rm", "--network", network, "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges", "--read-only", "--entrypoint", "python",
                   scanner_image, "-c", READY], 15).returncode != 0:
            if time.monotonic() >= deadline:
                raise RuntimeError("controlled target readiness timed out")
            time.sleep(1)
        with tempfile.TemporaryDirectory(prefix="vibesec-fuzz-live-") as temporary:
            private = Path(temporary)
            private.chmod(0o700)
            results = private / "results"
            results.mkdir(mode=0o700)
            plan_path = private / "plan.json"
            plan_path.write_bytes(canonical_json(plan))
            plan_path.chmod(0o600)
            scanner_attempted = True
            completed = run(trusted_injection_container_command(
                docker=docker, container_name=scanner, network=network, workspace=results,
                image=scanner_image, launcher=ROOT / "scripts/vibesec/api_fuzzing_launcher.py",
                plan=plan_path, registry=ROOT / "config/injection-payloads.json", port=8080,
                base_path="/", config=config, safe_methods_only=True, authenticated=args.authenticated,
            ), config["total_timeout_minutes"] * 60, input_text=(token + "\n") if token else None)
            report = results / "fuzzing-events.ndjson"
            if completed.returncode != 0 or not report.is_file():
                diagnostic = render_accountability_diagnostic(
                    return_code=completed.returncode, report=report,
                    stderr=completed.stderr, token=token,
                )
                raise RuntimeError(
                    "trusted injection launcher did not produce evidence; "
                    + diagnostic
                )
            findings, operations, runtime_failure = normalize_events(
                report, schema_source="openapi.yaml", mode="injection", registry=registry,
                maximum_bytes=config["maximum_raw_report_bytes"], maximum_findings=config["maximum_normalized_findings"],
            )
            observed = {item.get("payload_family_id") for item in findings}
            expected = {"sql-marker", "command-marker", "path-marker", "template-marker", "header-marker"}
            if observed != expected or runtime_failure or operations != 7:
                raise RuntimeError(f"controlled active evidence differs: families={sorted(observed)} operations={operations}")
            report.unlink()
            if any(results.iterdir()):
                raise RuntimeError("raw active API evidence survived validation")
        result = 0
        print(f"live bounded active API evidence: families=5 operations=7 authentication={'bearer' if token else 'none'} raw_deleted=true cleanup=true")
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f"live active API fixture failed: {exc}", file=sys.stderr)
    finally:
        if scanner_attempted:
            run([docker, "rm", "-f", scanner], 30)
        cleanup_failed = target_created and run([docker, "rm", "-f", target], 30).returncode != 0
        cleanup_failed |= network_created and run([docker, "network", "rm", network], 30).returncode != 0
        if cleanup_failed:
            result = 2
        token = None
    return result


if __name__ == "__main__":
    raise SystemExit(main())
