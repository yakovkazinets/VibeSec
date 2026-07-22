#!/usr/bin/env python3
"""Exercise pinned Schemathesis against the controlled internal API fixture.

This accountability-only harness assigns a numeric non-root user and mounts the
repository-owned fixture server. The consumer runner permits neither override.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

SCRIPT_ROOT = Path(__file__).resolve().parent
ROOT = SCRIPT_ROOT.parent
sys.path.insert(0, str(SCRIPT_ROOT))
from vibesec.api_security import (  # noqa: E402
    load_config, normalize_schemathesis_report, operation_index, validate_openapi_schema,
)
from vibesec.authenticated import consume_bearer_token  # noqa: E402
from vibesec.schemathesis_runtime import (  # noqa: E402
    REPORT_FILENAME, trusted_scanner_container_command, validate_private_workspace,
)
from vibesec.strict_json import loads_strict  # noqa: E402

READY_SCRIPT = "import urllib.request; urllib.request.urlopen('http://api-target:8080/compliant',timeout=5).read(1024)"


def run(command: list[str], timeout: int, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, input=input_text, stdin=subprocess.DEVNULL if input_text is None else None, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)


def flags(config: dict[str, object], tmpfs: int) -> list[str]:
    return ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
            "--cpus", str(config["container_cpu_limit"]), "--memory", f"{config['container_memory_megabytes']}m",
            "--pids-limit", str(config["container_pid_limit"]),
            "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={tmpfs}m"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-unavailable", action="store_true")
    parser.add_argument("--authenticated", action="store_true")
    args = parser.parse_args()
    token = consume_bearer_token() if args.authenticated else None
    if args.authenticated and token is None:
        print("authenticated API fixture secret is unavailable", file=sys.stderr)
        return 2
    docker = shutil.which("docker")
    if docker is None or run([docker, "info", "--format", "{{json .ServerVersion}}"], 30).returncode != 0:
        print("SKIP: Docker daemon is unavailable; live API container evidence was not produced.")
        return 0 if args.allow_unavailable else 2

    config = load_config(ROOT)
    tools = loads_strict((ROOT / "config/tools.json").read_bytes())
    scanner_image = f"{tools['schemathesis']['image']}@{tools['schemathesis']['digest']}"
    fixture_image = f"{tools['dast-fixture-python']['image']}@{tools['dast-fixture-python']['digest']}"
    for image in (scanner_image, fixture_image):
        if run([docker, "pull", image], 300).returncode != 0:
            print("live API fixture image pull failed", file=sys.stderr)
            return 2

    fixture = ROOT / "tests/security-fixtures/api-security"
    schema, payload, _ = validate_openapi_schema(fixture, "openapi.yaml", config=config, port=8080, base_path="/")
    suffix = secrets.token_hex(8)
    network = f"vibesec-api-live-net-{suffix}"
    target = f"vibesec-api-live-target-{suffix}"
    scanner = f"vibesec-api-live-scanner-{suffix}"
    network_created = target_created = scanner_attempted = False
    result = 2
    evidence = ""
    try:
        created = run([docker, "network", "create", "--internal", "--label", "org.vibesec.scope=api-live-test", network], 30)
        if created.returncode != 0:
            raise RuntimeError("live API fixture internal network creation failed")
        network_created = True
        target_command = [
            docker, "run", "--detach", "--name", target, "--network", network,
            "--network-alias", "api-target", "--restart", "no", "--user", "65532:65532",
            *flags(config, config["target_tmpfs_megabytes"]),
            "--mount", f"type=bind,src={fixture / 'server.py'},dst=/fixture/server.py,readonly",
            fixture_image, "python3", "/fixture/server.py",
        ]
        if run(target_command, 60).returncode != 0:
            raise RuntimeError("live API fixture target failed to start")
        target_created = True
        deadline = time.monotonic() + config["startup_timeout_seconds"]
        while True:
            probe = run([docker, "run", "--rm", "--network", network, *flags(config, 32),
                         "--entrypoint", "python", scanner_image, "-c", READY_SCRIPT], 15)
            if probe.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("live API fixture readiness timed out")
            time.sleep(1)

        with tempfile.TemporaryDirectory(prefix="vibesec-api-live-") as temporary:
            private = Path(temporary)
            private.chmod(0o700)
            report = private / REPORT_FILENAME
            validate_private_workspace(private, report_required=False)
            scanner_attempted = True
            scan = run(trusted_scanner_container_command(
                docker=docker, container_name=scanner, network=network, schema=schema,
                workspace=private, image=scanner_image, port=8080, base_path="/",
                config=config, safe_methods_only=True, authenticated=args.authenticated,
            ), config["total_scan_timeout_minutes"] * 60 + 60,
                input_text=(token + "\n") if token is not None else None)
            if scan.returncode not in {0, 1} or not report.is_file():
                raise RuntimeError("live Schemathesis fixture did not produce a completed report")
            validate_private_workspace(private, report_required=True)
            report_size = report.stat().st_size
            findings, observed_operations = normalize_schemathesis_report(
                report, schema_source="openapi.yaml", operations=operation_index(payload),
                maximum_bytes=config["maximum_report_bytes"],
                maximum_findings=config["maximum_normalized_findings"],
            )
            observed = [(item["operation_id"], item["rule_id"]) for item in findings]
            expected = [("getControlledDefect", "response_schema_conformance")]
            if args.authenticated:
                expected.append(("getPrivateDefect", "response_schema_conformance"))
            if observed != expected:
                raise RuntimeError(f"live API evidence differs: {observed!r}")
            if observed_operations != 5:
                raise RuntimeError("live API fixture did not exercise all five controlled operations")
            report.unlink()
            if any(private.iterdir()):
                raise RuntimeError("live API private evidence cleanup failed")
            evidence = (f"live API evidence: authentication={'bearer' if args.authenticated else 'none'} "
                        f"positive=response_schema_conformance negative=clean operations=5 "
                        f"report_bytes={report_size} raw_deleted=true")
        result = 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f"live API container fixture failed: {exc}", file=sys.stderr)
    finally:
        cleanup_failed = False
        if scanner_attempted:
            run([docker, "rm", "-f", scanner], 30)
        if target_created and run([docker, "rm", "-f", target], 30).returncode != 0:
            cleanup_failed = True
        if network_created and run([docker, "network", "rm", network], 30).returncode != 0:
            cleanup_failed = True
        if cleanup_failed:
            print("live API container fixture failed: current-run resource cleanup failed", file=sys.stderr)
            result = 2
    if result == 0:
        print(evidence + " cleanup=true")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
