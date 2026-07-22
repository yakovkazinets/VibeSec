#!/usr/bin/env python3
"""Exercise pinned ZAP against the repository-owned HTTP fixture.

This accountability harness may assign a numeric non-root user and mount the
repository-owned fixture. The consumer DAST runner deliberately permits neither.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

SCRIPT_ROOT = Path(__file__).resolve().parent
ROOT = SCRIPT_ROOT.parent
if __package__:
    from .vibesec.dast import load_config, normalize_zap_report
    from .vibesec.authenticated import consume_bearer_token
    from .vibesec.strict_json import loads_strict
    from .vibesec.zap_automation import (
        CONTAINER_ZAP_HOME, PLAN_FILENAME, REPORT_FILENAME, trusted_zap_container_command,
        validate_private_workspace, write_passive_plan,
    )
    from .vibesec.zap_diagnostics import (
        read_private_log_tail, render_zap_runtime_diagnostic,
    )
else:
    sys.path.insert(0, str(SCRIPT_ROOT))
    from vibesec.dast import load_config, normalize_zap_report  # type: ignore[no-redef]
    from vibesec.authenticated import consume_bearer_token  # type: ignore[no-redef]
    from vibesec.strict_json import loads_strict  # type: ignore[no-redef]
    from vibesec.zap_automation import (  # type: ignore[no-redef]
        CONTAINER_ZAP_HOME, PLAN_FILENAME, REPORT_FILENAME, trusted_zap_container_command,
        validate_private_workspace, write_passive_plan,
    )
    from vibesec.zap_diagnostics import (  # type: ignore[no-redef]
        read_private_log_tail, render_zap_runtime_diagnostic,
    )


def run(command: list[str], timeout: int, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, input=input_text, stdin=subprocess.DEVNULL if input_text is None else None, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)


def flags(config: dict[str, object], tmpfs: int) -> list[str]:
    return ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
            "--cpus", str(config["container_cpu_limit"]), "--memory", f"{config['container_memory_megabytes']}m",
            "--pids-limit", str(config["container_pid_limit"]),
            "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={tmpfs}m"]


def update_attempted(completed: subprocess.CompletedProcess[str]) -> bool:
    text = (completed.stdout + "\n" + completed.stderr)[:16384].casefold()
    return any(marker in text for marker in (
        "-addonupdate", "-addoninstall", "marketplace", "checking for add-on updates",
        "checking for addon updates", "installing add-on", "installing addon",
    ))


def capture_zap_runtime_diagnostic(*, docker: str, container: str,
                                   private: Path, case: str,
                                   scan: subprocess.CompletedProcess[str], report: Path) -> str:
    """Inspect a stopped scanner without exposing or retaining its raw logs."""
    state: dict[str, object] = {}
    runtime_parts = [scan.stdout[-65_536:], scan.stderr[-65_536:]]
    inspected = run([docker, "inspect", "--format", "{{json .State}}", container], 30)
    if inspected.returncode == 0:
        try:
            parsed = loads_strict(inspected.stdout.encode("utf-8"), maximum_bytes=32_768)
            if isinstance(parsed, dict):
                state = parsed
        except (UnicodeError, ValueError):
            runtime_parts.append("container state inspection failed")
    container_logs = run([docker, "logs", "--tail", "200", container], 30)
    runtime_parts.extend((container_logs.stdout[-65_536:], container_logs.stderr[-65_536:]))
    copied_log = private / ".vibesec-zap-runtime.log"
    copied_log.unlink(missing_ok=True)
    try:
        copied = run([docker, "cp", f"{container}:{CONTAINER_ZAP_HOME}/zap.log", str(copied_log)], 30)
        if copied.returncode == 0:
            runtime_parts.append(read_private_log_tail(copied_log))
        else:
            runtime_parts.append("ZAP private runtime log unavailable")
        return render_zap_runtime_diagnostic(
            case=case, exit_code=scan.returncode, state=state,
            report=report, runtime_text="\n".join(runtime_parts),
        )
    finally:
        copied_log.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-unavailable", action="store_true", help="return 0 with an explicit skip when Docker is unavailable")
    parser.add_argument("--authenticated", action="store_true")
    args = parser.parse_args()
    token = consume_bearer_token() if args.authenticated else None
    if args.authenticated and token is None:
        print("authenticated DAST fixture secret is unavailable", file=sys.stderr)
        return 2
    docker = shutil.which("docker")
    if docker is None or run([docker, "info", "--format", "{{json .ServerVersion}}"], 30).returncode != 0:
        print("SKIP: Docker daemon is unavailable; live DAST container evidence was not produced.")
        return 0 if args.allow_unavailable else 2
    config = load_config(ROOT)
    tools = loads_strict((ROOT / "config/tools.json").read_bytes())
    zap = f"{tools['zap-baseline']['image']}@{tools['zap-baseline']['digest']}"
    fixture = f"{tools['dast-fixture-python']['image']}@{tools['dast-fixture-python']['digest']}"
    for image in (zap, fixture):
        if run([docker, "pull", image], 300).returncode != 0:
            print("live DAST fixture image pull failed", file=sys.stderr)
            return 2
    suffix = secrets.token_hex(8)
    network = f"vibesec-dast-live-net-{suffix}"
    target = f"vibesec-dast-live-target-{suffix}"
    scanners: list[str] = []
    network_created = target_created = False
    success_evidence = ""
    try:
        if run([docker, "network", "create", "--internal", "--label", "org.vibesec.scope=dast-live-test", network], 30).returncode != 0:
            raise RuntimeError("live fixture internal network creation failed")
        network_created = True
        server = ROOT / "tests/security-fixtures/zap-baseline/server.py"
        command = [docker, "run", "--detach", "--name", target, "--network", network,
                   "--network-alias", "target", "--restart", "no", "--user", "65532:65532",
                   *flags(config, config["application_tmpfs_megabytes"]),
                   "--mount", f"type=bind,src={server},dst=/fixture/server.py,readonly",
                   fixture, "python3", "/fixture/server.py"]
        if run(command, 60).returncode != 0:
            raise RuntimeError("live fixture target failed to start")
        target_created = True
        ready_script = "import urllib.request; urllib.request.urlopen('http://target:8080/health',timeout=5).read(1024)"
        deadline = time.monotonic() + config["startup_timeout_seconds"]
        while True:
            probe = run([docker, "run", "--rm", "--network", network,
                         *flags(config, 64), zap, "python3", "-c", ready_script], 15)
            if probe.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("live fixture readiness timed out")
            time.sleep(1)
        observed: dict[str, list[str]] = {}
        exits: dict[str, int] = {}
        report_sizes: dict[str, int] = {}
        cases = ("private", "private-negative") if args.authenticated else ("positive", "negative")
        for case in cases:
            checker = f"vibesec-dast-live-check-{case}-{suffix}"
            scanner = f"vibesec-dast-live-zap-{case}-{suffix}"
            with tempfile.TemporaryDirectory(prefix=f"vibesec-zap-live-{case}-") as temporary:
                private = Path(temporary)
                private.chmod(0o700)
                plan = private / PLAN_FILENAME
                report = private / REPORT_FILENAME
                write_passive_plan(
                    plan, port=8080, base_path=f"/{case}",
                    spider_minutes=config["spider_duration_minutes"],
                    passive_wait_minutes=config["passive_scan_timeout_minutes"],
                    authenticated=args.authenticated,
                )
                validate_private_workspace(private, report_required=False)
                if not args.authenticated:
                    scanners.append(checker)
                    check = run(trusted_zap_container_command(
                        docker=docker, container_name=checker, network=network, workspace=private,
                        image=zap, config=config, operation="autocheck",
                    ), 60)
                    if check.returncode != 0 or update_attempted(check):
                        raise RuntimeError(capture_zap_runtime_diagnostic(
                            docker=docker, container=checker, private=private,
                            case=case, scan=check, report=report,
                        ))
                    validate_private_workspace(private, report_required=False)
                    if run([docker, "rm", "-f", checker], 30).returncode != 0:
                        raise RuntimeError("live ZAP autocheck container cleanup failed")
                    scanners.remove(checker)
                scanners.append(scanner)
                scan = run(trusted_zap_container_command(
                    docker=docker, container_name=scanner, network=network, workspace=private,
                    image=zap, config=config, authenticated=args.authenticated,
                ), config["total_scan_timeout_minutes"] * 60 + 60,
                    input_text=(token + "\n") if token is not None else None)
                if scan.returncode not in {0, 1, 2}:
                    raise RuntimeError(capture_zap_runtime_diagnostic(
                        docker=docker, container=scanner, private=private,
                        case=case, scan=scan, report=report,
                    ))
                if update_attempted(scan) or (scan.returncode == 1 and not report.is_file()):
                    raise RuntimeError(capture_zap_runtime_diagnostic(
                        docker=docker, container=scanner, private=private,
                        case=case, scan=scan, report=report,
                    ))
                validate_private_workspace(private, report_required=True)
                report_sizes[case] = report.stat().st_size
                findings, _ = normalize_zap_report(report, port=8080,
                                                   maximum_bytes=config["maximum_raw_report_bytes"],
                                                   maximum_findings=config["maximum_normalized_findings"])
                observed[case] = [item["rule_id"] for item in findings]
                exits[case] = scan.returncode
                report.unlink()
                plan.unlink()
                if any(private.iterdir()):
                    raise RuntimeError("live ZAP private evidence cleanup failed")
            if run([docker, "rm", "-f", scanner], 30).returncode != 0:
                raise RuntimeError("live ZAP scanner container cleanup failed")
            scanners.remove(scanner)
        expected_observed = ({"private": ["10020"], "private-negative": []} if args.authenticated
                             else {"positive": ["10020"], "negative": []})
        if observed != expected_observed:
            raise RuntimeError(f"live DAST evidence differs: {json.dumps(observed, sort_keys=True)}")
        if set(exits.values()) - {0, 1, 2}:
            raise RuntimeError("live DAST produced an undocumented Automation Framework exit")
        success_evidence = (
            f"live DAST evidence: authentication={'bearer' if args.authenticated else 'none'} "
            f"positive_exit={exits[cases[0]]} positive_report_bytes={report_sizes[cases[0]]} "
            f"negative_exit={exits[cases[1]]} negative_report_bytes={report_sizes[cases[1]]} "
            "home=ephemeral_tmpfs private_files_deleted=true"
        )
        result = 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f"live DAST container fixture failed: {exc}", file=sys.stderr)
        result = 2
    finally:
        cleanup_failed = False
        for scanner in scanners:
            if run([docker, "rm", "-f", scanner], 30).returncode != 0:
                cleanup_failed = True
        if target_created:
            if run([docker, "rm", "-f", target], 30).returncode != 0:
                cleanup_failed = True
        if network_created:
            if run([docker, "network", "rm", network], 30).returncode != 0:
                cleanup_failed = True
        if cleanup_failed:
            print("live DAST container fixture failed: current-run resource cleanup failed", file=sys.stderr)
            result = 2
    if result == 0:
        print(success_evidence + " cleanup=true")
        print("live DAST container fixture passed: positive=10020 negative=clean")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
