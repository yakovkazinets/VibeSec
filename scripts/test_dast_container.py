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
    from .vibesec.strict_json import loads_strict
else:
    sys.path.insert(0, str(SCRIPT_ROOT))
    from vibesec.dast import load_config, normalize_zap_report  # type: ignore[no-redef]
    from vibesec.strict_json import loads_strict  # type: ignore[no-redef]


def run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)


def flags(config: dict[str, object], tmpfs: int) -> list[str]:
    return ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
            "--cpus", str(config["container_cpu_limit"]), "--memory", f"{config['container_memory_megabytes']}m",
            "--pids-limit", str(config["container_pid_limit"]),
            "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={tmpfs}m"]


def classify_zap_failure(stderr: str) -> str:
    """Map bounded scanner stderr to a non-sensitive diagnostic category."""
    text = stderr[:8192].casefold()
    if any(marker in text for marker in ("config file not found", "config_file", "unable to open config", "/zap/wrk//zap/policy")):
        return "config_file_unavailable"
    if "report" in text and any(marker in text for marker in ("no such file", "cannot write", "can't write", "unable to write", "invalid path")):
        return "report_path_invalid"
    if any(marker in text for marker in ("failed to start zap", "zap startup", "zap daemon")):
        return "zap_startup_failed"
    if any(marker in text for marker in ("target unreachable", "failed to access url", "connection refused", "name or service not known")):
        return "target_unreachable"
    if any(marker in text for marker in ("permission denied", "read-only file system", "filesystem unavailable")):
        return "filesystem_unavailable"
    return "unknown_zap_exit"


def zap_failure_summary(case: str, scan: subprocess.CompletedProcess[str], report: Path) -> str:
    if case not in {"positive", "negative"}:
        case = "unknown"
    exists = report.is_file() and not report.is_symlink()
    size = report.stat().st_size if exists else 0
    category = classify_zap_failure(scan.stderr)
    return (f"live ZAP scan failed: case={case} exit={scan.returncode} "
            f"report_exists={str(exists).lower()} report_bytes={size} category={category}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-unavailable", action="store_true", help="return 0 with an explicit skip when Docker is unavailable")
    args = parser.parse_args()
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
        policy = ROOT / config["rule_disposition_file"]
        for case in ("positive", "negative"):
            scanner = f"vibesec-dast-live-zap-{case}-{suffix}"
            scanners.append(scanner)
            with tempfile.TemporaryDirectory(prefix=f"vibesec-zap-live-{case}-") as temporary:
                private = Path(temporary)
                private.chmod(0o733)
                target_url = f"http://target:8080/{case}"
                scan = run([docker, "run", "--name", scanner, "--network", network,
                            *flags(config, config["zap_tmpfs_megabytes"]),
                            "--tmpfs", f"/home/zap:rw,noexec,nosuid,nodev,size={config['zap_tmpfs_megabytes']}m",
                            "--mount", f"type=bind,src={private},dst=/zap/wrk",
                            "--mount", f"type=bind,src={policy},dst=/zap/wrk/vibesec-zap-baseline.conf,readonly",
                            zap, "zap-baseline.py", "-t", target_url, "-c", "vibesec-zap-baseline.conf",
                            "-m", str(config["spider_duration_minutes"]), "-T", str(config["passive_scan_timeout_minutes"]),
                            "-J", "zap-report.json", "-s", "-i", "--autooff"],
                           config["total_scan_timeout_minutes"] * 60 + 60)
                if scan.returncode not in {0, 1, 2}:
                    raise RuntimeError(zap_failure_summary(case, scan, private / "zap-report.json"))
                findings, _ = normalize_zap_report(private / "zap-report.json", port=8080,
                                                   maximum_bytes=config["maximum_raw_report_bytes"],
                                                   maximum_findings=config["maximum_normalized_findings"])
                observed[case] = [item["rule_id"] for item in findings]
            run([docker, "rm", "-f", scanner], 30)
            scanners.remove(scanner)
        if observed != {"positive": ["10020"], "negative": []}:
            raise RuntimeError(f"live DAST evidence differs: {json.dumps(observed, sort_keys=True)}")
        print("live DAST container fixture passed: positive=10020 negative=clean")
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f"live DAST container fixture failed: {exc}", file=sys.stderr)
        return 2
    finally:
        for scanner in scanners:
            run([docker, "rm", "-f", scanner], 30)
        if target_created:
            run([docker, "rm", "-f", target], 30)
        if network_created:
            run([docker, "network", "rm", network], 30)


if __name__ == "__main__":
    raise SystemExit(main())
