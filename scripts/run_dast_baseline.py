#!/usr/bin/env python3
"""Run passive ZAP automation against one isolated immutable application image.

Exit codes: 0 completed without policy violation, 1 policy violation,
2 Docker/ZAP/runtime failure, and 3 invalid configuration or scanner output.
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
sys.path.insert(0, str(SCRIPT_ROOT))
from vibesec.dast import (  # noqa: E402
    DastError, image_digest, load_config, normalize_zap_report, tool_error,
    trusted_event, validate_base_path, validate_image_reference, validate_port, write_artifacts,
)
from vibesec.strict_json import loads_strict  # noqa: E402
from vibesec.zap_automation import (  # noqa: E402
    PLAN_FILENAME, REPORT_FILENAME, trusted_zap_container_command,
    validate_private_workspace, write_passive_plan,
)

READY_SCRIPT = """import sys,urllib.request
url=sys.argv[1]; maximum=int(sys.argv[2])
with urllib.request.urlopen(url, timeout=5) as response:
 data=response.read(maximum+1)
 if response.status != 200 or len(data)>maximum: raise SystemExit(3)
"""


def run(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=timeout, check=False)


def security_flags(config: dict[str, object], *, tmpfs: int) -> list[str]:
    return ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
            "--cpus", str(config["container_cpu_limit"]), "--memory", f"{config['container_memory_megabytes']}m",
            "--pids-limit", str(config["container_pid_limit"]),
            "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={tmpfs}m"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--vibesec-root", type=Path, default=ROOT)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--event", default=os.getenv("GITHUB_EVENT_NAME", "workflow_dispatch"))
    parser.add_argument("--image-reference", default=os.getenv("VIBESEC_DAST_IMAGE_REFERENCE", ""))
    parser.add_argument("--container-port", default=os.getenv("VIBESEC_DAST_CONTAINER_PORT", "8080"))
    parser.add_argument("--base-path", default=os.getenv("VIBESEC_DAST_BASE_PATH", "/"))
    parser.add_argument("--enforcement", choices=("observe", "new", "all"), default=os.getenv("VIBESEC_DAST_ENFORCEMENT", "observe"))
    parser.add_argument("--minimum-severity", choices=("low", "medium", "high", "critical"), default=os.getenv("VIBESEC_DAST_MIN_SEVERITY", "high"))
    args = parser.parse_args()
    root = args.vibesec_root.resolve()
    results = args.results.resolve()
    started = time.monotonic()
    port = 8080
    base_path = "/"
    digest: str | None = None
    try:
        config = load_config(root)
        port = validate_port(args.container_port)
        base_path = validate_base_path(args.base_path)
        allowed = trusted_event(args.event)
        if not allowed:
            write_artifacts(results, root=root, state="not_configured", reason="DAST is disabled on pull-request events",
                            event=args.event, digest=None, port=port, base_path=base_path, findings=[], duration_seconds=0,
                            url_count=0, exit_code=0, enforcement=args.enforcement, minimum_severity=args.minimum_severity)
            return 0
        if not args.image_reference:
            write_artifacts(results, root=root, state="not_configured", reason="no immutable application image configured",
                            event=args.event, digest=None, port=port, base_path=base_path, findings=[], duration_seconds=0,
                            url_count=0, exit_code=0, enforcement=args.enforcement, minimum_severity=args.minimum_severity)
            return 0
        reference = validate_image_reference(args.image_reference)
        digest = image_digest(reference)
        tools = loads_strict((root / "config/tools.json").read_bytes())
        zap = f"{tools['zap-baseline']['image']}@{tools['zap-baseline']['digest']}"
        validate_image_reference(zap)
    except (DastError, OSError, KeyError, TypeError, ValueError) as exc:
        try:
            write_artifacts(results, root=root, state="tool_error", reason="invalid DAST configuration",
                            event=args.event, digest=digest, port=port, base_path=base_path,
                            findings=[tool_error("invalid DAST configuration")], duration_seconds=int(time.monotonic()-started),
                            url_count=0, exit_code=3, enforcement=args.enforcement, minimum_severity=args.minimum_severity)
        except Exception:
            pass
        print(f"DAST configuration failed closed: {exc}", file=sys.stderr)
        return 3
    docker = shutil.which(args.docker) if "/" not in args.docker else args.docker
    if not docker:
        write_artifacts(results, root=root, state="tool_error", reason="Docker executable unavailable", event=args.event,
                        digest=digest, port=port, base_path=base_path, findings=[tool_error("Docker executable unavailable")],
                        duration_seconds=0, url_count=0, exit_code=2, enforcement=args.enforcement, minimum_severity=args.minimum_severity)
        return 2
    suffix = secrets.token_hex(8)
    network = f"vibesec-dast-net-{suffix}"
    target = f"vibesec-dast-target-{suffix}"
    scanner = f"vibesec-dast-zap-{suffix}"
    created_network = False
    created_target = False
    scanner_attempted = False
    final_code = 2
    findings: list[dict[str, object]] = []
    url_count = 0
    reason = "DAST runtime did not complete"
    raw: Path | None = None
    plan: Path | None = None
    temporary: tempfile.TemporaryDirectory[str] | None = None
    cleanup_failed = False
    try:
        pulled = run([docker, "pull", reference], timeout=config["total_scan_timeout_minutes"] * 60)
        if pulled.returncode != 0:
            raise RuntimeError("application image pull failed")
        inspected = run([docker, "image", "inspect", "--format", "{{json .Config.User}}", reference], timeout=30)
        if inspected.returncode != 0:
            raise RuntimeError("application image inspection failed")
        try:
            user = json.loads(inspected.stdout.strip())
        except json.JSONDecodeError as exc:
            raise DastError("application image user metadata is malformed") from exc
        principal = user.split(":", 1)[0].casefold() if isinstance(user, str) else ""
        if not isinstance(user, str) or not user or principal in {"root", "0"}:
            raise DastError("application image declares a root or unspecified user")
        network_result = run([docker, "network", "create", "--internal", "--label", "org.vibesec.scope=dast-baseline", network], timeout=30)
        if network_result.returncode != 0:
            raise RuntimeError("isolated Docker network creation failed")
        created_network = True
        target_command = [docker, "run", "--detach", "--name", target, "--network", network, "--network-alias", "target",
                          "--restart", "no", *security_flags(config, tmpfs=config["application_tmpfs_megabytes"]), reference]
        target_result = run(target_command, timeout=60)
        if target_result.returncode != 0:
            raise RuntimeError("application container failed to start")
        created_target = True
        target_url = f"http://target:{port}{base_path}"
        deadline = time.monotonic() + config["startup_timeout_seconds"]
        ready = False
        while time.monotonic() < deadline:
            probe = run([docker, "run", "--rm", "--network", network, *security_flags(config, tmpfs=64), zap,
                         "python3", "-c", READY_SCRIPT, target_url, str(config["maximum_response_bytes"])], timeout=15)
            if probe.returncode == 0:
                ready = True
                break
            state = run([docker, "inspect", "--format", "{{.State.Running}}", target], timeout=10)
            if state.returncode != 0 or state.stdout.strip() != "true":
                raise RuntimeError("application container exited before readiness")
            time.sleep(1)
        if not ready:
            raise RuntimeError("application readiness timed out")
        temporary = tempfile.TemporaryDirectory(prefix="vibesec-zap-private-")
        private = Path(temporary.name)
        private.chmod(0o700)
        raw = private / REPORT_FILENAME
        plan = private / PLAN_FILENAME
        write_passive_plan(
            plan, port=port, base_path=base_path,
            spider_minutes=config["spider_duration_minutes"],
            passive_wait_minutes=config["passive_scan_timeout_minutes"],
        )
        validate_private_workspace(private, report_required=False)
        zap_command = trusted_zap_container_command(
            docker=docker, container_name=scanner, network=network, workspace=private,
            image=zap, config=config,
        )
        scanner_attempted = True
        zap_result = run(zap_command, timeout=config["total_scan_timeout_minutes"] * 60 + 60)
        if zap_result.returncode not in {0, 1, 2}:
            raise RuntimeError("ZAP automation returned an undocumented exit")
        if zap_result.returncode == 1 and not raw.is_file():
            raise RuntimeError("ZAP automation failed before producing a report")
        validate_private_workspace(private, report_required=True)
        findings, url_count = normalize_zap_report(raw, port=port, maximum_bytes=config["maximum_raw_report_bytes"],
                                                   maximum_findings=config["maximum_normalized_findings"])
        raw.unlink()
        plan.unlink()
        if any(private.iterdir()):
            raise DastError("private ZAP evidence survived normalization")
        reason = "passive ZAP automation completed and the report was structurally validated"
        evaluation_code = 0
        if args.enforcement != "observe":
            from datetime import date
            from vibesec.policy import active_suppressions, evaluate
            baseline = loads_strict((root / "policy/dast-baseline.json").read_bytes())
            suppression = loads_strict((root / "policy/dast-suppressions.json").read_bytes())
            active, _ = active_suppressions(suppression, date.today())
            evaluated = evaluate(findings, minimum_severity=args.minimum_severity, enforcement=args.enforcement,
                                 baseline=set(baseline["fingerprints"]), suppressions=active, today=date.today())
            evaluation_code = 1 if evaluated["violations"] else 0
        final_code = evaluation_code
    except DastError as exc:
        reason = "DAST scanner output or configuration was invalid"
        findings = [tool_error(reason)]
        final_code = 3
        print(f"DAST validation failed closed: {exc}", file=sys.stderr)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        reason = str(exc) if isinstance(exc, RuntimeError) else "DAST runtime infrastructure failed"
        findings = [tool_error(reason)]
        final_code = 2
        print(f"DAST runtime failed: {reason}", file=sys.stderr)
    finally:
        if raw is not None:
            raw.unlink(missing_ok=True)
        if plan is not None:
            plan.unlink(missing_ok=True)
        if temporary is not None:
            temporary.cleanup()
        for command, expected in (([docker, "rm", "-f", scanner], scanner_attempted), ([docker, "rm", "-f", target], created_target),
                                  ([docker, "network", "rm", network], created_network)):
            cleanup = run(command, timeout=30)
            if expected and cleanup.returncode != 0:
                cleanup_failed = True
        if cleanup_failed:
            final_code = 2
            reason = "DAST cleanup failed"
            findings = [tool_error(reason)]
    state = "ran" if final_code in {0, 1} else "tool_error"
    write_artifacts(results, root=root, state=state, reason=reason, event=args.event, digest=digest,
                    port=port, base_path=base_path, findings=findings, duration_seconds=int(time.monotonic()-started),
                    url_count=url_count, exit_code=final_code, enforcement=args.enforcement, minimum_severity=args.minimum_severity)
    return final_code


if __name__ == "__main__":
    raise SystemExit(main())
