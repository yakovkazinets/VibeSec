"""Generate and validate the single trusted passive ZAP Automation Framework plan."""

from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any

from .dast import DastError, validate_base_path, validate_port
from .strict_json import StrictJSONError, canonical_json, loads_strict

CONTEXT_NAME = "vibesec-passive"
PLAN_FILENAME = "vibesec-zap-plan.yaml"
REPORT_FILENAME = "zap-report.json"
CONTAINER_WORKDIR = "/zap/wrk"
CONTAINER_PLAN = f"{CONTAINER_WORKDIR}/{PLAN_FILENAME}"
REPORT_TEMPLATE = "traditional-json"
JOB_TYPES = ("spider", "passiveScan-wait", "report", "exitStatus")
COMMAND_OPERATIONS = {"autorun": "-autorun", "autocheck": "-autocheck"}
RUNTIME_ADDON_OPTIONS = {"-addonupdate", "-addoninstall", "-addoninstallall", "-addonuninstall"}
MAX_PLAN_BYTES = 32_768
DOCKER_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")


def _target(port: int, base_path: str) -> tuple[str, str, str]:
    checked_port = validate_port(port)
    checked_path = validate_base_path(base_path)
    origin = f"http://target:{checked_port}"
    url = origin + checked_path
    include = "^" + re.escape(url) + ("(?:.*)?$" if checked_path.endswith("/") else "(?:/.*)?$")
    return origin, url, include


def _validate_durations(spider_minutes: int, passive_wait_minutes: int) -> None:
    if isinstance(spider_minutes, bool) or not isinstance(spider_minutes, int) or not 1 <= spider_minutes <= 5:
        raise DastError("trusted ZAP spider duration is outside its reviewed bound")
    if (isinstance(passive_wait_minutes, bool) or not isinstance(passive_wait_minutes, int)
            or not 1 <= passive_wait_minutes <= 10):
        raise DastError("trusted ZAP passive wait is outside its reviewed bound")


def _expected_plan(*, port: int, base_path: str, spider_minutes: int,
                   passive_wait_minutes: int) -> dict[str, Any]:
    origin, target, include = _target(port, base_path)
    return {
        "env": {
            "contexts": [{
                "name": CONTEXT_NAME,
                "urls": [target],
                "includePaths": [include],
                "excludePaths": [],
            }],
            "parameters": {
                "failOnError": True,
                "failOnWarning": False,
                "progressToStdout": False,
            },
        },
        "jobs": [
            {"type": "spider", "parameters": {
                "context": CONTEXT_NAME, "url": target, "maxDuration": spider_minutes,
            }},
            {"type": "passiveScan-wait", "parameters": {"maxDuration": passive_wait_minutes}},
            {"type": "report", "parameters": {
                "template": REPORT_TEMPLATE,
                "reportDir": CONTAINER_WORKDIR,
                "reportFile": REPORT_FILENAME,
                "displayReport": False,
            }, "sites": [origin]},
            {"type": "exitStatus", "parameters": {
                "errorLevel": "High",
                "warnLevel": "Informational",
                "okExitValue": 0,
                "warnExitValue": 2,
                "errorExitValue": 1,
            }},
        ],
    }


def build_passive_plan(*, port: int, base_path: str, spider_minutes: int,
                       passive_wait_minutes: int) -> dict[str, Any]:
    """Build the complete plan from bounded scalar values; no fragments are accepted."""
    _validate_durations(spider_minutes, passive_wait_minutes)
    plan = _expected_plan(
        port=port, base_path=base_path, spider_minutes=spider_minutes,
        passive_wait_minutes=passive_wait_minutes,
    )
    validate_passive_plan(
        plan, port=port, base_path=base_path, spider_minutes=spider_minutes,
        passive_wait_minutes=passive_wait_minutes,
    )
    return plan


def validate_passive_plan(plan: Any, *, port: int, base_path: str, spider_minutes: int,
                          passive_wait_minutes: int) -> dict[str, Any]:
    """Fail closed unless the plan is byte-semantically equal to the reviewed shape."""
    _validate_durations(spider_minutes, passive_wait_minutes)
    expected = _expected_plan(
        port=port, base_path=base_path, spider_minutes=spider_minutes,
        passive_wait_minutes=passive_wait_minutes,
    )
    if plan != expected:
        raise DastError("trusted ZAP automation plan differs from the complete reviewed passive shape")
    return plan


def write_passive_plan(path: Path, *, port: int, base_path: str, spider_minutes: int,
                       passive_wait_minutes: int) -> dict[str, Any]:
    plan = build_passive_plan(
        port=port, base_path=base_path, spider_minutes=spider_minutes,
        passive_wait_minutes=passive_wait_minutes,
    )
    if path.name != PLAN_FILENAME or path.parent.is_symlink() or not path.parent.is_dir():
        raise DastError("trusted ZAP plan path is unsafe")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{PLAN_FILENAME}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(canonical_json(plan))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return load_passive_plan(
        path, port=port, base_path=base_path, spider_minutes=spider_minutes,
        passive_wait_minutes=passive_wait_minutes,
    )


def load_passive_plan(path: Path, *, port: int, base_path: str, spider_minutes: int,
                      passive_wait_minutes: int) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise DastError("trusted ZAP plan must be a restrictive regular file")
    try:
        payload = loads_strict(path.read_bytes(), maximum_bytes=MAX_PLAN_BYTES)
    except (OSError, StrictJSONError) as exc:
        raise DastError(f"trusted ZAP plan serialization is invalid: {exc}") from exc
    return validate_passive_plan(
        payload, port=port, base_path=base_path, spider_minutes=spider_minutes,
        passive_wait_minutes=passive_wait_minutes,
    )


def trusted_zap_command(operation: str = "autorun") -> list[str]:
    flag = COMMAND_OPERATIONS.get(operation)
    if flag is None:
        raise DastError("unsupported trusted ZAP automation operation")
    command = ["zap.sh", "-cmd", "-silent", flag, CONTAINER_PLAN]
    if RUNTIME_ADDON_OPTIONS.intersection(command):
        raise DastError("trusted ZAP command attempts a runtime add-on change")
    return command


def trusted_zap_container_command(*, docker: str, container_name: str, network: str,
                                  workspace: Path, image: str, config: dict[str, Any],
                                  operation: str = "autorun") -> list[str]:
    """Build the full scanner container command shared by production and accountability."""
    uid = os.getuid()
    gid = os.getgid()
    if uid == 0 or not DOCKER_NAME.fullmatch(container_name) or not DOCKER_NAME.fullmatch(network):
        raise DastError("trusted ZAP scanner requires a non-root runner and generated Docker names")
    if (workspace.is_symlink() or not workspace.is_dir() or stat.S_IMODE(workspace.stat().st_mode) != 0o700
            or any(character in str(workspace) for character in (",", "\n", "\r"))):
        raise DastError("private ZAP workspace is unsafe")
    tmpfs = config["zap_tmpfs_megabytes"]
    if isinstance(tmpfs, bool) or not isinstance(tmpfs, int) or not 64 <= tmpfs <= 2048:
        raise DastError("trusted ZAP tmpfs bound is invalid")
    return [
        docker, "run", "--name", container_name, "--network", network,
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
        "--cpus", str(config["container_cpu_limit"]),
        "--memory", f"{config['container_memory_megabytes']}m",
        "--pids-limit", str(config["container_pid_limit"]),
        "--user", f"{uid}:{gid}",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={tmpfs}m",
        "--tmpfs", f"/home/zap:rw,noexec,nosuid,nodev,size={tmpfs}m,uid={uid},gid={gid},mode=0700",
        "--mount", f"type=bind,src={workspace},dst={CONTAINER_WORKDIR}",
        image, *trusted_zap_command(operation),
    ]


def validate_private_workspace(directory: Path, *, report_required: bool) -> tuple[Path, Path]:
    plan = directory / PLAN_FILENAME
    report = directory / REPORT_FILENAME
    expected = {PLAN_FILENAME, REPORT_FILENAME} if report_required else {PLAN_FILENAME}
    observed = {path.name for path in directory.iterdir()}
    if observed != expected or plan.is_symlink() or not plan.is_file():
        raise DastError("private ZAP workspace contains missing or unapproved files")
    if report_required and (report.is_symlink() or not report.is_file()):
        raise DastError("ZAP automation report is missing or unsafe")
    return plan, report
