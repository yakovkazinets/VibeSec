"""Closed Schemathesis and Docker command builders shared by production and tests."""

from __future__ import annotations

import os
from pathlib import Path
import re
import stat
from typing import Any

from .api_security import ApiSecurityError
from .authenticated import (
    AuthenticatedSecurityError, sanitize_diagnostic, validate_publishable_bytes,
)

REPORT_FILENAME = "schemathesis.ndjson"
CONTAINER_SCHEMA = "/schema/openapi.yaml"
CONTAINER_REPORT = "/results/schemathesis.ndjson"
CONTAINER_RAW_REPORT = "/scanner-raw/schemathesis.ndjson"
ACTIVE_EVENTS = "/results/fuzzing-events.ndjson"
SENSITIVE_DIAGNOSTIC_FIELD = re.compile(
    r"(?i)\b(?:request|response)[ _-](?:body|headers?)\b|\b(?:cookie|set-cookie)\b",
)
DIAGNOSTIC_URL = re.compile(r"https?://\S+", re.IGNORECASE)
AUTHENTICATED_LAUNCHER = r'''import contextlib,os,re,sys
from schemathesis.cli import schemathesis
token=sys.stdin.readline(16385).rstrip("\n")
if not token or len(token.encode())>16384 or any(ord(c)<32 or ord(c)==127 for c in token): raise SystemExit(3)
if sys.stdin.read(1): raise SystemExit(3)
args=sys.argv[1:]+["--header","Authorization: Bearer "+token]
code=0
try:
 with open(os.devnull,"w") as null,contextlib.redirect_stdout(null),contextlib.redirect_stderr(null):
  result=schemathesis.main(args=args,prog_name="schemathesis",standalone_mode=False)
  code=result if isinstance(result,int) else 0
except SystemExit as exc: code=exc.code if isinstance(exc.code,int) else 3
raw="/scanner-raw/schemathesis.ndjson"
if not os.path.isfile(raw): raise SystemExit(code if code not in (0,1) else 3)
data=open(raw,"rb").read(10000001)
if not 0<len(data)<=10000000: raise SystemExit(3)
secret=token.encode()
data=data.replace(secret,b"[REDACTED]")
data=re.sub(rb"(?i)authorization\s*:\s*bearer\s+[^\s\"'<>]{1,16384}",b"[REDACTED AUTHORIZATION]",data)
if secret in data or re.search(rb"(?i)authorization\s*:\s*bearer\s+[^\s\"'<>]{1,16384}",data): raise SystemExit(3)
if re.search(rb"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])",data): raise SystemExit(3)
out="/results/schemathesis.ndjson"
fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"wb") as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
os.remove(raw)
raise SystemExit(code)
'''


def _non_root_host_identity() -> tuple[int, int]:
    uid, gid = os.getuid(), os.getgid()
    if uid == 0:
        raise ApiSecurityError("Schemathesis container execution as root is prohibited")
    return uid, gid


def render_accountability_diagnostic(*, return_code: int, report: Path,
                                     stderr: str, token: str | None = None) -> str:
    """Return bounded scanner state without publishing request or response data."""
    sanitized = sanitize_diagnostic(stderr, token)
    sanitized = DIAGNOSTIC_URL.sub("[REDACTED URL]", sanitized)
    if SENSITIVE_DIAGNOSTIC_FIELD.search(sanitized):
        sanitized = "[REDACTED SENSITIVE SCANNER OUTPUT]"
    try:
        validate_publishable_bytes(sanitized.encode("utf-8"), token)
    except AuthenticatedSecurityError:
        sanitized = "[REDACTED SENSITIVE SCANNER OUTPUT]"
    report_exists = report.is_file() and not report.is_symlink()
    return (
        f"scanner_return_code={return_code} "
        f"report_exists={str(report_exists).lower()} "
        f"stderr={sanitized or '[empty]'}"
    )


def validate_private_workspace(path: Path, *, report_required: bool) -> None:
    details = path.stat(follow_symlinks=False)
    if path.is_symlink() or not stat.S_ISDIR(details.st_mode) or details.st_mode & 0o077:
        raise ApiSecurityError("private API results directory must be a mode-0700 directory")
    allowed = {REPORT_FILENAME} if report_required else set()
    observed = {item.name for item in path.iterdir()}
    if observed - allowed or (report_required and observed != allowed):
        raise ApiSecurityError("private API results directory contains unexpected files")
    if report_required:
        report = path / REPORT_FILENAME
        if report.is_symlink() or not report.is_file():
            raise ApiSecurityError("Schemathesis report is missing or unsafe")


def trusted_schemathesis_command(*, port: int, base_path: str, config: dict[str, Any],
                                 safe_methods_only: bool, authenticated: bool = False) -> list[str]:
    url = f"http://api-target:{port}{base_path}"
    command = [
        "run", CONTAINER_SCHEMA, "--url", url,
        "--phases", "examples,coverage,fuzzing", "--mode", "all", "--workers", "1",
        "--max-examples", str(config["max_examples_per_operation"]),
        "--max-failures", str(config["max_failures"]), "--seed", str(config["fixed_seed"]),
        "--generation-deterministic", "--generation-with-security-parameters", "false",
        "--generation-database", "none", "--checks", ",".join((
            "not_a_server_error", "status_code_conformance", "content_type_conformance",
            "response_schema_conformance", "negative_data_rejection", "positive_data_acceptance",
        )), "--request-timeout", str(config["request_timeout_seconds"]), "--request-retries", "0",
        "--max-redirects", "0", "--continue-on-failure", "--no-shrink",
        "--report", "ndjson", "--report-ndjson-path", CONTAINER_RAW_REPORT if authenticated else CONTAINER_REPORT, "--no-color",
    ]
    if safe_methods_only:
        for method in config["safe_methods"]:
            command.extend(("--include-method", method))
    return command


def trusted_scanner_container_command(*, docker: str, container_name: str, network: str,
                                      schema: Path, workspace: Path, image: str,
                                      port: int, base_path: str, config: dict[str, Any],
                                      safe_methods_only: bool, authenticated: bool = False) -> list[str]:
    uid, gid = _non_root_host_identity()
    command = [
        docker, "run", "--rm", "--name", container_name, "--network", network,
        "--user", f"{uid}:{gid}",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
        "--cpus", str(config["container_cpu_limit"]), "--memory", f"{config['container_memory_megabytes']}m",
        "--pids-limit", str(config["container_pid_limit"]),
        "--tmpfs", (
            f"/tmp:rw,noexec,nosuid,nodev,size={config['scanner_tmpfs_megabytes']}m,"
            f"uid={uid},gid={gid},mode=0700"
        ),
        "--workdir", "/results", "--env", "HOME=/tmp",
        "--env", "SCHEMATHESIS_COVERAGE=false", "--env", "SCHEMATHESIS_HOOKS=",
        "--mount", f"type=bind,src={schema},dst={CONTAINER_SCHEMA},readonly",
        "--mount", f"type=bind,src={workspace},dst=/results",
    ]
    scanner = trusted_schemathesis_command(port=port, base_path=base_path, config=config,
                                           safe_methods_only=safe_methods_only, authenticated=authenticated)
    if authenticated:
        command.extend(("--tmpfs", (
                            f"/scanner-raw:rw,noexec,nosuid,nodev,size={config['scanner_tmpfs_megabytes']}m,"
                            f"uid={uid},gid={gid},mode=0700"
                        ),
                        "--interactive", "--entrypoint", "python", image, "-c", AUTHENTICATED_LAUNCHER, *scanner))
    else:
        command.extend((image, *scanner))
    return command


def trusted_active_schemathesis_command(*, port: int, base_path: str, config: dict[str, Any],
                                        mode: str, safe_methods_only: bool,
                                        authenticated: bool = False) -> list[str]:
    if mode not in {"contract", "fuzz", "combined"}:
        raise ApiSecurityError("unsupported active Schemathesis mode")
    phases = {"contract": "examples,coverage", "fuzz": "fuzzing", "combined": "examples,coverage,fuzzing"}[mode]
    command = [
        "run", CONTAINER_SCHEMA, "--url", f"http://api-target:{port}{base_path}",
        "--phases", phases, "--mode", "all", "--workers", "1",
        "--max-examples", str(config["max_examples_per_operation"]),
        "--max-failures", str(config["max_failures"]), "--seed", str(config["fixed_seed"]),
        "--generation-deterministic", "--generation-with-security-parameters", "false",
        "--generation-database", "none", "--generation-allow-x00", "false",
        "--checks", ",".join(("not_a_server_error", "status_code_conformance", "content_type_conformance",
                              "response_schema_conformance", "negative_data_rejection", "positive_data_acceptance")),
        "--request-timeout", str(config["request_timeout_seconds"]), "--request-retries", "0",
        "--max-redirects", "0", "--continue-on-failure", "--no-shrink",
        "--report", "ndjson", "--report-ndjson-path", CONTAINER_RAW_REPORT if authenticated else CONTAINER_REPORT,
        "--no-color",
    ]
    if safe_methods_only:
        for method in config["safe_methods"]:
            command.extend(("--include-method", method))
    return command


def trusted_active_scanner_container_command(*, docker: str, container_name: str, network: str,
                                             schema: Path, workspace: Path, image: str,
                                             port: int, base_path: str, config: dict[str, Any],
                                             mode: str, safe_methods_only: bool,
                                             authenticated: bool = False) -> list[str]:
    uid, gid = _non_root_host_identity()
    command = [
        docker, "run", "--rm", "--name", container_name, "--network", network,
        "--user", f"{uid}:{gid}",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
        "--cpus", "1", "--memory", "1024m", "--pids-limit", "256",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size=256m,uid={uid},gid={gid},mode=0700",
        "--workdir", "/results", "--env", "HOME=/tmp",
        "--env", "SCHEMATHESIS_COVERAGE=false", "--env", "SCHEMATHESIS_HOOKS=",
        "--mount", f"type=bind,src={schema},dst={CONTAINER_SCHEMA},readonly",
        "--mount", f"type=bind,src={workspace},dst=/results",
    ]
    scanner = trusted_active_schemathesis_command(port=port, base_path=base_path, config=config, mode=mode,
                                                   safe_methods_only=safe_methods_only, authenticated=authenticated)
    if authenticated:
        command.extend(("--tmpfs", (
                            f"/scanner-raw:rw,noexec,nosuid,nodev,size=256m,"
                            f"uid={uid},gid={gid},mode=0700"
                        ), "--interactive",
                        "--entrypoint", "python", image, "-c", AUTHENTICATED_LAUNCHER, *scanner))
    else:
        command.extend((image, *scanner))
    return command


def trusted_injection_container_command(*, docker: str, container_name: str, network: str,
                                        workspace: Path, image: str, launcher: Path, plan: Path,
                                        registry: Path, port: int, base_path: str,
                                        config: dict[str, Any], safe_methods_only: bool,
                                        authenticated: bool = False) -> list[str]:
    uid, gid = _non_root_host_identity()
    command = [
        docker, "run", "--rm", "--name", container_name, "--network", network,
        "--user", f"{uid}:{gid}",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
        "--cpus", "1", "--memory", "1024m", "--pids-limit", "256",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size=64m,uid={uid},gid={gid},mode=0700",
        "--workdir", "/results", "--env", "HOME=/tmp",
        "--mount", f"type=bind,src={workspace},dst=/results",
        "--mount", f"type=bind,src={launcher},dst=/vibesec/launcher.py,readonly",
        "--mount", f"type=bind,src={plan},dst=/vibesec/plan.json,readonly",
        "--mount", f"type=bind,src={registry},dst=/vibesec/payloads.json,readonly",
    ]
    if authenticated:
        command.append("--interactive")
    command.extend(("--entrypoint", "python", image, "/vibesec/launcher.py", "--plan", "/vibesec/plan.json",
                    "--registry", "/vibesec/payloads.json", "--output", ACTIVE_EVENTS,
                    "--url", f"http://api-target:{port}{base_path}",
                    "--timeout", str(config["request_timeout_seconds"]),
                    "--response-limit", str(config["maximum_response_body_bytes_read"]),
                    "--request-limit", str(config["maximum_request_body_bytes"]),
                    "--seed", str(config["fixed_seed"]),
                    "--safe-methods-only", str(safe_methods_only).lower(),
                    "--authenticated", str(authenticated).lower()))
    return command
