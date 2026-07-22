"""Closed Schemathesis and Docker command builders shared by production and tests."""

from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Any

from .api_security import ApiSecurityError

REPORT_FILENAME = "schemathesis.ndjson"
CONTAINER_SCHEMA = "/schema/openapi.yaml"
CONTAINER_REPORT = "/results/schemathesis.ndjson"
CONTAINER_RAW_REPORT = "/scanner-raw/schemathesis.ndjson"
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
    command = [
        docker, "run", "--rm", "--name", container_name, "--network", network,
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
        "--cpus", str(config["container_cpu_limit"]), "--memory", f"{config['container_memory_megabytes']}m",
        "--pids-limit", str(config["container_pid_limit"]),
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={config['scanner_tmpfs_megabytes']}m",
        "--workdir", "/results", "--env", "SCHEMATHESIS_COVERAGE=false", "--env", "SCHEMATHESIS_HOOKS=",
        "--mount", f"type=bind,src={schema},dst={CONTAINER_SCHEMA},readonly",
        "--mount", f"type=bind,src={workspace},dst=/results",
    ]
    scanner = trusted_schemathesis_command(port=port, base_path=base_path, config=config,
                                           safe_methods_only=safe_methods_only, authenticated=authenticated)
    if authenticated:
        command.extend(("--tmpfs", f"/scanner-raw:rw,noexec,nosuid,nodev,size={config['scanner_tmpfs_megabytes']}m",
                        "--interactive", "--entrypoint", "python", image, "-c", AUTHENTICATED_LAUNCHER, *scanner))
    else:
        command.extend((image, *scanner))
    return command
