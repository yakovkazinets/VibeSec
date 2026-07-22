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


def trusted_schemathesis_command(*, port: int, base_path: str, config: dict[str, Any], safe_methods_only: bool) -> list[str]:
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
        "--report", "ndjson", "--report-ndjson-path", CONTAINER_REPORT, "--no-color",
    ]
    if safe_methods_only:
        for method in config["safe_methods"]:
            command.extend(("--include-method", method))
    return command


def trusted_scanner_container_command(*, docker: str, container_name: str, network: str,
                                      schema: Path, workspace: Path, image: str,
                                      port: int, base_path: str, config: dict[str, Any],
                                      safe_methods_only: bool) -> list[str]:
    return [
        docker, "run", "--rm", "--name", container_name, "--network", network,
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
        "--cpus", str(config["container_cpu_limit"]), "--memory", f"{config['container_memory_megabytes']}m",
        "--pids-limit", str(config["container_pid_limit"]),
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={config['scanner_tmpfs_megabytes']}m",
        "--workdir", "/results", "--env", "SCHEMATHESIS_COVERAGE=false", "--env", "SCHEMATHESIS_HOOKS=",
        "--mount", f"type=bind,src={schema},dst={CONTAINER_SCHEMA},readonly",
        "--mount", f"type=bind,src={workspace},dst=/results",
        image, *trusted_schemathesis_command(port=port, base_path=base_path, config=config, safe_methods_only=safe_methods_only),
    ]
