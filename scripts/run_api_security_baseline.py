#!/usr/bin/env python3
"""Run bounded Schemathesis checks against one isolated immutable API image.

Exit codes: 0 completed without policy violation, 1 policy violation,
2 Docker/scanner/runtime failure, and 3 invalid configuration or scanner output.
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
from vibesec.api_security import (  # noqa: E402
    ApiSecurityError, image_digest, load_config, load_target_configuration, normalize_schemathesis_report, operation_index,
    tool_error, trusted_event, validate_base_path, validate_image_reference,
    validate_openapi_schema, validate_port, write_artifacts,
)
from vibesec.authenticated import (  # noqa: E402
    AUTH_ENVIRONMENT_VARIABLE, AuthenticatedSecurityError, consume_bearer_token,
    combine_result_directories, load_configuration, sanitize_diagnostic,
)
from vibesec.capabilities import CapabilityError, load_capabilities_file  # noqa: E402
from vibesec.policy import active_suppressions, evaluate  # noqa: E402
from vibesec.schemathesis_runtime import (  # noqa: E402
    REPORT_FILENAME, trusted_scanner_container_command, validate_private_workspace,
)
from vibesec.strict_json import StrictJSONError, loads_strict  # noqa: E402

READY_SCRIPT = """import sys,urllib.request
url=sys.argv[1]
with urllib.request.urlopen(url,timeout=5) as response:
 response.read(1)
 if response.status < 100 or response.status > 599: raise SystemExit(3)
"""


def run(command: list[str], *, timeout: int, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, input=input_text, stdin=subprocess.DEVNULL if input_text is None else None,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)


def security_flags(config: dict[str, object], *, tmpfs: int) -> list[str]:
    return ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
            "--cpus", str(config["container_cpu_limit"]), "--memory", f"{config['container_memory_megabytes']}m",
            "--pids-limit", str(config["container_pid_limit"]),
            "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={tmpfs}m"]


def parse_bool(value: str) -> bool:
    if value.casefold() == "true":
        return True
    if value.casefold() == "false":
        return False
    raise ApiSecurityError("safe-methods-only must be true or false")


def _write_state(results: Path, *, root: Path, state: str, reason: str, event: str,
                 digest: str | None, schema: str | None, port: int, base_path: str,
                 safe: bool, findings: list[dict[str, object]], started: float,
                 operations: int, code: int, enforcement: str, severity: str,
                 authenticated: bool = False, authentication_applied: bool | None = None) -> None:
    write_artifacts(results, root=root, state=state, reason=reason, event=event, digest=digest,
                    schema_source=schema, port=port, base_path=base_path, safe_methods_only=safe,
                    findings=findings, duration_seconds=int(time.monotonic() - started),
                    operation_count=operations, exit_code=code, enforcement=enforcement,
                    minimum_severity=severity, authenticated=authenticated,
                    authentication_applied=authentication_applied)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--vibesec-root", type=Path, default=ROOT)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--event", default=os.getenv("GITHUB_EVENT_NAME", "workflow_dispatch"))
    parser.add_argument("--schema", default=os.getenv("VIBESEC_API_SCHEMA_PATH", ""))
    parser.add_argument("--image-reference", default=os.getenv("VIBESEC_API_IMAGE_REFERENCE", ""))
    parser.add_argument("--container-port", default=os.getenv("VIBESEC_API_CONTAINER_PORT", "8080"))
    parser.add_argument("--base-path", default=os.getenv("VIBESEC_API_BASE_PATH", "/"))
    parser.add_argument("--safe-methods-only", default=os.getenv("VIBESEC_API_SAFE_METHODS_ONLY", "true"))
    parser.add_argument("--enforcement", choices=("observe", "new", "all"), default=os.getenv("VIBESEC_API_ENFORCEMENT", "observe"))
    parser.add_argument("--minimum-severity", choices=("low", "medium", "high", "critical"), default=os.getenv("VIBESEC_API_MIN_SEVERITY", "high"))
    parser.add_argument("--authentication-mode", default=os.getenv("VIBESEC_AUTH_MODE", "none"))
    args = parser.parse_args()
    root = args.vibesec_root.resolve()
    repository = args.repository.resolve()
    results = args.results.resolve()
    started = time.monotonic()
    port, base_path, safe = 8080, "/", True
    digest: str | None = None
    schema_source: str | None = args.schema or None
    operations = 0
    authenticated = args.authentication_mode == "bearer"
    token: str | None = None
    if authenticated and os.getenv("VIBESEC_AUTH_SINGLE_RUN") != "1":
        with tempfile.TemporaryDirectory(prefix="vibesec-api-comparison-") as comparison:
            root_directory = Path(comparison)
            unauthenticated_results = root_directory / "unauthenticated"
            authenticated_results = root_directory / "authenticated"
            original = list(sys.argv[1:])
            original[0] = str(unauthenticated_results)
            unauthenticated_environment = os.environ.copy()
            unauthenticated_environment.pop(AUTH_ENVIRONMENT_VARIABLE, None)
            unauthenticated_environment.update({"VIBESEC_AUTH_MODE": "none", "VIBESEC_AUTH_SINGLE_RUN": "1"})
            unauthenticated_run = subprocess.run([sys.executable, str(Path(__file__).resolve()), *original],
                                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                  text=True, env=unauthenticated_environment, check=False)
            original[0] = str(authenticated_results)
            authenticated_environment = os.environ.copy()
            authenticated_environment["VIBESEC_AUTH_SINGLE_RUN"] = "1"
            authenticated_run = subprocess.run([sys.executable, str(Path(__file__).resolve()), *original],
                                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                text=True, env=authenticated_environment, check=False)
            os.environ.pop(AUTH_ENVIRONMENT_VARIABLE, None)
            try:
                return combine_result_directories(
                    unauthenticated_results, authenticated_results, results,
                    unauthenticated_exit_code=unauthenticated_run.returncode,
                    authenticated_exit_code=authenticated_run.returncode,
                )
            except (AuthenticatedSecurityError, OSError, StrictJSONError):
                return 3
    try:
        if args.authentication_mode not in {"none", "bearer"}:
            raise ApiSecurityError("unsupported authenticated API security mode")
        config = load_config(root)
        port = validate_port(args.container_port)
        base_path = validate_base_path(args.base_path)
        safe = parse_bool(args.safe_methods_only)
        capabilities = load_capabilities_file(repository / ".vibesec/project-capabilities.json")
        values = capabilities["capabilities"]
        if authenticated and (not values["authentication"] or not values["authenticated_security_testing"]
                              or not values["api_security_target"]):
            _write_state(results, root=root, state="not_applicable", reason="project capability manifest excludes authenticated API testing",
                         event=args.event, digest=None, schema=schema_source, port=port, base_path=base_path, safe=safe,
                         findings=[], started=started, operations=0, code=0, enforcement=args.enforcement,
                         severity=args.minimum_severity, authenticated=True, authentication_applied=False)
            os.environ.pop(AUTH_ENVIRONMENT_VARIABLE, None)
            return 0
        if not values["api"] or not values["api_security_target"]:
            _write_state(results, root=root, state="not_applicable", reason="project capability manifest excludes an API security target",
                         event=args.event, digest=None, schema=schema_source, port=port, base_path=base_path, safe=safe,
                         findings=[], started=started, operations=0, code=0, enforcement=args.enforcement, severity=args.minimum_severity)
            os.environ.pop(AUTH_ENVIRONMENT_VARIABLE, None)
            return 0
        if authenticated:
            auth_config = load_configuration(repository)
            token = consume_bearer_token()
            if token is None:
                _write_state(results, root=root, state="not_configured", reason=f"GitHub Actions secret {auth_config['secret_name']} is unavailable",
                             event=args.event, digest=None, schema=schema_source, port=port, base_path=base_path, safe=safe,
                             findings=[], started=started, operations=0, code=0, enforcement=args.enforcement,
                             severity=args.minimum_severity, authenticated=True, authentication_applied=False)
                os.environ.pop(AUTH_ENVIRONMENT_VARIABLE, None)
                return 0
        if not trusted_event(args.event):
            _write_state(results, root=root, state="not_configured", reason="API security runtime is disabled on untrusted events",
                         event=args.event, digest=None, schema=schema_source, port=port, base_path=base_path, safe=safe,
                         findings=[], started=started, operations=0, code=0, enforcement=args.enforcement, severity=args.minimum_severity,
                         authenticated=authenticated, authentication_applied=False)
            os.environ.pop(AUTH_ENVIRONMENT_VARIABLE, None)
            return 0
        target_configuration = (load_target_configuration(repository)
                                if (repository / ".vibesec/api-security-baseline.json").exists() else None)
        if target_configuration is not None:
            if not args.schema:
                args.schema = target_configuration["schema_path"]
            if args.container_port == "8080":
                port = validate_port(target_configuration["container_port"])
            if args.base_path == "/":
                base_path = validate_base_path(target_configuration["base_path"])
            if args.safe_methods_only == "true":
                safe = target_configuration["safe_methods_only"]
        schema_source = args.schema or None
        if not args.image_reference or not args.schema:
            missing = "immutable target image" if not args.image_reference else "local OpenAPI schema"
            _write_state(results, root=root, state="not_configured", reason=f"no {missing} configured",
                         event=args.event, digest=None, schema=schema_source, port=port, base_path=base_path, safe=safe,
                         findings=[], started=started, operations=0, code=0, enforcement=args.enforcement, severity=args.minimum_severity,
                         authenticated=authenticated, authentication_applied=False)
            os.environ.pop(AUTH_ENVIRONMENT_VARIABLE, None)
            return 0
        reference = validate_image_reference(args.image_reference)
        digest = image_digest(reference)
        schema_path, schema_payload, operations = validate_openapi_schema(repository, args.schema, config=config, port=port, base_path=base_path)
        schema_operations = operation_index(schema_payload)
        tools = loads_strict((root / "config/tools.json").read_bytes())
        scanner = f"{tools['schemathesis']['image']}@{tools['schemathesis']['digest']}"
        validate_image_reference(scanner)
    except (ApiSecurityError, AuthenticatedSecurityError, CapabilityError, OSError, KeyError, TypeError, ValueError) as exc:
        try:
            _write_state(results, root=root, state="tool_error", reason="invalid API security configuration",
                         event=args.event, digest=digest, schema=schema_source, port=port, base_path=base_path, safe=safe,
                         findings=[tool_error("invalid API security configuration")], started=started,
                         operations=operations, code=3, enforcement=args.enforcement, severity=args.minimum_severity,
                         authenticated=authenticated, authentication_applied=False)
        except Exception:
            pass
        print(f"API security configuration failed closed: {sanitize_diagnostic(str(exc), token)}", file=sys.stderr)
        os.environ.pop(AUTH_ENVIRONMENT_VARIABLE, None)
        return 3
    docker = shutil.which(args.docker) if "/" not in args.docker else args.docker
    if not docker:
        _write_state(results, root=root, state="tool_error", reason="Docker executable unavailable",
                     event=args.event, digest=digest, schema=schema_source, port=port, base_path=base_path, safe=safe,
                     findings=[tool_error("Docker executable unavailable")], started=started,
                     operations=operations, code=2, enforcement=args.enforcement, severity=args.minimum_severity,
                     authenticated=authenticated, authentication_applied=False)
        os.environ.pop(AUTH_ENVIRONMENT_VARIABLE, None)
        return 2
    suffix = secrets.token_hex(8)
    network = f"vibesec-api-net-{suffix}"
    target = f"vibesec-api-target-{suffix}"
    scanner_name = f"vibesec-api-scanner-{suffix}"
    network_created = target_created = scanner_attempted = cleanup_failed = False
    raw: Path | None = None
    temporary: tempfile.TemporaryDirectory[str] | None = None
    findings: list[dict[str, object]] = []
    final_code = 2
    reason = "API security runtime did not complete"
    try:
        for image in (reference, scanner):
            if run([docker, "pull", image], timeout=config["total_scan_timeout_minutes"] * 60).returncode != 0:
                raise RuntimeError("immutable container image pull failed")
        inspected = run([docker, "image", "inspect", "--format", "{{json .Config.User}}", reference], timeout=30)
        if inspected.returncode != 0:
            raise RuntimeError("target image inspection failed")
        try:
            user = json.loads(inspected.stdout.strip())
        except json.JSONDecodeError as exc:
            raise ApiSecurityError("target image user metadata is malformed") from exc
        principal = user.split(":", 1)[0].casefold() if isinstance(user, str) else ""
        if not isinstance(user, str) or not user or principal in {"root", "0"}:
            raise ApiSecurityError("target image declares a root or unspecified user")
        created = run([docker, "network", "create", "--internal", "--label", "org.vibesec.scope=api-security-baseline", network], timeout=30)
        if created.returncode != 0:
            raise RuntimeError("isolated Docker network creation failed")
        network_created = True
        target_command = [docker, "run", "--detach", "--name", target, "--network", network,
                          "--network-alias", "api-target", "--restart", "no",
                          *security_flags(config, tmpfs=config["target_tmpfs_megabytes"]), reference]
        if run(target_command, timeout=60).returncode != 0:
            raise RuntimeError("target API container failed to start")
        target_created = True
        target_url = f"http://api-target:{port}{base_path}"
        deadline = time.monotonic() + config["startup_timeout_seconds"]
        ready = False
        while time.monotonic() < deadline:
            probe = run([docker, "run", "--rm", "--network", network, "--cap-drop", "ALL",
                         "--security-opt", "no-new-privileges", "--read-only", "--pids-limit", "64",
                         "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m", "--entrypoint", "python",
                         scanner, "-c", READY_SCRIPT, target_url], timeout=15)
            if probe.returncode == 0:
                ready = True
                break
            state = run([docker, "inspect", "--format", "{{.State.Running}}", target], timeout=10)
            if state.returncode != 0 or state.stdout.strip() != "true":
                raise RuntimeError("target API container exited before readiness")
            time.sleep(1)
        if not ready:
            raise RuntimeError("target API readiness timed out")
        temporary = tempfile.TemporaryDirectory(prefix="vibesec-api-private-")
        workspace = Path(temporary.name)
        workspace.chmod(0o700)
        raw = workspace / REPORT_FILENAME
        validate_private_workspace(workspace, report_required=False)
        command = trusted_scanner_container_command(docker=docker, container_name=scanner_name,
                                                     network=network, schema=schema_path, workspace=workspace,
                                                     image=scanner, port=port, base_path=base_path,
                                                     config=config, safe_methods_only=safe, authenticated=authenticated)
        scanner_attempted = True
        completed = run(command, timeout=config["total_scan_timeout_minutes"] * 60,
                        input_text=(token + "\n") if authenticated and token is not None else None)
        if completed.returncode not in {0, 1} or not raw.is_file():
            raise RuntimeError("Schemathesis did not produce a completed structured report")
        validate_private_workspace(workspace, report_required=True)
        findings, observed_operations = normalize_schemathesis_report(raw, schema_source=args.schema, operations=schema_operations,
                                                                       maximum_bytes=config["maximum_report_bytes"],
                                                                       maximum_findings=config["maximum_normalized_findings"])
        operations = max(operations, observed_operations)
        raw.unlink()
        if any(workspace.iterdir()):
            raise ApiSecurityError("private Schemathesis evidence survived normalization")
        final_code = 0
        if args.enforcement != "observe":
            baseline = loads_strict((root / "policy/api-security-baseline.json").read_bytes())
            suppressions = loads_strict((root / "policy/api-security-suppressions.json").read_bytes())
            from datetime import date
            active, _ = active_suppressions(suppressions, date.today())
            evaluation = evaluate(findings, minimum_severity=args.minimum_severity, enforcement=args.enforcement,
                                  baseline=set(baseline["fingerprints"]), suppressions=active, today=date.today())
            final_code = 1 if evaluation["violations"] else 0
        reason = "Schemathesis completed and its structured report was validated"
    except ApiSecurityError as exc:
        reason = "API scanner output or configuration was invalid"
        findings = [tool_error(reason)]
        final_code = 3
        print(f"API security validation failed closed: {sanitize_diagnostic(str(exc), token)}", file=sys.stderr)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        reason = str(exc) if isinstance(exc, RuntimeError) else "API runtime infrastructure failed"
        findings = [tool_error(reason)]
        final_code = 2
        print(f"API security runtime failed: {sanitize_diagnostic(reason, token)}", file=sys.stderr)
    finally:
        os.environ.pop(AUTH_ENVIRONMENT_VARIABLE, None)
        if raw is not None:
            raw.unlink(missing_ok=True)
        if temporary is not None:
            temporary.cleanup()
        for command, expected in (([docker, "rm", "-f", scanner_name], scanner_attempted),
                                  ([docker, "rm", "-f", target], target_created),
                                  ([docker, "network", "rm", network], network_created)):
            cleanup = run(command, timeout=30)
            if expected and cleanup.returncode != 0:
                cleanup_failed = True
        if cleanup_failed:
            final_code, reason, findings = 2, "API security cleanup failed", [tool_error("API security cleanup failed")]
    state = "ran" if final_code in {0, 1} else "tool_error"
    _write_state(results, root=root, state=state, reason=reason, event=args.event, digest=digest,
                 schema=schema_source, port=port, base_path=base_path, safe=safe, findings=findings,
                 started=started, operations=operations, code=final_code,
                 enforcement=args.enforcement, severity=args.minimum_severity,
                 authenticated=authenticated, authentication_applied=authenticated and token is not None and scanner_attempted)
    token = None
    return final_code


if __name__ == "__main__":
    raise SystemExit(main())
