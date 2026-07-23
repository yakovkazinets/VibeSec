#!/usr/bin/env python3
"""Run bounded opt-in API fuzzing and injection testing against an isolated target."""

from __future__ import annotations

import argparse
from datetime import date
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from vibesec.api_fuzzing import (  # noqa: E402
    ApiFuzzingError, adapt_contract_findings, build_injection_plan, load_config,
    load_installed_config, load_payload_registry, normalize_events, tool_error, write_artifacts,
)
from vibesec.api_security import (  # noqa: E402
    ApiSecurityError, image_digest, load_config as load_api_config, load_target_configuration,
    normalize_schemathesis_report, operation_index, trusted_event, validate_image_reference,
    validate_openapi_schema,
)
from vibesec.authenticated import (  # noqa: E402
    AUTH_ENVIRONMENT_VARIABLE, AuthenticatedSecurityError, consume_bearer_token, load_configuration,
    sanitize_diagnostic,
)
from vibesec.capabilities import CapabilityError, load_capabilities_file  # noqa: E402
from vibesec.policy import active_suppressions, evaluate  # noqa: E402
from vibesec.schemathesis_runtime import (  # noqa: E402
    REPORT_FILENAME, trusted_active_scanner_container_command, trusted_injection_container_command,
)
from vibesec.strict_json import canonical_json, loads_strict  # noqa: E402

READY_SCRIPT = """import sys,urllib.request
with urllib.request.urlopen(sys.argv[1],timeout=5) as response:
 response.read(1)
 if response.status < 100 or response.status > 599: raise SystemExit(3)
"""


def run(command: list[str], *, timeout: int, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, input=input_text, stdin=subprocess.DEVNULL if input_text is None else None,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)


def security_flags(api_config: dict[str, object], *, tmpfs: int) -> list[str]:
    return ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
            "--cpus", str(api_config["container_cpu_limit"]),
            "--memory", f"{api_config['container_memory_megabytes']}m",
            "--pids-limit", str(api_config["container_pid_limit"]),
            "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={tmpfs}m"]


def write_state(results: Path, *, state: str, reason: str, mode: str, findings: list[dict],
                operations: int, code: int, enforcement: str, severity: str,
                authenticated: bool, authentication_applied: bool, schema: str | None,
                digest: str | None, event: str, safe: bool, config: dict) -> None:
    write_artifacts(results, root=ROOT, state=state, reason=reason, mode=mode, findings=findings,
                    operation_count=operations, exit_code=code, enforcement=enforcement,
                    minimum_severity=severity, authenticated=authenticated,
                    authentication_applied=authentication_applied, schema_source=schema,
                    target_digest=digest, event=event, safe_methods_only=safe, config=config)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--event", default=os.getenv("GITHUB_EVENT_NAME", "workflow_dispatch"))
    parser.add_argument("--image-reference", default=os.getenv("VIBESEC_API_IMAGE_REFERENCE", ""))
    parser.add_argument("--enforcement", choices=("observe", "new", "all"), default=os.getenv("VIBESEC_API_FUZZING_ENFORCEMENT", "observe"))
    parser.add_argument("--minimum-severity", choices=("low", "medium", "high", "critical"), default=os.getenv("VIBESEC_API_FUZZING_MIN_SEVERITY", "high"))
    parser.add_argument("--authentication-mode", default=os.getenv("VIBESEC_AUTH_MODE", "none"))
    args = parser.parse_args()
    repository = args.repository.resolve()
    results = args.results.resolve()
    config = load_config(ROOT)
    mode, safe, schema_source, digest = "contract", True, None, None
    authenticated = args.authentication_mode == "bearer"
    token: str | None = None
    operations = 0
    try:
        if args.authentication_mode not in {"none", "bearer"}:
            raise ApiFuzzingError("unsupported active API authentication mode")
        capabilities = load_capabilities_file(repository / ".vibesec/project-capabilities.json")
        values = capabilities["capabilities"]
        if not values["api_fuzzing_target"]:
            write_state(results, state="not_applicable", reason="project capability manifest excludes bounded active API testing",
                        mode=mode, findings=[], operations=0, code=0, enforcement=args.enforcement,
                        severity=args.minimum_severity, authenticated=authenticated, authentication_applied=False,
                        schema=None, digest=None, event=args.event, safe=True, config=config)
            return 0
        if not (values["api"] and values["api_security_target"] and values["container_image"]):
            raise ApiFuzzingError("api_fuzzing_target dependencies are not satisfied")
        installed = load_installed_config(repository, config)
        mode, safe = installed["mode"], installed["safe_methods_only"]
        if authenticated:
            if not values["authentication"] or not values["authenticated_security_testing"]:
                write_state(results, state="not_applicable", reason="project capability manifest excludes authenticated active API testing",
                            mode=mode, findings=[], operations=0, code=0, enforcement=args.enforcement,
                            severity=args.minimum_severity, authenticated=True, authentication_applied=False,
                            schema=None, digest=None, event=args.event, safe=safe, config=config)
                return 0
            auth_config = load_configuration(repository)
            token = consume_bearer_token()
            if token is None:
                write_state(results, state="not_configured", reason=f"GitHub Actions secret {auth_config['secret_name']} is unavailable",
                            mode=mode, findings=[], operations=0, code=0, enforcement=args.enforcement,
                            severity=args.minimum_severity, authenticated=True, authentication_applied=False,
                            schema=None, digest=None, event=args.event, safe=safe, config=config)
                return 0
        if not trusted_event(args.event):
            write_state(results, state="not_configured", reason="active API testing is disabled on untrusted events",
                        mode=mode, findings=[], operations=0, code=0, enforcement=args.enforcement,
                        severity=args.minimum_severity, authenticated=authenticated, authentication_applied=False,
                        schema=None, digest=None, event=args.event, safe=safe, config=config)
            return 0
        target = load_target_configuration(repository)
        schema_source = target["schema_path"]
        if not args.image_reference:
            write_state(results, state="not_configured", reason="no immutable target image configured",
                        mode=mode, findings=[], operations=0, code=0, enforcement=args.enforcement,
                        severity=args.minimum_severity, authenticated=authenticated, authentication_applied=False,
                        schema=schema_source, digest=None, event=args.event, safe=safe, config=config)
            return 0
        reference = validate_image_reference(args.image_reference)
        digest = image_digest(reference)
        api_config = load_api_config(ROOT)
        schema_path, schema_payload, operations = validate_openapi_schema(
            repository, schema_source, config=api_config, port=target["container_port"], base_path=target["base_path"],
        )
        operation_map = operation_index(schema_payload)
        registry = load_payload_registry(ROOT)
        plan = build_injection_plan(schema_payload, maximum_operations=config["maximum_operations"])
        tools = loads_strict((ROOT / "config/tools.json").read_bytes())
        scanner = f"{tools['schemathesis']['image']}@{tools['schemathesis']['digest']}"
        validate_image_reference(scanner)
    except (ApiFuzzingError, ApiSecurityError, AuthenticatedSecurityError, CapabilityError,
            OSError, KeyError, TypeError, ValueError) as exc:
        try:
            write_state(results, state="tool_error", reason="invalid active API testing configuration", mode=mode,
                        findings=[tool_error("invalid active API testing configuration")], operations=operations,
                        code=3, enforcement=args.enforcement, severity=args.minimum_severity,
                        authenticated=authenticated, authentication_applied=False, schema=schema_source,
                        digest=digest, event=args.event, safe=safe, config=config)
        except Exception:
            pass
        print(f"Active API configuration failed closed: {sanitize_diagnostic(str(exc), token)}", file=sys.stderr)
        os.environ.pop(AUTH_ENVIRONMENT_VARIABLE, None)
        return 3
    docker = shutil.which(args.docker) if "/" not in args.docker else args.docker
    if not docker:
        write_state(results, state="tool_error", reason="Docker executable unavailable", mode=mode,
                    findings=[tool_error("Docker executable unavailable")], operations=operations, code=2,
                    enforcement=args.enforcement, severity=args.minimum_severity, authenticated=authenticated,
                    authentication_applied=False, schema=schema_source, digest=digest, event=args.event,
                    safe=safe, config=config)
        return 2
    suffix = secrets.token_hex(8)
    network = f"vibesec-fuzz-net-{suffix}"
    target_name = f"vibesec-fuzz-target-{suffix}"
    scanner_name = f"vibesec-fuzz-scanner-{suffix}"
    network_created = target_created = scanner_attempted = cleanup_failed = False
    contract_cleanup_needed = injection_cleanup_needed = False
    findings: list[dict] = []
    final_code, reason = 2, "active API runtime did not complete"
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        for image in (reference, scanner):
            if run([docker, "pull", image], timeout=config["total_timeout_minutes"] * 60).returncode != 0:
                raise RuntimeError("immutable container image pull failed")
        inspected = run([docker, "image", "inspect", "--format", "{{json .Config.User}}", reference], timeout=30)
        if inspected.returncode != 0:
            raise RuntimeError("target image inspection failed")
        user = json.loads(inspected.stdout.strip())
        principal = user.split(":", 1)[0].casefold() if isinstance(user, str) else ""
        if not isinstance(user, str) or not user or principal in {"root", "0"}:
            raise ApiFuzzingError("target image declares a root or unspecified user")
        if run([docker, "network", "create", "--internal", "--label", "org.vibesec.scope=api-fuzzing", network], timeout=30).returncode != 0:
            raise RuntimeError("isolated Docker network creation failed")
        network_created = True
        target_command = [docker, "run", "--detach", "--name", target_name, "--network", network,
                          "--network-alias", "api-target", "--restart", "no",
                          *security_flags(api_config, tmpfs=api_config["target_tmpfs_megabytes"]), reference]
        if run(target_command, timeout=60).returncode != 0:
            raise RuntimeError("target API container failed to start")
        target_created = True
        target_url = f"http://api-target:{target['container_port']}{target['base_path']}"
        deadline = time.monotonic() + api_config["startup_timeout_seconds"]
        while True:
            probe = run([docker, "run", "--rm", "--network", network, "--cap-drop", "ALL",
                         "--security-opt", "no-new-privileges", "--read-only", "--pids-limit", "64",
                         "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m", "--entrypoint", "python",
                         scanner, "-c", READY_SCRIPT, target_url], timeout=15)
            if probe.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("target API readiness timed out")
            state = run([docker, "inspect", "--format", "{{.State.Running}}", target_name], timeout=10)
            if state.returncode != 0 or state.stdout.strip() != "true":
                raise RuntimeError("target API container exited before readiness")
            time.sleep(1)
        temporary = tempfile.TemporaryDirectory(prefix="vibesec-fuzz-private-")
        private = Path(temporary.name)
        private.chmod(0o700)
        if mode in {"contract", "fuzz", "combined"}:
            contract = private / "contract"
            contract.mkdir(mode=0o700)
            scanner_attempted = True
            contract_cleanup_needed = True
            command = trusted_active_scanner_container_command(
                docker=docker, container_name=scanner_name, network=network, schema=schema_path,
                workspace=contract, image=scanner, port=target["container_port"], base_path=target["base_path"],
                config=config, mode=mode, safe_methods_only=safe, authenticated=authenticated,
            )
            completed = run(command, timeout=config["total_timeout_minutes"] * 60,
                            input_text=(token + "\n") if authenticated and token is not None else None)
            contract_cleanup_needed = False
            raw = contract / REPORT_FILENAME
            if completed.returncode not in {0, 1} or not raw.is_file():
                raise RuntimeError("Schemathesis did not produce a completed active API report")
            contract_findings, observed = normalize_schemathesis_report(
                raw, schema_source=schema_source, operations=operation_map,
                maximum_bytes=config["maximum_raw_report_bytes"], maximum_findings=config["maximum_normalized_findings"],
            )
            findings.extend(adapt_contract_findings(contract_findings, mode=mode, authenticated=authenticated,
                                                     replay_seed=config["fixed_seed"]))
            operations = max(operations, observed)
            raw.unlink()
        if mode in {"injection", "combined"}:
            injection = private / "injection"
            injection.mkdir(mode=0o700)
            plan_path = private / "plan.json"
            plan_path.write_bytes(canonical_json(plan))
            plan_path.chmod(0o600)
            scanner_attempted = True
            injection_cleanup_needed = True
            command = trusted_injection_container_command(
                docker=docker, container_name=scanner_name + "-injection", network=network,
                workspace=injection, image=scanner, launcher=ROOT / "scripts/vibesec/api_fuzzing_launcher.py",
                plan=plan_path, registry=ROOT / "config/injection-payloads.json",
                port=target["container_port"], base_path=target["base_path"], config=config,
                safe_methods_only=safe, authenticated=authenticated,
            )
            completed = run(command, timeout=config["total_timeout_minutes"] * 60,
                            input_text=(token + "\n") if authenticated and token is not None else None)
            injection_cleanup_needed = False
            raw = injection / "fuzzing-events.ndjson"
            if completed.returncode != 0 or not raw.is_file():
                raise RuntimeError("trusted injection launcher did not produce completed evidence")
            injection_findings, observed, runtime_failure = normalize_events(
                raw, schema_source=schema_source, mode="injection", registry=registry,
                maximum_bytes=config["maximum_raw_report_bytes"], maximum_findings=config["maximum_normalized_findings"],
            )
            raw.unlink()
            operations = max(operations, observed)
            if runtime_failure:
                raise RuntimeError("active API request timed out or the target connection terminated")
            findings.extend(injection_findings)
        findings = sorted({item["fingerprint"]: item for item in findings}.values(),
                          key=lambda item: (item.get("operation_id", ""), item["rule_id"], item["fingerprint"]))
        if len(findings) > config["maximum_normalized_findings"]:
            raise ApiFuzzingError("combined active API findings exceed the hard ceiling")
        final_code = 0
        if args.enforcement != "observe":
            baseline = loads_strict((ROOT / "policy/api-fuzzing-baseline.json").read_bytes())
            suppressions = loads_strict((ROOT / "policy/api-fuzzing-suppressions.json").read_bytes())
            active, _ = active_suppressions(suppressions, date.today())
            evaluation = evaluate(findings, minimum_severity=args.minimum_severity, enforcement=args.enforcement,
                                  baseline=set(baseline["fingerprints"]), suppressions=active, today=date.today())
            final_code = 1 if evaluation["violations"] else 0
        reason = "bounded active API testing completed and structured evidence was validated"
    except (ApiFuzzingError, ApiSecurityError) as exc:
        final_code, reason, findings = 3, "active API scanner evidence or configuration was invalid", [tool_error("active API scanner evidence or configuration was invalid")]
        print(f"Active API validation failed closed: {sanitize_diagnostic(str(exc), token)}", file=sys.stderr)
    except (OSError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        final_code = 2
        reason = str(exc) if isinstance(exc, RuntimeError) else "active API runtime infrastructure failed"
        findings = [tool_error(reason)]
        print(f"Active API runtime failed: {sanitize_diagnostic(reason, token)}", file=sys.stderr)
    finally:
        os.environ.pop(AUTH_ENVIRONMENT_VARIABLE, None)
        if temporary is not None:
            temporary.cleanup()
        for command, expected in (([docker, "rm", "-f", scanner_name], contract_cleanup_needed),
                                  ([docker, "rm", "-f", scanner_name + "-injection"], injection_cleanup_needed),
                                  ([docker, "rm", "-f", target_name], target_created),
                                  ([docker, "network", "rm", network], network_created)):
            cleanup = run(command, timeout=30)
            if expected and cleanup.returncode != 0:
                cleanup_failed = True
        if cleanup_failed:
            final_code, reason, findings = 2, "active API cleanup failed", [tool_error("active API cleanup failed")]
    state = "ran" if final_code in {0, 1} else "tool_error"
    write_state(results, state=state, reason=reason, mode=mode, findings=findings, operations=operations,
                code=final_code, enforcement=args.enforcement, severity=args.minimum_severity,
                authenticated=authenticated, authentication_applied=authenticated and token is not None and scanner_attempted,
                schema=schema_source, digest=digest, event=args.event, safe=safe, config=config)
    token = None
    return final_code


if __name__ == "__main__":
    raise SystemExit(main())
