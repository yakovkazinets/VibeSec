import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.vibesec.api_fuzzing import (
    ApiFuzzingError, build_injection_plan, default_installed_config, load_config, load_payload_registry,
    normalize_events, validate_installed_config, validate_payload_registry, write_artifacts,
)
from scripts.vibesec.authenticated import AUTH_ENVIRONMENT_VARIABLE, configuration_bytes
from scripts.vibesec.capabilities import all_capabilities, capability_bytes, scanner_applicability
from scripts.vibesec.schemathesis_runtime import (
    trusted_active_schemathesis_command, trusted_active_scanner_container_command,
    trusted_injection_container_command,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/security-fixtures/api-fuzzing"
API_FIXTURE = ROOT / "tests/security-fixtures/api-security"
IMAGE = "registry.example/api@sha256:" + "a" * 64

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json,os,pathlib,sys
args=sys.argv[1:]
with pathlib.Path(os.environ["FAKE_FUZZ_LOG"]).open("a",encoding="utf-8") as stream: stream.write(json.dumps(args)+"\n")
mode=os.environ.get("FAKE_FUZZ_MODE","success")
if args[:1] == ["pull"]: raise SystemExit(1 if mode == "pull_fail" else 0)
if args[:3] == ["image","inspect","--format"]: print(json.dumps("1000:1000")); raise SystemExit(0)
if args[:2] == ["network","create"]: raise SystemExit(0)
if args[:2] == ["network","rm"]: raise SystemExit(0)
if args[:2] == ["inspect","--format"]: print("true"); raise SystemExit(0)
if args[:2] == ["rm","-f"]: raise SystemExit(0)
if args[:1] == ["run"]:
 if "--detach" in args: print("fixture-id"); raise SystemExit(0)
 if "-c" in args and "/vibesec/launcher.py" not in args: raise SystemExit(0)
 mounts=[value for value in args if value.startswith("type=bind,src=")]
 result_mount=next(value for value in mounts if value.endswith(",dst=/results"))
 directory=pathlib.Path(next(part.split("=",1)[1] for part in result_mount.split(",") if part.startswith("src=")))
 if "/vibesec/launcher.py" in args:
  (directory/"fuzzing-events.ndjson").write_bytes(pathlib.Path(os.environ["FAKE_FUZZ_EVENTS"]).read_bytes())
  raise SystemExit(0)
 if "--report-ndjson-path" in args:
  if mode == "malformed_report": (directory/"schemathesis.ndjson").write_text("not-json\n",encoding="utf-8")
  else: (directory/"schemathesis.ndjson").write_bytes(pathlib.Path(os.environ["FAKE_FUZZ_CONTRACT"]).read_bytes())
  raise SystemExit(1)
raise SystemExit(0)
'''


class ApiFuzzingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)

    def repository(self, *, applicable=True, authenticated=False, mode="combined") -> Path:
        repository = self.work / f"repository-{len(list(self.work.glob('repository-*')))}"
        (repository / ".vibesec").mkdir(parents=True)
        capabilities = all_capabilities(False)
        if applicable:
            capabilities["capabilities"].update({
                "api": True, "container_image": True, "api_security_target": True,
                "api_fuzzing_target": True,
            })
        if authenticated:
            capabilities["capabilities"].update({"authentication": True, "authenticated_security_testing": True})
            (repository / ".vibesec/authenticated-security-testing.json").write_bytes(configuration_bytes("FIXTURE_BEARER"))
        (repository / ".vibesec/project-capabilities.json").write_bytes(capability_bytes(capabilities))
        (repository / "openapi.yaml").write_bytes((API_FIXTURE / "openapi.yaml").read_bytes())
        (repository / ".vibesec/api-security-baseline.json").write_text(json.dumps({
            "schema_version": 1, "schema_path": "openapi.yaml", "image_variable_name": "VIBESEC_API_IMAGE_REFERENCE",
            "container_port": 8080, "base_path": "/", "safe_methods_only": True,
            "authentication": False, "custom_headers": False, "external_target_url": None,
        }) + "\n")
        active = default_installed_config()
        active["mode"] = mode
        active["fuzzing_enabled"] = mode in {"fuzz", "combined"}
        active["injection_testing_enabled"] = mode in {"injection", "combined"}
        (repository / ".vibesec/api-fuzzing.json").write_text(json.dumps(active) + "\n")
        return repository

    def test_defaults_are_contract_only_safe_and_bounded(self):
        trusted = load_config(ROOT)
        installed = validate_installed_config(default_installed_config(), trusted)
        self.assertEqual(installed["mode"], "contract")
        self.assertTrue(installed["safe_methods_only"])
        self.assertFalse(installed["mutating_methods_enabled"])
        self.assertFalse(installed["fuzzing_enabled"])
        self.assertFalse(installed["injection_testing_enabled"])
        self.assertEqual(trusted["workers"], 1)
        self.assertLessEqual(trusted["maximum_request_body_bytes"], 65_536)
        self.assertLessEqual(trusted["maximum_response_body_bytes_read"], 262_144)

    def test_modes_require_explicit_opt_in_and_hard_ceilings(self):
        trusted = load_config(ROOT)
        for mode, field in (("fuzz", "fuzzing_enabled"), ("injection", "injection_testing_enabled")):
            payload = default_installed_config()
            payload["mode"] = mode
            with self.assertRaises(ApiFuzzingError):
                validate_installed_config(payload, trusted)
            payload[field] = True
            self.assertEqual(validate_installed_config(payload, trusted)["mode"], mode)
        combined = default_installed_config()
        combined.update({"mode": "combined", "fuzzing_enabled": True, "injection_testing_enabled": True})
        self.assertEqual(validate_installed_config(combined, trusted)["mode"], "combined")
        for field in ("max_examples_per_operation", "max_failures", "request_timeout_seconds", "total_timeout_minutes"):
            excessive = copy.deepcopy(combined)
            excessive[field] = trusted[field] + 1
            with self.subTest(field=field), self.assertRaisesRegex(ApiFuzzingError, "ceiling"):
                validate_installed_config(excessive, trusted)

    def test_mutating_methods_are_separate_explicit_opt_in(self):
        trusted = load_config(ROOT)
        payload = default_installed_config()
        payload["safe_methods_only"] = False
        with self.assertRaises(ApiFuzzingError):
            validate_installed_config(payload, trusted)
        payload["mutating_methods_enabled"] = True
        self.assertFalse(validate_installed_config(payload, trusted)["safe_methods_only"])

    def test_prohibited_configuration_fails_closed(self):
        trusted = load_config(ROOT)
        for field, value in (
            ("stateful_testing", True), ("auth_header_fuzzing", True), ("raw_body_artifacts", True),
            ("custom_payload_path", "payloads.txt"), ("external_target_url", "https://example.invalid"),
        ):
            payload = default_installed_config()
            payload[field] = value
            with self.subTest(field=field), self.assertRaises(ApiFuzzingError):
                validate_installed_config(payload, trusted)

    def test_payload_registry_is_exact_bounded_and_non_destructive(self):
        registry = load_payload_registry(ROOT)
        self.assertEqual([item["family_id"] for item in registry["families"]], [
            "command-marker", "header-marker", "path-marker", "sql-marker", "template-marker",
        ])
        serialized = "\n".join(item["payload"] for item in registry["families"]).casefold()
        for prohibited in ("http://", "https://", "drop table", "delete from", "/bin/sh", "powershell", "authorization", "bearer"):
            self.assertNotIn(prohibited, serialized)
        unknown = copy.deepcopy(registry)
        unknown["families"][0]["family_id"] = "unknown-family"
        with self.assertRaises(ApiFuzzingError):
            validate_payload_registry(unknown)

    def test_positive_negative_and_runtime_failure_normalization(self):
        registry = load_payload_registry(ROOT)
        positive, operations, failure = normalize_events(
            FIXTURE / "positive/events.ndjson", schema_source="openapi.yaml", mode="combined",
            registry=registry, maximum_bytes=10_485_760, maximum_findings=1000,
        )
        self.assertEqual(len(positive), 3)
        self.assertEqual(operations, 3)
        self.assertFalse(failure)
        self.assertEqual({item["title"] for item in positive}, {
            "API fuzzing contract weakness", "Potential SQL injection handling weakness",
            "Path traversal input handling weakness",
        })
        self.assertTrue(all("payload" not in item and "body" not in item for item in positive))
        negative, operations, failure = normalize_events(
            FIXTURE / "negative/events.ndjson", schema_source="openapi.yaml", mode="combined",
            registry=registry, maximum_bytes=10_485_760, maximum_findings=1000,
        )
        self.assertEqual((negative, operations, failure), ([], 3, False))
        runtime, _, failure = normalize_events(
            FIXTURE / "failure/events.ndjson", schema_source="openapi.yaml", mode="fuzz",
            registry=registry, maximum_bytes=10_485_760, maximum_findings=1000,
        )
        self.assertEqual(runtime, [])
        self.assertTrue(failure)

    def test_raw_or_unknown_fields_and_auth_header_location_fail_closed(self):
        registry = load_payload_registry(ROOT)
        event = json.loads((FIXTURE / "positive/events.ndjson").read_text().splitlines()[1])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.ndjson"
            for field, value in (("request_body", "secret"), ("authorization", "Bearer secret")):
                changed = dict(event)
                changed[field] = value
                path.write_text(json.dumps(changed) + "\n" + json.dumps({"event": "summary", "completed": True, "mode": "combined", "operation_count": 1}) + "\n")
                with self.subTest(field=field), self.assertRaises(ApiFuzzingError):
                    normalize_events(path, schema_source="openapi.yaml", mode="combined", registry=registry,
                                     maximum_bytes=10_485_760, maximum_findings=1000)
            changed = dict(event)
            changed["parameter_location"] = "authorization"
            path.write_text(json.dumps(changed) + "\n" + json.dumps({"event": "summary", "completed": True, "mode": "combined", "operation_count": 1}) + "\n")
            with self.assertRaises(ApiFuzzingError):
                normalize_events(path, schema_source="openapi.yaml", mode="combined", registry=registry,
                                 maximum_bytes=10_485_760, maximum_findings=1000)

    def test_artifacts_publish_no_raw_values_and_policy_states_remain_distinct(self):
        registry = load_payload_registry(ROOT)
        findings, operations, _ = normalize_events(
            FIXTURE / "positive/events.ndjson", schema_source="openapi.yaml", mode="combined",
            registry=registry, maximum_bytes=10_485_760, maximum_findings=1000,
        )
        with tempfile.TemporaryDirectory() as temporary:
            results = Path(temporary)
            write_artifacts(results, root=ROOT, state="ran", reason="controlled fixture", mode="combined",
                            findings=findings, operation_count=operations, exit_code=0, enforcement="observe",
                            minimum_severity="high", authenticated=False, authentication_applied=False,
                            schema_source="openapi.yaml", target_digest="sha256:" + "a" * 64,
                            event="workflow_dispatch", safe_methods_only=True, config=load_config(ROOT))
            self.assertEqual({item.name for item in results.iterdir()}, {
                "fuzzing-coverage.json", "fuzzing-findings.json", "fuzzing-policy-result.json",
                "fuzzing-report.md", "finding-groups.json", "prioritized-findings.json",
            })
            coverage = json.loads((results / "fuzzing-coverage.json").read_text())
            policy = json.loads((results / "fuzzing-policy-result.json").read_text())
            self.assertFalse(coverage["raw_request_bodies_published"])
            self.assertFalse(coverage["raw_response_bodies_published"])
            self.assertFalse(coverage["authorization_header_fuzzed"])
            self.assertTrue(policy["clean"])
            published = b"\n".join(path.read_bytes() for path in results.iterdir())
            self.assertNotIn(b"VIBESEC_SQL_MARKER'\"", published)
            self.assertNotIn(b"Authorization: Bearer", published)

    def test_capability_dependency_and_vibesec_not_applicable(self):
        values = all_capabilities(False)
        values["capabilities"]["api_fuzzing_target"] = True
        with self.assertRaises(Exception):
            capability_bytes(values)
        self_payload = json.loads((ROOT / ".vibesec/project-capabilities.json").read_text())
        self.assertFalse(self_payload["capabilities"].get("api_fuzzing_target", False))
        state = scanner_applicability(self_payload)
        self.assertEqual(state.get("fuzzing-and-injection-testing", {}).get("state"), "not_applicable")

    def test_trusted_commands_are_deterministic_isolated_and_never_fuzz_authorization(self):
        config = load_config(ROOT)
        command = trusted_active_schemathesis_command(port=8080, base_path="/", config=config,
                                                       mode="combined", safe_methods_only=True)
        serialized = "\0".join(command)
        self.assertIn("examples,coverage,fuzzing", command)
        self.assertIn("--generation-deterministic", command)
        self.assertNotIn("stateful", serialized)
        self.assertNotIn("--header", command)
        for method in config["safe_methods"]:
            self.assertIn(method, command)
        private = self.work / "private"
        private.mkdir()
        schema = self.work / "openapi.yaml"
        schema.write_text("openapi: 3.1.0\n")
        active = trusted_active_scanner_container_command(
            docker="docker", container_name="scanner", network="internal", schema=schema,
            workspace=private, image="scanner@sha256:" + "b" * 64, port=8080, base_path="/",
            config=config, mode="fuzz", safe_methods_only=True, authenticated=True,
        )
        plan = self.work / "plan.json"
        registry = ROOT / "config/injection-payloads.json"
        launcher = ROOT / "scripts/vibesec/api_fuzzing_launcher.py"
        injection = trusted_injection_container_command(
            docker="docker", container_name="injection", network="internal", workspace=private,
            image="scanner@sha256:" + "b" * 64, launcher=launcher, plan=plan, registry=registry,
            port=8080, base_path="/", config=config, safe_methods_only=True, authenticated=True,
        )
        for container in (active, injection):
            joined = "\0".join(container)
            self.assertIn("--cap-drop\0ALL", joined)
            self.assertIn("--security-opt\0no-new-privileges", joined)
            self.assertIn("--read-only", container)
            self.assertNotIn("vibesec-obvious-active-fixture-token", joined)
            self.assertNotIn(AUTH_ENVIRONMENT_VARIABLE, joined)
            self.assertNotIn("--network\0host", joined)

    def test_plan_excludes_authentication_headers_and_contains_no_schema_values(self):
        from scripts.vibesec.api_security import load_config as load_api_config, validate_openapi_schema
        repository = self.repository()
        _, schema, _ = validate_openapi_schema(repository, "openapi.yaml", config=load_api_config(ROOT), port=8080, base_path="/")
        plan = build_injection_plan(schema, maximum_operations=200)
        serialized = json.dumps(plan).casefold()
        self.assertNotIn("authorization", serialized)
        self.assertNotIn("bearer", serialized)
        self.assertLessEqual(len(plan["operations"]), 200)

    def test_complete_orchestration_writes_sanitized_artifacts_and_deletes_raw_output(self):
        repository = self.repository()
        docker = self.work / "docker"
        docker.write_text(FAKE_DOCKER)
        docker.chmod(0o700)
        results = self.work / "results"
        environment = os.environ.copy()
        environment.update({
            "FAKE_FUZZ_LOG": str(self.work / "docker.log"),
            "FAKE_FUZZ_EVENTS": str(FIXTURE / "positive/injection-events.ndjson"),
            "FAKE_FUZZ_CONTRACT": str(API_FIXTURE / "positive/raw.ndjson"),
        })
        completed = subprocess.run([
            sys.executable, "scripts/run_api_fuzzing.py", str(results), "--repository", str(repository),
            "--docker", str(docker), "--event", "workflow_dispatch", "--image-reference", IMAGE,
        ], cwd=ROOT, env=environment, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        coverage = json.loads((results / "fuzzing-coverage.json").read_text())
        findings = json.loads((results / "fuzzing-findings.json").read_text())
        self.assertEqual(coverage["state"], "ran")
        self.assertEqual(coverage["mode"], "combined")
        self.assertGreaterEqual(len(findings["results"]), 3)
        self.assertFalse(any(path.name.endswith(".ndjson") for path in results.iterdir()))
        validated = subprocess.run([sys.executable, "scripts/validate_api_fuzzing_artifacts.py", "--results", str(results), "--expect-state", "ran"], cwd=ROOT)
        self.assertEqual(validated.returncode, 0)

    def test_tool_failure_and_authenticated_token_are_redacted_and_blocking(self):
        repository = self.repository(authenticated=True, mode="fuzz")
        docker = self.work / "docker-fail"
        docker.write_text(FAKE_DOCKER)
        docker.chmod(0o700)
        results = self.work / "failed"
        token = "vibesec-obvious-active-fixture-token"
        environment = os.environ.copy()
        environment.update({
            "FAKE_FUZZ_LOG": str(self.work / "docker-fail.log"), "FAKE_FUZZ_MODE": "pull_fail",
            "FAKE_FUZZ_EVENTS": str(FIXTURE / "positive/injection-events.ndjson"),
            "FAKE_FUZZ_CONTRACT": str(API_FIXTURE / "positive/raw.ndjson"),
            AUTH_ENVIRONMENT_VARIABLE: token, "VIBESEC_AUTH_MODE": "bearer",
        })
        completed = subprocess.run([
            sys.executable, "scripts/run_api_fuzzing.py", str(results), "--repository", str(repository),
            "--docker", str(docker), "--event", "workflow_dispatch", "--image-reference", IMAGE,
        ], cwd=ROOT, env=environment, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertNotIn(token, completed.stdout + completed.stderr)
        coverage = json.loads((results / "fuzzing-coverage.json").read_text())
        policy = json.loads((results / "fuzzing-policy-result.json").read_text())
        self.assertEqual(coverage["state"], "tool_error")
        self.assertEqual(policy["exit_code"], 2)
        self.assertFalse(policy["clean"])
        published = b"\n".join(path.read_bytes() for path in results.iterdir())
        self.assertNotIn(token.encode(), published)

    def test_malformed_scanner_evidence_is_invalid_input_not_clean_or_runtime_failure(self):
        repository = self.repository(mode="contract")
        docker = self.work / "docker-malformed"
        docker.write_text(FAKE_DOCKER)
        docker.chmod(0o700)
        results = self.work / "malformed"
        environment = os.environ.copy()
        environment.update({
            "FAKE_FUZZ_LOG": str(self.work / "docker-malformed.log"),
            "FAKE_FUZZ_MODE": "malformed_report",
            "FAKE_FUZZ_EVENTS": str(FIXTURE / "positive/injection-events.ndjson"),
            "FAKE_FUZZ_CONTRACT": str(API_FIXTURE / "positive/raw.ndjson"),
        })
        completed = subprocess.run([
            sys.executable, "scripts/run_api_fuzzing.py", str(results), "--repository", str(repository),
            "--docker", str(docker), "--event", "workflow_dispatch", "--image-reference", IMAGE,
        ], cwd=ROOT, env=environment, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 3, completed.stderr)
        coverage = json.loads((results / "fuzzing-coverage.json").read_text())
        policy = json.loads((results / "fuzzing-policy-result.json").read_text())
        self.assertEqual(coverage["state"], "tool_error")
        self.assertEqual(policy["exit_code"], 3)
        self.assertEqual(policy["exit_category"], "invalid_input")
        self.assertFalse(policy["clean"])


if __name__ == "__main__":
    unittest.main()
