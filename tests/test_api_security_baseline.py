import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.vibesec.api_security import (
    ApiSecurityError, CHECKS, load_config, normalize_schemathesis_report,
    operation_index, validate_openapi_schema,
)
from scripts.vibesec.capabilities import all_capabilities, capability_bytes, scanner_applicability
from scripts.vibesec.schemathesis_runtime import trusted_schemathesis_command, trusted_scanner_container_command

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/security-fixtures/api-security"
IMAGE = "registry.example/api@sha256:" + "a" * 64

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json,os,pathlib,sys
args=sys.argv[1:]
with pathlib.Path(os.environ["FAKE_API_LOG"]).open("a",encoding="utf-8") as stream: stream.write(json.dumps(args)+"\n")
mode=os.environ.get("FAKE_API_MODE","success")
if args[:1] == ["pull"]: raise SystemExit(1 if mode == "pull_fail" else 0)
if args[:3] == ["image","inspect","--format"]:
 print(json.dumps("" if mode == "root" else "1000:1000")); raise SystemExit(0)
if args[:2] == ["network","create"]: raise SystemExit(1 if mode == "network_fail" else 0)
if args[:2] == ["network","rm"]: raise SystemExit(1 if mode == "cleanup_fail" else 0)
if args[:2] == ["inspect","--format"]: print("true"); raise SystemExit(0)
if args[:2] == ["rm","-f"]: raise SystemExit(1 if mode == "cleanup_fail" else 0)
if args[:1] == ["run"]:
 if "--detach" in args: print("fixture-id"); raise SystemExit(0)
 if "--entrypoint" in args: raise SystemExit(0)
 if "--report-ndjson-path" in args:
  mount=next(value for value in args if value.startswith("type=bind,src=") and value.endswith(",dst=/results"))
  directory=pathlib.Path(next(part.split("=",1)[1] for part in mount.split(",") if part.startswith("src=")))
  if mode != "missing_report": (directory/"schemathesis.ndjson").write_bytes(pathlib.Path(os.environ["FAKE_API_REPORT"]).read_bytes())
  raise SystemExit(1 if os.environ.get("FAKE_API_CASE","positive") == "positive" else 0)
raise SystemExit(0)
'''


class ApiSecurityBaselineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.docker = self.work / "docker"
        self.docker.write_text(FAKE_DOCKER, encoding="utf-8")
        self.docker.chmod(0o755)
        self.log = self.work / "docker.log"

    def repository(self, *, applicable=True) -> Path:
        repository = self.work / f"repo-{len(list(self.work.glob('repo-*')))}"
        (repository / ".vibesec").mkdir(parents=True)
        payload = all_capabilities(False)
        if applicable:
            payload["capabilities"].update({"api": True, "container_image": True, "api_security_target": True})
        (repository / ".vibesec/project-capabilities.json").write_bytes(capability_bytes(payload))
        (repository / "openapi.yaml").write_bytes((FIXTURE / "openapi.yaml").read_bytes())
        return repository

    def run_profile(self, case="positive", *, mode="success", applicable=True, safe="true"):
        repository = self.repository(applicable=applicable)
        results = self.work / f"results-{len(list(self.work.glob('results-*')))}"
        environment = {key: value for key, value in os.environ.items() if not key.startswith(("FAKE_API_", "VIBESEC_API_"))}
        environment.update({"FAKE_API_LOG": str(self.log), "FAKE_API_MODE": mode, "FAKE_API_CASE": case,
                            "FAKE_API_REPORT": str(FIXTURE / case / "raw.ndjson")})
        completed = subprocess.run([
            sys.executable, "scripts/run_api_security_baseline.py", str(results), "--repository", str(repository),
            "--docker", str(self.docker), "--event", "workflow_dispatch", "--schema", "openapi.yaml",
            "--image-reference", IMAGE, "--container-port", "8080", "--base-path", "/",
            "--safe-methods-only", safe, "--enforcement", "observe",
        ], cwd=ROOT, env=environment, text=True, capture_output=True, check=False)
        return completed, results

    def test_schema_validator_accepts_openapi_30_and_31_and_bounds_operations(self):
        config = load_config(ROOT)
        for version in ("3.0.3", "3.1.0"):
            repository = self.repository()
            schema = (repository / "openapi.yaml").read_text().replace("3.1.0", version)
            (repository / "openapi.yaml").write_text(schema)
            _, payload, operations = validate_openapi_schema(repository, "openapi.yaml", config=config, port=8080, base_path="/")
            self.assertEqual(payload["openapi"], version)
            self.assertEqual(operations, 5)

    def test_schema_rejects_remote_refs_servers_callbacks_webhooks_aliases_and_swagger(self):
        config = load_config(ROOT)
        cases = {
            "remote-ref": "$ref: https://example.invalid/schema.json",
            "dynamic-ref": "$dynamicRef: '#/$defs/item'",
            "recursive-ref": "$recursiveRef: '#'",
            "schema-id": "$id: https://example.invalid/schema.json",
            "external-value": "externalValue: https://example.invalid/example.json",
            "server": "servers:\n  - url: https://example.invalid",
            "callback": "callbacks: {}",
            "external": "externalDocs:\n  url: https://example.invalid",
        }
        for name, insertion in cases.items():
            repository = self.repository()
            text = (repository / "openapi.yaml").read_text() + f"\n{insertion}\n"
            (repository / "openapi.yaml").write_text(text)
            with self.subTest(name=name), self.assertRaises(ApiSecurityError):
                validate_openapi_schema(repository, "openapi.yaml", config=config, port=8080, base_path="/")
        repository = self.repository()
        (repository / "openapi.yaml").write_text("openapi: 3.1.0\ninfo: &i {title: x, version: x}\npaths: {}\nx: *i\n")
        with self.assertRaises(ApiSecurityError):
            validate_openapi_schema(repository, "openapi.yaml", config=config, port=8080, base_path="/")
        repository = self.repository()
        (repository / "openapi.yaml").write_text("swagger: '2.0'\ninfo: {title: x, version: x}\npaths: {}\n")
        with self.assertRaises(ApiSecurityError):
            validate_openapi_schema(repository, "openapi.yaml", config=config, port=8080, base_path="/")

    def test_normalization_is_structured_sanitized_and_unknown_checks_fail_closed(self):
        _, payload, _ = validate_openapi_schema(FIXTURE, "openapi.yaml", config=load_config(ROOT), port=8080, base_path="/")
        index = operation_index(payload)
        findings, count = normalize_schemathesis_report(FIXTURE / "positive/raw.ndjson", schema_source="openapi.yaml", operations=index,
                                                        maximum_bytes=10_485_760, maximum_findings=1000)
        self.assertEqual(count, 1)
        self.assertEqual([(item["rule_id"], item["severity"], item["operation_id"]) for item in findings],
                         [("response_schema_conformance", "high", "getControlledDefect")])
        serialized = json.dumps(findings).casefold()
        for prohibited in ("must-not-survive", "sensitive response", "set-cookie", "http://"):
            self.assertNotIn(prohibited, serialized)
        clean, count = normalize_schemathesis_report(FIXTURE / "negative/raw.ndjson", schema_source="openapi.yaml", operations=index,
                                                     maximum_bytes=10_485_760, maximum_findings=1000)
        self.assertEqual((clean, count), ([], 1))
        raw = (FIXTURE / "positive/raw.ndjson").read_text().replace("response_schema_conformance", "future_check")
        path = self.work / "unknown.ndjson"; path.write_text(raw)
        with self.assertRaisesRegex(ApiSecurityError, "unreviewed"):
            normalize_schemathesis_report(path, schema_source="openapi.yaml", operations=index, maximum_bytes=10_485_760, maximum_findings=1000)
        for event in (
            {"NonFatalError": {"value": "private diagnostic"}},
            {"FatalError": {"value": "private diagnostic"}},
            {"Interrupted": {}},
            {"EngineFinished": {"stop_reason": "interrupted"}},
            {"EngineFinished": {"stop_reason": "completed", "failures": [{"value": "private"}]}},
        ):
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            with self.subTest(event=next(iter(event))), self.assertRaises(ApiSecurityError):
                normalize_schemathesis_report(path, schema_source="openapi.yaml", operations=index,
                                               maximum_bytes=10_485_760, maximum_findings=1000)

    def test_reviewed_check_severity_mapping_is_fixed(self):
        self.assertEqual({key: value[0] for key, value in CHECKS.items()}, {
            "not_a_server_error": "high", "status_code_conformance": "medium",
            "content_type_conformance": "medium", "response_schema_conformance": "high",
            "negative_data_rejection": "medium", "positive_data_acceptance": "medium",
        })

    def test_command_is_bounded_deterministic_stateless_and_safe_by_default(self):
        config = load_config(ROOT)
        command = trusted_schemathesis_command(port=8080, base_path="/", config=config, safe_methods_only=True)
        flattened = " ".join(command)
        for expected in ("--phases examples,coverage,fuzzing", "--mode all", "--workers 1", "--max-examples 20",
                         "--max-failures 20", "--request-timeout 5", "--generation-deterministic",
                         "--generation-database none", "--report ndjson"):
            self.assertIn(expected, flattened)
        for forbidden in ("stateful", "--header", "--auth", "--hooks", "--config", "--proxy", "--report-junit"):
            self.assertNotIn(forbidden, flattened)
        self.assertEqual([command[index + 1] for index, item in enumerate(command) if item == "--include-method"], ["GET", "HEAD", "OPTIONS"])
        unsafe = trusted_schemathesis_command(port=8080, base_path="/", config=config, safe_methods_only=False)
        self.assertNotIn("--include-method", unsafe)

    def test_container_command_uses_immutable_image_internal_network_and_two_mounts(self):
        config = load_config(ROOT)
        command = trusted_scanner_container_command(docker="docker", container_name="scanner", network="internal",
                                                     schema=FIXTURE / "openapi.yaml", workspace=self.work,
                                                     image="ghcr.io/schemathesis/schemathesis@sha256:" + "b" * 64,
                                                     port=8080, base_path="/", config=config, safe_methods_only=True)
        flattened = " ".join(map(str, command))
        for expected in ("--cap-drop ALL", "no-new-privileges", "--read-only", "SCHEMATHESIS_COVERAGE=false", "SCHEMATHESIS_HOOKS="):
            self.assertIn(expected, flattened)
        self.assertEqual(command.count("--mount"), 2)
        for forbidden in ("--publish", "--privileged", "/var/run/docker.sock", "--network host", "--env-file"):
            self.assertNotIn(forbidden, flattened)

    def test_production_and_accountability_share_the_closed_command_builder(self):
        production = (ROOT / "scripts/run_api_security_baseline.py").read_text(encoding="utf-8")
        accountability = (ROOT / "scripts/test_api_security_container.py").read_text(encoding="utf-8")
        for source in (production, accountability):
            self.assertIn("trusted_scanner_container_command(", source)
        self.assertIn("tests/security-fixtures/api-security", accountability)
        self.assertIn('"--internal"', accountability)
        self.assertNotIn("http://127.0.0.1", accountability)

    def test_complete_orchestration_positive_negative_and_raw_deletion(self):
        positive, results = self.run_profile("positive")
        self.assertEqual(positive.returncode, 0, positive.stderr)
        normalized = json.loads((results / "normalized.json").read_text())
        self.assertEqual([item["rule_id"] for item in normalized["results"]], ["response_schema_conformance"])
        self.assertFalse(any(path.name.endswith(".ndjson") for path in results.iterdir()))
        self.assertEqual(
            {path.name for path in results.iterdir()},
            {"normalized.json", "coverage.json", "policy-result.json", "report.md",
             "finding-groups.json", "prioritized-findings.json"},
        )
        self.assertEqual(len(json.loads((results / "finding-groups.json").read_text())["groups"]), 1)
        self.assertEqual(subprocess.run([sys.executable, "scripts/validate_api_security_artifacts.py", "--results", str(results), "--expect-state", "ran"], cwd=ROOT).returncode, 0)
        groups_bytes = (results / "finding-groups.json").read_bytes()
        (results / "finding-groups.json").unlink()
        missing_intelligence = subprocess.run(
            [sys.executable, "scripts/validate_api_security_artifacts.py", "--results", str(results), "--expect-state", "ran"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(missing_intelligence.returncode, 3)
        (results / "finding-groups.json").write_bytes(groups_bytes)
        negative, clean_results = self.run_profile("negative")
        self.assertEqual(negative.returncode, 0, negative.stderr)
        self.assertEqual(json.loads((clean_results / "normalized.json").read_text())["results"], [])
        self.assertEqual(json.loads((clean_results / "finding-groups.json").read_text())["groups"], [])
        self.assertEqual(json.loads((clean_results / "prioritized-findings.json").read_text())["groups"], [])

    def test_tool_and_parser_failures_are_not_clean_and_exit_contract_is_preserved(self):
        for mode, expected in (("pull_fail", 2), ("missing_report", 2), ("root", 3), ("cleanup_fail", 2)):
            completed, results = self.run_profile(mode=mode)
            self.assertEqual(completed.returncode, expected, (mode, completed.stderr))
            policy = json.loads((results / "policy-result.json").read_text())
            self.assertFalse(policy["clean"])
            self.assertEqual(policy["exit_code"], expected)
            self.assertEqual(json.loads((results / "finding-groups.json").read_text())["groups"], [])

    def test_runtime_commands_enforce_internal_alias_and_no_host_ports(self):
        completed, _ = self.run_profile()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        commands = [json.loads(line) for line in self.log.read_text().splitlines()]
        network = next(command for command in commands if command[:2] == ["network", "create"])
        self.assertIn("--internal", network)
        target = next(command for command in commands if command[:1] == ["run"] and "--detach" in command)
        self.assertEqual(target[target.index("--network-alias") + 1], "api-target")
        self.assertNotIn("--publish", target)
        scanner = next(command for command in commands if "--report-ndjson-path" in command)
        self.assertIn("--network", scanner)
        self.assertNotIn("--network=host", scanner)

    def test_vibesec_is_not_applicable_and_never_invokes_docker(self):
        payload = json.loads((ROOT / ".vibesec/project-capabilities.json").read_text())
        self.assertFalse(payload["capabilities"]["api"])
        self.assertFalse(payload["capabilities"]["api_security_target"])
        self.assertEqual(scanner_applicability(payload)["api-security-baseline"]["state"], "not_applicable")
        completed, results = self.run_profile(applicable=False)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(json.loads((results / "coverage.json").read_text())["state"], "not_applicable")
        self.assertFalse(json.loads((results / "policy-result.json").read_text())["clean"])
        self.assertEqual(json.loads((results / "finding-groups.json").read_text())["groups"], [])
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
