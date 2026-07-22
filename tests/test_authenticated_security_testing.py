import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from vibesec.authenticated import (  # noqa: E402
    AUTH_ENVIRONMENT_VARIABLE, AuthenticatedSecurityError, configuration_bytes,
    combine_result_directories, consume_bearer_token, correlate_findings, redact_bytes, validate_configuration,
    validate_publishable_bytes, validate_secret_name,
)
from vibesec.bundle import build_bundle_bytes  # noqa: E402
from vibesec.capabilities import CapabilityError, all_capabilities, capability_bytes, scanner_applicability  # noqa: E402
from vibesec.dast import load_config as load_dast_config  # noqa: E402
from vibesec.finding_intelligence import SourceDocument, build as build_finding_intelligence  # noqa: E402
from vibesec.schemathesis_runtime import trusted_scanner_container_command, trusted_schemathesis_command  # noqa: E402
from vibesec.zap_automation import build_passive_plan, trusted_zap_container_command  # noqa: E402
from vibesec_doctor import _auth_workflow_problems  # noqa: E402
while str(ROOT / "scripts") in sys.path:
    sys.path.remove(str(ROOT / "scripts"))


def load_fixture(relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(path.stem + "_auth_fixture", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AuthenticatedSecurityTestingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_capability_dependencies_and_vibesec_state_fail_closed(self):
        values = all_capabilities(False)
        values["capabilities"]["authenticated_security_testing"] = True
        with self.assertRaisesRegex(CapabilityError, "authentication"):
            capability_bytes(values)
        values["capabilities"].update({"web_application": True, "authentication": True})
        with self.assertRaisesRegex(CapabilityError, "dast_target"):
            capability_bytes(values)
        self_state = scanner_applicability(json.loads((ROOT / ".vibesec/project-capabilities.json").read_text()))
        self.assertEqual(self_state["authenticated-security-testing"]["state"], "not_applicable")

    def test_only_strict_authorization_bearer_configuration_is_accepted(self):
        self.assertEqual(validate_secret_name("VIBESEC_TEST_BEARER"), "VIBESEC_TEST_BEARER")
        for value in ("", "lowercase", "1TOKEN", "GITHUB_TOKEN", "TOKEN-NAME", "${{ secrets.X }}"):
            with self.subTest(value=value), self.assertRaises(AuthenticatedSecurityError):
                validate_secret_name(value)
        valid = json.loads(configuration_bytes("VIBESEC_TEST_BEARER"))
        self.assertEqual(set(valid), {"schema_version", "secret_name", "header_name", "scheme"})
        for field, value in (("header_name", "X-API-Key"), ("scheme", "Basic")):
            invalid = dict(valid)
            invalid[field] = value
            with self.assertRaisesRegex(AuthenticatedSecurityError, "Authorization: Bearer"):
                validate_configuration(invalid)

    def test_token_is_consumed_redacted_and_never_derived(self):
        token = "vibesec-opaque-test-token"
        environment = {AUTH_ENVIRONMENT_VARIABLE: token}
        self.assertEqual(consume_bearer_token(environment), token)
        self.assertNotIn(AUTH_ENVIRONMENT_VARIABLE, environment)
        redacted = redact_bytes(f"prefix {token} AUTHORIZATION: bearer {token} suffix".encode(), token)
        self.assertNotIn(token.encode(), redacted)
        self.assertNotIn(b"bearer vibesec", redacted.lower())
        for unsafe in (b"Authorization: Bearer residual", b"aaaaaaaa.bbbbbbbb.cccccccc"):
            with self.assertRaises(AuthenticatedSecurityError):
                validate_publishable_bytes(unsafe)

    def test_scanner_commands_keep_token_out_of_arguments_and_docker_environment(self):
        token = "vibesec-opaque-test-token"
        workspace = self.root / "private"
        workspace.mkdir(mode=0o700)
        schema = self.root / "openapi.yaml"
        schema.write_text("openapi: 3.1.0\n", encoding="utf-8")
        config = load_dast_config(ROOT)
        zap = trusted_zap_container_command(docker="docker", container_name="vibesec-auth-zap",
                                            network="vibesec-auth-net", workspace=workspace,
                                            image="scanner@sha256:" + "a" * 64, config=config,
                                            authenticated=True)
        api_config = json.loads((ROOT / "config/api-security-baseline.json").read_text())
        api = trusted_scanner_container_command(docker="docker", container_name="vibesec-auth-api",
                                                network="vibesec-auth-net", schema=schema, workspace=workspace,
                                                image="scanner@sha256:" + "a" * 64, port=8080,
                                                base_path="/", config=api_config, safe_methods_only=True,
                                                authenticated=True)
        for command in (zap, api):
            serialized = "\0".join(command)
            self.assertNotIn(token, serialized)
            self.assertNotIn("Bearer " + token, serialized)
            self.assertIn("--interactive", command)
            self.assertNotIn(AUTH_ENVIRONMENT_VARIABLE, serialized)
            self.assertNotIn("--env\0ZAP_AUTH_HEADER_VALUE", serialized)

    def test_correlation_is_narrow_same_scanner_and_deterministic(self):
        base = {
            "tool": "schemathesis", "rule_id": "response_schema_conformance", "method": "GET",
            "path_template": "/private", "status_class": "2xx",
            "contract_class": "response_schema_conformance", "result_type": "finding",
            "fingerprint": "a" * 64,
        }
        correlated = correlate_findings([base], [{**base, "fingerprint": "b" * 64}])
        self.assertEqual(len(correlated), 1)
        self.assertTrue(correlated[0]["observed_unauthenticated"])
        self.assertTrue(correlated[0]["observed_authenticated"])
        separate = correlate_findings([base], [{**base, "status_class": "4xx", "fingerprint": "c" * 64}])
        self.assertEqual(len(separate), 2)
        cross = correlate_findings([base], [{**base, "tool": "zap-baseline", "fingerprint": "d" * 64}])
        self.assertEqual(len(cross), 2)

    def test_initializer_stores_only_secret_name_and_scopes_exact_reference(self):
        target = self.root / "consumer"
        target.mkdir()
        initialized = subprocess.run(
            [sys.executable, "scripts/init_vibesec.py", "--profile", "minimal", "--target", str(target),
             "--all-capabilities", "--auth-secret-name", "MY_RUNTIME_BEARER", "--write"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(initialized.returncode, 0, initialized.stdout)
        config = json.loads((target / ".vibesec/authenticated-security-testing.json").read_text())
        self.assertEqual(config["secret_name"], "MY_RUNTIME_BEARER")
        self.assertNotIn("token", json.dumps(config).casefold())
        addon = subprocess.run(
            [sys.executable, "scripts/init_vibesec.py", "--addon", "dast-baseline", "--target", str(target), "--write"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(addon.returncode, 0, addon.stdout)
        workflow = (target / ".github/workflows/vibesec-dast-baseline.yml").read_text()
        self.assertEqual(workflow.count("secrets.MY_RUNTIME_BEARER"), 1)
        secret_line = next(line for line in workflow.splitlines() if "secrets.MY_RUNTIME_BEARER" in line)
        self.assertIn(AUTH_ENVIRONMENT_VARIABLE, secret_line)
        checkout = workflow.split("- name: Check out", 1)[1].split("- name: Run isolated", 1)[0]
        upload = workflow.split("- name: Upload sanitized", 1)[1]
        self.assertNotIn("secrets.", checkout)
        self.assertNotIn("secrets.", upload)

    def test_missing_secret_is_not_configured_and_unknown_mode_is_invalid(self):
        repository = self.root / "repository"
        (repository / ".vibesec").mkdir(parents=True)
        capabilities = all_capabilities(False)
        capabilities["capabilities"].update({
            "web_application": True, "container_image": True, "authentication": True,
            "dast_target": True, "authenticated_security_testing": True,
        })
        (repository / ".vibesec/project-capabilities.json").write_bytes(capability_bytes(capabilities))
        (repository / ".vibesec/authenticated-security-testing.json").write_bytes(configuration_bytes("MISSING_BEARER"))
        results = self.root / "results"
        environment = {key: value for key, value in os.environ.items() if key != AUTH_ENVIRONMENT_VARIABLE}
        environment["VIBESEC_AUTH_MODE"] = "bearer"
        completed = subprocess.run(
            [sys.executable, "scripts/run_dast_baseline.py", str(results), "--repository", str(repository)],
            cwd=ROOT, env=environment, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        coverage = json.loads((results / "coverage.json").read_text())
        self.assertEqual(coverage["state"], "not_configured")
        self.assertFalse(coverage["authentication_applied"])
        policy = json.loads((results / "policy-result.json").read_text())
        self.assertFalse(policy["clean"])
        invalid = subprocess.run(
            [sys.executable, "scripts/run_dast_baseline.py", str(self.root / "invalid"),
             "--repository", str(repository), "--authentication-mode", "digest"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(invalid.returncode, 3)

    def test_authenticated_tool_failure_is_distinct_redacted_and_not_clean(self):
        repository = self.root / "tool-error-repository"
        (repository / ".vibesec").mkdir(parents=True)
        capabilities = all_capabilities(False)
        capabilities["capabilities"].update({
            "web_application": True, "container_image": True, "authentication": True,
            "dast_target": True, "authenticated_security_testing": True,
        })
        (repository / ".vibesec/project-capabilities.json").write_bytes(capability_bytes(capabilities))
        (repository / ".vibesec/authenticated-security-testing.json").write_bytes(configuration_bytes("FIXTURE_BEARER"))
        fake_docker = self.root / "fake-docker"
        fake_log = self.root / "fake-docker.log"
        fake_docker.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$FAKE_AUTH_DOCKER_LOG"\nexit 1\n', encoding="utf-8")
        fake_docker.chmod(0o700)
        results = self.root / "tool-error-results"
        token = "vibesec-obvious-local-fixture-token"
        environment = os.environ.copy()
        environment.pop("VIBESEC_AUTH_SINGLE_RUN", None)
        environment.update({AUTH_ENVIRONMENT_VARIABLE: token, "VIBESEC_AUTH_MODE": "bearer",
                            "FAKE_AUTH_DOCKER_LOG": str(fake_log)})
        completed = subprocess.run(
            [sys.executable, "scripts/run_dast_baseline.py", str(results), "--repository", str(repository),
             "--docker", str(fake_docker), "--event", "workflow_dispatch",
             "--image-reference", "fixture/app@sha256:" + "a" * 64],
            cwd=ROOT, env=environment, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("pull", fake_log.read_text())
        self.assertNotIn(token, completed.stdout + completed.stderr)
        self.assertLessEqual(len(completed.stderr.encode()), 2_000)
        coverage = json.loads((results / "coverage.json").read_text())
        policy = json.loads((results / "policy-result.json").read_text())
        self.assertEqual(coverage["state"], "tool_error")
        self.assertFalse(coverage["authentication_applied"])
        self.assertEqual(policy["exit_code"], 2)
        self.assertEqual(policy["exit_category"], "tool_error")
        self.assertFalse(policy["clean"])
        self.assertEqual({path.name for path in results.iterdir()},
                         {"normalized.json", "coverage.json", "policy-result.json", "report.md",
                          "finding-groups.json", "prioritized-findings.json"})
        self.assertEqual(json.loads((results / "finding-groups.json").read_text())["model"],
                         "vibesec-finding-groups")
        published = b"\n".join(path.read_bytes() for path in results.iterdir())
        self.assertNotIn(token.encode(), published)
        self.assertNotIn(b"authorization: bearer", published.lower())
        validate_publishable_bytes(published, token)

    def test_authenticated_api_tool_failure_preserves_exit_and_redaction(self):
        repository = self.root / "api-tool-error-repository"
        (repository / ".vibesec").mkdir(parents=True)
        capabilities = all_capabilities(False)
        capabilities["capabilities"].update({
            "api": True, "container_image": True, "authentication": True,
            "api_security_target": True, "authenticated_security_testing": True,
        })
        (repository / ".vibesec/project-capabilities.json").write_bytes(capability_bytes(capabilities))
        (repository / ".vibesec/authenticated-security-testing.json").write_bytes(configuration_bytes("FIXTURE_BEARER"))
        (repository / "openapi.yaml").write_bytes(
            (ROOT / "tests/security-fixtures/api-security/openapi.yaml").read_bytes()
        )
        fake_docker = self.root / "fake-api-docker"
        fake_log = self.root / "fake-api-docker.log"
        fake_docker.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$FAKE_AUTH_DOCKER_LOG"\nexit 1\n', encoding="utf-8")
        fake_docker.chmod(0o700)
        results = self.root / "api-tool-error-results"
        token = "vibesec-obvious-local-api-fixture-token"
        environment = os.environ.copy()
        environment.pop("VIBESEC_AUTH_SINGLE_RUN", None)
        environment.update({AUTH_ENVIRONMENT_VARIABLE: token, "VIBESEC_AUTH_MODE": "bearer",
                            "FAKE_AUTH_DOCKER_LOG": str(fake_log)})
        completed = subprocess.run(
            [sys.executable, "scripts/run_api_security_baseline.py", str(results),
             "--repository", str(repository), "--docker", str(fake_docker),
             "--event", "workflow_dispatch", "--schema", "openapi.yaml",
             "--image-reference", "fixture/api@sha256:" + "b" * 64],
            cwd=ROOT, env=environment, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("pull", fake_log.read_text())
        self.assertNotIn(token, completed.stdout + completed.stderr)
        self.assertLessEqual(len(completed.stderr.encode()), 2_000)
        coverage = json.loads((results / "coverage.json").read_text())
        policy = json.loads((results / "policy-result.json").read_text())
        self.assertEqual(coverage["state"], "tool_error")
        self.assertFalse(coverage["authentication_applied"])
        self.assertEqual(policy["exit_code"], 2)
        self.assertEqual(policy["exit_category"], "tool_error")
        self.assertFalse(policy["clean"])
        self.assertEqual({path.name for path in results.iterdir()},
                         {"normalized.json", "coverage.json", "policy-result.json", "report.md",
                          "finding-groups.json", "prioritized-findings.json"})
        self.assertEqual(json.loads((results / "prioritized-findings.json").read_text())["model"],
                         "vibesec-prioritized-findings")
        published = b"\n".join(path.read_bytes() for path in results.iterdir())
        self.assertNotIn(token.encode(), published)
        self.assertNotIn(b"authorization: bearer", published.lower())
        validate_publishable_bytes(published, token)

    def test_paired_result_fails_closed_when_either_side_has_tool_error(self):
        def write_result(directory: Path, state: str, code: int) -> None:
            directory.mkdir()
            finding = ({"result_type": "tool_error", "tool": "zap-baseline", "rule_id": "tool-error"}
                       if state == "tool_error" else [])
            results = [finding] if finding else []
            documents = {
                "normalized.json": {"schema_version": 1, "profile": "dast-baseline", "results": results},
                "coverage.json": {"schema_version": 1, "profile": "dast-baseline", "state": state},
                "policy-result.json": {"schema_version": 1, "profile": "dast-baseline", "exit_code": code,
                                       "clean": state == "ran" and code == 0},
            }
            for name, document in documents.items():
                (directory / name).write_text(json.dumps(document) + "\n", encoding="utf-8")
            groups, priorities = build_finding_intelligence([
                SourceDocument("dast-baseline", "normalized.json", documents["normalized.json"]),
            ])
            (directory / "finding-groups.json").write_text(json.dumps(groups) + "\n", encoding="utf-8")
            (directory / "prioritized-findings.json").write_text(json.dumps(priorities) + "\n", encoding="utf-8")
            (directory / "report.md").write_text("sanitized\n", encoding="utf-8")

        unauthenticated = self.root / "unauthenticated"
        authenticated = self.root / "authenticated"
        output = self.root / "combined"
        write_result(unauthenticated, "tool_error", 2)
        write_result(authenticated, "ran", 0)
        self.assertEqual(combine_result_directories(
            unauthenticated, authenticated, output,
            unauthenticated_exit_code=2, authenticated_exit_code=0,
        ), 2)
        self.assertEqual(json.loads((output / "coverage.json").read_text())["state"], "tool_error")
        self.assertFalse(json.loads((output / "policy-result.json").read_text())["clean"])
        with self.assertRaisesRegex(AuthenticatedSecurityError, "process and policy exits differ"):
            combine_result_directories(
                unauthenticated, authenticated, self.root / "mismatched",
                unauthenticated_exit_code=0, authenticated_exit_code=0,
            )

    def test_authenticated_commands_remain_internal_passive_and_stateless(self):
        dast_config = load_dast_config(ROOT)
        plan = build_passive_plan(port=8080, base_path="/", spider_minutes=1,
                                  passive_wait_minutes=3, authenticated=True)
        self.assertEqual([job["type"] for job in plan["jobs"]],
                         ["spider", "passiveScan-wait", "report", "exitStatus"])
        self.assertEqual(plan["env"]["contexts"][0]["urls"], ["http://target:8080/"])
        self.assertNotIn("activeScan", json.dumps(plan))
        api_config = json.loads((ROOT / "config/api-security-baseline.json").read_text())
        command = trusted_schemathesis_command(port=8080, base_path="/", config=api_config,
                                               safe_methods_only=True, authenticated=True)
        serialized = "\0".join(command)
        self.assertIn("http://api-target:8080/", command)
        self.assertNotIn("--stateful", serialized)
        self.assertNotIn("--hook", serialized)
        self.assertNotIn("Authorization", serialized)
        for method in api_config["safe_methods"]:
            self.assertIn(method, command)

    def test_doctor_contract_rejects_secret_movement_literals_dynamic_refs_and_triggers(self):
        template = (ROOT / "templates/github-actions/dast-baseline.yml").read_text()
        valid = template.replace(
            "          # AUTHENTICATED_SCANNER_ENV_MARKER\n",
            "          VIBESEC_AUTH_MODE: bearer\n"
            "          VIBESEC_AUTH_BEARER_TOKEN: ${{ secrets.FIXTURE_BEARER }}\n",
        )
        self.assertEqual(_auth_workflow_problems(valid, secret_name="FIXTURE_BEARER", enabled=True), [])
        moved = valid.replace(
            "          VIBESEC_AUTH_BEARER_TOKEN: ${{ secrets.FIXTURE_BEARER }}\n", "",
        ).replace(
            "      - name: Upload sanitized DAST artifacts\n",
            "      - name: Upload sanitized DAST artifacts\n"
            "        env:\n"
            "          VIBESEC_AUTH_BEARER_TOKEN: ${{ secrets.FIXTURE_BEARER }}\n",
        )
        self.assertIn("secret reference exists outside the reviewed scanner step",
                      _auth_workflow_problems(moved, secret_name="FIXTURE_BEARER", enabled=True))
        literal = valid.replace("${{ secrets.FIXTURE_BEARER }}", "vibesec-obvious-local-fixture-token")
        self.assertTrue(_auth_workflow_problems(literal, secret_name="FIXTURE_BEARER", enabled=True))
        dynamic = valid.replace("${{ secrets.FIXTURE_BEARER }}", "${{ secrets[inputs.secret_name] }}")
        self.assertIn("unsafe dynamic secret expression",
                      _auth_workflow_problems(dynamic, secret_name="FIXTURE_BEARER", enabled=True))
        pushed = valid.replace("  workflow_dispatch:\n", "  push:\n")
        self.assertIn("untrusted workflow trigger",
                      _auth_workflow_problems(pushed, secret_name="FIXTURE_BEARER", enabled=True))

    def test_consumer_bundle_contains_support_but_no_bearer_value(self):
        token = "vibesec-obvious-local-fixture-token-never-bundle"
        bundle, manifest = build_bundle_bytes(ROOT, "a" * 40)
        self.assertIn("scripts/vibesec/authenticated.py", {item["path"] for item in manifest["files"]})
        self.assertNotIn(token.encode(), bundle)

    def test_controlled_dast_and_api_fixtures_enforce_bearer_without_external_access(self):
        for relative in ("tests/security-fixtures/zap-baseline/server.py", "tests/security-fixtures/api-security/server.py"):
            module = load_fixture(relative)
            with patch("socket.getfqdn", return_value="localhost"):
                server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            private = "/private" if "zap" in relative else "/private-defect"
            url = f"http://127.0.0.1:{server.server_port}{private}"
            with self.assertRaises(HTTPError) as missing:
                urlopen(url, timeout=2)
            self.assertEqual(missing.exception.code, 401)
            request = Request(url, headers={"Authorization": f"Bearer {module.FIXTURE_TOKEN}"})
            with urlopen(request, timeout=2) as response:
                self.assertEqual(response.status, 200)


if __name__ == "__main__":
    unittest.main()
