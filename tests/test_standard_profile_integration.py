import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
import zipfile
from datetime import date
from unittest.mock import patch

from scripts.run_standard_profile import CHECKOV_CONTAINER_CONFIG, checkov_command, run as run_scanner
from scripts.test_checkov_container import scan as smoke_scan

ROOT = Path(__file__).resolve().parents[1]


class StandardProfileIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.tools = base / "tools"
        self.results = base / "results"
        self.target = base / "target"
        self.tools.mkdir()
        (self.target / ".git").mkdir(parents=True)
        (self.target / ".github/workflows").mkdir(parents=True)
        (self.target / "main.py").write_text("print('fixture')\n", encoding="utf-8")
        (self.target / "requirements.txt").write_text("fixture==1\n", encoding="utf-8")
        (self.target / ".github/workflows/test.yml").write_text("name: test\non: push\njobs: {}\n", encoding="utf-8")
        (self.target / "main.tf").write_text("resource \"test\" \"fixture\" {}\n", encoding="utf-8")
        # Target-controlled scanner configuration must never become authoritative.
        (self.target / ".gitleaks.toml").write_text("[[rules]]\nid='disable'\n", encoding="utf-8")
        (self.target / ".semgrepignore").write_text("**\n", encoding="utf-8")
        (self.target / ".syft.yaml").write_text("enrich: [all]\n", encoding="utf-8")
        (self.target / ".checkov.yml").write_text(
            "skip-check: [CKV_AWS_24]\nskip-framework: [terraform]\n", encoding="utf-8")
        (self.target / ".checkov.yaml").write_text(
            "bc-api-key: target-controlled-not-a-real-key\ndownload-external-modules: true\n", encoding="utf-8")
        expected = str(ROOT)
        self.write_tool("opengrep", r'''#!/usr/bin/env python3
import json, os, sys
expected = os.environ["VIBESEC_EXPECTED_ROOT"]
assert sys.argv[sys.argv.index("--config") + 1] == expected + "/rules/opengrep"
assert "--no-git-ignore" in sys.argv
assert "--legacy" in sys.argv and "--x-ignore-semgrepignore-files" in sys.argv
assert "--semgrepignore-filename" not in sys.argv
output = sys.argv[sys.argv.index("--json-output") + 1]
mode = os.getenv("FAKE_OPENGREP_MODE", "pass")
if mode == "fail": raise SystemExit(9)
if mode == "malformed": open(output, "w").write("not-json")
elif mode == "finding": json.dump({"results":[{"check_id":"vibesec.python.test","path":"fixture.py","start":{"line":1},"extra":{"severity":"ERROR","message":"Synthetic test finding","lines":"OMITTED_SECRET"}}]}, open(output, "w"))
else: json.dump({"results":[]}, open(output, "w"))
''')
        self.write_tool("osv-scanner", r'''#!/usr/bin/env python3
import json, os, sys
assert sys.argv[sys.argv.index("--config") + 1] == "/dev/null"
assert "--no-call-analysis=go" in sys.argv and "--no-call-analysis=rust" in sys.argv
assert "--no-resolve" in sys.argv
assert sys.argv[1:3] == ["scan", "source"]
mode = os.getenv("FAKE_OSV_MODE", "pass")
if mode == "fail": raise SystemExit(8)
output = sys.argv[sys.argv.index("--output-file") + 1]
if mode == "malformed": open(output, "w").write("{"); raise SystemExit(0)
payload = {"results":[]}
if mode == "finding": payload = {"results":[{"source":{"path":"requirements.txt"},"packages":[{"package":{"name":"fixture"},"vulnerabilities":[{"id":"OSV-TEST","summary":"Synthetic advisory","database_specific":{"severity":"HIGH"}}]}]}]}
json.dump(payload, open(output, "w"))
if mode == "finding": raise SystemExit(1)
''')
        self.write_tool("syft", r'''#!/usr/bin/env python3
import json, os, sys
expected = os.environ["VIBESEC_EXPECTED_ROOT"]
assert sys.argv[sys.argv.index("--config") + 1] == expected + "/config/syft-standard.yaml"
assert "dir:." in sys.argv and sys.argv[sys.argv.index("--base-path") + 1] == "."
mode = os.getenv("FAKE_SYFT_MODE", "pass")
if mode == "fail": raise SystemExit(7)
for index, value in enumerate(sys.argv):
    if value == "--output":
        form, path = sys.argv[index + 1].split("=", 1)
        if mode == "malformed": open(path, "w").write("{"); continue
        payload = ({"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"fixture"}]} if form == "cyclonedx-json" else {"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[{"name":"fixture"}]})
        json.dump(payload, open(path, "w"))
''')
        self.write_tool("trivy", r'''#!/usr/bin/env python3
import json, os, sys
expected = os.environ["VIBESEC_EXPECTED_ROOT"]
assert sys.argv[sys.argv.index("--config") + 1] == expected + "/config/trivy-standard.yaml"
output = sys.argv[sys.argv.index("--output") + 1]
mode = os.getenv("FAKE_TRIVY_IMAGE_MODE" if "image" in sys.argv else "FAKE_TRIVY_MODE", "pass")
if mode == "fail": raise SystemExit(7)
if mode == "malformed": open(output, "w").write("{"); raise SystemExit(0)
json.dump({"Results":[]}, open(output, "w"))
''')
        self.write_tool("gitleaks", r'''#!/usr/bin/env python3
import json, os, sys
expected = os.environ["VIBESEC_EXPECTED_ROOT"]
assert sys.argv[sys.argv.index("--config") + 1] == expected + "/config/gitleaks-standard.toml"
assert sys.argv[sys.argv.index("--gitleaks-ignore-path") + 1] == expected + "/config/gitleaks-standard-ignore.txt"
output = sys.argv[sys.argv.index("--report-path") + 1]
mode = os.getenv("FAKE_GITLEAKS_MODE", "pass")
if mode == "fail": raise SystemExit(7)
if mode == "malformed": open(output, "w").write("{"); raise SystemExit(0)
json.dump([], open(output, "w"))
''')
        self.write_tool("actionlint", r'''#!/usr/bin/env python3
import os, sys
expected = os.environ["VIBESEC_EXPECTED_ROOT"]
assert os.path.basename(os.environ["HOME"]) == ".scanner-home"
assert sys.argv[sys.argv.index("-config-file") + 1] == expected + "/config/actionlint-standard.yaml"
assert sys.argv[sys.argv.index("-format") + 1] == "{{json .}}"
assert sys.argv[sys.argv.index("-shellcheck") + 1] == ""
assert sys.argv[sys.argv.index("-pyflakes") + 1] == ""
mode = os.getenv("FAKE_ACTIONLINT_MODE", "pass")
if mode == "fail": raise SystemExit(7)
if mode == "malformed": print("not actionlint output")
else: print('[{"filepath":".github/workflows/test.yml","line":3,"column":1,"end_column":2,"kind":"syntax-check","message":"Synthetic workflow diagnostic","snippet":"MUST_NOT_SURVIVE"}]')
''')
        self.write_tool("docker", r'''#!/usr/bin/env python3
import json, sys
expected = __import__("os").environ["VIBESEC_EXPECTED_ROOT"]
assert sys.argv[sys.argv.index("--network") + 1] == "none"
assert sys.argv[sys.argv.index("--config-file") + 1] == "/vibesec/checkov-standard.yaml"
assert sys.argv[sys.argv.index("--workdir") + 1] == "/tmp"
assert sys.argv[sys.argv.index("--download-external-modules") + 1] == "false"
assert "--file" in sys.argv and "--directory" not in sys.argv
joined = " ".join(sys.argv)
assert "--read-only" in sys.argv and "ALL" in sys.argv and "/workspace:ro" in joined
assert expected + "/config/checkov-standard.yaml:/vibesec/checkov-standard.yaml:ro" in joined
assert "HOME=/tmp/vibesec-home" in sys.argv and "XDG_CACHE_HOME=/tmp/vibesec-cache" in sys.argv
assert "/var/run/docker.sock" not in joined and "terraform" not in sys.argv and "GITHUB_ACTIONS" not in sys.argv
import os
mode = os.getenv("FAKE_CHECKOV_MODE", "pass")
if mode == "fail": raise SystemExit(7)
if mode == "usage": raise SystemExit(2)
if mode == "stale":
    assert os.fstat(1).st_size == 0
    raise SystemExit(7)
if mode == "malformed": print("{"); raise SystemExit(0)
print(json.dumps({"results":{"failed_checks":[]}}))
''')

    def write_tool(self, name: str, source: str) -> None:
        path = self.tools / name
        path.write_text(textwrap.dedent(source), encoding="utf-8")
        path.chmod(0o755)

    def run_profile(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        environment = {
            key: value for key, value in os.environ.items()
            if key not in {"GITHUB_ACTIONS", "GITHUB_EVENT_NAME"}
            and not key.startswith(("VIBESEC_", "FAKE_"))
        }
        environment.update({"PATH": f"{self.tools}:{environment['PATH']}", "VIBESEC_EXPECTED_ROOT": str(ROOT), **overrides})
        return subprocess.run(
            ["python3", "scripts/run_standard_profile.py", str(self.target), str(self.results), "--vibesec-root", str(ROOT), "--tool-dir", str(self.tools)],
            cwd=ROOT, env=environment, text=True, capture_output=True, check=False,
        )

    def load_json(self, name: str) -> dict:
        data = (self.results / name).read_bytes()
        self.assertTrue(data.endswith(b"\n"))
        self.assertFalse(data.endswith(b"\\n"))
        return json.loads(data)

    def test_complete_orchestration_outputs_reports_coverage_and_sboms(self):
        completed = self.run_profile()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.load_json("normalized.json")["profile"], "standard")
        states = {entry["tool"]: entry["state"] for entry in self.load_json("coverage.json")["tools"]}
        self.assertEqual(states["opengrep"], "ran")
        self.assertEqual(states["checkov"], "ran")
        self.assertEqual(states["trivy-image"], "not_applicable")
        coverage = self.load_json("coverage.json")
        self.assertTrue(all(entry["version"] for entry in coverage["tools"]))
        self.assertTrue(all(entry["application_code_executed"] is False for entry in coverage["tools"]))
        self.assertEqual(len({entry["tool"] for entry in coverage["tools"]}), 8)
        self.assertEqual(coverage["sbom_formats"], ["CycloneDX 1.6", "SPDX-2.3"])
        self.assertIn("Standard profile coverage", (self.results / "report.md").read_text(encoding="utf-8"))
        self.assertTrue((self.results / "sbom.cyclonedx.json").is_file())
        self.assertTrue((self.results / "sbom.spdx.json").is_file())
        policy = self.load_json("policy-result.json")
        self.assertEqual(policy["exit_category"], "pass")
        self.assertFalse(policy["security_guarantee"])
        validated = subprocess.run(
            ["python3", "scripts/validate_security_artifacts.py", "--profile", "standard", "--results", str(self.results),
             "--expect-state", "opengrep=ran", "--expect-state", "osv-scanner=ran", "--expect-state", "syft=ran",
             "--expect-state", "checkov=ran", "--expect-state", "trivy=ran", "--expect-state", "gitleaks=ran",
             "--expect-state", "actionlint=ran", "--expect-state", "trivy-image=not_applicable"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(validated.returncode, 0, validated.stderr)

    def test_tool_execution_failure_returns_two(self):
        completed = self.run_profile(FAKE_OSV_MODE="fail")
        self.assertEqual(completed.returncode, 2, completed.stderr)
        results = self.load_json("normalized.json")["results"]
        self.assertTrue(any(item["tool"] == "osv-scanner" and item["result_type"] == "tool_error" for item in results))
        self.assertEqual(self.load_json("policy-result.json")["exit_category"], "tool_error")

    def test_every_scanner_nonzero_exit_is_a_non_clean_tool_error(self):
        scenarios = {
            "opengrep": {"FAKE_OPENGREP_MODE": "fail"},
            "osv-scanner": {"FAKE_OSV_MODE": "fail"},
            "syft": {"FAKE_SYFT_MODE": "fail"},
            "checkov": {"FAKE_CHECKOV_MODE": "fail"},
            "trivy": {"FAKE_TRIVY_MODE": "fail"},
            "gitleaks": {"FAKE_GITLEAKS_MODE": "fail"},
            "actionlint": {"FAKE_ACTIONLINT_MODE": "fail"},
            "trivy-image": {
                "FAKE_TRIVY_IMAGE_MODE": "fail",
                "VIBESEC_IMAGE_REFERENCE": "registry.example/image@sha256:" + "d" * 64,
            },
        }
        for tool, environment in scenarios.items():
            with self.subTest(tool=tool):
                completed = self.run_profile(**environment)
                self.assertEqual(completed.returncode, 2, completed.stderr)
                coverage = {item["tool"]: item["state"] for item in self.load_json("coverage.json")["tools"]}
                self.assertEqual(coverage[tool], "tool_error")
                policy = self.load_json("policy-result.json")
                self.assertEqual(policy["exit_category"], "tool_error")
                self.assertFalse(policy["clean"])

    def test_every_scanner_malformed_output_is_invalid_not_clean(self):
        scenarios = {
            "opengrep": {"FAKE_OPENGREP_MODE": "malformed"},
            "osv-scanner": {"FAKE_OSV_MODE": "malformed"},
            "syft": {"FAKE_SYFT_MODE": "malformed"},
            "checkov": {"FAKE_CHECKOV_MODE": "malformed"},
            "trivy": {"FAKE_TRIVY_MODE": "malformed"},
            "gitleaks": {"FAKE_GITLEAKS_MODE": "malformed"},
            "actionlint": {"FAKE_ACTIONLINT_MODE": "malformed"},
            "trivy-image": {
                "FAKE_TRIVY_IMAGE_MODE": "malformed",
                "VIBESEC_IMAGE_REFERENCE": "registry.example/image@sha256:" + "e" * 64,
            },
        }
        for tool, environment in scenarios.items():
            with self.subTest(tool=tool):
                completed = self.run_profile(**environment)
                self.assertEqual(completed.returncode, 3, completed.stderr)
                coverage = {item["tool"]: item["state"] for item in self.load_json("coverage.json")["tools"]}
                self.assertEqual(coverage[tool], "tool_error")
                policy = self.load_json("policy-result.json")
                self.assertEqual(policy["exit_category"], "invalid_input")
                self.assertFalse(policy["clean"])

    def test_every_scanner_missing_executable_is_a_non_clean_tool_error(self):
        scenarios = {
            "opengrep": ("opengrep", {}),
            "osv-scanner": ("osv-scanner", {}),
            "syft": ("syft", {}),
            "checkov": ("docker", {}),
            "trivy": ("trivy", {}),
            "gitleaks": ("gitleaks", {}),
            "actionlint": ("actionlint", {}),
            "trivy-image": (
                "trivy",
                {"VIBESEC_IMAGE_REFERENCE": "registry.example/image@sha256:" + "f" * 64},
            ),
        }
        for tool, (binary_name, environment) in scenarios.items():
            binary = self.tools / binary_name
            saved = binary.read_bytes()
            binary.unlink()
            try:
                with self.subTest(tool=tool):
                    completed = self.run_profile(**environment)
                    self.assertEqual(completed.returncode, 2, completed.stderr)
                    coverage = {item["tool"]: item["state"] for item in self.load_json("coverage.json")["tools"]}
                    self.assertEqual(coverage[tool], "tool_error")
                    self.assertFalse(self.load_json("policy-result.json")["clean"])
            finally:
                binary.write_bytes(saved)
                binary.chmod(0o755)

    def test_timeout_is_a_tool_error_for_every_scanner_identity(self):
        with patch("scripts.run_standard_profile.subprocess.run", side_effect=subprocess.TimeoutExpired(["fixture"], 1)):
            for tool in ("opengrep", "osv-scanner", "syft", "checkov", "trivy", "gitleaks", "actionlint", "trivy-image"):
                with self.subTest(tool=tool):
                    error = run_scanner(tool, ["fixture"], None, cwd=self.target, env={})
                    self.assertEqual(error, f"{tool} timed out")

    def test_osv_finding_exit_is_not_misclassified_as_tool_failure(self):
        completed = self.run_profile(FAKE_OSV_MODE="finding", VIBESEC_ENFORCEMENT="all")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        results = self.load_json("normalized.json")["results"]
        self.assertTrue(any(item["tool"] == "osv-scanner" and item["result_type"] == "finding" for item in results))
        self.assertFalse(any(item["tool"] == "osv-scanner" and item["result_type"] == "tool_error" for item in results))

    def test_malformed_scanner_output_returns_three_not_clean(self):
        completed = self.run_profile(FAKE_OPENGREP_MODE="malformed")
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertIn("tool_error", json.dumps(self.load_json("normalized.json")))
        self.assertNotIn("Status: **pass**", (self.results / "report.md").read_text(encoding="utf-8"))

    def test_pull_request_actionlint_json_is_sanitized_and_coverage_ran(self):
        completed = self.run_profile(GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="pull_request")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        coverage = {item["tool"]: item["state"] for item in self.load_json("coverage.json")["tools"]}
        self.assertEqual(coverage["actionlint"], "ran")
        self.assertEqual(coverage["opengrep"], "ran")
        self.assertEqual(coverage["trivy-image"], "not_configured")
        normalized = json.dumps(self.load_json("normalized.json"))
        self.assertIn("Synthetic workflow diagnostic", normalized)
        self.assertNotIn("MUST_NOT_SURVIVE", normalized)

    def test_actionlint_malformed_output_has_bounded_safe_diagnostic(self):
        completed = self.run_profile(FAKE_ACTIONLINT_MODE="malformed")
        self.assertEqual(completed.returncode, 3)
        self.assertIn("component=actionlint category=invalid_input", completed.stderr)
        self.assertIn("artifact=raw/actionlint.txt", completed.stderr)
        self.assertNotIn("not actionlint output", completed.stderr)
        self.assertNotIn(str(self.target.parent), completed.stderr)

    def test_checkov_command_preserves_container_and_configuration_isolation(self):
        image = "bridgecrew/checkov@sha256:" + "a" * 64
        argv = checkov_command(self.target, ROOT / "config/checkov-standard.yaml", image, ["main.tf"])
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertEqual(argv[argv.index("--config-file") + 1], CHECKOV_CONTAINER_CONFIG)
        self.assertEqual(argv[argv.index("--download-external-modules") + 1], "false")
        self.assertIn(f"{self.target}:/workspace:ro", argv)
        self.assertIn(f"{ROOT / 'config/checkov-standard.yaml'}:{CHECKOV_CONTAINER_CONFIG}:ro", argv)
        self.assertEqual(argv[argv.index("--file") + 1], "/workspace/main.tf")
        self.assertNotIn("--directory", argv)
        self.assertNotIn("/dev/null", argv)

    def test_target_checkov_configuration_cannot_change_coverage(self):
        completed = self.run_profile(GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="pull_request")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        entry = next(item for item in self.load_json("coverage.json")["tools"] if item["tool"] == "checkov")
        self.assertEqual(entry["state"], "ran")

    def test_checkov_docker_unavailable_is_a_non_clean_tool_error(self):
        docker = self.tools / "docker"
        docker.unlink()
        completed = self.run_profile()
        self.assertEqual(completed.returncode, 2)
        self.assertIn("component=checkov category=tool_error reason=Docker is unavailable", completed.stderr)
        self.assertEqual(next(item for item in self.load_json("coverage.json")["tools"] if item["tool"] == "checkov")["state"], "tool_error")
        self.assertFalse(self.load_json("policy-result.json")["clean"])

    def test_checkov_cli_exit_two_is_a_non_clean_tool_error(self):
        completed = self.run_profile(FAKE_CHECKOV_MODE="usage")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("Checkov CLI or image execution exited with status 2", completed.stderr)
        self.assertEqual(next(item for item in self.load_json("coverage.json")["tools"] if item["tool"] == "checkov")["state"], "tool_error")
        self.assertFalse(self.load_json("policy-result.json")["clean"])

    def test_checkov_stale_raw_output_is_removed_before_failed_execution(self):
        raw = self.results / "raw"
        raw.mkdir(parents=True)
        stale = raw / "checkov.json"
        stale.write_text("stale-sensitive-content", encoding="utf-8")
        completed = self.run_profile(FAKE_CHECKOV_MODE="stale")
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(stale.read_bytes(), b"")
        self.assertNotIn("stale-sensitive-content", json.dumps(self.load_json("normalized.json")))

    def test_checkov_negative_smoke_does_not_treat_missing_json_as_clean(self):
        completed = subprocess.CompletedProcess(["docker"], 0)
        with patch("scripts.test_checkov_container.subprocess.run", return_value=completed):
            self.assertEqual(smoke_scan("negative", 0), (False, []))

    def test_security_finding_returns_one_in_enforce_all_mode(self):
        completed = self.run_profile(FAKE_OPENGREP_MODE="finding", VIBESEC_ENFORCEMENT="all")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        serialized = json.dumps(self.load_json("normalized.json"))
        self.assertIn("Synthetic test finding", serialized)
        self.assertNotIn("OMITTED_SECRET", serialized)

    def test_tag_only_image_reference_is_invalid_configuration(self):
        completed = self.run_profile(VIBESEC_IMAGE_REFERENCE="example/image:latest")
        self.assertEqual(completed.returncode, 3)

    def test_observe_mode_reports_finding_without_policy_failure(self):
        completed = self.run_profile(FAKE_OPENGREP_MODE="finding", VIBESEC_ENFORCEMENT="observe")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Synthetic test finding", json.dumps(self.load_json("normalized.json")))

    def test_new_mode_blocks_unbaselined_finding(self):
        completed = self.run_profile(FAKE_OPENGREP_MODE="finding", VIBESEC_ENFORCEMENT="new")
        self.assertEqual(completed.returncode, 1, completed.stderr)

    def test_offline_mode_requires_and_uses_explicit_fresh_database(self):
        database = self.target.parent / "osv-db"
        (database / "PyPI").mkdir(parents=True)
        with zipfile.ZipFile(database / "PyPI/all.zip", "w") as bundle:
            bundle.writestr("OSV-TEST.json", "{}")
        completed = self.run_profile(
            VIBESEC_NETWORK_MODE="offline", VIBESEC_OSV_DATABASE_DIR=str(database),
            VIBESEC_OSV_DATABASE_DATE=date.today().isoformat(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        coverage = self.load_json("coverage.json")
        osv = next(item for item in coverage["tools"] if item["tool"] == "osv-scanner")
        self.assertEqual(osv["network_access"], "local_database")
        self.assertEqual(coverage["osv_database"]["age_days"], 0)

    def test_offline_mode_without_database_is_invalid_configuration(self):
        completed = self.run_profile(VIBESEC_NETWORK_MODE="offline", VIBESEC_OSV_DATABASE_DATE=date.today().isoformat())
        self.assertEqual(completed.returncode, 3)

    def test_stale_sboms_are_removed_when_syft_fails(self):
        self.results.mkdir()
        for name in ("sbom.cyclonedx.json", "sbom.spdx.json"):
            (self.results / name).write_text("stale", encoding="utf-8")
        completed = self.run_profile(FAKE_SYFT_MODE="fail")
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertFalse((self.results / "sbom.cyclonedx.json").exists())
        self.assertFalse((self.results / "sbom.spdx.json").exists())

    def test_image_scan_is_disabled_for_unknown_github_events(self):
        completed = self.run_profile(
            GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="pull_request",
            VIBESEC_IMAGE_REFERENCE="registry.example/image@sha256:" + "a" * 64,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        entry = next(item for item in self.load_json("coverage.json")["tools"] if item["tool"] == "trivy-image")
        self.assertEqual(entry["state"], "not_configured")
        self.assertIn("untrusted", entry["reason"])

    def test_ambient_github_event_does_not_change_local_test_behavior(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request"}):
            completed = self.run_profile()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        entry = next(item for item in self.load_json("coverage.json")["tools"] if item["tool"] == "trivy-image")
        self.assertEqual(entry["state"], "not_applicable")
        self.assertEqual(entry["relevant_artifacts"], [])

    def test_ambient_image_reference_does_not_enable_image_scan(self):
        reference = "registry.example/image@sha256:" + "c" * 64
        with patch.dict(os.environ, {"VIBESEC_IMAGE_REFERENCE": reference}):
            completed = self.run_profile()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        entry = next(item for item in self.load_json("coverage.json")["tools"] if item["tool"] == "trivy-image")
        self.assertEqual(entry["state"], "not_applicable")
        self.assertEqual(entry["relevant_artifacts"], [])

    def test_ambient_network_mode_does_not_switch_to_offline(self):
        with patch.dict(os.environ, {"VIBESEC_NETWORK_MODE": "offline"}):
            completed = self.run_profile()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        entry = next(item for item in self.load_json("coverage.json")["tools"] if item["tool"] == "osv-scanner")
        self.assertEqual(entry["network_access"], "advisory_queries")

    def test_dockerfile_without_image_is_an_explicit_coverage_gap(self):
        (self.target / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        completed = self.run_profile()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        entry = next(item for item in self.load_json("coverage.json")["tools"] if item["tool"] == "trivy-image")
        self.assertEqual(entry["state"], "not_configured")
        self.assertEqual(entry["relevant_artifacts"], ["Dockerfile"])

    def test_digest_image_runs_only_on_trusted_event(self):
        completed = self.run_profile(
            GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="push",
            VIBESEC_IMAGE_REFERENCE="registry.example/image@sha256:" + "b" * 64,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        entry = next(item for item in self.load_json("coverage.json")["tools"] if item["tool"] == "trivy-image")
        self.assertEqual(entry["state"], "ran")
        self.assertEqual(entry["network_access"], "scanner_managed")

    def test_no_relevant_standard_artifacts_are_not_reported_as_clean_runs(self):
        for relative in ("main.py", "requirements.txt", "main.tf", ".github/workflows/test.yml"):
            (self.target / relative).unlink()
        completed = self.run_profile()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        states = {item["tool"]: item["state"] for item in self.load_json("coverage.json")["tools"]}
        for tool in ("opengrep", "osv-scanner", "syft", "checkov", "actionlint", "trivy-image"):
            self.assertEqual(states[tool], "not_applicable")
        image = next(item for item in self.load_json("coverage.json")["tools"] if item["tool"] == "trivy-image")
        self.assertEqual(image["relevant_artifacts"], [])


if __name__ == "__main__":
    unittest.main()
