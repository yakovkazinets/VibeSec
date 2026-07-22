import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from scripts.vibesec.detection import DetectionError, inventory


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/consumer-fixtures"
INIT = ROOT / "scripts/init_vibesec.py"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


class ConsumerAdoptionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.target = base / "consumer"
        self.target.mkdir()
        self.tools = base / "tools"
        self.tools.mkdir()
        self.write_fake_tools()

    def copy_fixture(self, name: str) -> None:
        shutil.copytree(FIXTURES / name, self.target, dirs_exist_ok=True)

    def initialize(self, profile: str, stage: str | None = None):
        command = ["python3", str(INIT), "--profile", profile, "--target", str(self.target), "--write"]
        if stage:
            command += ["--stage", stage]
        else:
            command.append("--all-capabilities")
        return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)

    def initialize_dast(self):
        return subprocess.run(
            ["python3", str(INIT), "--addon", "dast-baseline", "--target", str(self.target), "--write"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )

    def write_fake_tools(self) -> None:
        source = r'''#!/usr/bin/env python3
import json, os, sys
name = os.path.basename(sys.argv[0])
mode = os.getenv("FAKE_SCANNER_MODE", "pass")
def option(flag): return sys.argv[sys.argv.index(flag) + 1]
if name == "trivy":
    output = option("--output")
    if mode == "fail": raise SystemExit(9)
    if mode == "malformed": open(output, "w").write("not-json")
    else: json.dump({"Results":[]}, open(output, "w"))
elif name == "gitleaks":
    output = option("--report-path")
    payload = []
    if mode == "finding": payload = [{"RuleID":"fictional-rule","Description":"Synthetic documented finding","File":"fixture.txt","StartLine":1}]
    json.dump(payload, open(output, "w"))
    if mode == "finding": raise SystemExit(1)
elif name == "opengrep":
    json.dump({"results":[]}, open(option("--json-output"), "w"))
elif name == "osv-scanner":
    json.dump({"results":[]}, open(option("--output-file"), "w"))
elif name == "syft":
    for index, value in enumerate(sys.argv):
        if value == "--output":
            form, output = sys.argv[index + 1].split("=", 1)
            payload = {"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"fictional"}]} if form == "cyclonedx-json" else {"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[{"name":"fictional"}]}
            json.dump(payload, open(output, "w"))
elif name == "docker":
    print(json.dumps({"results":{"failed_checks":[]}}))
'''
        for name in ("trivy", "gitleaks", "actionlint", "opengrep", "osv-scanner", "syft", "docker"):
            path = self.tools / name
            path.write_text(textwrap.dedent(source), encoding="utf-8")
            path.chmod(0o755)

    def controlled_environment(self, **overrides):
        environment = {
            key: value for key, value in os.environ.items()
            if key not in {"GITHUB_ACTIONS", "GITHUB_EVENT_NAME"}
            and not key.startswith(("VIBESEC_", "FAKE_"))
        }
        environment.update({"PATH": f"{self.tools}:{environment['PATH']}", **overrides})
        return environment

    def run_copied_minimal(self, **environment):
        results = Path(self.temporary.name) / "minimal-results"
        env = self.controlled_environment(VIBESEC_TOOL_DIR=str(self.tools), **environment)
        completed = subprocess.run(
            ["bash", "scripts/run_minimal_profile.sh", ".", str(results)],
            cwd=self.target, env=env, text=True, capture_output=True, check=False,
        )
        return completed, results

    def run_copied_standard(self, **environment):
        results = Path(self.temporary.name) / "standard-results"
        env = self.controlled_environment(**environment)
        completed = subprocess.run(
            ["python3", "scripts/run_standard_profile.py", ".", str(results), "--vibesec-root", ".", "--tool-dir", str(self.tools)],
            cwd=self.target, env=env, text=True, capture_output=True, check=False,
        )
        return completed, results

    def test_minimal_copy_uses_exact_consumer_files_and_runs(self):
        completed = self.initialize("minimal")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        copied = self.target / ".github/workflows/vibesec-minimal.yml"
        self.assertEqual(copied.read_bytes(), (ROOT / "templates/github-actions/security-baseline.yml").read_bytes())
        run, results = self.run_copied_minimal()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue((results / "normalized.json").is_file())
        self.assertTrue((results / "report.md").is_file())

    def test_copied_minimal_observe_findings_and_fail_closed_errors(self):
        self.assertEqual(self.initialize("minimal").returncode, 0)
        finding, finding_results = self.run_copied_minimal(FAKE_SCANNER_MODE="finding")
        self.assertEqual(finding.returncode, 0, finding.stderr)
        self.assertIn("finding", (finding_results / "normalized.json").read_text(encoding="utf-8"))
        shutil.rmtree(finding_results)
        failure, failure_results = self.run_copied_minimal(FAKE_SCANNER_MODE="fail")
        self.assertEqual(failure.returncode, 2, failure.stderr)
        self.assertIn("tool_error", (failure_results / "normalized.json").read_text(encoding="utf-8"))
        shutil.rmtree(failure_results)
        malformed, malformed_results = self.run_copied_minimal(FAKE_SCANNER_MODE="malformed")
        self.assertEqual(malformed.returncode, 3)
        self.assertIn("Status: **invalid_input**", (malformed_results / "report.md").read_text(encoding="utf-8"))
        policy = json.loads((malformed_results / "policy-result.json").read_text(encoding="utf-8"))
        self.assertEqual(policy["exit_category"], "invalid_input")
        self.assertFalse(policy["clean"])

    def test_standard_copy_uses_exact_two_stage_files_and_runs(self):
        self.copy_fixture("unsupported-repo")
        self.assertEqual(self.initialize("standard").returncode, 0)
        workflow = self.initialize("standard", "workflow")
        self.assertEqual(workflow.returncode, 0, workflow.stderr)
        copied = self.target / ".github/workflows/vibesec-standard.yml"
        self.assertEqual(copied.read_bytes(), (ROOT / "templates/github-actions/security-standard.yml").read_bytes())
        run, results = self.run_copied_standard()
        self.assertEqual(run.returncode, 0, run.stderr)
        coverage = json.loads((results / "coverage.json").read_text(encoding="utf-8"))
        self.assertTrue(coverage["outside_coverage"])
        self.assertTrue(all(item["application_code_executed"] is False for item in coverage["tools"]))

    def test_fork_pull_request_disables_image_and_keeps_trusted_harness_paths(self):
        self.copy_fixture("dockerfile-repo")
        self.assertEqual(self.initialize("standard").returncode, 0)
        self.assertEqual(self.initialize("standard", "workflow").returncode, 0)
        reference = "registry.invalid/fictional@sha256:" + "a" * 64
        run, results = self.run_copied_standard(
            GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="pull_request", VIBESEC_IMAGE_REFERENCE=reference,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        coverage = json.loads((results / "coverage.json").read_text(encoding="utf-8"))
        image = next(item for item in coverage["tools"] if item["tool"] == "trivy-image")
        self.assertEqual(image["state"], "not_configured")
        self.assertIn("untrusted", image["reason"])
        workflow = (self.target / ".github/workflows/vibesec-standard.yml").read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.base.sha", workflow)
        self.assertNotIn("secrets.", workflow)

    def test_profile_baselines_cannot_be_interchanged(self):
        self.assertEqual(self.initialize("minimal").returncode, 0)
        results = Path(self.temporary.name) / "empty.json"
        results.write_text('{"schema_version":1,"results":[]}\n', encoding="utf-8")
        completed = subprocess.run([
            "python3", "scripts/policy_gate.py", "--results", str(results),
            "--policy", "policy/severity-thresholds.yml", "--baseline", str(ROOT / "policy/standard-baseline.json"),
            "--suppressions", "policy/suppressions.yml", "--profile", "minimal", "--report", str(results.with_suffix(".md")),
        ], cwd=self.target, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 3)
        self.assertIn("baseline profile", completed.stderr)

    def test_catalog_paths_exist_and_workflow_contract_is_safe(self):
        catalog = json.loads((ROOT / "config/adoption-files.json").read_text(encoding="utf-8"))
        for profile, config in catalog["profiles"].items():
            for path in [*catalog["common"], *config["support"], config["workflow_source"]]:
                self.assertTrue((ROOT / path).is_file(), f"{profile}: {path}")
            text = (ROOT / config["workflow_source"]).read_text(encoding="utf-8")
            self.assertRegex(text, r"(?m)^permissions:\n  contents: read$")
            self.assertNotIn("pull_request_target", text)
            self.assertNotIn("secrets.", text)
            for line in text.splitlines():
                if "uses:" in line:
                    reference = line.split("uses:", 1)[1].split("#", 1)[0].strip()
                    self.assertRegex(reference.rsplit("@", 1)[1], FULL_SHA)
            for prohibited in ("docker build", "terraform apply", "terraform plan", "npm install", "npm ci", "pip install -r", "mvn package", "gradle build"):
                self.assertNotIn(prohibited, text)
        addon = catalog["addons"]["dast-baseline"]
        for path in [*addon["support"], addon["workflow_source"]]:
            self.assertTrue((ROOT / path).is_file(), path)
        text = (ROOT / addon["workflow_source"]).read_text(encoding="utf-8")
        self.assertNotIn("pull_request:", text)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("docker build", text)
        self.assertIn("validate_dast_artifacts.py", text)

    def test_dast_addon_is_opt_in_and_does_not_replace_minimal(self):
        self.assertNotEqual(self.initialize_dast().returncode, 0)
        self.assertEqual(self.initialize("minimal").returncode, 0)
        completed = self.initialize_dast()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue((self.target / ".github/workflows/vibesec-minimal.yml").is_file())
        self.assertTrue((self.target / ".github/workflows/vibesec-dast-baseline.yml").is_file())
        manifest = json.loads((self.target / ".vibesec/install-addon-dast-baseline.json").read_text(encoding="utf-8"))
        self.assertEqual((manifest["profile"], manifest["stage"]), ("dast-baseline", "addon"))

    def test_fixture_inventory_matches_documented_expectations(self):
        for fixture in sorted(path for path in FIXTURES.iterdir() if path.is_dir()):
            expected_path = fixture / "expected.json"
            self.assertTrue(expected_path.is_file(), fixture.name)
            expected = json.loads(expected_path.read_text(encoding="utf-8"))
            detected = inventory(fixture)
            for key in ("languages", "package_managers", "monorepo", "dockerfiles", "workflows"):
                if key in expected:
                    self.assertEqual(detected[key], expected[key], fixture.name)
            if "iac" in expected:
                for category, paths in expected["iac"].items():
                    self.assertEqual(detected["iac"][category], paths, fixture.name)

    def test_monorepo_retains_paths_and_routes_every_ecosystem(self):
        detected = inventory(FIXTURES / "monorepo")
        self.assertEqual(detected["package_managers"], ["go", "gradle", "npm", "pip"])
        self.assertEqual(
            [path for path in detected["manifests"] if path.endswith("package.json")],
            ["packages/alpha/package.json", "packages/beta/package.json"],
        )
        self.assertIn("infra/main.tf", detected["iac"]["terraform"])
        self.assertIn("services/go/Dockerfile.worker", detected["dockerfiles"])
        self.assertEqual(detected["workflows"], [".github/workflows/root.yml", "services/python/.github/workflows/nested.yml"])
        self.assertNotIn("vendor/ignored.py", detected["source_files"])
        package_names = [
            json.loads((FIXTURES / "monorepo" / path).read_text(encoding="utf-8"))["name"]
            for path in ("packages/alpha/package.json", "packages/beta/package.json")
        ]
        self.assertEqual(package_names, ["fictional-shared-name", "fictional-shared-name"])

    def test_empty_markdown_binary_no_manifest_and_malformed_names_are_explicit(self):
        cases = {
            "empty": {},
            "markdown": {"README.md": b"# fixture\n"},
            "binary": {"asset.bin": b"\x00\xff\x00"},
            "unsupported": {"main.rb": b"puts 'fixture'\n"},
            "no-manifest": {"app.py": b"VALUE = 1\n"},
            "malformed-name": {"bad\nname.py": b"VALUE = 1\n"},
        }
        for name, files in cases.items():
            root = Path(self.temporary.name) / name
            root.mkdir()
            for relative, data in files.items():
                (root / relative).write_bytes(data)
            detected = inventory(root)
            self.assertEqual(detected["manifests"], [], name)
            if name in {"empty", "markdown", "binary", "unsupported"}:
                self.assertEqual(detected["source_files"], [], name)

    def test_traversal_limit_fails_closed(self):
        root = Path(self.temporary.name) / "bounded"
        root.mkdir()
        for index in range(5):
            (root / f"requirements-{index}.txt").write_text("fictional==0\n", encoding="utf-8")
        with patch("scripts.vibesec.detection.MAX_FILES", 4), self.assertRaises(DetectionError):
            inventory(root)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlink_fixture_cannot_escape_initializer_target(self):
        self.copy_fixture("symlink-boundary")
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (self.target / "scripts").symlink_to(outside, target_is_directory=True)
        completed = self.initialize("minimal")
        self.assertEqual(completed.returncode, 3)
        self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
