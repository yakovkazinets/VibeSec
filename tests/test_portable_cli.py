import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import textwrap
import unittest

from scripts.vibesec.portable import PortableExecutionError, load_support, platform_id, select_execution_mode

ROOT = Path(__file__).resolve().parents[1]


class PortableCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.tools = Path(self.temporary.name) / "tools"
        self.tools.mkdir()
        self.support = load_support(ROOT / "config/portable-execution.json")

    def add_tools(self, profile="minimal"):
        names = ["trivy", "gitleaks", "actionlint"]
        if profile == "standard":
            names += ["opengrep", "osv-scanner", "syft"]
        for name in names:
            path = self.tools / name
            path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    def test_supported_platform_detection(self):
        cases = {
            ("Linux", "x86_64"): "linux-amd64", ("Linux", "aarch64"): "linux-arm64",
            ("Darwin", "x86_64"): "macos-amd64", ("Darwin", "arm64"): "macos-arm64",
        }
        for inputs, expected in cases.items():
            self.assertEqual(platform_id(*inputs), expected)
        with self.assertRaises(PortableExecutionError):
            platform_id("Windows", "AMD64")

    def test_native_and_auto_require_complete_regular_executable_set(self):
        with self.assertRaisesRegex(PortableExecutionError, "incomplete"):
            select_execution_mode(requested="native", profile="minimal", current_platform="linux-amd64", tool_dir=self.tools, support=self.support)
        self.add_tools()
        native = select_execution_mode(requested="native", profile="minimal", current_platform="linux-amd64", tool_dir=self.tools, support=self.support)
        automatic = select_execution_mode(requested="auto", profile="minimal", current_platform="linux-amd64", tool_dir=self.tools, support=self.support)
        self.assertEqual((native.selected_mode, automatic.selected_mode), ("native", "native"))

    def test_auto_never_silently_falls_back_to_unverified_mode(self):
        with self.assertRaisesRegex(PortableExecutionError, "no fallback"):
            select_execution_mode(requested="auto", profile="minimal", current_platform="macos-arm64", tool_dir=self.tools, support=self.support)
        with self.assertRaisesRegex(PortableExecutionError, "not distributed"):
            select_execution_mode(requested="container", profile="minimal", current_platform="linux-amd64", tool_dir=self.tools, support=self.support)

    def test_symlink_tool_is_not_a_verified_native_boundary(self):
        self.add_tools()
        (self.tools / "trivy").unlink()
        (self.tools / "trivy").symlink_to(self.tools / "gitleaks")
        with self.assertRaisesRegex(PortableExecutionError, "trivy"):
            select_execution_mode(requested="native", profile="minimal", current_platform="linux-amd64", tool_dir=self.tools, support=self.support)

    def test_cli_routes_verify_and_preserves_exit_code(self):
        target = Path(self.temporary.name) / "consumer"
        target.mkdir()
        completed = subprocess.run([str(ROOT / "vibesec"), "verify", "--target", str(target), "--json"], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "unverifiable_legacy_installation")

    def test_cli_routes_initializer_dry_run_without_interactive_prompts(self):
        target = Path(self.temporary.name) / "init-target"
        target.mkdir()
        completed = subprocess.run([
            str(ROOT / "vibesec"), "init", "--profile", "minimal", "--target", str(target),
            "--capabilities-file", ".vibesec/project-capabilities.json",
        ], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["would_create"])
        self.assertEqual(list(target.iterdir()), [])

    def test_cli_container_failure_is_explicit_json(self):
        completed = subprocess.run([str(ROOT / "vibesec"), "scan", "--execution-mode", "container", "--json"], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 3)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "invalid")
        self.assertIn("not distributed", payload["errors"][0])

    def test_portability_metadata_records_all_required_platforms(self):
        self.assertEqual(set(self.support["platforms"]), {"linux-amd64", "linux-arm64", "macos-amd64", "macos-arm64"})
        for platform_name in ("linux-arm64", "macos-amd64", "macos-arm64"):
            self.assertTrue(self.support["platforms"][platform_name]["unsupported_reason"])

    @unittest.skipUnless(platform_id() == "linux-amd64", "complete native profile is pinned only for Linux amd64")
    def test_cli_scan_preserves_all_minimal_exit_categories(self):
        target = Path(self.temporary.name) / "repository"
        target.mkdir()
        (target / "README.md").write_text("fixture\n", encoding="utf-8")
        tools = Path(self.temporary.name) / "scanner-tools"
        tools.mkdir()
        scripts = {
            "trivy": r'''#!/usr/bin/env bash
output=""
while [[ $# -gt 0 ]]; do if [[ "$1" == "--output" ]]; then output="$2"; shift 2; else shift; fi; done
if [[ "${FAKE_MODE:-clean}" == "tool" ]]; then exit 7; fi
if [[ "${FAKE_MODE:-clean}" == "invalid" ]]; then printf 'not-json' > "$output"; exit 0; fi
printf '{"Results":[]}\n' > "$output"
''',
            "gitleaks": r'''#!/usr/bin/env bash
report=""
while [[ $# -gt 0 ]]; do if [[ "$1" == "--report-path" ]]; then report="$2"; shift 2; else shift; fi; done
if [[ "${FAKE_MODE:-clean}" == "finding" ]]; then printf '[{"RuleID":"portable-fixture","Description":"Controlled finding","File":"README.md","StartLine":1}]\n' > "$report"; exit 1; fi
printf '[]\n' > "$report"
''',
            "actionlint": "#!/usr/bin/env bash\nexit 0\n",
        }
        for name, source in scripts.items():
            path = tools / name
            path.write_text(textwrap.dedent(source), encoding="utf-8")
            path.chmod(0o755)
        cases = (("clean", 0, "success"), ("finding", 1, "policy_violation"), ("tool", 2, "tool_error"), ("invalid", 3, "invalid_input"))
        for execution_mode in ("native", "auto"):
            for mode, expected_code, expected_status in cases:
                with self.subTest(execution_mode=execution_mode, exit_category=mode):
                    results = Path(self.temporary.name) / f"results-{execution_mode}-{mode}"
                    environment = dict(os.environ)
                    environment["FAKE_MODE"] = mode
                    if mode == "finding":
                        environment["VIBESEC_ENFORCEMENT"] = "all"
                    completed = subprocess.run([
                        str(ROOT / "vibesec"), "scan", "--profile", "minimal", "--execution-mode", execution_mode,
                        "--target", str(target), "--results", str(results), "--tool-dir", str(tools), "--json",
                    ], cwd=ROOT, env=environment, text=True, capture_output=True, check=False)
                    self.assertEqual(completed.returncode, expected_code, completed.stderr + completed.stdout)
                    self.assertEqual(json.loads(completed.stdout)["status"], expected_status)
                    for artifact in ("normalized.json", "coverage.json", "report.md", "policy-result.json"):
                        self.assertTrue((results / artifact).is_file(), artifact)
                    normalized_bytes = (results / "normalized.json").read_bytes()
                    self.assertTrue(normalized_bytes.endswith(b"\n"))
                    normalized = json.loads(normalized_bytes)
                    policy = json.loads((results / "policy-result.json").read_text(encoding="utf-8"))
                    self.assertEqual(policy["exit_code"], expected_code)
                    if expected_code == 3:
                        self.assertEqual(normalized["scan_status"], "invalid_input")
                        self.assertEqual(normalized["results"], [])
                    else:
                        self.assertNotIn("scan_status", normalized)


if __name__ == "__main__":
    unittest.main()
