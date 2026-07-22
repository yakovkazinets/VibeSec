import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
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


if __name__ == "__main__":
    unittest.main()
