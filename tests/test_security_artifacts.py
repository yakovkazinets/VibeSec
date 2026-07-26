import json
from pathlib import Path
import subprocess
import sys
import unittest

import tests.test_standard_profile_integration as standard_integration


ROOT = Path(__file__).resolve().parents[1]


class StandardSyftArtifactTests(unittest.TestCase):
    def harness(self) -> standard_integration.StandardProfileIntegrationTests:
        harness = standard_integration.StandardProfileIntegrationTests(
            "test_complete_orchestration_outputs_reports_coverage_and_sboms",
        )
        harness.setUp()
        self.addCleanup(harness.doCleanups)
        return harness

    @staticmethod
    def syft_state(harness: standard_integration.StandardProfileIntegrationTests) -> str:
        coverage = json.loads((harness.results / "coverage.json").read_text(encoding="utf-8"))
        return next(item["state"] for item in coverage["tools"] if item["tool"] == "syft")

    def test_successful_syft_artifacts_pass_the_standard_validator(self):
        harness = self.harness()
        completed = harness.run_profile()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        validated = subprocess.run(
            [
                sys.executable, "scripts/validate_security_artifacts.py",
                "--profile", "standard", "--results", str(harness.results),
                "--expect-state", "syft=ran",
            ],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(validated.returncode, 0, validated.stderr)
        self.assertEqual(self.syft_state(harness), "ran")
        self.assertTrue((harness.results / "sbom.cyclonedx.json").is_file())
        self.assertTrue((harness.results / "sbom.spdx.json").is_file())

    def test_syft_process_failure_is_tool_error_and_non_clean(self):
        harness = self.harness()
        completed = harness.run_profile(FAKE_SYFT_MODE="fail")
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(self.syft_state(harness), "tool_error")
        policy = harness.load_json("policy-result.json")
        self.assertEqual(policy["exit_code"], 2)
        self.assertEqual(policy["exit_category"], "tool_error")
        self.assertFalse(policy["clean"])
        self.assertFalse((harness.results / "sbom.cyclonedx.json").exists())
        self.assertFalse((harness.results / "sbom.spdx.json").exists())

    def test_malformed_syft_artifacts_are_invalid_and_never_clean(self):
        harness = self.harness()
        completed = harness.run_profile(FAKE_SYFT_MODE="malformed")
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertEqual(self.syft_state(harness), "tool_error")
        policy = harness.load_json("policy-result.json")
        self.assertEqual(policy["exit_code"], 3)
        self.assertEqual(policy["exit_category"], "invalid_input")
        self.assertFalse(policy["clean"])
        self.assertFalse((harness.results / "sbom.cyclonedx.json").exists())
        self.assertFalse((harness.results / "sbom.spdx.json").exists())


if __name__ == "__main__":
    unittest.main()
