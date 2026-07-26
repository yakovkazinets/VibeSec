import json
import os
from pathlib import Path
import tempfile
import unittest

import tests.test_standard_profile_integration as standard_integration
from scripts.vibesec.sbom import (
    CYCLONEDX_SPEC_VERSION, SPDX_SPEC_VERSION, build_syft_command,
    validate_cyclonedx, validate_spdx,
)


ROOT = Path(__file__).resolve().parents[1]


class StandardProfileSyftTests(unittest.TestCase):
    def harness(self) -> standard_integration.StandardProfileIntegrationTests:
        harness = standard_integration.StandardProfileIntegrationTests(
            "test_complete_orchestration_outputs_reports_coverage_and_sboms",
        )
        harness.setUp()
        self.addCleanup(harness.doCleanups)
        return harness

    def test_pinned_linux_syft_is_installed_executable(self):
        inventory = json.loads((ROOT / "config/tools.json").read_text(encoding="utf-8"))
        syft = inventory["syft"]
        self.assertEqual(syft["version"], "1.49.0")
        self.assertEqual(syft["archive"], "syft_1.49.0_linux_amd64.tar.gz")
        self.assertRegex(syft["sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("/v1.49.0/syft_1.49.0_linux_amd64.tar.gz", syft["url"])
        installer = (ROOT / "scripts/install_standard_tools.sh").read_text(encoding="utf-8")
        self.assertIn("for tool in cosign opengrep osv-scanner syft", installer)
        self.assertIn('install -m 0755 "${staging}/${tool}"', installer)

    def test_syft_149_command_uses_repository_source_and_private_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            binary = base / "syft"
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            results = base / "results"
            results.mkdir(mode=0o700)
            command = build_syft_command(
                binary, ROOT / "config/syft-standard.yaml",
                results / "sbom.cyclonedx.json", results / "sbom.spdx.json",
            )
            self.assertTrue(os.access(binary, os.X_OK))
            self.assertEqual(command[1:3], ["dir:.", "--config"])
            self.assertEqual(command[4:6], ["--base-path", "."])
            self.assertEqual(command[-1], "--quiet")
            self.assertEqual(command.count("--output"), 2)
            self.assertIn(f"cyclonedx-json={results / 'sbom.cyclonedx.json'}", command)
            self.assertIn(f"spdx-json={results / 'sbom.spdx.json'}", command)
            self.assertEqual(results.stat().st_mode & 0o777, 0o700)
            self.assertTrue(os.access(results, os.W_OK))

    def test_standard_success_generates_and_preserves_valid_sboms(self):
        harness = self.harness()
        completed = harness.run_profile()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        coverage = harness.load_json("coverage.json")
        syft = next(item for item in coverage["tools"] if item["tool"] == "syft")
        self.assertEqual(syft["state"], "ran")
        self.assertEqual(coverage["sbom_formats"], [
            f"CycloneDX {CYCLONEDX_SPEC_VERSION}", SPDX_SPEC_VERSION,
        ])
        cyclonedx = validate_cyclonedx(harness.results / "sbom.cyclonedx.json")
        spdx = validate_spdx(harness.results / "sbom.spdx.json")
        self.assertEqual(cyclonedx["specVersion"], "1.7")
        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
        policy = harness.load_json("policy-result.json")
        self.assertEqual(policy["exit_code"], 0)
        self.assertEqual(policy["exit_category"], "pass")


if __name__ == "__main__":
    unittest.main()
