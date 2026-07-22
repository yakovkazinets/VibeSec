import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.vibesec.self_scan import (
    EXPECTED_EXCLUDED_ROOTS, build_product_view, load_scope,
)


ROOT = Path(__file__).resolve().parents[1]


class VibeSecSelfScanTests(unittest.TestCase):
    def test_scope_is_fixed_and_every_root_has_mandatory_accountability(self):
        payload, exclusions = load_scope(ROOT)
        self.assertEqual(exclusions, EXPECTED_EXCLUDED_ROOTS)
        entries = {item["path"]: item for item in payload["excluded_fixture_roots"]}
        self.assertEqual(set(entries), {
            "examples/reports", "tests/consumer-fixtures", "tests/security-fixtures",
        })
        self.assertTrue(all(item["capability_ids"] for item in entries.values()))
        self.assertTrue(all(item["test_modules"] for item in entries.values()))
        self.assertTrue(all(item["ci_enforcement"] for item in entries.values()))

    def test_product_view_excludes_only_fixtures_and_keeps_product_configuration(self):
        _, exclusions = load_scope(ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            view = Path(temporary) / "view"
            included = build_product_view(ROOT, view, exclusions)
            for excluded in exclusions:
                self.assertFalse((view / excluded).exists())
                self.assertFalse(any(item == excluded or item.startswith(excluded + "/") for item in included))
            for product in (
                ".github/workflows/ci.yml", "config/tools.json", "config/checkov-standard.yaml",
                "policy/severity-thresholds.yml", "rules/opengrep/python.yml",
                "scripts/run_standard_profile.py", "templates/github-actions/security-standard.yml",
            ):
                self.assertIn(product, included)
                self.assertTrue((view / product).is_file())

    def test_consumer_standard_profile_has_no_self_scan_scope_control(self):
        template = (ROOT / "templates/github-actions/security-standard.yml").read_text(encoding="utf-8")
        adoption = json.loads((ROOT / "config/adoption-files.json").read_text(encoding="utf-8"))
        consumer_files = set(adoption["common"]) | set(adoption["profiles"]["standard"]["support"])
        self.assertNotIn("run_vibesec_self_scan.py", template)
        self.assertNotIn("self-scan-scope.json", template)
        self.assertNotIn("scripts/run_vibesec_self_scan.py", consumer_files)
        self.assertNotIn("config/self-scan-scope.json", consumer_files)

    def test_wrapper_rejects_target_or_exclusion_arguments(self):
        completed = subprocess.run(
            [sys.executable, "scripts/run_vibesec_self_scan.py", "/tmp/vibesec-test-results",
             "--exclude", "product"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("unrecognized arguments", completed.stderr)

    def test_controlled_product_self_scan_has_event_aware_exact_states_and_exit_zero(self):
        from tests.test_standard_profile_integration import StandardProfileIntegrationTests

        harness = StandardProfileIntegrationTests(
            methodName="test_complete_orchestration_outputs_reports_coverage_and_sboms",
        )
        harness.setUp()
        try:
            environment = {
                key: value for key, value in os.environ.items()
                if key not in {"GITHUB_ACTIONS", "GITHUB_EVENT_NAME"}
                and not key.startswith(("VIBESEC_", "FAKE_"))
            }
            environment.update({
                "PATH": f"{harness.tools}:{environment['PATH']}",
                "VIBESEC_EXPECTED_ROOT": str(ROOT), "GITHUB_ACTIONS": "true",
            })
            for event, image_state in (("pull_request", "not_applicable"), ("push", "not_applicable")):
                with self.subTest(event=event):
                    environment["GITHUB_EVENT_NAME"] = event
                    results = harness.target.parent / f"self-scan-results-{event}"
                    completed = subprocess.run(
                        [sys.executable, "scripts/run_vibesec_self_scan.py", str(results),
                         "--tool-dir", str(harness.tools)],
                        cwd=ROOT, env=environment, text=True, capture_output=True, check=False,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    coverage = json.loads((results / "coverage.json").read_text(encoding="utf-8"))
                    states = {item["tool"]: item["state"] for item in coverage["tools"]}
                    self.assertEqual(states, {
                        "opengrep": "ran", "osv-scanner": "ran", "syft": "ran",
                        "checkov": "ran", "trivy": "ran", "gitleaks": "ran",
                        "actionlint": "ran", "trivy-image": image_state,
                    })
                    validation = subprocess.run(
                        [sys.executable, "scripts/validate_security_artifacts.py", "--profile", "standard",
                         "--results", str(results), "--expect-state", "opengrep=ran",
                         "--expect-state", "osv-scanner=ran", "--expect-state", "syft=ran",
                         "--expect-state", "checkov=ran", "--expect-state", "trivy=ran",
                         "--expect-state", "gitleaks=ran", "--expect-state", "actionlint=ran",
                         "--expect-state", f"trivy-image={image_state}"],
                        cwd=ROOT, env=environment, text=True, capture_output=True, check=False,
                    )
                    self.assertEqual(validation.returncode, 0, validation.stderr)
                    policy = json.loads((results / "policy-result.json").read_text(encoding="utf-8"))
                    self.assertEqual(policy["exit_code"], 0)
        finally:
            harness.doCleanups()


if __name__ == "__main__":
    unittest.main()
