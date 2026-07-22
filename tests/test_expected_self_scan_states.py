import subprocess
import sys
from pathlib import Path
import unittest

from scripts.vibesec.detection import ImageStateError, derive_image_expectation


ROOT = Path(__file__).resolve().parents[1]
DIGEST = "registry.example/vibesec@sha256:" + "a" * 64


class ExpectedSelfScanStateTests(unittest.TestCase):
    def test_pull_request_without_image_is_not_configured(self):
        result = derive_image_expectation(
            github_actions=True, github_event="pull_request", image_reference="",
            has_dockerfile=False, strict_event=True,
        )
        self.assertEqual(result.state, "not_configured")

    def test_trusted_push_without_dockerfile_or_image_is_not_applicable(self):
        result = derive_image_expectation(
            github_actions=True, github_event="push", image_reference="",
            has_dockerfile=False, strict_event=True,
        )
        self.assertEqual(result.state, "not_applicable")

    def test_trusted_event_with_dockerfile_but_no_image_is_not_configured(self):
        result = derive_image_expectation(
            github_actions=True, github_event="workflow_dispatch", image_reference="",
            has_dockerfile=True, strict_event=True,
        )
        self.assertEqual(result.state, "not_configured")

    def test_trusted_event_with_immutable_image_is_ran(self):
        result = derive_image_expectation(
            github_actions=True, github_event="schedule", image_reference=DIGEST,
            has_dockerfile=False, strict_event=True,
        )
        self.assertEqual(result.state, "ran")

    def test_tag_only_image_is_rejected(self):
        with self.assertRaises(ImageStateError):
            derive_image_expectation(
                github_actions=True, github_event="push", image_reference="vibesec:latest",
                has_dockerfile=False, strict_event=True,
            )

    def test_unknown_or_malformed_event_fails_closed(self):
        for event in ("", "push ", "repository_dispatch", "PUSH"):
            with self.subTest(event=event), self.assertRaises(ImageStateError):
                derive_image_expectation(
                    github_actions=True, github_event=event, image_reference="",
                    has_dockerfile=False, strict_event=True,
                )

    def test_helper_uses_current_trusted_product_view_for_supported_events(self):
        expected = {
            "pull_request": "TRIVY_IMAGE_STATE=not_applicable\n",
            "push": "TRIVY_IMAGE_STATE=not_applicable\n",
        }
        for event, output in expected.items():
            with self.subTest(event=event):
                completed = subprocess.run(
                    [sys.executable, "scripts/expected_self_scan_states.py", "--github-event", event,
                     "--format", "shell"],
                    cwd=ROOT, text=True, capture_output=True, check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout, output)

    def test_helper_cannot_accept_a_caller_selected_target_or_results(self):
        completed = subprocess.run(
            [sys.executable, "scripts/expected_self_scan_states.py", "--github-event", "push",
             "--target", "tests/security-fixtures", "--results", "coverage.json"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("unrecognized arguments", completed.stderr)
        source = (ROOT / "scripts/expected_self_scan_states.py").read_text(encoding="utf-8")
        self.assertNotIn("coverage.json", source)

    def test_helper_rejects_unknown_events_with_invalid_configuration_exit(self):
        completed = subprocess.run(
            [sys.executable, "scripts/expected_self_scan_states.py", "--github-event", "unknown"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 3)
        self.assertIn("failed closed", completed.stderr)


if __name__ == "__main__":
    unittest.main()
