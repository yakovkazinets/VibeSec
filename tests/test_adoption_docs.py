import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from scripts.vibesec.coverage import validate_coverage
from scripts.vibesec.results import _validate_document
from scripts.vibesec.sbom import validate_cyclonedx, validate_spdx


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "examples/reports"


class AdoptionDocumentationTests(unittest.TestCase):
    def test_documentation_links_resolve(self):
        for document in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]:
            text = document.read_text(encoding="utf-8")
            for destination in re.findall(r"\[[^]]+\]\(([^)#]+)(?:#[^)]+)?\)", text):
                if "://" in destination or destination.startswith("mailto:"):
                    continue
                self.assertTrue((document.parent / destination).resolve().exists(), f"{document}: {destination}")

    def test_environment_reference_matches_implementation(self):
        catalog = json.loads((ROOT / "config/environment-variables.json").read_text(encoding="utf-8"))
        documented = {item["name"] for item in catalog["variables"]}
        internal = {item["name"] for item in catalog["workflow_internal"]}
        implementation = "\n".join(
            path.read_text(encoding="utf-8")
            for root in (ROOT / "scripts", ROOT / "templates")
            for path in root.rglob("*") if path.is_file() and path.suffix in {".py", ".sh", ".yml", ".yaml"}
        )
        referenced = set(re.findall(r"\bVIBESEC_[A-Z0-9_]+\b", implementation))
        self.assertEqual(referenced, documented | internal)
        configuration = (ROOT / "docs/configuration.md").read_text(encoding="utf-8")
        for name in documented | internal:
            self.assertIn(name, configuration)
        for item in catalog["variables"]:
            self.assertIn(item["default"], configuration)
            self.assertFalse(item["sensitive"])

    def test_quickstart_covers_required_adoption_flow(self):
        text = (ROOT / "docs/quickstart.md").read_text(encoding="utf-8")
        for phrase in (
            "Minimal: one-stage adoption", "Standard: required two-stage bootstrap",
            "Existing repository with no VibeSec files", "Repository with existing security workflows",
            "VIBESEC_ENFORCEMENT: observe", "not_applicable", "not_configured", "tool_error",
            "move from `observe` to `new`", "Remove VibeSec", "Network and privacy",
        ):
            self.assertIn(phrase, text)
        self.assertNotIn("guarantees that your application is secure", text)

    def test_sample_normalized_results_are_structurally_valid(self):
        for path in sorted(REPORTS.glob("*.normalized.json")) + [REPORTS / "normalized.json"]:
            payload = json.loads(path.read_text(encoding="utf-8"))
            _validate_document(payload)
            serialized = json.dumps(payload).casefold()
            self.assertNotIn("password", serialized)
            self.assertNotIn("private key", serialized)

    def test_sample_coverage_and_sboms_validate(self):
        coverage_paths = sorted(REPORTS.glob("*.coverage.json")) + [
            REPORTS / "coverage.json", REPORTS / "standard-mixed-coverage.json",
        ]
        for path in coverage_paths:
            validate_coverage(json.loads(path.read_text(encoding="utf-8")))
        validate_cyclonedx(REPORTS / "sbom.cyclonedx.json")
        validate_spdx(REPORTS / "sbom.spdx.json")

    def test_preflight_reports_complete_and_partial_installations(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "consumer"
            target.mkdir()
            initialized = subprocess.run(
                ["python3", "scripts/init_vibesec.py", "--profile", "minimal", "--target", str(target), "--write"],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            ready = subprocess.run(
                ["python3", str(target / "scripts/preflight.py"), "--profile", "minimal", "--target", str(target)],
                cwd=target, text=True, capture_output=True, check=False,
            )
            self.assertEqual(ready.returncode, 0, ready.stderr)
            self.assertTrue(json.loads(ready.stdout)["ready"])
            (target / "scripts/policy_gate.py").unlink()
            partial = subprocess.run(
                ["python3", str(target / "scripts/preflight.py"), "--profile", "minimal", "--target", str(target)],
                cwd=target, text=True, capture_output=True, check=False,
            )
            self.assertEqual(partial.returncode, 2)
            self.assertIn("required file", partial.stdout)

    def test_preflight_rejects_tag_only_image_and_incomplete_offline_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "consumer"
            target.mkdir()
            initialized = subprocess.run(
                ["python3", "scripts/init_vibesec.py", "--profile", "standard", "--target", str(target), "--write"],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            environment = os.environ.copy()
            environment.update({"VIBESEC_IMAGE_REFERENCE": "example.invalid/app:latest", "VIBESEC_NETWORK_MODE": "offline"})
            checked = subprocess.run(
                ["python3", str(target / "scripts/preflight.py"), "--profile", "standard", "--target", str(target)],
                cwd=target, env=environment, text=True, capture_output=True, check=False,
            )
            self.assertEqual(checked.returncode, 2)
            payload = json.loads(checked.stdout)
            self.assertTrue(any("tag-only" in item for item in payload["error"]))
            self.assertTrue(any("offline OSV" in item for item in payload["error"]))


if __name__ == "__main__":
    unittest.main()
