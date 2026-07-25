import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from vibesec.v1_contract import build_readiness, canonical_readiness, validate_readiness  # noqa: E402


class V1ReleaseReadinessTests(unittest.TestCase):
    def test_committed_readiness_is_complete_and_non_publishing(self):
        value = json.loads((ROOT / "machine/release-readiness.json").read_text())
        validate_readiness(value, source_commit="eb8fb0e0f2b8a8c2c89de0cc77b801558d9f3f9a")
        self.assertEqual(value["status"], "ready_with_known_limitations")
        self.assertEqual(value["release_blockers"], [])
        discovered = unittest.defaultTestLoader.discover(str(ROOT / "tests")).countTestCases()
        self.assertEqual(value["test_totals"]["automated_tests"], discovered)

    def test_readiness_generation_is_deterministic(self):
        first = build_readiness(
            ROOT, main_commit="c" * 40, test_total=123, test_evidence="controlled-test",
        )
        second = build_readiness(
            ROOT, main_commit="c" * 40, test_total=123, test_evidence="controlled-test",
        )
        self.assertEqual(canonical_readiness(first), canonical_readiness(second))

    def test_generator_refuses_overwrite_and_invalid_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "readiness.json"
            command = [
                sys.executable, "scripts/generate_release_readiness.py",
                "--output", str(output), "--main-commit", "bad",
                "--test-total", "1", "--test-evidence", "controlled-test",
            ]
            invalid = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(invalid.returncode, 3)
            command[command.index("bad")] = "d" * 40
            created = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(created.returncode, 0, created.stderr)
            repeated = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(repeated.returncode, 3)

    def test_release_workflow_has_no_publication_trigger_or_command(self):
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(encoding="utf-8")
        self.assertIn("release-readiness.json", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        for forbidden in ("pull_request_target", "gh release", "git tag", "git push", "contents: write"):
            self.assertNotIn(forbidden, workflow)


if __name__ == "__main__":
    unittest.main()
