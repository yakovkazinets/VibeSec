from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class V1DocumentationTests(unittest.TestCase):
    def run_script(self, script, *arguments):
        return subprocess.run(
            [sys.executable, str(ROOT / "scripts" / script), *arguments],
            cwd=ROOT, stdin=subprocess.DEVNULL, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

    def test_interface_contract_command(self):
        completed = self.run_script("validate_v1_interfaces.py")
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_documentation_contract_command(self):
        completed = self.run_script("validate_documentation_contract.py")
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_generated_reference_is_current_and_deterministic(self):
        before = {
            path: (ROOT / path).read_bytes()
            for path in ("docs/v1-interface-reference.md", "docs/examples.md")
        }
        first = self.run_script("generate_v1_reference.py", "--check")
        second = self.run_script("generate_v1_reference.py", "--check")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(before, {path: (ROOT / path).read_bytes() for path in before})

    def test_required_reference_contains_all_public_ids_and_statuses(self):
        reference = (ROOT / "docs/v1-interface-reference.md").read_text(encoding="utf-8")
        self.assertIn("`vibesec.cli.scan`", reference)
        self.assertIn("`vibesec.execution.modes` | `experimental`", reference)
        self.assertIn("`vibesec.profiles.dast-baseline` | `conditionally_enforced`", reference)
        for flag in (
            "--tool-dir", "--repository", "--fuzzing-max-examples",
            "--fuzzing-max-failures", "--fuzzing-request-timeout",
            "--fuzzing-total-timeout",
        ):
            self.assertIn(f"`{flag}`", reference)
        for artifact in (
            "inventory.json", "fuzzing-findings.json", "fuzzing-coverage.json",
            "finding-groups.json", "prioritized-findings.json",
        ):
            self.assertIn(f"`{artifact}`", reference)
        self.assertIn("`validate`", (ROOT / "docs/v1-stability-policy.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
