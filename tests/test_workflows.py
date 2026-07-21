import re
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = [ROOT / ".github/workflows/ci.yml", ROOT / "templates/github-actions/security-baseline.yml"]
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


class WorkflowSecurityTests(unittest.TestCase):
    def test_no_pull_request_target_or_placeholders(self):
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("pull_request_target", text)
            self.assertNotRegex(text, r"<[^>]*sha[^>]*>|TODO|REPLACE_ME")

    def test_actions_are_pinned_to_full_shas(self):
        for path in WORKFLOWS:
            for line in path.read_text(encoding="utf-8").splitlines():
                if "uses:" not in line:
                    continue
                reference = line.split("uses:", 1)[1].split("#", 1)[0].strip().strip("'\"")
                self.assertIn("@", reference, line)
                self.assertRegex(reference.rsplit("@", 1)[1], FULL_SHA, line)

    def test_workflow_level_permissions_are_read_only(self):
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            self.assertRegex(text, r"(?m)^permissions:\n  contents: read$")

    def test_no_secret_context_in_pull_request_workflows(self):
        for path in WORKFLOWS:
            self.assertNotIn("secrets.", path.read_text(encoding="utf-8"))

    def test_required_scripts_and_outputs_align(self):
        for script in ("install_tools.sh", "run_minimal_profile.sh", "normalize_results.py", "append_tool_errors.py", "policy_gate.py", "validate_repository.py"):
            self.assertTrue((ROOT / "scripts" / script).is_file())
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            self.assertIn("results/normalized.json", text)
            self.assertIn("results/report.md", text)

    def test_raw_scanner_output_is_not_uploaded(self):
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("results/trivy.json\n", text)
            self.assertNotIn("results/gitleaks.json\n", text)
            self.assertNotIn("results/actionlint.txt\n", text)

    def test_ci_lints_the_copyable_workflow(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("actionlint -no-color .github/workflows/ci.yml templates/github-actions/security-baseline.yml", text)

    def test_ci_validates_the_bundled_skill(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("pip install --disable-pip-version-check --requirement requirements.txt", text)
        self.assertIn("python3 scripts/validate_skill.py skills/appsec-guardian", text)


if __name__ == "__main__":
    unittest.main()
