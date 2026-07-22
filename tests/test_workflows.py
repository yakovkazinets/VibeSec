import re
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github/workflows/ci.yml"
DAST_INTEGRATION = ROOT / ".github/workflows/dast-integration.yml"
API_INTEGRATION = ROOT / ".github/workflows/api-security-integration.yml"
AUTH_DAST_INTEGRATION = ROOT / ".github/workflows/authenticated-dast-integration.yml"
AUTH_API_INTEGRATION = ROOT / ".github/workflows/authenticated-api-integration.yml"
RELEASE_CANDIDATE = ROOT / ".github/workflows/release-candidate.yml"
STARTERS = [ROOT / "templates/github-actions/security-baseline.yml", ROOT / "templates/github-actions/security-standard.yml", ROOT / "templates/github-actions/dast-baseline.yml", ROOT / "templates/github-actions/api-security-baseline.yml"]
WORKFLOWS = [CI, DAST_INTEGRATION, API_INTEGRATION, AUTH_DAST_INTEGRATION, AUTH_API_INTEGRATION, RELEASE_CANDIDATE, *STARTERS]
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
        for path in [CI, DAST_INTEGRATION, API_INTEGRATION, *STARTERS]:
            self.assertNotIn("secrets.", path.read_text(encoding="utf-8"))

    def test_authenticated_live_workflows_scope_one_secret_to_the_scanner_step(self):
        for path in (AUTH_DAST_INTEGRATION, AUTH_API_INTEGRATION):
            text = path.read_text(encoding="utf-8")
            self.assertIn("workflow_dispatch:", text)
            self.assertIn("schedule:", text)
            self.assertNotIn("pull_request:", text)
            self.assertNotIn("push:", text)
            self.assertEqual(text.count("secrets.VIBESEC_AUTH_FIXTURE_BEARER"), 1)
            checkout, scanner = text.split("- name: Exercise authenticated", 1)
            self.assertNotIn("secrets.", checkout)
            self.assertIn("VIBESEC_AUTH_BEARER_TOKEN", scanner)

    def test_required_scripts_and_outputs_align(self):
        for script in ("install_tools.sh", "run_minimal_profile.sh", "normalize_results.py", "append_tool_errors.py", "policy_gate.py", "validate_repository.py"):
            self.assertTrue((ROOT / "scripts" / script).is_file())
        for path in [CI, *STARTERS]:
            text = path.read_text(encoding="utf-8")
            self.assertIn("normalized.json", text)
            self.assertIn("report.md", text)

    def test_standard_workflow_never_builds_or_installs_target_code(self):
        text = (ROOT / "templates/github-actions/security-standard.yml").read_text(encoding="utf-8")
        for prohibited in ("docker build", "npm install", "npm ci", "yarn install", "pnpm install", "pip install -r", "go build", "mvn package", "gradle build"):
            self.assertNotIn(prohibited, text)
        self.assertIn("run_standard_profile.py", text)
        self.assertNotIn("secrets.", text)

    def test_standard_workflow_uploads_only_sanitized_outputs(self):
        text = (ROOT / "templates/github-actions/security-standard.yml").read_text(encoding="utf-8")
        self.assertNotIn("results/raw", text)
        self.assertIn("runner.temp }}/vibesec-results/coverage.json", text)
        self.assertIn("runner.temp }}/vibesec-results/sbom.cyclonedx.json", text)
        self.assertIn("if-no-files-found: error", text)

    def test_standard_workflow_uses_base_revision_harness_for_pull_requests(self):
        text = (ROOT / "templates/github-actions/security-standard.yml").read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.base.sha", text)
        self.assertIn('git archive "$TRUSTED_SHA" scripts config policy rules', text)
        self.assertIn('--vibesec-root "$VIBESEC_ROOT"', text)
        self.assertNotIn("python3 scripts/run_standard_profile.py", text)

    def test_raw_scanner_output_is_not_uploaded(self):
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("results/trivy.json\n", text)
            self.assertNotIn("results/gitleaks.json\n", text)
            self.assertNotIn("results/actionlint.txt\n", text)

    def test_ci_lints_the_copyable_workflow(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        actionlint_line = next(line for line in text.splitlines() if "actionlint -no-color" in line)
        for relative in (
            ".github/workflows/ci.yml",
            ".github/workflows/dast-integration.yml",
            ".github/workflows/api-security-integration.yml",
            ".github/workflows/authenticated-dast-integration.yml",
            ".github/workflows/authenticated-api-integration.yml",
            ".github/workflows/release-candidate.yml",
            "templates/github-actions/security-baseline.yml",
            "templates/github-actions/security-standard.yml",
            "templates/github-actions/dast-baseline.yml",
            "templates/github-actions/api-security-baseline.yml",
        ):
            self.assertIn(relative, actionlint_line)
        self.assertIn("python3 scripts/test_opengrep_rules.py .tools/bin/opengrep", text)

    def test_standard_self_scan_exercises_checkov_and_always_validates_evidence(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("python3 scripts/test_checkov_container.py", text)
        self.assertIn("python3 scripts/run_vibesec_self_scan.py", text)
        self.assertIn("python3 scripts/expected_self_scan_states.py", text)
        self.assertIn("steps.expectations.outputs.trivy_image_state", text)
        self.assertIn('--expect-state "trivy-image=$EXPECTED_TRIVY_IMAGE_STATE"', text)
        self.assertNotIn("--expect-state trivy-image=not_configured", text)
        self.assertIn("if: always() && steps.standard.outcome != 'skipped'", text)
        self.assertIn("Preserve Standard scan exit contract", text)
        self.assertIn('"$SELF_SCAN_RESULTS/scan-exit-code.txt"', text)
        self.assertIn("python3 scripts/preserve_scan_exit.py", text)
        self.assertNotIn("STANDARD_SCAN_EXIT", text)
        self.assertNotIn("continue-on-error: true", text.split("  self-scan-standard:", 1)[1].split("\n  scanner-accountability:", 1)[0])

    def test_standard_exit_file_is_written_atomically_and_artifacts_validate_first(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn('exit_file="$(mktemp "$SELF_SCAN_RESULTS/.scan-exit-code.XXXXXX")"', text)
        self.assertIn('mv "$exit_file" "$SELF_SCAN_RESULTS/scan-exit-code.txt"', text)
        self.assertIn("needs: [self-scan-minimal, self-scan-standard, scanner-accountability, security-artifacts, dast-artifacts, api-security-artifacts, authenticated-security-artifacts, supply-chain-artifacts]", text)
        self.assertNotIn("dast-accountability", text)
        validation = text.index("Validate Standard self-scan artifacts and exact states")
        preservation = text.index("Preserve Standard scan exit contract")
        self.assertLess(validation, preservation)

    def test_ci_validates_the_bundled_skill(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("pip install --disable-pip-version-check --requirement requirements.txt", text)
        self.assertIn("python3 scripts/validate_skill.py skills/appsec-guardian", text)

    def test_live_controlled_dast_fixture_is_separate_from_required_ci(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertNotIn("python3 scripts/test_dast_container.py", text)
        integration = DAST_INTEGRATION.read_text(encoding="utf-8")
        self.assertIn("name: DAST integration accountability", integration)
        self.assertIn("workflow_dispatch:", integration)
        self.assertIn("schedule:", integration)
        self.assertNotIn("pull_request:", integration)
        self.assertNotIn("pull_request_target", integration)
        self.assertIn("python3 scripts/test_dast_container.py", integration)
        self.assertNotIn("http://", integration)
        self.assertNotIn("https://", integration)
        self.assertNotIn("secrets.", integration)
        self.assertNotIn("release", integration.casefold())
        harness = (ROOT / "scripts/test_dast_container.py").read_text(encoding="utf-8")
        self.assertIn('"--internal"', harness)
        self.assertIn('"--user", "65532:65532"', harness)
        self.assertNotIn("docker build", harness)

    def test_required_validate_keeps_dast_artifacts_without_live_dast(self):
        text = CI.read_text(encoding="utf-8")
        needs = next(line for line in text.splitlines() if line.strip().startswith("needs: ["))
        for job in ("self-scan-minimal", "self-scan-standard", "scanner-accountability", "security-artifacts", "dast-artifacts", "api-security-artifacts"):
            self.assertIn(job, needs)
        self.assertIn("authenticated-security-artifacts", needs)
        self.assertIn("supply-chain-artifacts", needs)
        self.assertNotIn("dast-accountability", needs)
        dast = text.split("  dast-artifacts:", 1)[1].split("\n  validate:", 1)[0]
        self.assertIn("tests.test_dast_baseline", dast)

    def test_api_runtime_is_manual_scheduled_and_live_workflow_is_not_required(self):
        starter = (ROOT / "templates/github-actions/api-security-baseline.yml").read_text(encoding="utf-8")
        integration = API_INTEGRATION.read_text(encoding="utf-8")
        for text in (starter, integration):
            self.assertIn("workflow_dispatch:", text)
            self.assertIn("schedule:", text)
            self.assertNotIn("pull_request:", text)
            self.assertNotIn("pull_request_target", text)
            self.assertNotIn("push:", text)
            self.assertNotIn("secrets.", text)
        needs = next(line for line in CI.read_text(encoding="utf-8").splitlines() if line.strip().startswith("needs: ["))
        self.assertIn("api-security-artifacts", needs)
        self.assertNotIn("api-security-integration", needs)
        self.assertNotIn("authenticated-dast-integration", needs)
        self.assertNotIn("authenticated-api-integration", needs)

    def test_ci_skips_security_upload_after_early_failure(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("if: always() && steps.security.outcome != 'skipped'", text)

    def test_ci_uploads_reports_after_scanner_failure(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("continue-on-error: true", text)
        self.assertIn("steps.security.outcome != 'skipped'", text)

    def test_ci_fails_when_completed_scan_has_no_reports(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("if-no-files-found: error", text)

    def test_ci_uploads_reports_after_successful_scan(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("results/normalized.json", text)
        self.assertIn("results/report.md", text)
        self.assertNotIn("if: success()", text)


if __name__ == "__main__":
    unittest.main()
