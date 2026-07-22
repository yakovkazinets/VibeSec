import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = str(ROOT / "scripts")
sys.path.insert(0, SCRIPTS)
from vibesec.bundle import build_bundle_bytes, verify_bundle  # noqa: E402
from vibesec.github_actions import (  # noqa: E402
    GitHubActionsError, KNOWN_NODE20_PINS, PROHIBITED_OVERRIDES,
    audit_tracked_files, audit_workflow_text, load_inventory, parse_inventory,
    validate_inventory,
)
sys.path.remove(SCRIPTS)


WORKFLOWS = (
    ".github/workflows/ci.yml",
    ".github/workflows/api-security-integration.yml",
    ".github/workflows/dast-integration.yml",
    ".github/workflows/authenticated-api-integration.yml",
    ".github/workflows/authenticated-dast-integration.yml",
    ".github/workflows/release-candidate.yml",
    "templates/github-actions/api-security-baseline.yml",
    "templates/github-actions/dast-baseline.yml",
    "templates/github-actions/security-baseline.yml",
    "templates/github-actions/security-standard.yml",
    "tests/security-fixtures/actionlint/negative/.github/workflows/valid.yml",
)


class GitHubActionsInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = load_inventory(ROOT / "config/github-actions.json")

    def test_inventory_is_strict_and_node24_only(self):
        self.assertEqual(self.inventory["minimum_runner_version"], "2.327.1")
        self.assertEqual(set(self.inventory["actions"]), {"actions/checkout", "actions/upload-artifact"})
        self.assertEqual({item["runtime"] for item in self.inventory["actions"].values()}, {"node24"})
        for mutation in (
            lambda value: value.update({"unknown": True}),
            lambda value: value["actions"]["actions/checkout"].update({"runtime": "node20"}),
            lambda value: value["actions"]["actions/checkout"].update({"commit": "abc"}),
            lambda value: value.update({"minimum_runner_version": "2.326.0"}),
            lambda value: value["actions"]["actions/checkout"].update({"verified_on": "July 22"}),
        ):
            payload = copy.deepcopy(self.inventory)
            mutation(payload)
            with self.assertRaises(GitHubActionsError):
                validate_inventory(payload)

    def test_inventory_rejects_duplicate_keys_bom_size_and_symlink(self):
        with self.assertRaises(GitHubActionsError):
            parse_inventory(b'{"schema_version":1,"schema_version":1}')
        with self.assertRaises(GitHubActionsError):
            parse_inventory(b"\xef\xbb\xbf{}")
        with self.assertRaises(GitHubActionsError):
            parse_inventory(b" " * 16_385)
        if hasattr(Path, "symlink_to"):
            with tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "target.json"
                target.write_text("{}", encoding="utf-8")
                link = Path(directory) / "link.json"
                link.symlink_to(target)
                with self.assertRaises(GitHubActionsError):
                    load_inventory(link)

    def test_every_tracked_action_reference_matches_inventory(self):
        self.assertEqual(audit_tracked_files(ROOT, self.inventory), [])
        combined = "\n".join((ROOT / path).read_text(encoding="utf-8") for path in WORKFLOWS)
        for commit in KNOWN_NODE20_PINS:
            self.assertNotIn(f"@{commit}", combined)

    def test_audit_rejects_floating_mixed_and_weakened_references(self):
        checkout = self.inventory["actions"]["actions/checkout"]
        upload = self.inventory["actions"]["actions/upload-artifact"]
        valid = (
            f"steps:\n  - uses: actions/checkout@{checkout['commit']} # {checkout['version']}, Node 24, verified {checkout['verified_on']}\n"
            "    with:\n      persist-credentials: false\n"
            f"  - uses: actions/upload-artifact@{upload['commit']} # {upload['version']}, Node 24, verified {upload['verified_on']}\n"
            "    with:\n      if-no-files-found: error\n      include-hidden-files: false\n      archive: true\n"
        )
        self.assertEqual(audit_workflow_text(valid, "valid.yml", self.inventory), [])
        mutations = (
            valid.replace(checkout["commit"], "v6", 1),
            valid.replace("Node 24", "Node 20", 1),
            valid.replace("persist-credentials: false", "persist-credentials: true"),
            valid.replace("include-hidden-files: false", "include-hidden-files: true"),
            valid.replace("archive: true", "archive: false"),
            valid + "  - uses: owner/unreviewed@" + "a" * 40 + "\n",
            valid + "env:\n  ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION: true\n",
        )
        for text in mutations:
            self.assertTrue(audit_workflow_text(text, "bad.yml", self.inventory))

    def test_artifact_contract_and_checkout_credential_contract_are_preserved(self):
        expected_fetch_depths = {
            ".github/workflows/ci.yml": [0, 0, None, None, None, None, None, None, 0],
            ".github/workflows/api-security-integration.yml": [None],
            ".github/workflows/dast-integration.yml": [None],
            ".github/workflows/authenticated-api-integration.yml": [None],
            ".github/workflows/authenticated-dast-integration.yml": [None],
            ".github/workflows/release-candidate.yml": [1],
            "templates/github-actions/api-security-baseline.yml": [None],
            "templates/github-actions/dast-baseline.yml": [None],
            "templates/github-actions/security-baseline.yml": [0],
            "templates/github-actions/security-standard.yml": [0],
            "tests/security-fixtures/actionlint/negative/.github/workflows/valid.yml": [None],
        }
        expected_paths = {
            ".github/workflows/ci.yml": [["results/normalized.json", "results/report.md", "results/coverage.json", "results/policy-result.json"]],
            ".github/workflows/release-candidate.yml": [["release-candidate/"]],
            "templates/github-actions/api-security-baseline.yml": [[
                "${{ runner.temp }}/vibesec-api-security-results/normalized.json",
                "${{ runner.temp }}/vibesec-api-security-results/coverage.json",
                "${{ runner.temp }}/vibesec-api-security-results/report.md",
                "${{ runner.temp }}/vibesec-api-security-results/policy-result.json",
            ]],
            "templates/github-actions/dast-baseline.yml": [[
                "${{ runner.temp }}/vibesec-dast-results/normalized.json",
                "${{ runner.temp }}/vibesec-dast-results/coverage.json",
                "${{ runner.temp }}/vibesec-dast-results/report.md",
                "${{ runner.temp }}/vibesec-dast-results/policy-result.json",
            ]],
            "templates/github-actions/security-baseline.yml": [["results/normalized.json", "results/report.md"]],
            "templates/github-actions/security-standard.yml": [[
                "${{ runner.temp }}/vibesec-results/normalized.json",
                "${{ runner.temp }}/vibesec-results/coverage.json",
                "${{ runner.temp }}/vibesec-results/inventory.json",
                "${{ runner.temp }}/vibesec-results/report.md",
            ], [
                "${{ runner.temp }}/vibesec-results/sbom.cyclonedx.json",
                "${{ runner.temp }}/vibesec-results/sbom.spdx.json",
            ]],
        }
        for relative in WORKFLOWS:
            document = yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))
            steps = [step for job in document["jobs"].values() for step in job.get("steps", [])]
            observed_fetch_depths = []
            for step in steps:
                if str(step.get("uses", "")).startswith("actions/checkout@"):
                    self.assertIs(step.get("with", {}).get("persist-credentials"), False)
                    observed_fetch_depths.append(step.get("with", {}).get("fetch-depth"))
            self.assertEqual(observed_fetch_depths, expected_fetch_depths[relative])
            uploads = [step for step in steps if str(step.get("uses", "")).startswith("actions/upload-artifact@")]
            if relative in expected_paths:
                self.assertEqual([[item for item in step["with"]["path"].splitlines()] for step in uploads], expected_paths[relative])
                for step in uploads:
                    self.assertEqual(step["with"]["retention-days"], 7 if relative == ".github/workflows/release-candidate.yml" else 14)
                    self.assertEqual(step["with"]["if-no-files-found"], "error")
                    self.assertIs(step["with"]["include-hidden-files"], False)
                    self.assertIs(step["with"]["archive"], True)

    def test_bundle_distributes_inventory_and_validator(self):
        data, _ = build_bundle_bytes(ROOT, "a" * 40)
        with tempfile.TemporaryDirectory() as directory:
            bundle_path = Path(directory) / "consumer.zip"
            bundle_path.write_bytes(data)
            entries = verify_bundle(bundle_path).entries
        self.assertIn("config/github-actions.json", entries)
        self.assertIn("scripts/vibesec/github_actions.py", entries)
        self.assertIn("docs/github-actions-runtime.md", entries)
        for template in (
            "templates/github-actions/security-baseline.yml",
            "templates/github-actions/security-standard.yml",
            "templates/github-actions/dast-baseline.yml",
            "templates/github-actions/api-security-baseline.yml",
        ):
            text = entries[template].decode("utf-8")
            for action in self.inventory["actions"].values():
                if action["commit"] in "\n".join((ROOT / path).read_text(encoding="utf-8") for path in WORKFLOWS if path == template):
                    self.assertIn(action["commit"], text)
            for old in KNOWN_NODE20_PINS:
                self.assertNotIn(old, text)

    def test_required_runtime_documentation_and_validate_aggregator(self):
        for relative in (
            "README.md", "CHANGELOG.md", "docs/quickstart.md", "docs/configuration.md",
            "docs/distribution.md", "docs/installation-verification.md", "docs/doctor.md",
            "docs/upgrading.md", "docs/self-hosted-validation.md", "docs/github-actions-runtime.md",
            "skills/appsec-guardian/SKILL.md",
        ):
            self.assertIn("Node 24", (ROOT / relative).read_text(encoding="utf-8"), relative)
        runtime = (ROOT / "docs/github-actions-runtime.md").read_text(encoding="utf-8")
        for marker in ("2.327.1", "Node 20", "Node 26", "GHES", "runs.using: node24"):
            self.assertIn(marker, runtime)
        ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
        self.assertIn("validate", ci["jobs"])
        self.assertEqual(ci["jobs"]["validate"]["needs"], [
            "self-scan-minimal", "self-scan-standard", "scanner-accountability",
            "security-artifacts", "dast-artifacts",
            "api-security-artifacts",
            "authenticated-security-artifacts",
            "supply-chain-artifacts",
        ])

    def test_repository_has_no_owned_node_runtime_or_compatibility_override(self):
        paths = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, check=True, capture_output=True, text=True,
        ).stdout.splitlines()
        node_metadata = [path for path in paths if Path(path).name in {"package.json", "package-lock.json", ".nvmrc", ".node-version"}]
        self.assertTrue(all(path.startswith("tests/") for path in node_metadata))
        javascript = [path for path in paths if Path(path).suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}]
        self.assertTrue(all(path.startswith("tests/") for path in javascript))
        tracked_text = "\n".join(
            (ROOT / path).read_text(encoding="utf-8", errors="ignore")
            for path in paths if (ROOT / path).is_file() and (ROOT / path).stat().st_size <= 1_000_000
        )
        for override in PROHIBITED_OVERRIDES:
            self.assertNotRegex(tracked_text, rf"(?m)^\s*(?:export\s+)?{override}\s*(?::|=)")


if __name__ == "__main__":
    unittest.main()
