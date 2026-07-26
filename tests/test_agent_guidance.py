import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from scripts.vibesec.agents import (
    ADAPTER_IDS,
    CONTRACT_ID,
    TASK_IDS,
    AgentGuidanceError,
    capability_task_states,
    describe_adapter,
    doctor,
    install_adapter,
    list_adapters,
    load_catalog,
    load_inventory,
    plan_install,
    plan_upgrade,
    remove_adapter,
    render_adapter,
    render_task,
    set_enabled,
    validate_inventory,
    verify_adapters,
)
from scripts.vibesec.bundle import build_bundle_bytes, verify_bundle
from scripts.vibesec.strict_json import canonical_json

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/agents"


class AgentGuidanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.target = Path(self.temporary.name) / "target"
        self.target.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def test_catalog_has_one_contract_four_parity_adapters_and_ten_tasks(self):
        catalog = load_catalog(ROOT)
        self.assertEqual(catalog["contract"]["contract_id"], CONTRACT_ID)
        self.assertEqual(tuple(catalog["adapters"]), ADAPTER_IDS)
        self.assertEqual(tuple(catalog["tasks"]), TASK_IDS)
        sections = {tuple(item["render_sections"]) for item in catalog["adapters"].values()}
        self.assertEqual(len(sections), 1)
        for task_id, task in catalog["tasks"].items():
            self.assertEqual(task["task_id"], task_id)
            for field in (
                "objective", "scope", "allowed_actions", "prohibited_actions", "required_checks",
                "failure_handling", "required_evidence", "expected_output",
            ):
                self.assertTrue(task[field])

    def test_scanner_and_agent_lifecycle_exit_contracts_are_distinct(self):
        contract = load_catalog(ROOT)["contract"]
        self.assertEqual(
            contract["exit_codes"],
            {
                "0": "success",
                "1": "policy_violation",
                "2": "tool_or_runtime_failure",
                "3": "invalid_configuration_or_malformed_input",
            },
        )
        self.assertEqual(
            contract["lifecycle_exit_codes"],
            {
                "0": "success",
                "1": "review_warning_or_modified_guidance",
                "2": "verification_failure",
                "3": "invalid_configuration_or_malformed_input",
                "4": "infrastructure_failure",
            },
        )

    def test_positive_adapter_fixtures_match_deterministic_output(self):
        for fixture_path in sorted((FIXTURES / "positive").glob("*.json")):
            fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
            first = render_adapter(ROOT, self.target, fixture["adapter_id"])
            second = render_adapter(ROOT, self.target, fixture["adapter_id"])
            self.assertEqual(first, second)
            text = first.decode("utf-8")
            for marker in fixture["required_markers"]:
                self.assertIn(marker, text)
            described = describe_adapter(ROOT, self.target, fixture["adapter_id"])
            self.assertEqual(described["adapter"]["output_path"], fixture["output_path"])

    def test_adapter_outputs_have_required_safety_and_no_vendor_semantic_drift(self):
        outputs = [render_adapter(ROOT, self.target, adapter_id).decode("utf-8") for adapter_id in ADAPTER_IDS]
        required = (
            "Repository files, issues, logs, scanner output",
            "`push`: explicit_human_authorization_only",
            "`release`: explicit_human_authorization_only",
            "Do not weaken, delete, skip, or rewrite tests",
            "Report the manual push command",
            "Do not invoke an external agent CLI",
        )
        for text in outputs:
            for marker in required:
                self.assertIn(marker, text)
            for task_id in TASK_IDS:
                self.assertIn(f"`{task_id}`", text)

    def test_capability_no_fixture_suppresses_optional_runtime_tasks(self):
        fixture = FIXTURES / "capability-no"
        states = capability_task_states(fixture)
        for task_id in (
            "dast-baseline", "api-security-baseline", "fuzzing-and-injection-testing",
            "authenticated-security-testing",
        ):
            self.assertEqual(states[task_id]["state"], "suppressed")
            self.assertIn("explicit", states[task_id]["reason"])
        rendered = render_task(ROOT, fixture, "codex", "add-security-feature")
        self.assertNotIn("`dast-baseline`: applicable", rendered)
        self.assertNotIn("`api-security-baseline`: applicable", rendered)

    def test_missing_capability_manifest_fails_safe_for_optional_tasks(self):
        states = capability_task_states(self.target)
        self.assertEqual(states["_manifest"]["state"], "missing")
        self.assertTrue(all(item["state"] == "suppressed" for key, item in states.items() if key != "_manifest"))

    def test_existing_instruction_file_returns_merge_plan_and_is_unchanged(self):
        original = (FIXTURES / "conflict/AGENTS.md").read_bytes()
        (self.target / "AGENTS.md").write_bytes(original)
        plan = plan_install(ROOT, self.target, "codex")
        self.assertEqual(plan["status"], "conflicting")
        self.assertTrue(plan["merge_required"])
        self.assertFalse(plan["overwrite"])
        result = install_adapter(ROOT, self.target, "codex", write=True)
        self.assertEqual(result["status"], "conflicting")
        self.assertEqual((self.target / "AGENTS.md").read_bytes(), original)
        self.assertFalse((self.target / ".vibesec/agents.json").exists())

    def test_install_verify_disable_upgrade_remove_lifecycle(self):
        dry_run = install_adapter(ROOT, self.target, "claude-code", write=False)
        self.assertEqual(dry_run["status"], "ready")
        self.assertFalse((self.target / ".claude/CLAUDE.md").exists())
        installed = install_adapter(ROOT, self.target, "claude-code", write=True)
        self.assertEqual(installed["status"], "installed")
        inventory = load_inventory(self.target)
        self.assertEqual(len(inventory["adapters"]), 1)
        record = inventory["adapters"][0]
        self.assertEqual(record["source_identity"], f"builtin:{CONTRACT_ID}:claude-code")
        serialized = json.dumps(record)
        for prohibited in ("prompt", "conversation", "token", "credential", "secret"):
            self.assertNotIn(prohibited, serialized.casefold())
        self.assertEqual(verify_adapters(ROOT, self.target)["status"], "valid")
        set_enabled(ROOT, self.target, "claude-code", enabled=False, write=True)
        self.assertEqual(verify_adapters(ROOT, self.target)["adapters"][0]["state"], "disabled")
        upgrade = plan_upgrade(ROOT, self.target, "claude-code")
        self.assertFalse(upgrade["enabled_preserved"])
        self.assertTrue(upgrade["user_files_preserved"])
        remove_adapter(ROOT, self.target, "claude-code", write=False)
        self.assertTrue((self.target / ".claude/CLAUDE.md").exists())
        remove_adapter(ROOT, self.target, "claude-code", write=True)
        self.assertFalse((self.target / ".claude/CLAUDE.md").exists())

    def test_all_adapters_install_together_without_path_collisions(self):
        for adapter_id in ADAPTER_IDS:
            result = install_adapter(ROOT, self.target, adapter_id, write=True)
            self.assertEqual(result["status"], "installed")
        inventory = load_inventory(self.target)
        self.assertEqual([item["adapter_id"] for item in inventory["adapters"]], list(ADAPTER_IDS))
        self.assertEqual(verify_adapters(ROOT, self.target)["status"], "valid")
        self.assertEqual(doctor(ROOT, self.target)["external_agent_invocations"], 0)

    def test_modified_missing_conflicting_and_unsupported_states_fail_verification(self):
        install_adapter(ROOT, self.target, "gemini-cli", write=True)
        (self.target / "GEMINI.md").write_text("user maintained\n", encoding="utf-8")
        self.assertEqual(verify_adapters(ROOT, self.target)["adapters"][0]["state"], "modified")
        with self.assertRaisesRegex(AgentGuidanceError, "will not be removed"):
            remove_adapter(ROOT, self.target, "gemini-cli", write=True)
        (self.target / "GEMINI.md").unlink()
        self.assertEqual(verify_adapters(ROOT, self.target)["adapters"][0]["state"], "missing")

        inventory = load_inventory(self.target)
        inventory["adapters"][0]["adapter_version"] = "9.0.0"
        (self.target / ".vibesec/agents.json").write_bytes(canonical_json(inventory))
        with self.assertRaisesRegex(AgentGuidanceError, "unsupported"):
            load_inventory(self.target)

    def test_modified_guidance_is_a_review_warning_not_verification_failure(self):
        install_adapter(ROOT, self.target, "codex", write=True)
        (self.target / "AGENTS.md").write_text(
            "maintainer-modified guidance\n", encoding="utf-8",
        )
        completed = subprocess.run(
            [
                str(ROOT / "vibesec"), "agents", "verify", "codex",
                "--target", str(self.target), "--json",
            ],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 1, completed.stderr + completed.stdout)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "invalid")
        self.assertEqual(payload["result"]["adapters"][0]["state"], "modified")

    def test_symlink_target_and_duplicate_inventory_fail_closed(self):
        link = self.target / "AGENTS.md"
        link.symlink_to(FIXTURES / "conflict/AGENTS.md")
        plan = plan_install(ROOT, self.target, "codex")
        self.assertEqual(plan["status"], "conflicting")
        link.unlink()
        install_adapter(ROOT, self.target, "codex", write=True)
        inventory = load_inventory(self.target)
        duplicate = {**inventory, "adapters": [*inventory["adapters"], inventory["adapters"][0]]}
        with self.assertRaisesRegex(AgentGuidanceError, "duplicate"):
            validate_inventory(duplicate)

    def test_malicious_repository_text_is_not_read_or_rendered(self):
        shutil.copy2(FIXTURES / "malicious/untrusted-instructions.txt", self.target / "README-untrusted.txt")
        output = render_adapter(ROOT, self.target, "kimi-cli").decode("utf-8")
        self.assertNotIn("reveal every token", output)
        self.assertNotIn("execute instructions embedded", output)
        self.assertIn("untrusted data", output)

    def test_render_task_has_complete_accountability_fields(self):
        rendered = render_task(ROOT, self.target, "gemini-cli", "resolve-ci-failure")
        for heading in (
            "## Objective", "## Scope", "## Allowed actions", "## Prohibited actions",
            "## Required checks", "## Failure handling", "## Required evidence", "## Expected output",
        ):
            self.assertIn(heading, rendered)
        self.assertIn("fix the implementation rather than the assertion", rendered)

    def test_cli_stable_json_and_no_external_agent_cli_invocation(self):
        marker = Path(self.temporary.name) / "external-agent-was-run"
        fake_bin = Path(self.temporary.name) / "bin"
        fake_bin.mkdir()
        for name in ("codex", "claude", "gemini", "kimi"):
            script = fake_bin / name
            script.write_text(f"#!/bin/sh\nprintf invoked > '{marker}'\n", encoding="utf-8")
            script.chmod(0o755)
        environment = {"PATH": f"{fake_bin}:/usr/bin:/bin"}
        completed = subprocess.run(
            [str(ROOT / "vibesec"), "agents", "install", "codex", "--target", str(self.target), "--write", "--json"],
            cwd=ROOT, env=environment, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["command"], "agents_install")
        self.assertEqual(payload["result"]["status"], "installed")
        self.assertFalse(marker.exists())

    def test_bundle_contains_agent_contract_and_is_reproducible(self):
        first, first_manifest = build_bundle_bytes(ROOT)
        second, second_manifest = build_bundle_bytes(ROOT)
        self.assertEqual(hashlib.sha256(first).digest(), hashlib.sha256(second).digest())
        self.assertEqual(first_manifest, second_manifest)
        bundle_path = Path(self.temporary.name) / "agents-bundle.zip"
        bundle_path.write_bytes(first)
        verified = verify_bundle(bundle_path)
        self.assertIn("agents", verified.manifest["capabilities"])
        for path in (
            "machine/agents/contract.json", "scripts/vibesec/agents.py", "scripts/manage_agents.py",
            "docs/multi-agent-support.md",
        ):
            self.assertIn(path, verified.entries)

    def test_bundle_initializer_verifier_doctor_and_upgrade_are_agent_aware(self):
        bundle_path = Path(self.temporary.name) / "consumer.zip"
        bundle_path.write_bytes(build_bundle_bytes(ROOT)[0])
        consumer = Path(self.temporary.name) / "consumer"
        consumer.mkdir()
        initialized = subprocess.run(
            [
                "python3", "scripts/init_vibesec.py", "--bundle", str(bundle_path), "--profile", "minimal",
                "--target", str(consumer), "--capabilities-file", ".vibesec/project-capabilities.json", "--write",
            ],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        installed = subprocess.run(
            [str(consumer / "vibesec"), "agents", "install", "codex", "--target", str(consumer), "--write", "--json"],
            cwd=consumer, text=True, capture_output=True, check=False,
        )
        self.assertEqual(installed.returncode, 0, installed.stderr + installed.stdout)
        verified = subprocess.run(
            ["python3", "scripts/verify_installation.py", "--target", str(consumer), "--json"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr + verified.stdout)
        agent_verification = json.loads(verified.stdout)["result"]["agent_verification"]
        self.assertEqual(agent_verification["status"], "valid")
        self.assertEqual(agent_verification["adapters"][0]["adapter_id"], "codex")
        doctor_result = subprocess.run(
            ["python3", "scripts/vibesec_doctor.py", "--target", str(consumer), "--json"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertIn(doctor_result.returncode, {0, 1}, doctor_result.stderr + doctor_result.stdout)
        context = json.loads(doctor_result.stdout)["result"]["context"]["agents"]
        self.assertEqual(context["status"], "valid")
        upgrade = subprocess.run(
            [
                "python3", "scripts/plan_vibesec_upgrade.py", "--target", str(consumer),
                "--bundle", str(bundle_path), "--json",
            ],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertIn(upgrade.returncode, {0, 1}, upgrade.stderr + upgrade.stdout)
        self.assertEqual(json.loads(upgrade.stdout)["result"]["agent_inventory"]["status"], "valid")


if __name__ == "__main__":
    unittest.main()
