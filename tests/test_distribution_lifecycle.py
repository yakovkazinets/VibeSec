import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = str(ROOT / "scripts")
sys.path.insert(0, SCRIPTS)
from vibesec.bundle import build_bundle_bytes  # noqa: E402
from vibesec.installation import verify_installation  # noqa: E402
from vibesec.manifest import parse_installation_manifest  # noqa: E402
sys.path.remove(SCRIPTS)


class DistributionLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / "consumer.zip"
        self.bundle.write_bytes(build_bundle_bytes(ROOT, "a" * 40)[0])

    def target(self, name="consumer"):
        path = self.root / name
        path.mkdir()
        return path

    def init(self, target, profile="minimal", stage=None, bundle=True, write=True):
        command = ["python3", "scripts/init_vibesec.py", "--profile", profile, "--target", str(target)]
        if stage != "workflow":
            command.append("--all-capabilities")
        if bundle:
            command += ["--bundle", str(self.bundle)]
        if stage:
            command += ["--stage", stage]
        if write:
            command.append("--write")
        completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        return completed, json.loads(completed.stdout)

    def init_addon(self, target, bundle=True, write=True):
        command = ["python3", "scripts/init_vibesec.py", "--addon", "dast-baseline", "--target", str(target)]
        if bundle:
            command += ["--bundle", str(self.bundle)]
        if write:
            command.append("--write")
        completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        return completed, json.loads(completed.stdout)

    def command_json(self, script, *arguments, env=None):
        completed = subprocess.run(["python3", script, *map(str, arguments), "--json"], cwd=ROOT, text=True, capture_output=True, env=env)
        return completed, json.loads(completed.stdout)

    def test_bundle_minimal_dry_run_write_and_manifest_metadata(self):
        target = self.target()
        dry, payload = self.init(target, write=False)
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertEqual(list(target.iterdir()), [])
        self.assertEqual(payload["source"]["type"], "bundle")
        written, _ = self.init(target)
        self.assertEqual(written.returncode, 0, written.stderr)
        manifest = parse_installation_manifest((target / ".vibesec/install-minimal-all.json").read_bytes())
        self.assertEqual(manifest["development_version"], "0.3.0-dev")
        self.assertEqual(manifest["source_commit"], "a" * 40)
        self.assertRegex(manifest["bundle_manifest_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(manifest["initializer_network_behavior"], "none")
        self.assertEqual(verify_installation(target).status, "valid")
        installed = subprocess.run(["python3", str(target / "scripts/verify_installation.py"), "--target", str(target), "--json"],
                                   cwd=target, text=True, capture_output=True)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        self.assertEqual(json.loads(installed.stdout)["status"], "valid")

    def test_bundle_standard_two_stage_and_workflow_prerequisite(self):
        target = self.target()
        premature, _ = self.init(target, "standard", "workflow")
        self.assertEqual(premature.returncode, 3)
        support, _ = self.init(target, "standard", "support")
        self.assertEqual(support.returncode, 0, support.stderr)
        self.assertEqual(verify_installation(target).status, "valid")
        workflow, _ = self.init(target, "standard", "workflow")
        self.assertEqual(workflow.returncode, 0, workflow.stderr)
        state = verify_installation(target)
        self.assertEqual(state.status, "valid", state.errors)
        self.assertEqual({item["stage"] for item in state.manifests}, {"support", "workflow"})

    def test_dast_addon_requires_base_and_coexists_with_each_profile(self):
        empty = self.target("empty-addon")
        refused, _ = self.init_addon(empty)
        self.assertEqual(refused.returncode, 3)
        self.assertEqual(list(empty.iterdir()), [])
        for profile in ("minimal", "standard"):
            target = self.target(f"{profile}-dast")
            self.assertEqual(self.init(target, profile, "support" if profile == "standard" else None)[0].returncode, 0)
            if profile == "standard":
                self.assertEqual(self.init(target, profile, "workflow")[0].returncode, 0)
            installed, payload = self.init_addon(target)
            self.assertEqual(installed.returncode, 0, payload)
            state = verify_installation(target)
            self.assertEqual(state.status, "valid", state.errors)
            self.assertEqual(set(state.profiles), {profile, "dast-baseline"})
            self.assertTrue((target / ".github/workflows/vibesec-dast-baseline.yml").is_file())
            self.assertTrue((target / ".vibesec/install-addon-dast-baseline.json").is_file())

    def test_dast_addon_conflict_is_atomic_and_upgrade_preserves_policy(self):
        target = self.target("addon-conflict")
        self.init(target)
        conflict = target / "scripts/run_dast_baseline.py"
        conflict.write_text("local\n", encoding="utf-8")
        before = {path.relative_to(target): path.read_bytes() for path in target.rglob("*") if path.is_file()}
        refused, _ = self.init_addon(target)
        after = {path.relative_to(target): path.read_bytes() for path in target.rglob("*") if path.is_file()}
        self.assertEqual(refused.returncode, 2)
        self.assertEqual(before, after)
        conflict.unlink()
        self.assertEqual(self.init_addon(target)[0].returncode, 0)
        completed, payload = self.command_json("scripts/plan_vibesec_upgrade.py", "--target", target, "--bundle", self.bundle)
        self.assertIn(completed.returncode, {0, 1})
        self.assertIn("policy/dast-baseline.json", payload["result"]["files_to_preserve"])
        self.assertIn("policy/dast-suppressions.json", payload["result"]["files_to_preserve"])

    def test_invalid_bundle_is_rejected_before_target_planning(self):
        target = self.target()
        marker = target / "marker"; marker.write_bytes(b"unchanged")
        before = {path.relative_to(target): path.read_bytes() for path in target.rglob("*") if path.is_file()}
        self.bundle.write_bytes(b"not a zip")
        completed, payload = self.init(target)
        after = {path.relative_to(target): path.read_bytes() for path in target.rglob("*") if path.is_file()}
        self.assertEqual(completed.returncode, 2)
        self.assertTrue(payload["error"])
        self.assertEqual(before, after)

    def test_source_tree_initialization_remains_valid(self):
        target = self.target()
        completed, payload = self.init(target, bundle=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["source"]["type"], "source_tree")
        self.assertEqual(verify_installation(target).status, "valid")

    def test_verifier_distinguishes_local_changes_missing_mode_symlink_and_baseline(self):
        target = self.target(); self.init(target)
        script = target / "scripts/run_minimal_profile.sh"
        script.write_bytes(script.read_bytes() + b"\n# local\n")
        self.assertEqual(verify_installation(target).status, "valid_with_local_changes")
        script.unlink()
        self.assertEqual(verify_installation(target).status, "partial")

        mode_target = self.target("mode"); self.init(mode_target)
        executable = mode_target / "scripts/run_minimal_profile.sh"
        executable.chmod(0o644)
        self.assertEqual(verify_installation(mode_target).status, "invalid")

        baseline_target = self.target("baseline"); self.init(baseline_target)
        (baseline_target / "policy/baseline.json").write_text('{"profile":"standard","fingerprints":[]}\n', encoding="utf-8")
        state = verify_installation(baseline_target)
        self.assertEqual(state.status, "invalid")
        self.assertTrue(any("baseline" in item for item in state.errors))

        if hasattr(os, "symlink"):
            link_target = self.target("link"); self.init(link_target)
            replaced = link_target / "config/tools.json"; replaced.unlink(); replaced.symlink_to(ROOT / "config/tools.json")
            self.assertEqual(verify_installation(link_target).status, "invalid")

    def test_malformed_unsupported_conflicting_and_legacy_manifests(self):
        malformed = self.target("malformed"); (malformed / ".vibesec").mkdir()
        (malformed / ".vibesec/install-minimal-all.json").write_text("{", encoding="utf-8")
        self.assertEqual(verify_installation(malformed).status, "invalid")

        unsupported = self.target("unsupported"); (unsupported / ".vibesec").mkdir()
        (unsupported / ".vibesec/install-minimal-all.json").write_text('{"schema_version":99}\n', encoding="utf-8")
        self.assertEqual(verify_installation(unsupported).status, "invalid")

        conflict = self.target("conflict"); self.init(conflict)
        original = json.loads((conflict / ".vibesec/install-minimal-all.json").read_text())
        (conflict / ".vibesec/install-minimal-duplicate.json").write_text(json.dumps(original), encoding="utf-8")
        self.assertEqual(verify_installation(conflict).status, "conflict")

        legacy = self.target("legacy"); (legacy / ".vibesec").mkdir()
        baseline = legacy / "policy/baseline.json"; baseline.parent.mkdir(); baseline.write_text('{"profile":"minimal","fingerprints":[]}\n')
        payload = {"schema_version": 1, "profile": "minimal", "stage": "all", "source_version": "0.2.0",
                   "installed_files": ["policy/baseline.json"], "enforcement": "observe", "network_used_by_initializer": False}
        (legacy / ".vibesec/install-minimal-all.json").write_text(json.dumps(payload))
        self.assertEqual(verify_installation(legacy).status, "unverifiable_legacy_installation")

    def test_verifier_cli_and_doctor_json_are_structured_and_redacted(self):
        target = self.target(); self.init(target)
        verified, payload = self.command_json("scripts/verify_installation.py", "--target", target)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(payload["result"]["installation_status"], "valid")
        environment = os.environ.copy(); environment["VIBESEC_ENFORCEMENT"] = "secret-value-must-not-appear"
        doctor, diagnosis = self.command_json("scripts/vibesec_doctor.py", "--target", target, env=environment)
        self.assertEqual(doctor.returncode, 2)
        rendered = json.dumps(diagnosis)
        self.assertNotIn("secret-value-must-not-appear", rendered)
        self.assertIn("redacted", rendered)
        self.assertTrue(all(set(item) == {"component", "code", "severity", "explanation", "next_action", "documentation"}
                            for item in diagnosis["result"]["diagnostics"]))

    def test_upgrade_plan_is_read_only_and_preserves_policy(self):
        target = self.target(); self.init(target)
        baseline = target / "policy/baseline.json"
        baseline.write_bytes(baseline.read_bytes() + b"\n")
        before = {path.relative_to(target): (hashlib.sha256(path.read_bytes()).hexdigest(), stat.S_IMODE(path.stat().st_mode))
                  for path in target.rglob("*") if path.is_file()}
        completed, payload = self.command_json("scripts/plan_vibesec_upgrade.py", "--target", target, "--bundle", self.bundle)
        after = {path.relative_to(target): (hashlib.sha256(path.read_bytes()).hexdigest(), stat.S_IMODE(path.stat().st_mode))
                 for path in target.rglob("*") if path.is_file()}
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertTrue(payload["result"]["read_only"])
        self.assertIn("policy/baseline.json", payload["result"]["files_to_preserve"])
        self.assertEqual(before, after)

    def test_upgrade_preserves_explicit_no_answers(self):
        target = self.target("capability-upgrade")
        answers = self.root / "answers.json"
        payload = {
            "schema_version": 1,
            "capabilities": {
                "web_application": False, "api": False, "container_image": False,
                "kubernetes": False, "infrastructure_as_code": True, "github_actions": True,
                "javascript_typescript": False, "python": True, "java": False,
                "public_runtime": False, "authentication": False, "database": False,
                "secrets_configuration": True, "dast_target": False,
            },
        }
        answers.write_text(json.dumps(payload), encoding="utf-8")
        command = ["python3", "scripts/init_vibesec.py", "--profile", "minimal", "--target", str(target),
                   "--bundle", str(self.bundle), "--capabilities-file", str(answers), "--write"]
        installed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        before = (target / ".vibesec/project-capabilities.json").read_bytes()
        completed, plan = self.command_json("scripts/plan_vibesec_upgrade.py", "--target", target, "--bundle", self.bundle)
        self.assertIn(completed.returncode, {0, 1})
        self.assertIn(".vibesec/project-capabilities.json", plan["result"]["files_to_preserve"])
        record = next(item for item in plan["result"]["files"] if item["path"] == ".vibesec/project-capabilities.json")
        self.assertEqual(record["classification"], "capability_preserve")
        self.assertEqual((target / ".vibesec/project-capabilities.json").read_bytes(), before)

    def test_upgrade_invalid_bundle_is_code_two_and_target_unchanged(self):
        target = self.target(); self.init(target)
        bad = self.root / "bad.zip"; bad.write_bytes(b"bad")
        before = sorted((path.relative_to(target), path.read_bytes()) for path in target.rglob("*") if path.is_file())
        completed, payload = self.command_json("scripts/plan_vibesec_upgrade.py", "--target", target, "--bundle", bad)
        after = sorted((path.relative_to(target), path.read_bytes()) for path in target.rglob("*") if path.is_file())
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(payload["status"], "invalid_bundle")
        self.assertEqual(before, after)

    def test_doctor_and_upgrade_plan_identify_known_node20_workflow_pin(self):
        target = self.target("old-action-pin")
        self.assertEqual(self.init(target)[0].returncode, 0)
        workflow = target / ".github/workflows/vibesec-minimal.yml"
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace(
                "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
                "11bd71901bbe5b1630ceea73d27597364c9af683",
            ),
            encoding="utf-8",
        )
        doctor, diagnosis = self.command_json("scripts/vibesec_doctor.py", "--target", target)
        self.assertEqual(doctor.returncode, 2)
        codes = {item["code"] for item in diagnosis["result"]["diagnostics"]}
        self.assertIn("GITHUB_ACTION_NODE20_PIN", codes)
        planned, payload = self.command_json("scripts/plan_vibesec_upgrade.py", "--target", target, "--bundle", self.bundle)
        self.assertEqual(planned.returncode, 1)
        self.assertIn(".github/workflows/vibesec-minimal.yml", payload["result"]["workflow_pin_changes"])
        self.assertTrue(payload["result"]["read_only"])


if __name__ == "__main__":
    unittest.main()
