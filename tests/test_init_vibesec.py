import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/init_vibesec.py"
SPEC = importlib.util.spec_from_file_location("init_vibesec", SCRIPT)
assert SPEC and SPEC.loader
INIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INIT
SPEC.loader.exec_module(INIT)


class InitVibeSecTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.target = Path(self.temporary.name) / "consumer"
        self.target.mkdir()

    def run_init(self, profile="minimal", *, target=None, stage=None, write=False):
        command = ["python3", str(SCRIPT), "--profile", profile, "--target", str(target or self.target)]
        if stage:
            command += ["--stage", stage]
        if write:
            command.append("--write")
        completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        return completed, json.loads(completed.stdout)

    def test_minimal_dry_run_is_non_mutating_and_deterministic(self):
        first, payload = self.run_init()
        second, second_payload = self.run_init()
        self.assertEqual(first.returncode, second.returncode, first.stderr)
        self.assertEqual(payload, second_payload)
        self.assertTrue(payload["would_create"])
        self.assertEqual(list(self.target.iterdir()), [])

    def test_standard_dry_run_explains_two_stage_bootstrap(self):
        completed, payload = self.run_init("standard")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(any("two-stage" in item for item in payload["warning"]))
        self.assertNotIn(".github/workflows/vibesec-standard.yml", payload["would_create"])

    def test_minimal_write_creates_observe_workflow_baseline_and_manifest(self):
        completed, payload = self.run_init(write=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(sorted(payload["created"]), sorted(payload["would_create"]))
        workflow = (self.target / ".github/workflows/vibesec-minimal.yml").read_text(encoding="utf-8")
        self.assertIn("VIBESEC_ENFORCEMENT: observe", workflow)
        baseline = json.loads((self.target / "policy/baseline.json").read_text(encoding="utf-8"))
        self.assertEqual(baseline["profile"], "minimal")
        manifest = json.loads((self.target / ".vibesec/install-minimal-all.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["profile"], "minimal")
        self.assertEqual(manifest["initializer_network_behavior"], "none")
        self.assertEqual(manifest["development_version"], "0.3.0-dev")
        self.assertTrue(all(set(item) == {"path", "sha256", "mode"} for item in manifest["installed_files"]))

    def test_standard_support_then_workflow_write(self):
        support, support_payload = self.run_init("standard", write=True)
        self.assertEqual(support.returncode, 0, support.stderr)
        self.assertNotIn(".github/workflows/vibesec-standard.yml", support_payload["created"])
        workflow, workflow_payload = self.run_init("standard", stage="workflow", write=True)
        self.assertEqual(workflow.returncode, 0, workflow.stderr)
        self.assertIn(".github/workflows/vibesec-standard.yml", workflow_payload["created"])
        self.assertTrue((self.target / "policy/standard-baseline.json").is_file())
        self.assertFalse((self.target / "policy/baseline.json").exists())
        text = (self.target / ".github/workflows/vibesec-standard.yml").read_text(encoding="utf-8")
        self.assertIn("VIBESEC_ENFORCEMENT: observe", text)

    def test_standard_workflow_requires_completed_support_stage(self):
        completed, payload = self.run_init("standard", stage="workflow", write=True)
        self.assertEqual(completed.returncode, 3)
        self.assertTrue(any("requires support files" in item for item in payload["error"]))
        self.assertEqual(list(self.target.iterdir()), [])

    def test_existing_conflict_and_partial_install_leave_no_new_files(self):
        conflict = self.target / "config/tools.json"
        conflict.parent.mkdir()
        conflict.write_text("owned by consumer\n", encoding="utf-8")
        before = sorted(path.relative_to(self.target).as_posix() for path in self.target.rglob("*") if path.is_file())
        completed, payload = self.run_init(write=True)
        after = sorted(path.relative_to(self.target).as_posix() for path in self.target.rglob("*") if path.is_file())
        self.assertEqual(completed.returncode, 2)
        self.assertIn("config/tools.json", payload["conflict"])
        self.assertEqual(before, after)
        self.assertEqual(conflict.read_text(encoding="utf-8"), "owned by consumer\n")

    def test_existing_vibesec_workflow_is_a_conflict(self):
        workflow = self.target / ".github/workflows/vibesec-minimal.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: existing\n", encoding="utf-8")
        completed, payload = self.run_init(write=True)
        self.assertEqual(completed.returncode, 2)
        self.assertIn(".github/workflows/vibesec-minimal.yml", payload["conflict"])

    def test_overlapping_security_workflow_produces_warning(self):
        workflow = self.target / ".github/workflows/security.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: Existing\njobs:\n  semgrep: {}\n", encoding="utf-8")
        completed, payload = self.run_init()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(any("semgrep" in item for item in payload["warning"]))

    def test_invalid_targets_fail_with_configuration_exit(self):
        missing = Path(self.temporary.name) / "missing"
        missing_result, _ = self.run_init(target=missing)
        file_target = Path(self.temporary.name) / "file"
        file_target.write_text("x", encoding="utf-8")
        file_result, _ = self.run_init(target=file_target)
        source_result, _ = self.run_init(target=ROOT)
        self.assertEqual((missing_result.returncode, file_result.returncode, source_result.returncode), (3, 3, 3))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_target_and_nested_symlink_escapes_are_rejected(self):
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        linked_target = Path(self.temporary.name) / "linked"
        linked_target.symlink_to(outside, target_is_directory=True)
        target_result, _ = self.run_init(target=linked_target)
        self.assertEqual(target_result.returncode, 3)
        (self.target / "scripts").symlink_to(outside, target_is_directory=True)
        nested_result, payload = self.run_init(write=True)
        self.assertEqual(nested_result.returncode, 3)
        self.assertTrue(any("symbolic link" in item for item in payload["error"]))
        self.assertEqual(list(outside.iterdir()), [])

    def test_interrupted_write_rolls_back_files_and_directories(self):
        catalog = INIT.load_catalog()
        plan = INIT.build_plan(catalog, "minimal", "all")
        output = INIT.result()
        INIT.preflight(self.target, plan, output)
        real_link = os.link
        calls = 0

        def fail_second(source, destination, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated interruption")
            return real_link(source, destination, **kwargs)

        with patch.object(INIT.os, "link", side_effect=fail_second):
            with self.assertRaises(OSError):
                INIT.write_plan(self.target, plan, output)
        self.assertEqual(list(self.target.iterdir()), [])
        self.assertEqual(output["created"], [])

    def test_repeat_write_is_safe_and_does_not_overwrite(self):
        first, _ = self.run_init(write=True)
        before = {path.relative_to(self.target): path.read_bytes() for path in self.target.rglob("*") if path.is_file()}
        second, _ = self.run_init(write=True)
        after = {path.relative_to(self.target): path.read_bytes() for path in self.target.rglob("*") if path.is_file()}
        self.assertEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 2)
        self.assertEqual(before, after)

    def test_executable_permissions_are_preserved(self):
        completed, _ = self.run_init(write=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        mode = stat.S_IMODE((self.target / "scripts/run_minimal_profile.sh").stat().st_mode)
        self.assertTrue(mode & stat.S_IXUSR)
        self.assertFalse(stat.S_IMODE((self.target / "policy/baseline.json").stat().st_mode) & stat.S_IXUSR)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root bypasses directory permissions")
    def test_read_only_destination_fails_without_partial_installation(self):
        self.target.chmod(0o555)
        try:
            completed, payload = self.run_init(write=True)
            self.assertEqual(completed.returncode, 4)
            self.assertTrue(payload["error"])
            self.assertEqual(list(self.target.iterdir()), [])
        finally:
            self.target.chmod(0o755)

    def test_initializer_has_no_command_network_or_package_execution(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for prohibited in ("subprocess", "socket", "urllib", "requests", "pip install", "npm install", "git commit", "git push"):
            self.assertNotIn(prohibited, text)

    def test_case_collision_is_rejected(self):
        upper = self.target / "CONFIG"
        upper.mkdir()
        completed, payload = self.run_init()
        self.assertEqual(completed.returncode, 2)
        self.assertTrue(payload["conflict"])


if __name__ == "__main__":
    unittest.main()
