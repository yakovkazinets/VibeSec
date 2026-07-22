import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from vibesec.capabilities import (  # noqa: E402
    CAPABILITY_KEYS,
    QUESTIONS,
    CapabilityError,
    all_capabilities,
    ask_capabilities,
    capability_bytes,
    load_capabilities_file,
    parse_answer,
    parse_capabilities,
    scanner_applicability,
)
sys.path.remove(str(ROOT / "scripts"))


class ProjectCapabilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_every_question_defaults_to_yes_and_enter_records_yes(self):
        prompt = io.StringIO()
        result = ask_capabilities(io.StringIO("\n" * len(QUESTIONS)), prompt)
        self.assertTrue(all(result["capabilities"].values()))
        self.assertEqual(prompt.getvalue().count("[Y/n]"), len(QUESTIONS))
        self.assertEqual(tuple(result["capabilities"]), CAPABILITY_KEYS)

    def test_yes_no_parsing_is_case_insensitive_and_invalid_reprompts(self):
        for value in ("y", "Y", "yes", "YES", " Yes "):
            self.assertIs(parse_answer(value), True)
        for value in ("n", "N", "no", "NO", " No "):
            self.assertIs(parse_answer(value), False)
        self.assertIsNone(parse_answer("maybe"))
        answers = "maybe\nyes\n" + "\n" * (len(QUESTIONS) - 1)
        prompt = io.StringIO()
        result = ask_capabilities(io.StringIO(answers), prompt)
        self.assertTrue(result["capabilities"]["web_application"])
        self.assertIn("Please answer Yes or No", prompt.getvalue())

    def test_eof_never_invents_answers(self):
        with self.assertRaisesRegex(CapabilityError, "ended"):
            ask_capabilities(io.StringIO(""), io.StringIO())
        target = self.root / "target"
        target.mkdir()
        completed = subprocess.run(
            ["python3", "scripts/init_vibesec.py", "--profile", "minimal", "--target", str(target)],
            cwd=ROOT, stdin=subprocess.DEVNULL, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 3)
        self.assertEqual(list(target.iterdir()), [])
        self.assertIn("--capabilities-file or --all-capabilities", completed.stdout)

    def test_strict_schema_unknown_duplicate_non_boolean_and_dependencies_fail_closed(self):
        valid = all_capabilities()
        for mutation in (
            {**valid, "unknown": False},
            {"schema_version": 1, "capabilities": {**valid["capabilities"], "unknown": False}},
            {"schema_version": 1, "capabilities": {**valid["capabilities"], "python": 1}},
            {"schema_version": 1, "capabilities": {**valid["capabilities"], "web_application": False}},
        ):
            with self.assertRaises(CapabilityError):
                capability_bytes(mutation)
        duplicate = b'{"schema_version":1,"schema_version":1,"capabilities":{}}'
        with self.assertRaises(CapabilityError):
            parse_capabilities(duplicate)
        conflict = all_capabilities(False)
        conflict["capabilities"]["public_runtime"] = True
        with self.assertRaisesRegex(CapabilityError, "public_runtime"):
            capability_bytes(conflict)
        conflict = all_capabilities(False)
        conflict["capabilities"]["authentication"] = True
        with self.assertRaisesRegex(CapabilityError, "authentication"):
            capability_bytes(conflict)
        for dependency in ("api", "container_image"):
            conflict = all_capabilities(False)
            conflict["capabilities"].update({"api": True, "container_image": True, "api_security_target": True})
            conflict["capabilities"][dependency] = False
            with self.subTest(dependency=dependency), self.assertRaisesRegex(CapabilityError, dependency):
                capability_bytes(conflict)

    def test_file_loader_rejects_bom_oversize_and_symlink(self):
        manifest = self.root / "manifest.json"
        manifest.write_bytes(b"\xef\xbb\xbf" + capability_bytes(all_capabilities()))
        with self.assertRaises(CapabilityError):
            load_capabilities_file(manifest)
        manifest.write_bytes(b" " * 20_000)
        with self.assertRaises(CapabilityError):
            load_capabilities_file(manifest)
        if hasattr(os, "symlink"):
            source = self.root / "source.json"
            source.write_bytes(capability_bytes(all_capabilities()))
            manifest.unlink()
            manifest.symlink_to(source)
            with self.assertRaisesRegex(CapabilityError, "symbolic"):
                load_capabilities_file(manifest)

    def test_dry_run_shows_manifest_and_write_is_atomic_and_no_overwrite(self):
        target = self.root / "target"
        target.mkdir()
        base = ["python3", "scripts/init_vibesec.py", "--profile", "minimal", "--target", str(target), "--all-capabilities"]
        dry = subprocess.run(base, cwd=ROOT, text=True, capture_output=True, check=False)
        payload = json.loads(dry.stdout)
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertEqual(payload["project_capabilities"], all_capabilities())
        self.assertIn(".vibesec/project-capabilities.json", payload["would_create"])
        self.assertEqual(list(target.iterdir()), [])
        written = subprocess.run([*base, "--write"], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(written.returncode, 0, written.stderr)
        path = target / ".vibesec/project-capabilities.json"
        self.assertEqual(load_capabilities_file(path), all_capabilities())
        before = path.read_bytes()
        repeated = subprocess.run([*base, "--write"], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(repeated.returncode, 2)
        self.assertEqual(path.read_bytes(), before)
        self.assertFalse(any(item.name.startswith(".project-capabilities.json.") for item in path.parent.iterdir()))

    def test_capabilities_file_is_authoritative_and_scanner_mapping_is_honest(self):
        payload = all_capabilities(False)
        payload["capabilities"].update({"infrastructure_as_code": True, "github_actions": True, "secrets_configuration": True})
        manifest = self.root / "answers.json"
        manifest.write_bytes(capability_bytes(payload))
        target = self.root / "target"
        target.mkdir()
        completed = subprocess.run(
            ["python3", "scripts/init_vibesec.py", "--profile", "minimal", "--target", str(target),
             "--capabilities-file", str(manifest), "--write"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(load_capabilities_file(target / ".vibesec/project-capabilities.json"), payload)
        states = scanner_applicability(payload)
        self.assertEqual(states["gitleaks"]["state"], "applicable")
        self.assertEqual(states["checkov"]["state"], "applicable")
        self.assertEqual(states["actionlint"]["state"], "applicable")
        self.assertEqual(states["trivy-image"]["state"], "not_applicable")
        self.assertEqual(states["dast-baseline"]["state"], "not_applicable")

    def test_vibesec_manifest_is_exactly_not_applicable_for_dast(self):
        payload = load_capabilities_file(ROOT / ".vibesec/project-capabilities.json")
        self.assertFalse(payload["capabilities"]["web_application"])
        self.assertFalse(payload["capabilities"]["dast_target"])
        state = scanner_applicability(payload)["dast-baseline"]
        self.assertEqual(state["state"], "not_applicable")
        self.assertEqual(state["reason"], "project capability manifest declares no runnable web application target")
        self.assertTrue((ROOT / "scripts/test_dast_container.py").is_file())

    def test_vibesec_manifest_is_exactly_not_applicable_for_api_security(self):
        payload = load_capabilities_file(ROOT / ".vibesec/project-capabilities.json")
        self.assertFalse(payload["capabilities"]["api"])
        self.assertFalse(payload["capabilities"]["api_security_target"])
        state = scanner_applicability(payload)["api-security-baseline"]
        self.assertEqual(state["state"], "not_applicable")
        self.assertEqual(state["reason"], "project capability manifest declares no runnable OpenAPI API target")

    def test_dast_addon_is_not_installed_when_explicitly_not_applicable(self):
        payload = all_capabilities(False)
        payload["capabilities"]["secrets_configuration"] = True
        answers = self.root / "answers.json"
        answers.write_bytes(capability_bytes(payload))
        target = self.root / "consumer"
        target.mkdir()
        base = subprocess.run(
            ["python3", "scripts/init_vibesec.py", "--profile", "minimal", "--target", str(target),
             "--capabilities-file", str(answers), "--write"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(base.returncode, 0, base.stderr)
        addon = subprocess.run(
            ["python3", "scripts/init_vibesec.py", "--addon", "dast-baseline", "--target", str(target), "--write"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        result = json.loads(addon.stdout)
        self.assertEqual(addon.returncode, 0, addon.stderr)
        self.assertIn("dast-baseline = not_applicable", result["skipped"][0])
        self.assertFalse((target / ".github/workflows/vibesec-dast-baseline.yml").exists())
        self.assertFalse((target / ".vibesec/install-addon-dast-baseline.json").exists())

        doctor = subprocess.run(
            ["python3", "scripts/vibesec_doctor.py", "--target", str(target), "--json"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        diagnosis = json.loads(doctor.stdout)
        codes = {item["code"] for item in diagnosis["result"]["diagnostics"]}
        self.assertIn("DAST_NOT_APPLICABLE", codes)
        self.assertNotIn("DAST_SUPPORT_MISSING", codes)

    def test_doctor_detects_missing_dast_support_and_manifest_drift(self):
        target = self.root / "consumer"
        target.mkdir()
        installed = subprocess.run(
            ["python3", "scripts/init_vibesec.py", "--profile", "minimal", "--target", str(target),
             "--all-capabilities", "--write"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(installed.returncode, 0, installed.stderr)
        doctor = subprocess.run(
            ["python3", "scripts/vibesec_doctor.py", "--target", str(target), "--json"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        diagnosis = json.loads(doctor.stdout)
        self.assertIn("DAST_SUPPORT_MISSING", {item["code"] for item in diagnosis["result"]["diagnostics"]})
        manifest = target / ".vibesec/project-capabilities.json"
        changed = all_capabilities(False)
        changed["capabilities"]["secrets_configuration"] = True
        manifest.write_bytes(capability_bytes(changed))
        doctor = subprocess.run(
            ["python3", "scripts/vibesec_doctor.py", "--target", str(target), "--json"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        diagnosis = json.loads(doctor.stdout)
        self.assertIn("CAPABILITY_MANIFEST_CHANGED", {item["code"] for item in diagnosis["result"]["diagnostics"]})


if __name__ == "__main__":
    unittest.main()
