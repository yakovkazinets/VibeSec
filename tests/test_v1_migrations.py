import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from vibesec.bundle import build_bundle_bytes  # noqa: E402
from vibesec.v1_contract import validate_migrations  # noqa: E402


class V1MigrationTests(unittest.TestCase):
    def test_all_representative_paths_and_preservation_contract_validate(self):
        value = validate_migrations(ROOT)
        self.assertEqual(len(value["records"]), 11)
        self.assertEqual(
            {record["fixture_id"] for record in value["records"]},
            {"v0.1.0", "v0.2.0", "current-pre-v1", "minimal-only", "standard",
             "dast", "api", "authenticated", "fuzzing", "extension", "multi-agent"},
        )

    def test_fixtures_preserve_explicit_no_and_never_contain_secret_values(self):
        value = json.loads(
            (ROOT / "tests/fixtures/v1-migrations/representative-installations.json").read_text()
        )
        for fixture in value["fixtures"]:
            self.assertIn(False, fixture["explicit_answers"].values())
            self.assertFalse(fixture["secret_values_present"])
            self.assertTrue(fixture["secret_names"])

    def test_real_upgrade_plan_is_read_only_and_preserves_local_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            bundle = base / "bundle.zip"
            bundle.write_bytes(build_bundle_bytes(ROOT, "b" * 40)[0])
            target = base / "target"
            target.mkdir()
            initialized = subprocess.run(
                [sys.executable, "scripts/init_vibesec.py", "--bundle", str(bundle),
                 "--profile", "minimal", "--target", str(target), "--all-capabilities", "--write"],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            local = target / ".github/workflows/vibesec-minimal.yml"
            local.write_text(local.read_text(encoding="utf-8") + "# local customization\n", encoding="utf-8")
            unrelated = target / "application-owned.txt"
            unrelated.write_text("preserve\n", encoding="utf-8")
            before = {
                str(path.relative_to(target)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in target.rglob("*") if path.is_file()
            }
            planned = subprocess.run(
                [sys.executable, "scripts/plan_vibesec_upgrade.py", "--target", str(target),
                 "--bundle", str(bundle), "--json"],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(planned.returncode, 1, planned.stderr)
            payload = json.loads(planned.stdout)["result"]
            record = next(item for item in payload["files"] if item["path"] == ".github/workflows/vibesec-minimal.yml")
            self.assertEqual(record["classification"], "locally_modified_upstream_unchanged")
            self.assertTrue(record["preservation_sensitive"])
            after = {
                str(path.relative_to(target)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in target.rglob("*") if path.is_file()
            }
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
