import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from vibesec.branding import (  # noqa: E402
    POSITIONING_LINE, PRODUCT_DISPLAY_NAME, PRODUCT_ID, REPOSITORY_SLUG,
    REPOSITORY_URL,
)
from vibesec.bundle import BUNDLE_MANIFEST, _validate_manifest, build_bundle_bytes  # noqa: E402
from vibesec.supply_chain import (  # noqa: E402
    BUNDLE_NAME, CORE_NAMES, REPOSITORY, create_release_manifest,
    validate_release_manifest,
)
from vibesec.v1_contract import validate_migrations, validate_readiness  # noqa: E402
sys.path.remove(str(ROOT / "scripts"))


BRANDING_FIELDS = {"product_display_name", "positioning_line", "product_id"}


class BrandingTests(unittest.TestCase):
    def test_public_display_name_and_positioning_are_canonical(self):
        self.assertEqual(PRODUCT_DISPLAY_NAME, "VibeSec Guardian")
        self.assertEqual(
            POSITIONING_LINE,
            "Open-source security for vibe-coded and AI-built software.",
        )
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
        self.assertTrue(readme.startswith(f"# {PRODUCT_DISPLAY_NAME}\n\n{POSITIONING_LINE}\n"))
        self.assertIn(f"# {PRODUCT_DISPLAY_NAME} documentation", index)
        self.assertIn(POSITIONING_LINE, index)
        completed = subprocess.run(
            [str(ROOT / "vibesec"), "--help"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            "Portable VibeSec Guardian command-line entry point.",
            completed.stdout,
        )
        report = (ROOT / "examples/reports/report.md").read_text(encoding="utf-8")
        self.assertTrue(report.startswith("# VibeSec Guardian standard profile\n"))

    def test_stable_technical_identifiers_and_repository_identity_do_not_change(self):
        self.assertEqual(PRODUCT_ID, "vibesec")
        self.assertEqual(REPOSITORY_SLUG, "yakovkazinets/VibeSec")
        self.assertEqual(REPOSITORY_URL, "https://github.com/yakovkazinets/VibeSec")
        self.assertEqual(REPOSITORY, REPOSITORY_URL)
        self.assertEqual(BUNDLE_MANIFEST, "vibesec-bundle-manifest.json")
        self.assertEqual(BUNDLE_NAME, "vibesec-consumer-bundle.zip")
        self.assertTrue((ROOT / "vibesec").is_file())
        release_schema = json.loads(
            (ROOT / "config/release-manifest-schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            release_schema["$id"],
            "https://github.com/yakovkazinets/VibeSec/schemas/release-manifest-v1.json",
        )
        self.assertEqual(
            release_schema["properties"]["source"]["properties"]["repository"]["const"],
            REPOSITORY_URL,
        )

    def test_bundle_metadata_separates_display_brand_from_artifact_identity(self):
        _, manifest = build_bundle_bytes(ROOT, "a" * 40)
        self.assertEqual(manifest["product_display_name"], PRODUCT_DISPLAY_NAME)
        self.assertEqual(manifest["positioning_line"], POSITIONING_LINE)
        self.assertEqual(manifest["product_id"], PRODUCT_ID)
        bundle_paths = [item["path"] for item in manifest["files"]]
        self.assertEqual(bundle_paths.count("vibesec"), 1)
        self.assertEqual(bundle_paths.count("scripts/vibesec/branding.py"), 1)
        self.assertEqual(_validate_manifest(manifest), manifest)
        legacy = {key: value for key, value in manifest.items() if key not in BRANDING_FIELDS}
        self.assertEqual(_validate_manifest(legacy), legacy)

    def test_release_manifest_branding_does_not_change_artifact_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in CORE_NAMES:
                (directory / name).write_bytes(b"fixture\n")
            manifest = create_release_manifest(
                directory=directory,
                version="1.1.0-dev",
                source_commit="b" * 40,
                tool_versions={"syft": "1.49.0"},
                creation_mode="local-preparation",
            )
        self.assertEqual(manifest["product_display_name"], PRODUCT_DISPLAY_NAME)
        self.assertEqual(manifest["positioning_line"], POSITIONING_LINE)
        self.assertEqual(manifest["product_id"], PRODUCT_ID)
        self.assertEqual(manifest["version"], "1.1.0-dev")
        self.assertEqual([item["name"] for item in manifest["artifacts"]], list(CORE_NAMES))
        self.assertEqual(manifest["source"]["repository"], REPOSITORY_URL)
        self.assertEqual(validate_release_manifest(manifest), manifest)
        legacy = {key: value for key, value in manifest.items() if key not in BRANDING_FIELDS}
        self.assertEqual(validate_release_manifest(legacy), legacy)

    def test_release_readiness_has_display_metadata_and_accepts_legacy_record(self):
        readiness = json.loads(
            (ROOT / "machine/release-readiness.json").read_text(encoding="utf-8")
        )
        self.assertEqual(readiness["product_display_name"], PRODUCT_DISPLAY_NAME)
        self.assertEqual(readiness["positioning_line"], POSITIONING_LINE)
        self.assertEqual(readiness["product_id"], PRODUCT_ID)
        self.assertEqual(readiness["stable_id"], "vibesec.release-readiness.v1")
        self.assertEqual(validate_readiness(readiness), readiness)
        legacy = copy.deepcopy(readiness)
        for field in BRANDING_FIELDS:
            legacy.pop(field)
        self.assertEqual(validate_readiness(legacy), legacy)

    def test_machine_and_generated_documentation_are_synchronized(self):
        completed = subprocess.run(
            [sys.executable, "scripts/generate_v1_reference.py", "--check"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        interfaces = json.loads(
            (ROOT / "machine/interfaces.json").read_text(encoding="utf-8")
        )
        self.assertEqual(interfaces["required_status"], "validate")
        self.assertTrue(all(item["stable_id"].startswith("vibesec.") for item in interfaces["interfaces"]))

    def test_existing_vibesec_migration_contracts_remain_available(self):
        migrations = validate_migrations(ROOT)
        fixture_ids = {item["fixture_id"] for item in migrations["records"]}
        self.assertIn("v0.1.0", fixture_ids)
        self.assertIn("v0.2.0", fixture_ids)
        upgrading = (ROOT / "docs/upgrading.md").read_text(encoding="utf-8")
        self.assertIn("earlier VibeSec display name", upgrading)
        self.assertIn("remain valid inputs", upgrading)


if __name__ == "__main__":
    unittest.main()
