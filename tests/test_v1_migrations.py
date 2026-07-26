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
from vibesec.agents import install_adapter, set_enabled as set_agent_enabled  # noqa: E402
from vibesec.capabilities import all_capabilities, capability_bytes  # noqa: E402
from vibesec.extensions import install_extension, set_enabled as set_extension_enabled  # noqa: E402
from vibesec.strict_json import canonical_json  # noqa: E402
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

    def test_every_representative_migration_is_materialized_executed_and_preserved(self):
        catalog = validate_migrations(ROOT)
        fixture_catalog = json.loads(
            (ROOT / "tests/fixtures/v1-migrations/representative-installations.json").read_text()
        )
        fixtures = {item["id"]: item for item in fixture_catalog["fixtures"]}
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            bundle = base / "bundle.zip"
            bundle.write_bytes(build_bundle_bytes(ROOT, "b" * 40)[0])
            capabilities = all_capabilities()
            capabilities["capabilities"]["java"] = False
            answers = base / "capabilities.json"
            answers.write_bytes(capability_bytes(capabilities))
            for record in catalog["records"]:
                with self.subTest(migration=record["stable_id"]):
                    fixture = fixtures[record["fixture_id"]]
                    target = base / record["fixture_id"]
                    target.mkdir()
                    (target / "openapi.json").write_bytes(canonical_json({
                        "openapi": "3.1.0",
                        "info": {"title": "fixture", "version": "1.0.0"},
                        "paths": {
                            "/health": {
                                "get": {
                                    "operationId": "getHealth",
                                    "responses": {"200": {"description": "ok"}},
                                },
                            },
                        },
                    }))
                    profile = "standard" if fixture["installation"] == "standard" else "minimal"
                    initialized = subprocess.run(
                        [
                            sys.executable, "scripts/init_vibesec.py", "--bundle", str(bundle),
                            "--profile", profile, "--target", str(target),
                            "--capabilities-file", str(answers),
                            "--auth-secret-name", "VIBESEC_TEST_TOKEN", "--write",
                        ],
                        cwd=ROOT, text=True, capture_output=True, check=False,
                    )
                    self.assertEqual(initialized.returncode, 0, initialized.stderr)
                    if profile == "standard":
                        workflow = subprocess.run(
                            [
                                sys.executable, "scripts/init_vibesec.py",
                                "--bundle", str(bundle), "--profile", "standard",
                                "--stage", "workflow", "--target", str(target), "--write",
                            ],
                            cwd=ROOT, text=True, capture_output=True, check=False,
                        )
                        self.assertEqual(workflow.returncode, 0, workflow.stderr)

                    installation = fixture["installation"]
                    if installation in {"dast"}:
                        self._install_addon(bundle, target, "dast-baseline")
                    if installation in {"api", "authenticated", "fuzzing"}:
                        self._install_addon(
                            bundle, target, "api-security-baseline",
                            "--api-schema", "openapi.json",
                        )
                    if installation == "fuzzing":
                        self._install_addon(
                            bundle, target, "api-fuzzing",
                            "--fuzzing-mode", "combined", "--fuzzing-enabled",
                            "--injection-testing-enabled",
                        )

                    install_extension(
                        target, ROOT / "extensions/examples/repository-metadata", write=True,
                    )
                    set_extension_enabled(
                        target, "vibesec.repository-metadata-example",
                        enabled=False, write=True,
                    )
                    install_adapter(ROOT, target, "kimi-cli", write=True)
                    set_agent_enabled(
                        ROOT, target, "kimi-cli", enabled=False, write=True,
                    )
                    (target / "AGENTS.md").write_text(
                        "# User-maintained agent guidance\n", encoding="utf-8",
                    )
                    unrelated = target / fixture["unrelated_files"][0]
                    unrelated.parent.mkdir(parents=True, exist_ok=True)
                    unrelated.write_text("application-owned\n", encoding="utf-8")

                    for relative in [
                        *fixture["baselines"], *fixture["suppressions"],
                        *fixture["local_workflows"],
                    ]:
                        path = target / relative
                        self.assertTrue(path.is_file(), relative)
                        path.write_bytes(path.read_bytes() + b"\n")

                    if fixture["source_version"] in {"0.1.0", "0.2.0", "0.3.0-dev"}:
                        manifest_path = target / ".vibesec/install-minimal-all.json"
                        current = json.loads(manifest_path.read_text())
                        legacy = {
                            "schema_version": 1,
                            "profile": "minimal",
                            "stage": "all",
                            "source_version": fixture["source_version"],
                            "installed_files": [
                                item["path"] for item in current["installed_files"]
                            ],
                            "enforcement": "observe",
                            "network_used_by_initializer": False,
                        }
                        manifest_path.write_bytes(canonical_json(legacy))

                    before = self._file_hashes(target)
                    planned = subprocess.run(
                        [
                            sys.executable, "scripts/plan_vibesec_upgrade.py",
                            "--target", str(target), "--bundle", str(bundle), "--json",
                        ],
                        cwd=ROOT, text=True, capture_output=True, check=False,
                    )
                    self.assertEqual(planned.returncode, record["expected_exit"], planned.stderr)
                    self.assertNotIn("fixture-secret-value", planned.stdout)
                    payload = json.loads(planned.stdout)["result"]
                    by_path = {item["path"]: item for item in payload["files"]}
                    self.assertEqual(
                        by_path[fixture["baselines"][0]]["classification"],
                        "baseline_preserve",
                    )
                    self.assertEqual(
                        by_path[fixture["suppressions"][0]]["classification"],
                        "suppression_preserve",
                    )
                    self.assertEqual(
                        by_path[".vibesec/project-capabilities.json"]["classification"],
                        "capability_preserve",
                    )
                    self.assertTrue(
                        by_path[fixture["local_workflows"][0]]["preservation_sensitive"]
                    )
                    self.assertFalse(
                        next(
                            item for item in payload["extension_inventory"]["extensions"]
                            if item["extension_id"] == "vibesec.repository-metadata-example"
                        )["enabled"]
                    )
                    self.assertEqual(
                        payload["agent_inventory"]["adapters"][0]["state"], "disabled",
                    )
                    self.assertIn(
                        "VIBESEC_TEST_TOKEN",
                        (target / ".vibesec/authenticated-security-testing.json").read_text(),
                    )
                    self.assertFalse(
                        json.loads(
                            (target / ".vibesec/project-capabilities.json").read_text()
                        )["capabilities"]["java"]
                    )
                    self.assertEqual(before, self._file_hashes(target))

    def _install_addon(self, bundle: Path, target: Path, addon: str, *extra: str):
        completed = subprocess.run(
            [
                sys.executable, "scripts/init_vibesec.py", "--bundle", str(bundle),
                "--addon", addon, "--target", str(target), *extra, "--write",
            ],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    @staticmethod
    def _file_hashes(target: Path):
        return {
            path.relative_to(target).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in target.rglob("*") if path.is_file()
        }


if __name__ == "__main__":
    unittest.main()
