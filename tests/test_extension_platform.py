import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from scripts.vibesec.extensions import (
    ExtensionError, collect_source, describe_extension, execute_adapter, install_extension,
    list_extensions, parse_manifest, plan_extension_upgrade, remove_extension, set_enabled,
    validate_manifest, verify_extensions,
)
from scripts.vibesec.strict_json import canonical_json

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "extensions/examples/repository-metadata"
POSITIVE = ROOT / "tests/fixtures/extensions/positive"
NEGATIVE = ROOT / "tests/fixtures/extensions/negative"


class ExtensionPlatformTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.target = Path(self.temporary.name) / "target"
        self.target.mkdir()

    def install(self):
        return install_extension(self.target, EXAMPLE, write=True)

    def mutable_source(self) -> Path:
        source = Path(self.temporary.name) / "source"
        shutil.copytree(EXAMPLE, source)
        return source

    def manifest(self):
        return json.loads((EXAMPLE / "vibesec-extension.json").read_text(encoding="utf-8"))

    def test_reference_manifest_and_schema_are_strict(self):
        source = collect_source(EXAMPLE)
        self.assertEqual(source.manifest["extension_id"], "vibesec.repository-metadata-example")
        self.assertEqual(source.manifest["permissions"]["network"], False)
        self.assertEqual(source.manifest["network"], "none")
        self.assertEqual(source.manifest["capabilities"], ["extension.vibesec.repository-metadata-example.metadata-marker"])

    def test_duplicate_json_keys_fail_closed(self):
        raw = (EXAMPLE / "vibesec-extension.json").read_text(encoding="utf-8")
        duplicate = raw.replace('"schema_version": 1,', '"schema_version": 1,\n  "schema_version": 1,')
        with self.assertRaisesRegex(ExtensionError, "duplicate"):
            parse_manifest(duplicate.encode())

    def test_unknown_fields_traversal_and_core_override_are_rejected(self):
        manifest = self.manifest()
        manifest["unknown"] = True
        with self.assertRaises(ExtensionError):
            validate_manifest(manifest)
        manifest = self.manifest()
        manifest["entrypoint"] = "../adapter.py"
        with self.assertRaisesRegex(ExtensionError, "unsafe"):
            validate_manifest(manifest)
        manifest = self.manifest()
        manifest["capabilities"] = ["source_code"]
        with self.assertRaisesRegex(ExtensionError, "namespace"):
            validate_manifest(manifest)

    def test_unsupported_permissions_are_rejected(self):
        for permission in ("repository_write", "network", "docker", "secrets"):
            manifest = self.manifest()
            manifest["permissions"][permission] = True
            with self.assertRaisesRegex(ExtensionError, "permission"):
                validate_manifest(manifest)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_source_symlinks_are_rejected(self):
        source = self.mutable_source()
        (source / "linked.py").symlink_to(source / "adapter.py")
        with self.assertRaisesRegex(ExtensionError, "symlink"):
            collect_source(source)

    def test_install_dry_run_is_non_mutating_then_write_is_atomic_and_non_overwriting(self):
        preview = install_extension(self.target, EXAMPLE, write=False)
        self.assertFalse((self.target / ".vibesec").exists())
        self.assertFalse(preview["write"])
        written = self.install()
        self.assertTrue(written["write"])
        inventory = list_extensions(self.target)
        self.assertEqual(len(inventory), 1)
        self.assertEqual(verify_extensions(self.target)["status"], "valid")
        with self.assertRaisesRegex(ExtensionError, "not be overwritten"):
            self.install()

    def test_tampering_and_untracked_files_are_detected(self):
        self.install()
        record = describe_extension(self.target, "vibesec.repository-metadata-example")
        root = self.target / ".vibesec/extensions" / record["extension_id"] / record["version"]
        (root / "adapter.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
        result = verify_extensions(self.target)
        self.assertEqual(result["status"], "invalid")
        self.assertIn("modified", result["errors"][0])

    def test_disable_and_remove_require_explicit_write(self):
        self.install()
        preview = set_enabled(self.target, "vibesec.repository-metadata-example", enabled=False, write=False)
        self.assertFalse(preview["write"])
        self.assertTrue(describe_extension(self.target, "vibesec.repository-metadata-example")["enabled"])
        set_enabled(self.target, "vibesec.repository-metadata-example", enabled=False, write=True)
        self.assertFalse(describe_extension(self.target, "vibesec.repository-metadata-example")["enabled"])
        remove_extension(self.target, "vibesec.repository-metadata-example", write=False)
        self.assertEqual(len(list_extensions(self.target)), 1)
        remove_extension(self.target, "vibesec.repository-metadata-example", write=True)
        self.assertEqual(list_extensions(self.target), [])

    def test_upgrade_plan_never_applies(self):
        self.install()
        plan = plan_extension_upgrade(self.target, EXAMPLE)
        self.assertEqual(plan["status"], "no_changes")
        self.assertFalse(plan["automatic_apply"])
        source = self.mutable_source()
        manifest = json.loads((source / "vibesec-extension.json").read_text())
        manifest["version"] = "1.0.1"
        (source / "vibesec-extension.json").write_bytes(canonical_json(manifest))
        changed = plan_extension_upgrade(self.target, source)
        self.assertEqual(changed["status"], "review_required")
        self.assertFalse(changed["automatic_apply"])

    def test_positive_and_negative_reference_fixtures(self):
        self.install()
        for name, fixture, expected in (("positive", POSITIVE, 1), ("negative", NEGATIVE, 0)):
            results = Path(self.temporary.name) / f"results-{name}"
            response = execute_adapter(self.target, "vibesec.repository-metadata-example", repository=fixture, results=results, profile="minimal", current_platform="macos-arm64")
            self.assertEqual(response["exit_code"], 0)
            self.assertEqual(response["coverage"], "ran")
            payload = json.loads((results / "normalized.json").read_text())
            self.assertEqual(len(payload["results"]), expected)
            if expected:
                self.assertEqual(payload["results"][0]["rule_id"], "controlled-marker")

    def test_adapter_failure_preserves_exact_failure_and_redacts_bearer(self):
        source = self.mutable_source()
        (source / "adapter.py").write_text(
            "#!/usr/bin/env python3\nimport json,sys\n"
            "sys.stderr.write('Authorization: Bearer top-secret-token')\n"
            "print(json.dumps({'schema_version':1,'exit_code':2,'coverage':'tool_error','normalized_findings_path':None,'artifacts':[],'diagnostics':['Bearer top-secret-token']}))\n"
            "raise SystemExit(2)\n", encoding="utf-8",
        )
        install_extension(self.target, source, write=True)
        response = execute_adapter(self.target, "vibesec.repository-metadata-example", repository=NEGATIVE, results=Path(self.temporary.name) / "unused", profile="minimal", current_platform="linux-amd64")
        self.assertEqual(response["exit_code"], 2)
        self.assertEqual(response["coverage"], "tool_error")
        rendered = json.dumps(response)
        self.assertNotIn("top-secret-token", rendered)
        self.assertNotIn("Authorization: Bearer top-secret-token", rendered)
        self.assertIn("[REDACTED]", rendered)

    def test_invalid_adapter_output_cannot_become_clean(self):
        source = self.mutable_source()
        (source / "adapter.py").write_text("#!/usr/bin/env python3\nprint('not json')\nraise SystemExit(0)\n", encoding="utf-8")
        install_extension(self.target, source, write=True)
        response = execute_adapter(self.target, "vibesec.repository-metadata-example", repository=NEGATIVE, results=Path(self.temporary.name) / "unused", profile="minimal", current_platform="linux-amd64")
        self.assertEqual(response["exit_code"], 2)
        self.assertEqual(response["coverage"], "tool_error")

    def test_cli_lifecycle_routes_without_importing_adapter(self):
        command = [str(ROOT / "vibesec"), "extensions", "install", str(EXAMPLE), "--target", str(self.target), "--write", "--json"]
        installed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        listed = subprocess.run([str(ROOT / "vibesec"), "extensions", "list", "--target", str(self.target), "--json"], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertEqual(json.loads(listed.stdout)["result"]["extensions"][0]["extension_id"], "vibesec.repository-metadata-example")


if __name__ == "__main__":
    unittest.main()
