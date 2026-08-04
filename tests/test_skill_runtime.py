import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
import zipfile

from scripts.vibesec.bundle import build_bundle_bytes

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "skills/appsec-guardian/scripts/bootstrap_scan.py"


def load_bootstrap():
    spec = importlib.util.spec_from_file_location("vibesec_skill_bootstrap", BOOTSTRAP)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class SkillRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime_source_temporary = tempfile.TemporaryDirectory()
        runtime_source = Path(cls.runtime_source_temporary.name) / "v1.1.0-runtime"
        shutil.copytree(
            ROOT,
            runtime_source,
            ignore=shutil.ignore_patterns(".git", ".tools", "__pycache__", "results"),
        )
        (runtime_source / "VERSION").write_text("1.1.0-dev\n", encoding="utf-8")
        cls.v1_1_0_bundle = build_bundle_bytes(runtime_source)[0]

    @classmethod
    def tearDownClass(cls):
        cls.runtime_source_temporary.cleanup()

    def setUp(self):
        self.bootstrap = load_bootstrap()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.cache = self.base / "cache"
        self.bundle = self.base / "consumer.zip"
        self.bundle.write_bytes(self.v1_1_0_bundle)
        self.digest = hashlib.sha256(self.bundle.read_bytes()).hexdigest()
        self.metadata = {
            "schema_version": 1,
            "release_version": "1.1.0",
            "development_version": "1.1.0-dev",
            "bundle_name": "vibesec-consumer-bundle.zip",
            "bundle_url": "https://github.com/yakovkazinets/VibeSec/releases/download/v1.1.0/vibesec-consumer-bundle.zip",
            "bundle_sha256": "0" * 64,
        }

    def test_local_override_installs_verifies_and_reuses_complete_runtime(self):
        executable, reused = self.bootstrap._install_runtime(
            metadata=self.metadata, cache=self.cache, local_bundle=self.bundle,
            local_sha256=self.digest,
        )
        self.assertFalse(reused)
        self.assertTrue(executable.is_file())
        self.assertTrue(executable.stat().st_mode & stat.S_IXUSR)
        self.assertTrue((executable.parent / "scripts/vibesec/toolchain.py").is_file())
        repeated, reused = self.bootstrap._install_runtime(
            metadata=self.metadata, cache=self.cache, local_bundle=self.bundle,
            local_sha256=self.digest,
        )
        self.assertEqual(repeated, executable)
        self.assertTrue(reused)

    def test_nested_explicit_runtime_cache_is_created_privately(self):
        nested = self.base / "new" / "nested" / "cache"
        executable, reused = self.bootstrap._install_runtime(
            metadata=self.metadata, cache=nested, local_bundle=self.bundle,
            local_sha256=self.digest,
        )
        self.assertFalse(reused)
        self.assertTrue(executable.is_file())
        for directory in (self.base / "new", self.base / "new/nested", nested):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_local_override_requires_independently_trusted_digest(self):
        with self.assertRaisesRegex(self.bootstrap.BootstrapError, "explicit SHA-256"):
            self.bootstrap._install_runtime(
                metadata=self.metadata, cache=self.cache, local_bundle=self.bundle,
                local_sha256=None,
            )
        with self.assertRaisesRegex(self.bootstrap.BootstrapError, "checksum mismatch"):
            self.bootstrap._install_runtime(
                metadata=self.metadata, cache=self.cache, local_bundle=self.bundle,
                local_sha256="f" * 64,
            )

    def test_runtime_version_mismatch_fails_closed(self):
        wrong = dict(self.metadata)
        wrong["development_version"] = "1.1.1-dev"
        with self.assertRaisesRegex(self.bootstrap.BootstrapError, "version"):
            self.bootstrap._install_runtime(
                metadata=wrong, cache=self.cache, local_bundle=self.bundle,
                local_sha256=self.digest,
            )

    def test_cached_runtime_tampering_is_rejected_before_execution(self):
        executable, _ = self.bootstrap._install_runtime(
            metadata=self.metadata, cache=self.cache, local_bundle=self.bundle,
            local_sha256=self.digest,
        )
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        with self.assertRaisesRegex(self.bootstrap.BootstrapError, "verification"):
            self.bootstrap._install_runtime(
                metadata=self.metadata, cache=self.cache, local_bundle=self.bundle,
                local_sha256=self.digest,
            )

    def test_traversal_and_symlink_runtime_entries_are_rejected(self):
        for label, name, mode in (
            ("traversal", "../escape", stat.S_IFREG | 0o644),
            ("symlink", "escape", stat.S_IFLNK | 0o777),
        ):
            with self.subTest(label=label):
                path = self.base / f"{label}.zip"
                with zipfile.ZipFile(path, "w") as archive:
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = mode << 16
                    archive.writestr(info, b"data")
                with self.assertRaises(self.bootstrap.BootstrapError):
                    self.bootstrap._verified_entries(path, "1.1.0-dev")

    def test_skill_metadata_separates_release_identity_from_stable_repository_slug(self):
        metadata = json.loads(
            (ROOT / "skills/appsec-guardian/runtime.json").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["release_version"], "1.1.0")
        self.assertIn("yakovkazinets/VibeSec/releases/download/v1.1.0/", metadata["bundle_url"])
        self.assertRegex(metadata["bundle_sha256"], r"^[0-9a-f]{64}$")

    def test_skill_routes_missing_runtime_to_real_scan_without_source_only_evidence(self):
        skill = (ROOT / "skills/appsec-guardian/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Do not stop because VibeSec Guardian", skill)
        self.assertIn("never substitute source inspection for scanner evidence", skill)
        self.assertIn("scripts/bootstrap_scan.py", skill)
        self.assertIn("--acknowledge-downloads", skill)
        self.assertIn("Validate `normalized.json`, `coverage.json`", skill)

    def test_cached_runtime_directory_symlink_is_rejected(self):
        executable, _ = self.bootstrap._install_runtime(
            metadata=self.metadata, cache=self.cache, local_bundle=self.bundle,
            local_sha256=self.digest,
        )
        outside = self.base / "outside"
        outside.mkdir()
        linked = executable.parent / "linked-directory"
        linked.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(self.bootstrap.BootstrapError, "unsafe"):
            self.bootstrap._install_runtime(
                metadata=self.metadata, cache=self.cache, local_bundle=self.bundle,
                local_sha256=self.digest,
            )

    def test_local_bundle_symlink_is_rejected(self):
        linked = self.base / "linked-bundle.zip"
        linked.symlink_to(self.bundle)
        with self.assertRaisesRegex(self.bootstrap.BootstrapError, "regular file"):
            self.bootstrap._install_runtime(
                metadata=self.metadata, cache=self.cache, local_bundle=linked,
                local_sha256=self.digest,
            )


if __name__ == "__main__":
    unittest.main()
