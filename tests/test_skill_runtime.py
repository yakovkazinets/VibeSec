from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts.vibesec.bundle import build_bundle_bytes

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "skills/appsec-guardian/scripts/bootstrap_scan.py"
LOCAL_VERIFIED_BUNDLE = Path("/tmp/vibesec-v1.1.1-final/vibesec-consumer-bundle.zip")
PINNED_BUNDLE_SHA256 = "98c021322c6065e4de553e5d802e284a377ae11a5c6bbb9b2e6c9168b7904566"
PINNED_BUNDLE_URL = (
    "https://github.com/yakovkazinets/VibeSec/releases/download/"
    "v1.1.1/vibesec-consumer-bundle.zip"
)


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
        runtime_source = Path(cls.runtime_source_temporary.name) / "v1.1.1-runtime"
        shutil.copytree(
            ROOT,
            runtime_source,
            ignore=shutil.ignore_patterns(".git", ".tools", "__pycache__", "results"),
        )
        (runtime_source / "VERSION").write_text("1.1.1\n", encoding="utf-8")
        cls.v1_1_1_bundle = build_bundle_bytes(runtime_source)[0]

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
        self.bundle.write_bytes(self.v1_1_1_bundle)
        self.digest = hashlib.sha256(self.bundle.read_bytes()).hexdigest()
        self.metadata = dict(self.bootstrap.TRUSTED_RUNTIME_METADATA)

    def rewrite_bundle(
        self, name: str, *, data_updates: dict[str, bytes] | None = None,
        mode_updates: dict[str, int] | None = None,
    ) -> Path:
        destination = self.base / name
        with zipfile.ZipFile(self.bundle) as source, zipfile.ZipFile(destination, "w") as output:
            for info in source.infolist():
                copied = copy.copy(info)
                if mode_updates and info.filename in mode_updates:
                    copied.external_attr = (
                        stat.S_IFREG | mode_updates[info.filename]
                    ) << 16
                data = (
                    data_updates[info.filename]
                    if data_updates and info.filename in data_updates
                    else source.read(info)
                )
                output.writestr(copied, data)
        return destination

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
        wrong["development_version"] = "1.1.0-dev"
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
                    self.bootstrap._verified_entries(path, "1.1.1")

    def test_skill_metadata_exactly_pins_verified_v1_1_1_release(self):
        metadata = json.loads(
            (ROOT / "skills/appsec-guardian/runtime.json").read_text(encoding="utf-8")
        )
        expected = {
            "schema_version": 1,
            "release_version": "1.1.1",
            "development_version": "1.1.1",
            "bundle_name": "vibesec-consumer-bundle.zip",
            "bundle_url": PINNED_BUNDLE_URL,
            "bundle_sha256": PINNED_BUNDLE_SHA256,
        }
        self.assertEqual(metadata, expected)
        self.assertEqual(self.bootstrap.TRUSTED_RUNTIME_METADATA, expected)

    def test_local_verified_v1_1_1_zip_matches_pin_when_available(self):
        if not LOCAL_VERIFIED_BUNDLE.is_file():
            self.skipTest("verified local v1.1.1 bundle is not available")
        self.assertEqual(
            hashlib.sha256(LOCAL_VERIFIED_BUNDLE.read_bytes()).hexdigest(),
            PINNED_BUNDLE_SHA256,
        )
        entries, modes = self.bootstrap._verified_entries(
            LOCAL_VERIFIED_BUNDLE, "1.1.1",
        )
        self.assertEqual(entries["VERSION"], b"1.1.1\n")
        self.assertEqual(set(entries), set(modes))

    def test_trusted_metadata_contract_rejects_v1_1_0_and_every_modified_field(self):
        valid_path = self.base / "runtime-valid.json"
        valid_path.write_text(
            json.dumps(self.metadata, sort_keys=True) + "\n", encoding="utf-8",
        )
        with patch.object(self.bootstrap, "RUNTIME_METADATA", valid_path):
            self.assertEqual(self.bootstrap._load_metadata(), self.metadata)

        v1_1_0 = {
            "schema_version": 1,
            "release_version": "1.1.0",
            "development_version": "1.1.0-dev",
            "bundle_name": "vibesec-consumer-bundle.zip",
            "bundle_url": (
                "https://github.com/yakovkazinets/VibeSec/releases/download/"
                "v1.1.0/vibesec-consumer-bundle.zip"
            ),
            "bundle_sha256": "818381f65c3c2301165deef76164ac77b148550368c590a7b8624bc89cd35c13",
        }
        mutations = {
            "v1.1.0 metadata": v1_1_0,
            "schema": {**self.metadata, "schema_version": 2},
            "release version": {**self.metadata, "release_version": "1.1.2"},
            "development version": {**self.metadata, "development_version": "1.1.1-dev"},
            "filename": {**self.metadata, "bundle_name": "renamed.zip"},
            "URL": {**self.metadata, "bundle_url": PINNED_BUNDLE_URL + "?alternate=1"},
            "checksum": {**self.metadata, "bundle_sha256": "f" * 64},
            "extra field": {**self.metadata, "source_commit": "0" * 40},
        }
        for label, payload in mutations.items():
            with self.subTest(label=label):
                path = self.base / f"runtime-invalid-{len(label)}.json"
                path.write_text(
                    json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8",
                )
                with patch.object(self.bootstrap, "RUNTIME_METADATA", path):
                    with self.assertRaisesRegex(
                        self.bootstrap.BootstrapError, "reviewed v1.1.1 release",
                    ):
                        self.bootstrap._load_metadata()

    def test_internal_manifest_version_inventory_modes_and_checksums_remain_enforced(self):
        malformed_manifest = self.rewrite_bundle(
            "malformed-manifest.zip",
            data_updates={"vibesec-bundle-manifest.json": b"{"},
        )

        with zipfile.ZipFile(self.bundle) as archive:
            manifest = json.loads(archive.read("vibesec-bundle-manifest.json"))
        wrong_version = b"1.1.0\n"
        for record in manifest["files"]:
            if record["path"] == "VERSION":
                record["size"] = len(wrong_version)
                record["sha256"] = hashlib.sha256(wrong_version).hexdigest()
        version_mismatch = self.rewrite_bundle(
            "version-mismatch.zip",
            data_updates={
                "VERSION": wrong_version,
                "vibesec-bundle-manifest.json": (
                    json.dumps(manifest, indent=2, sort_keys=True) + "\n"
                ).encode(),
            },
        )

        with zipfile.ZipFile(self.bundle) as archive:
            incomplete_manifest = json.loads(
                archive.read("vibesec-bundle-manifest.json")
            )
        incomplete_manifest["files"] = [
            record for record in incomplete_manifest["files"]
            if record["path"] != "README.md"
        ]
        incomplete_inventory = self.rewrite_bundle(
            "incomplete-inventory.zip",
            data_updates={
                "vibesec-bundle-manifest.json": (
                    json.dumps(incomplete_manifest, indent=2, sort_keys=True) + "\n"
                ).encode(),
            },
        )
        wrong_mode = self.rewrite_bundle(
            "wrong-mode.zip", mode_updates={"README.md": 0o600},
        )
        wrong_checksum = self.rewrite_bundle(
            "wrong-checksum.zip", data_updates={"README.md": b"modified\n"},
        )

        cases = (
            ("manifest", malformed_manifest, "manifest"),
            ("VERSION", version_mismatch, "VERSION"),
            ("inventory", incomplete_inventory, "inventory"),
            ("mode", wrong_mode, "verification"),
            ("checksum", wrong_checksum, "verification"),
        )
        for label, path, error in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(self.bootstrap.BootstrapError, error):
                    self.bootstrap._verified_entries(path, "1.1.1")

    def test_skill_routes_missing_runtime_to_real_scan_without_source_only_evidence(self):
        skill = (ROOT / "skills/appsec-guardian/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Do not stop because VibeSec Guardian", skill)
        self.assertIn("never substitute source inspection for scanner evidence", skill)
        self.assertIn("scripts/bootstrap_scan.py", skill)
        self.assertIn("--acknowledge-downloads", skill)
        self.assertIn("Validate `normalized.json`, `coverage.json`", skill)
        warning = skill.index("Managed scan download and storage warning")
        approval = skill.index("Obtain explicit acknowledgment")
        bootstrap = skill.index("bootstrap_scan.py --profile")
        self.assertLess(warning, approval)
        self.assertLess(approval, bootstrap)
        for required in (
            "skill itself is small", "may exceed 600 MB", "cache directory",
            "Trivy, Gitleaks, and actionlint",
            "cosign, Opengrep, OSV-Scanner, and Syft",
            "separately downloaded container image", "OSV.dev or deps.dev",
            "Do not start the bootstrap or any download while approval is pending",
        ):
            self.assertIn(required, skill)

    def test_bootstrap_requires_approval_before_download_or_progress(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        arguments = [
            str(BOOTSTRAP), "--profile", "standard", "--target", str(ROOT),
        ]
        with patch.object(sys, "argv", arguments), patch.object(
            self.bootstrap, "_download",
            side_effect=AssertionError("download must not start"),
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            code = self.bootstrap.main()
        self.assertEqual(code, 2)
        self.assertEqual(
            json.loads(stdout.getvalue())["status"], "bootstrap_error",
        )
        self.assertEqual(stderr.getvalue(), "")
        self.assertFalse(self.cache.exists())

    def test_runtime_progress_is_stderr_safe_and_cache_reuse_is_accurate(self):
        progress: list[str] = []
        executable, reused = self.bootstrap._install_runtime(
            metadata=self.metadata, cache=self.cache, local_bundle=self.bundle,
            local_sha256=self.digest, progress=progress.append,
        )
        self.assertFalse(reused)
        self.assertEqual(progress, [
            "Loading trusted local VibeSec Guardian runtime bundle",
            "Verifying VibeSec Guardian runtime checksum",
            "Installing verified VibeSec Guardian runtime",
            "Installed verified VibeSec Guardian runtime",
        ])
        self.assertFalse(any(str(self.base) in line or "\x1b" in line for line in progress))

        repeated_progress: list[str] = []
        repeated, reused = self.bootstrap._install_runtime(
            metadata=self.metadata, cache=self.cache, local_bundle=self.bundle,
            local_sha256=self.digest, progress=repeated_progress.append,
        )
        self.assertEqual(repeated, executable)
        self.assertTrue(reused)
        self.assertEqual(repeated_progress, [
            "Revalidating cached VibeSec Guardian runtime",
            "Reusing verified VibeSec Guardian runtime cache",
        ])

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
