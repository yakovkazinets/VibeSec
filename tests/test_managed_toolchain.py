import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts.vibesec.portable import PROFILE_TOOLS, platform_id
from scripts.vibesec.toolchain import (
    ToolchainError, install_profile_tools, managed_results_dir, tool_cache_dir,
    validate_profile_tools,
)

ROOT = Path(__file__).resolve().parents[1]


class ManagedToolchainTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.cache = self.base / "cache"
        self.assets = self.base / "assets"
        self.assets.mkdir()
        self.metadata = json.loads((ROOT / "config/tools.json").read_text(encoding="utf-8"))

    def _tar(self, path: Path, name: str, content: bytes, *, member_type: bytes | None = None):
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo(name)
            info.mode = 0o755
            info.size = len(content)
            if member_type is not None:
                info.type = member_type
            archive.addfile(info, io.BytesIO(content) if info.isfile() else None)

    def fixture_metadata(self, profile="minimal", *, cosign_exit=0) -> Path:
        selected = set(PROFILE_TOOLS[profile])
        for name in selected:
            tool = self.metadata["tools"][name]
            asset = tool["platforms"]["macos-arm64"]
            path = self.assets / asset["asset_name"]
            source = f"#!/bin/sh\nexit {cosign_exit if name == 'cosign' else 0}\n".encode()
            if asset["archive_type"] == "tar.gz":
                self._tar(path, asset["executable_name"], source)
            else:
                path.write_bytes(source)
            asset["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            if "signature_url" in asset:
                (self.assets / f"{name}.sig").write_bytes(b"signature")
                (self.assets / f"{name}.cert").write_bytes(b"certificate")
        path = self.base / "tools.json"
        path.write_text(json.dumps(self.metadata), encoding="utf-8")
        return path

    def downloader(self, url: str, destination: Path):
        if url.endswith(".sig"):
            source = self.assets / "opengrep.sig"
        elif url.endswith(".cert"):
            source = self.assets / "opengrep.cert"
        else:
            source = self.assets / url.rsplit("/", 1)[-1]
        shutil.copyfile(source, destination)

    def test_platform_and_exact_asset_selection_are_deterministic(self):
        self.assertEqual(platform_id("Darwin", "arm64"), "macos-arm64")
        self.assertEqual(platform_id("Darwin", "x86_64"), "macos-amd64")
        self.assertEqual(platform_id("Linux", "x86_64"), "linux-amd64")
        tools = self.metadata["tools"]
        self.assertEqual(
            tools["trivy"]["platforms"]["macos-arm64"]["asset_name"],
            "trivy_0.72.0_macOS-ARM64.tar.gz",
        )
        self.assertEqual(
            tools["opengrep"]["platforms"]["macos-amd64"]["asset_name"],
            "opengrep_osx_x86",
        )

    def test_atomic_install_verified_reuse_and_tamper_rejection(self):
        metadata = self.fixture_metadata()
        tool_dir, reused = install_profile_tools(
            metadata_path=metadata, cache_home=self.cache, version="1.1.0-dev",
            platform_name="macos-arm64", profile="minimal", download=self.downloader,
        )
        self.assertFalse(reused)
        self.assertEqual(set(path.name for path in tool_dir.iterdir()), set(PROFILE_TOOLS["minimal"]))
        self.assertTrue(all(os.access(path, os.X_OK) for path in tool_dir.iterdir()))
        repeated, reused = install_profile_tools(
            metadata_path=metadata, cache_home=self.cache, version="1.1.0-dev",
            platform_name="macos-arm64", profile="minimal", download=self.downloader,
        )
        self.assertEqual(repeated, tool_dir)
        self.assertTrue(reused)
        (tool_dir / "trivy").write_bytes(b"tampered")
        with self.assertRaisesRegex(ToolchainError, "trivy"):
            validate_profile_tools(
                metadata_path=metadata, cache_home=self.cache, version="1.1.0-dev",
                platform_name="macos-arm64", profile="minimal",
            )

    def test_checksum_mismatch_never_publishes_partial_cache(self):
        metadata = self.fixture_metadata()

        def corrupt(url: str, destination: Path):
            self.downloader(url, destination)
            if "trivy" in url:
                destination.write_bytes(b"corrupt")

        with self.assertRaisesRegex(ToolchainError, "checksum mismatch"):
            install_profile_tools(
                metadata_path=metadata, cache_home=self.cache, version="1.1.0-dev",
                platform_name="macos-arm64", profile="minimal", download=corrupt,
            )
        self.assertFalse(
            tool_cache_dir(self.cache, "1.1.0-dev", "macos-arm64", "minimal").exists()
        )

    def test_nested_explicit_cache_override_is_created_privately(self):
        metadata = self.fixture_metadata()
        nested = self.base / "new" / "nested" / "cache"
        tool_dir, reused = install_profile_tools(
            metadata_path=metadata, cache_home=nested, version="1.1.0-dev",
            platform_name="macos-arm64", profile="minimal", download=self.downloader,
        )
        self.assertFalse(reused)
        self.assertTrue(tool_dir.is_dir())
        for directory in (self.base / "new", self.base / "new/nested", nested):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_opengrep_signature_failure_never_publishes_standard(self):
        metadata = self.fixture_metadata("standard", cosign_exit=7)
        with self.assertRaisesRegex(ToolchainError, "signature"):
            install_profile_tools(
                metadata_path=metadata, cache_home=self.cache, version="1.1.0-dev",
                platform_name="macos-arm64", profile="standard", download=self.downloader,
            )
        self.assertFalse(
            tool_cache_dir(self.cache, "1.1.0-dev", "macos-arm64", "standard").exists()
        )

    def test_malicious_archive_traversal_is_rejected(self):
        metadata = self.fixture_metadata()
        asset = self.metadata["tools"]["trivy"]["platforms"]["macos-arm64"]
        archive = self.assets / asset["asset_name"]
        self._tar(archive, "../trivy", b"unsafe")
        asset["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
        metadata.write_text(json.dumps(self.metadata), encoding="utf-8")
        with self.assertRaisesRegex(ToolchainError, "safe extraction"):
            install_profile_tools(
                metadata_path=metadata, cache_home=self.cache, version="1.1.0-dev",
                platform_name="macos-arm64", profile="minimal", download=self.downloader,
            )

    def test_symlink_oversized_and_malformed_archives_are_rejected(self):
        for label in ("symlink", "oversized", "malformed"):
            with self.subTest(label=label):
                self.cache = self.base / f"cache-{label}"
                metadata = self.fixture_metadata()
                asset = self.metadata["tools"]["trivy"]["platforms"]["macos-arm64"]
                archive = self.assets / asset["asset_name"]
                if label == "symlink":
                    with tarfile.open(archive, "w:gz") as bundle:
                        info = tarfile.TarInfo(asset["executable_name"])
                        info.type = tarfile.SYMTYPE
                        info.linkname = "outside"
                        bundle.addfile(info)
                elif label == "oversized":
                    self._tar(archive, asset["executable_name"], b"x" * 32)
                else:
                    archive.write_bytes(b"not-a-tar-archive")
                asset["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
                metadata.write_text(json.dumps(self.metadata), encoding="utf-8")
                limit = 16 if label == "oversized" else 500 * 1024 * 1024
                with patch("scripts.vibesec.toolchain._tool_archive.MAX_EXECUTABLE_BYTES", limit):
                    with self.assertRaisesRegex(ToolchainError, "safe extraction"):
                        install_profile_tools(
                            metadata_path=metadata, cache_home=self.cache, version="1.1.0-dev",
                            platform_name="macos-arm64", profile="minimal", download=self.downloader,
                        )
                self.assertFalse(
                    tool_cache_dir(self.cache, "1.1.0-dev", "macos-arm64", "minimal").exists()
                )

    def test_unsafe_cache_symlink_is_rejected(self):
        metadata = self.fixture_metadata()
        self.cache.mkdir()
        outside = self.base / "outside-tools"
        outside.mkdir()
        (self.cache / "tools").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ToolchainError, "unsafe"):
            install_profile_tools(
                metadata_path=metadata, cache_home=self.cache, version="1.1.0-dev",
                platform_name="macos-arm64", profile="minimal", download=self.downloader,
            )
        self.assertEqual(list(outside.iterdir()), [])

    def test_unsupported_platform_has_no_unverified_fallback(self):
        metadata = self.fixture_metadata()
        with self.assertRaisesRegex(ToolchainError, "no verified asset"):
            install_profile_tools(
                metadata_path=metadata, cache_home=self.cache, version="1.1.0-dev",
                platform_name="linux-arm64", profile="minimal", download=self.downloader,
            )

    def test_partial_cache_is_rejected_without_path_fallback(self):
        metadata = self.fixture_metadata()
        partial = tool_cache_dir(self.cache, "1.1.0-dev", "macos-arm64", "minimal")
        (partial / "bin").mkdir(parents=True)
        fallback = self.base / "target-controlled-path"
        fallback.mkdir()
        (fallback / "trivy").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        with self.assertRaisesRegex(ToolchainError, "partial"):
            install_profile_tools(
                metadata_path=metadata, cache_home=self.cache, version="1.1.0-dev",
                platform_name="macos-arm64", profile="minimal", download=self.downloader,
            )

    def test_results_use_opaque_identifier_outside_target(self):
        target = self.base / "application"
        target.mkdir()
        results = managed_results_dir(self.cache, target)
        self.assertEqual(results.name, "latest")
        self.assertNotIn("application", results.as_posix())
        with self.assertRaises(ValueError):
            results.relative_to(target)


if __name__ == "__main__":
    unittest.main()
