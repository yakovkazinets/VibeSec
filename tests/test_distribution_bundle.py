import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = str(ROOT / "scripts")
sys.path.insert(0, SCRIPTS)
from vibesec.bundle import (  # noqa: E402
    BUNDLE_MANIFEST, MAX_ENTRIES, MAX_FILE_SIZE, BundleError, build_bundle_bytes,
    configured_bundle_paths, verify_bundle,
)
from vibesec.strict_json import canonical_json, loads_strict  # noqa: E402
from vibesec.version import VersionError, parse_version_bytes  # noqa: E402
sys.path.remove(SCRIPTS)


def regular_info(name, mode=0o644, compression=zipfile.ZIP_DEFLATED):
    info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.compress_type = compression
    info.external_attr = (stat.S_IFREG | mode) << 16
    return info


class DistributionBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.valid = self.root / "valid.zip"
        self.valid.write_bytes(build_bundle_bytes(ROOT)[0])

    def entries(self):
        with zipfile.ZipFile(self.valid) as archive:
            return [(info.filename, archive.read(info), stat.S_IMODE(info.external_attr >> 16), info.compress_type) for info in archive.infolist()]

    def write_entries(self, name, entries):
        path = self.root / name
        with zipfile.ZipFile(path, "w") as archive:
            for entry_name, data, mode, compression in entries:
                archive.writestr(regular_info(entry_name, mode, compression), data)
        return path

    def test_version_parser_accepts_one_newline_and_rejects_ambiguous_values(self):
        self.assertEqual(parse_version_bytes(b"0.3.0-dev\n"), "0.3.0-dev")
        invalid = [b"", b" 0.3.0-dev\n", b"0.3.0-dev \n", b"\xef\xbb\xbf0.3.0-dev\n",
                   b"0.3.0-dev\x00\n", b"0.3.0-dev\n\n", b"x" * 66]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(VersionError):
                parse_version_bytes(value)

    def test_build_is_byte_identical_and_has_exact_reviewed_metadata(self):
        source_a = self.root / "source-a"
        source_b = self.root / "source-b"
        ignored = shutil.ignore_patterns(".git", "__pycache__", ".tools", "results")
        shutil.copytree(ROOT, source_a, ignore=ignored)
        shutil.copytree(ROOT, source_b, ignore=ignored)
        for path in source_b.rglob("*"):
            if path.is_file():
                os.utime(path, (946684800, 946684800))
        original_directory = Path.cwd()
        original_timezone = os.environ.get("TZ")
        original_language = os.environ.get("LANG")
        old_mask = os.umask(0o022)
        try:
            os.chdir(source_a)
            os.environ["TZ"] = "UTC"
            os.environ["LANG"] = "C"
            os.umask(0o022)
            first, manifest = build_bundle_bytes(source_a, "a" * 40)
            os.chdir(source_b)
            os.environ["TZ"] = "Pacific/Honolulu"
            os.environ["LANG"] = "en_US.UTF-8"
            os.umask(0o077)
            second, _ = build_bundle_bytes(source_b, "a" * 40)
        finally:
            os.chdir(original_directory)
            os.umask(old_mask)
            if original_timezone is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = original_timezone
            if original_language is None:
                os.environ.pop("LANG", None)
            else:
                os.environ["LANG"] = original_language
        self.assertEqual(hashlib.sha256(first).digest(), hashlib.sha256(second).digest())
        path = self.root / "deterministic.zip"
        path.write_bytes(first)
        bundle = verify_bundle(path)
        self.assertEqual(set(bundle.entries) - {BUNDLE_MANIFEST}, {item["path"] for item in manifest["files"]})
        self.assertNotIn("tests/test_distribution_bundle.py", bundle.entries)
        with zipfile.ZipFile(path) as archive:
            self.assertEqual([item.filename for item in archive.infolist()], [BUNDLE_MANIFEST, *sorted(bundle.entries.keys() - {BUNDLE_MANIFEST})])
            self.assertTrue(all(item.date_time == (2020, 1, 1, 0, 0, 0) for item in archive.infolist()))

    def test_valid_bundle_and_cli_json(self):
        verified = verify_bundle(self.valid)
        catalog = loads_strict(verified.entries["config/adoption-files.json"])
        self.assertEqual(set(verified.entries) - {BUNDLE_MANIFEST}, set(configured_bundle_paths(catalog)))
        completed = subprocess.run(["python3", "scripts/verify_consumer_bundle.py", str(self.valid), "--json"], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "valid")

    def test_path_collision_and_special_file_attacks_fail_closed(self):
        attacks = [
            ("traversal", "../escape"), ("absolute", "/escape"), ("drive", "C:/escape"),
            ("backslash", "..\\escape"), ("case", "version"), ("unicode", "VERSIO\u0301N"),
        ]
        base = self.entries()
        for label, name in attacks:
            entries = list(base)
            if label == "unicode":
                entries += [("VERSI\u00d3N", b"x", 0o644, zipfile.ZIP_DEFLATED), (name, b"x", 0o644, zipfile.ZIP_DEFLATED)]
            else:
                entries.append((name, b"x", 0o644, zipfile.ZIP_DEFLATED))
            with self.subTest(label=label), self.assertRaises(BundleError):
                verify_bundle(self.write_entries(f"{label}.zip", entries))
        symlink = list(base)
        symlink.append(("link", b"target", 0o644, zipfile.ZIP_DEFLATED))
        path = self.write_entries("symlink.zip", symlink)
        with zipfile.ZipFile(path, "a") as archive:
            info = zipfile.ZipInfo("special")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, b"target")
        with self.assertRaises(BundleError):
            verify_bundle(path)

    def test_duplicate_missing_malformed_and_ambiguous_manifests_fail(self):
        base = self.entries()
        cases = {
            "missing": [item for item in base if item[0] != BUNDLE_MANIFEST],
            "malformed": [(n, b"{", m, c) if n == BUNDLE_MANIFEST else (n, d, m, c) for n, d, m, c in base],
            "duplicate-key": [(n, b'{"schema_version":1,"schema_version":1}\n', m, c) if n == BUNDLE_MANIFEST else (n, d, m, c) for n, d, m, c in base],
        }
        for label, entries in cases.items():
            with self.subTest(label=label), self.assertRaises(BundleError):
                verify_bundle(self.write_entries(f"{label}.zip", entries))
        duplicate = self.root / "duplicate.zip"
        with zipfile.ZipFile(duplicate, "w") as archive:
            for name, data, mode, compression in base:
                archive.writestr(regular_info(name, mode, compression), data)
            archive.writestr(regular_info(BUNDLE_MANIFEST), base[0][1])
        with self.assertRaises(BundleError):
            verify_bundle(duplicate)

    def test_manifest_corruption_extra_missing_and_modes_fail(self):
        base = self.entries()
        manifest = loads_strict(next(data for name, data, _, _ in base if name == BUNDLE_MANIFEST))
        mutations = []
        for field, value in (("schema_version", 99), ("total_file_count", 0)):
            changed = dict(manifest); changed[field] = value
            mutations.append((field, changed, base))
        for field, value in (("sha256", "0" * 64), ("size", 1), ("mode", 0o755)):
            changed = json.loads(json.dumps(manifest)); changed["files"][0][field] = value
            mutations.append((field, changed, base))
        for label, changed, entries in mutations:
            rewritten = [(n, canonical_json(changed), m, c) if n == BUNDLE_MANIFEST else (n, d, m, c) for n, d, m, c in entries]
            with self.subTest(label=label), self.assertRaises(BundleError):
                verify_bundle(self.write_entries(f"manifest-{label}.zip", rewritten))
        with self.assertRaises(BundleError):
            verify_bundle(self.write_entries("extra.zip", [*base, ("extra.txt", b"x", 0o644, zipfile.ZIP_DEFLATED)]))
        removed = next(item["path"] for item in manifest["files"] if item["path"] != "VERSION")
        with self.assertRaises(BundleError):
            verify_bundle(self.write_entries("missing-file.zip", [item for item in base if item[0] != removed]))
        wrong_mode = [(n, d, 0o755 if n == "VERSION" else m, c) for n, d, m, c in base]
        with self.assertRaises(BundleError):
            verify_bundle(self.write_entries("unexpected-executable.zip", wrong_mode))

    def test_resource_compression_and_encryption_limits_fail(self):
        base = self.entries()
        cases = [
            ("oversized", [*base, ("large", b"x" * (MAX_FILE_SIZE + 1), 0o644, zipfile.ZIP_STORED)]),
            ("ratio", [*base, ("ratio", b"0" * 1_100_000, 0o644, zipfile.ZIP_DEFLATED)]),
            ("unsupported", [*base, ("bzip", b"x", 0o644, zipfile.ZIP_BZIP2)]),
            ("count", [*base, *((f"f-{index}", b"", 0o644, zipfile.ZIP_STORED) for index in range(MAX_ENTRIES))]),
        ]
        for label, entries in cases:
            with self.subTest(label=label), self.assertRaises(BundleError):
                verify_bundle(self.write_entries(f"{label}.zip", entries))
        encrypted = bytearray(self.valid.read_bytes())
        local = encrypted.find(b"PK\x03\x04")
        central = encrypted.find(b"PK\x01\x02")
        struct.pack_into("<H", encrypted, local + 6, struct.unpack_from("<H", encrypted, local + 6)[0] | 1)
        struct.pack_into("<H", encrypted, central + 8, struct.unpack_from("<H", encrypted, central + 8)[0] | 1)
        encrypted_path = self.root / "encrypted.zip"
        encrypted_path.write_bytes(encrypted)
        with self.assertRaises(BundleError):
            verify_bundle(encrypted_path)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_configured_source_symlink_and_untracked_file_are_excluded(self):
        copy = self.root / "source"
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        (copy / "untracked-secret.txt").write_text("not selected", encoding="utf-8")
        data, _ = build_bundle_bytes(copy)
        candidate = self.root / "copy.zip"; candidate.write_bytes(data)
        self.assertNotIn("untracked-secret.txt", verify_bundle(candidate).entries)
        selected = copy / "VERSION"
        selected.unlink(); selected.symlink_to(ROOT / "VERSION")
        with self.assertRaises((BundleError, VersionError)):
            build_bundle_bytes(copy)


if __name__ == "__main__":
    unittest.main()
