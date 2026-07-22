"""Deterministic consumer bundle construction and strict in-memory verification."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any
import zipfile

from .paths import UnsafePath, safe_posix_path, validate_unique_paths
from .strict_json import StrictJSONError, canonical_json, loads_strict
from .version import VersionError, parse_version_bytes, read_version, validate_version

BUNDLE_MANIFEST = "vibesec-bundle-manifest.json"
BUNDLE_SCHEMA = 1
BUNDLE_FORMAT = 1
MAX_ENTRIES = 256
MAX_FILE_SIZE = 5_000_000
MAX_TOTAL_SIZE = 25_000_000
MAX_COMPRESSED_SIZE = 25_000_000
MAX_COMPRESSION_RATIO = 200
SOURCE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
ALLOWED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
FIXED_TIME = (2020, 1, 1, 0, 0, 0)
ALLOWED_SOURCE_ROOTS = {"VERSION", "CHANGELOG.md", "LICENSE", "README.md", "SECURITY.md", "config", "docs", "policy", "rules", "scripts", "templates"}
PROHIBITED_PARTS = {".git", ".tools", ".venv", "__pycache__", "dist", "fixtures", "node_modules", "results", "tests", "venv"}
PROHIBITED_SUFFIXES = {".db", ".gz", ".log", ".pyc", ".tar", ".zip"}
REQUIRED_CONSUMER_PATHS = {
    "VERSION", "config/adoption-files.json", "config/tools.json",
    "policy/baseline.json", "policy/standard-baseline.json", "policy/suppressions.yml",
    "scripts/init_vibesec.py", "scripts/run_minimal_profile.sh", "scripts/run_standard_profile.py",
    "scripts/vibesec/capabilities.py",
    "scripts/verify_consumer_bundle.py", "scripts/verify_installation.py", "scripts/vibesec_doctor.py",
    "scripts/plan_vibesec_upgrade.py", "scripts/vibesec/bundle.py",
    "scripts/validate_project_capabilities.py",
    "templates/github-actions/security-baseline.yml", "templates/github-actions/security-standard.yml",
    "templates/github-actions/dast-baseline.yml", "scripts/run_dast_baseline.py",
    "config/zap-passive-plan-schema.json", "scripts/vibesec/zap_automation.py",
    "docs/distribution.md", "docs/dast-baseline.md", "docs/dast-threat-model.md", "docs/installation-verification.md", "docs/doctor.md", "docs/upgrading.md",
}
REQUIRED_EXECUTABLES = {
    "scripts/init_vibesec.py", "scripts/run_minimal_profile.sh", "scripts/run_standard_profile.py", "scripts/run_dast_baseline.py", "scripts/validate_dast_artifacts.py",
    "scripts/verify_consumer_bundle.py", "scripts/verify_installation.py", "scripts/vibesec_doctor.py",
    "scripts/plan_vibesec_upgrade.py",
    "scripts/validate_project_capabilities.py",
}


class BundleError(ValueError):
    """A bundle source or archive violates the reviewed format."""


def _reviewed_source_path(value: str) -> str:
    path = safe_posix_path(value)
    parts = Path(path).parts
    root = parts[0]
    if root not in ALLOWED_SOURCE_ROOTS or any(part in PROHIBITED_PARTS for part in parts) or Path(path).suffix.casefold() in PROHIBITED_SUFFIXES:
        raise BundleError(f"consumer catalog contains a prohibited development path: {path}")
    return path


@dataclass(frozen=True)
class BundleFile:
    path: str
    data: bytes
    mode: int


@dataclass(frozen=True)
class VerifiedBundle:
    path: Path
    manifest: dict[str, Any]
    manifest_sha256: str
    entries: dict[str, bytes]
    modes: dict[str, int]

    @property
    def version(self) -> str:
        return str(self.manifest["development_version"])

    @property
    def source_commit(self) -> str | None:
        value = self.manifest.get("source_commit")
        return value if isinstance(value, str) else None


def validate_catalog(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "common", "bundle_additional", "executable_files", "profiles", "addons"}:
        raise BundleError("adoption catalog fields or schema are invalid")
    if payload.get("schema_version") != 1 or not isinstance(payload.get("common"), list):
        raise BundleError("adoption catalog schema is unsupported")
    profiles = payload.get("profiles")
    if not isinstance(profiles, dict) or set(profiles) != {"minimal", "standard"}:
        raise BundleError("adoption catalog must define Minimal and Standard")
    all_paths: list[str] = []
    for key in ("common", "bundle_additional", "executable_files"):
        values = payload.get(key)
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise BundleError(f"adoption catalog {key} must be an array of paths")
        validate_unique_paths(values)
        for value in values:
            _reviewed_source_path(value)
        all_paths.extend(values)
    for profile, config in profiles.items():
        if not isinstance(config, dict) or set(config) != {"support", "workflow_source", "workflow_destination"}:
            raise BundleError(f"adoption catalog {profile} profile is malformed")
        support = config["support"]
        if not isinstance(support, list) or not all(isinstance(item, str) for item in support):
            raise BundleError(f"adoption catalog {profile} support must be paths")
        validate_unique_paths(support)
        for value in support:
            _reviewed_source_path(value)
        all_paths.extend(support)
        all_paths.append(_reviewed_source_path(config["workflow_source"]))
        destination = safe_posix_path(config["workflow_destination"])
        if destination != f".github/workflows/vibesec-{profile}.yml":
            raise BundleError(f"adoption catalog {profile} workflow destination is invalid")
    addons = payload.get("addons")
    if not isinstance(addons, dict) or set(addons) != {"dast-baseline"}:
        raise BundleError("adoption catalog must define the reviewed DAST add-on")
    addon = addons["dast-baseline"]
    if not isinstance(addon, dict) or set(addon) != {"support", "workflow_source", "workflow_destination"}:
        raise BundleError("DAST add-on catalog is malformed")
    validate_unique_paths(addon["support"])
    for value in addon["support"]:
        _reviewed_source_path(value)
    all_paths.extend(addon["support"])
    all_paths.append(_reviewed_source_path(addon["workflow_source"]))
    if safe_posix_path(addon["workflow_destination"]) != ".github/workflows/vibesec-dast-baseline.yml":
        raise BundleError("DAST add-on workflow destination is invalid")
    validate_unique_paths(sorted(set(all_paths)))
    selected = set(configured_bundle_paths_unchecked(payload))
    executable = set(payload["executable_files"])
    if not REQUIRED_CONSUMER_PATHS <= selected:
        raise BundleError("adoption catalog omits required consumer files")
    if not REQUIRED_EXECUTABLES <= executable or not executable <= selected:
        raise BundleError("adoption catalog executable allowlist is incomplete or references unselected files")
    return payload


def configured_bundle_paths_unchecked(catalog: dict[str, Any]) -> list[str]:
    values = ["VERSION", "config/adoption-files.json", *catalog["common"], *catalog["bundle_additional"]]
    for config in catalog["profiles"].values():
        values.extend(config["support"])
        values.append(config["workflow_source"])
    for config in catalog["addons"].values():
        values.extend(config["support"])
        values.append(config["workflow_source"])
    return sorted(set(values))


def configured_bundle_paths(catalog: dict[str, Any]) -> list[str]:
    paths = configured_bundle_paths_unchecked(catalog)
    validate_unique_paths(paths)
    return paths


def _tree_file(root: Path, relative: str, mode: int) -> BundleFile:
    safe_posix_path(relative)
    source = root / relative
    try:
        root_resolved = root.resolve(strict=True)
        source.resolve(strict=True).relative_to(root_resolved)
        current = root_resolved
        for part in Path(relative).parts[:-1]:
            current = current / part
            if current.is_symlink():
                raise BundleError(f"configured source traverses a symlink: {relative}")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
    except (OSError, ValueError) as exc:
        raise BundleError(f"configured source file is unavailable: {relative}") from exc
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise BundleError(f"configured source must be a regular non-symlink file: {relative}")
        if details.st_size > MAX_FILE_SIZE:
            raise BundleError(f"configured source exceeds per-file limit: {relative}")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            data = stream.read(MAX_FILE_SIZE + 1)
        if len(data) > MAX_FILE_SIZE:
            raise BundleError(f"configured source grew beyond its limit: {relative}")
    except OSError as exc:
        raise BundleError(f"could not read configured source: {relative}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return BundleFile(relative, data, mode)


def collect_tree_files(root: Path) -> tuple[str, dict[str, Any], list[BundleFile]]:
    version = read_version(root)
    try:
        catalog = validate_catalog(loads_strict((root / "config/adoption-files.json").read_bytes()))
    except (OSError, StrictJSONError, UnsafePath) as exc:
        raise BundleError(f"adoption catalog is invalid: {exc}") from exc
    executable = set(catalog["executable_files"])
    paths = configured_bundle_paths(catalog)
    files = [_tree_file(root, path, 0o755 if path in executable else 0o644) for path in paths]
    total = sum(len(item.data) for item in files)
    if len(files) + 1 > MAX_ENTRIES or total > MAX_TOTAL_SIZE:
        raise BundleError("configured bundle exceeds entry or total-size limit")
    return version, catalog, files


def create_manifest(version: str, source_commit: str | None, files: list[BundleFile]) -> dict[str, Any]:
    validate_version(version)
    if source_commit is not None and not SOURCE_COMMIT.fullmatch(source_commit):
        raise BundleError("source commit must be a full lowercase 40-character SHA")
    records = [{
        "path": item.path,
        "sha256": hashlib.sha256(item.data).hexdigest(),
        "size": len(item.data),
        "mode": item.mode,
    } for item in sorted(files, key=lambda item: item.path)]
    return {
        "schema_version": BUNDLE_SCHEMA,
        "bundle_format_version": BUNDLE_FORMAT,
        "development_version": version,
        "source_commit": source_commit,
        "supported_profiles": ["minimal", "standard"],
        "supported_addons": ["dast-baseline"],
        "files": records,
        "total_file_count": len(records),
        "total_uncompressed_size": sum(item["size"] for item in records),
        "capabilities": ["initialize", "verify_installation", "doctor", "plan_upgrade"],
        "network_behavior": "distribution tools are offline; scanners retain documented profile behavior",
        "scanner_binaries_included": False,
        "application_code_executed": False,
        "signed": False,
        "signature_status": "unsigned development bundle",
    }


def _zip_info(path: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, FIXED_TIME)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.flag_bits = 0
    return info


def build_bundle_bytes(root: Path, source_commit: str | None = None) -> tuple[bytes, dict[str, Any]]:
    version, _, files = collect_tree_files(root)
    manifest = create_manifest(version, source_commit, files)
    manifest_bytes = canonical_json(manifest)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, strict_timestamps=True) as archive:
        archive.writestr(_zip_info(BUNDLE_MANIFEST, 0o644), manifest_bytes, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        for item in sorted(files, key=lambda value: value.path):
            archive.writestr(_zip_info(item.path, item.mode), item.data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return output.getvalue(), manifest


def write_bundle(root: Path, output: Path, source_commit: str | None = None) -> tuple[str, dict[str, Any]]:
    if output.exists() or output.is_symlink():
        raise BundleError("output already exists; remove or select it explicitly after review")
    data, manifest = build_bundle_bytes(root, source_commit)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, output, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)
    return hashlib.sha256(data).hexdigest(), manifest


def _validate_manifest(payload: Any) -> dict[str, Any]:
    required = {
        "schema_version", "bundle_format_version", "development_version", "source_commit",
        "supported_profiles", "supported_addons", "files", "total_file_count", "total_uncompressed_size",
        "capabilities", "network_behavior", "scanner_binaries_included",
        "application_code_executed", "signed", "signature_status",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise BundleError("bundle manifest contains missing or unknown fields")
    if (not isinstance(payload["schema_version"], int) or isinstance(payload["schema_version"], bool)
            or not isinstance(payload["bundle_format_version"], int) or isinstance(payload["bundle_format_version"], bool)
            or payload["schema_version"] != BUNDLE_SCHEMA or payload["bundle_format_version"] != BUNDLE_FORMAT):
        raise BundleError("bundle manifest schema or format is unsupported")
    validate_version(payload["development_version"])
    if payload["source_commit"] is not None and (not isinstance(payload["source_commit"], str) or not SOURCE_COMMIT.fullmatch(payload["source_commit"])):
        raise BundleError("bundle source commit is invalid")
    if payload["supported_profiles"] != ["minimal", "standard"]:
        raise BundleError("bundle profile declaration is invalid")
    if payload["supported_addons"] != ["dast-baseline"]:
        raise BundleError("bundle add-on declaration is invalid")
    if payload["capabilities"] != ["initialize", "verify_installation", "doctor", "plan_upgrade"]:
        raise BundleError("bundle capability declaration is invalid")
    if payload["network_behavior"] != "distribution tools are offline; scanners retain documented profile behavior":
        raise BundleError("bundle network declaration is invalid")
    if payload["scanner_binaries_included"] is not False or payload["application_code_executed"] is not False or payload["signed"] is not False:
        raise BundleError("bundle security declarations are invalid")
    if payload["signature_status"] != "unsigned development bundle":
        raise BundleError("bundle signature declaration is invalid")
    records = payload["files"]
    if not isinstance(records, list) or len(records) > MAX_ENTRIES - 1:
        raise BundleError("bundle manifest file list is invalid")
    paths: list[str] = []
    total = 0
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "size", "mode"}:
            raise BundleError("bundle file record is malformed")
        path = safe_posix_path(record["path"])
        if not isinstance(record["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"]):
            raise BundleError(f"bundle file hash is invalid: {path}")
        if not isinstance(record["size"], int) or isinstance(record["size"], bool) or not 0 <= record["size"] <= MAX_FILE_SIZE:
            raise BundleError(f"bundle file size is invalid: {path}")
        if record["mode"] not in {0o644, 0o755}:
            raise BundleError(f"bundle file mode is invalid: {path}")
        paths.append(path)
        total += record["size"]
    validate_unique_paths(paths)
    if paths != sorted(paths):
        raise BundleError("bundle manifest file records are not sorted")
    if (not isinstance(payload["total_file_count"], int) or isinstance(payload["total_file_count"], bool)
            or not isinstance(payload["total_uncompressed_size"], int) or isinstance(payload["total_uncompressed_size"], bool)
            or payload["total_file_count"] != len(records) or payload["total_uncompressed_size"] != total or total > MAX_TOTAL_SIZE):
        raise BundleError("bundle manifest totals are inconsistent")
    return payload


def verify_bundle(path: Path) -> VerifiedBundle:
    try:
        archive_size = path.stat().st_size
    except OSError as exc:
        raise BundleError(f"bundle is unavailable: {exc}") from exc
    if path.is_symlink() or not path.is_file() or archive_size > MAX_COMPRESSED_SIZE:
        raise BundleError("bundle must be a bounded regular non-symlink file")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            if archive.comment:
                raise BundleError("bundle archive comment is prohibited")
            infos = archive.infolist()
            if not 2 <= len(infos) <= MAX_ENTRIES:
                raise BundleError("bundle entry count is outside limits")
            names = [info.filename for info in infos]
            validate_unique_paths(names)
            if names.count(BUNDLE_MANIFEST) != 1:
                raise BundleError("bundle must contain exactly one canonical manifest")
            total = 0
            entries: dict[str, bytes] = {}
            modes: dict[str, int] = {}
            for info in infos:
                name = safe_posix_path(info.filename)
                if info.flag_bits & 0x1:
                    raise BundleError(f"encrypted bundle entry is prohibited: {name}")
                if info.compress_type not in ALLOWED_COMPRESSION:
                    raise BundleError(f"unsupported compression method: {name}")
                if info.date_time != FIXED_TIME or info.create_system != 3 or info.extra:
                    raise BundleError(f"bundle entry metadata is non-canonical: {name}")
                if info.file_size > MAX_FILE_SIZE or info.compress_size > MAX_COMPRESSED_SIZE:
                    raise BundleError(f"bundle entry exceeds size limit: {name}")
                if info.file_size > 1_000_000 and info.file_size > max(1, info.compress_size) * MAX_COMPRESSION_RATIO:
                    raise BundleError(f"bundle entry has suspicious compression ratio: {name}")
                total += info.file_size
                if total > MAX_TOTAL_SIZE:
                    raise BundleError("bundle exceeds total uncompressed-size limit")
                full_mode = info.external_attr >> 16
                if not stat.S_ISREG(full_mode):
                    raise BundleError(f"bundle entry is not a regular file: {name}")
                permission = stat.S_IMODE(full_mode)
                if permission not in {0o644, 0o755}:
                    raise BundleError(f"bundle entry has unsafe mode: {name}")
                try:
                    data = archive.read(info)
                except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                    raise BundleError(f"could not safely read bundle entry: {name}") from exc
                if len(data) != info.file_size:
                    raise BundleError(f"bundle entry size changed while reading: {name}")
                entries[name] = data
                modes[name] = permission
    except (OSError, zipfile.BadZipFile, UnsafePath) as exc:
        if isinstance(exc, BundleError):
            raise
        raise BundleError(f"invalid ZIP bundle: {exc}") from exc
    manifest_bytes = entries[BUNDLE_MANIFEST]
    try:
        manifest = _validate_manifest(loads_strict(manifest_bytes))
    except (StrictJSONError, VersionError, UnsafePath) as exc:
        raise BundleError(f"bundle manifest is invalid: {exc}") from exc
    if canonical_json(manifest) != manifest_bytes:
        raise BundleError("bundle manifest JSON is not canonical")
    records = {record["path"]: record for record in manifest["files"]}
    if names != [BUNDLE_MANIFEST, *sorted(records)]:
        raise BundleError("bundle archive entries are not in canonical order")
    if set(entries) != {BUNDLE_MANIFEST, *records}:
        raise BundleError("bundle manifest and archive entries do not correspond one-to-one")
    for name, record in records.items():
        data = entries[name]
        if len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"] or modes[name] != record["mode"]:
            raise BundleError(f"bundle file metadata mismatch: {name}")
    try:
        catalog = validate_catalog(loads_strict(entries["config/adoption-files.json"]))
    except (StrictJSONError, UnsafePath) as exc:
        raise BundleError(f"bundled adoption catalog is invalid: {exc}") from exc
    if set(records) != set(configured_bundle_paths(catalog)):
        raise BundleError("bundle does not contain exactly the configured consumer file set")
    if parse_version_bytes(entries["VERSION"]) != manifest["development_version"]:
        raise BundleError("bundle VERSION and manifest version differ")
    executable = set(catalog["executable_files"])
    for name, mode in modes.items():
        if name == BUNDLE_MANIFEST:
            continue
        expected = 0o755 if name in executable else 0o644
        if mode != expected:
            raise BundleError(f"unexpected executable mode: {name}")
    return VerifiedBundle(
        path=path, manifest=manifest,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        entries=entries, modes=modes,
    )
