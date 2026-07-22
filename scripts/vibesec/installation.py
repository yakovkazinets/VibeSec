"""Read-only installation verification shared by verifier, doctor, and planner."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import unicodedata
from typing import Any

from .bundle import BundleError, validate_catalog
from .manifest import ManifestError, parse_installation_manifest
from .paths import UnsafePath, collision_key, safe_posix_path
from .strict_json import StrictJSONError, loads_strict
from .version import VersionError, parse_version_bytes

ACTION = re.compile(r"uses:\s*[^\s#]+@([0-9a-f]{40})(?:\s|$)")
ANY_ACTION = re.compile(r"uses:\s*([^\s#]+)")
MAX_MANIFESTS = 4
MAX_WORKFLOW_BYTES = 1_000_000
PRESERVATION_SENSITIVE = {
    "policy/baseline.json", "policy/standard-baseline.json", "policy/suppressions.yml",
}


class InstallationError(ValueError):
    """The target or installation state cannot be safely interpreted."""


@dataclass(frozen=True)
class InstallationState:
    status: str
    target: Path
    manifests: list[dict[str, Any]]
    errors: list[str]
    warnings: list[str]
    information: list[str]
    files: list[dict[str, Any]]
    profiles: list[str]
    version: str | None
    source_type: str | None

    def result(self) -> dict[str, Any]:
        return {
            "installation_status": self.status,
            "profiles": self.profiles,
            "development_version": self.version,
            "source_type": self.source_type,
            "manifests": self.manifests,
            "files": self.files,
            "security_statement": "Installation validity does not prove application security.",
        }


def _validate_target(raw: Path) -> Path:
    if raw.is_symlink():
        raise InstallationError("target root is a symbolic link")
    try:
        target = raw.resolve(strict=True)
    except OSError as exc:
        raise InstallationError(f"target is unavailable: {exc}") from exc
    if not target.is_dir():
        raise InstallationError("target must be a directory")
    return target


def _safe_target_file(target: Path, relative: str) -> Path:
    safe_posix_path(relative)
    path = target / relative
    current = target
    for part in Path(relative).parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise InstallationError(f"installed path traverses a symlink: {relative}")
    try:
        path.resolve(strict=False).relative_to(target)
    except ValueError as exc:
        raise InstallationError(f"installed path escapes target: {relative}") from exc
    return path


def _workflow_checks(path: Path, relative: str, errors: list[str], warnings: list[str]) -> None:
    try:
        if path.stat().st_size > MAX_WORKFLOW_BYTES:
            errors.append(f"workflow is oversized: {relative}")
            return
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        errors.append(f"workflow cannot be inspected: {relative}: {type(exc).__name__}")
        return
    if "pull_request_target" in text:
        errors.append(f"unsafe workflow trigger in {relative}: pull_request_target")
    if not re.search(r"(?m)^permissions:\n  contents: read$", text):
        errors.append(f"workflow permissions are not least privilege: {relative}")
    for match in ANY_ACTION.finditer(text):
        reference = match.group(1)
        if not re.search(r"@[0-9a-f]{40}$", reference):
            errors.append(f"workflow action is not immutably pinned: {relative}")
    if "VIBESEC_ENFORCEMENT: observe" not in text and "VIBESEC_ENFORCEMENT: new" not in text and "VIBESEC_ENFORCEMENT: all" not in text:
        warnings.append(f"workflow enforcement mode is not identifiable: {relative}")


def verify_installation(target_path: Path) -> InstallationState:
    target = _validate_target(target_path)
    root = target / ".vibesec"
    if root.is_symlink():
        raise InstallationError(".vibesec manifest directory is a symbolic link")
    if root.exists() and not root.is_dir():
        raise InstallationError(".vibesec manifest path is not a directory")
    manifest_paths = sorted(root.glob("install-*.json")) if root.is_dir() else []
    if not manifest_paths:
        return InstallationState("unverifiable_legacy_installation", target, [], [],
                                 ["No installation manifest was found."], [], [], [], None, None)
    if len(manifest_paths) > MAX_MANIFESTS:
        raise InstallationError("too many installation manifests")
    manifests: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []
    information: list[str] = []
    legacy = False
    seen_stage: set[tuple[str, str]] = set()
    for path in manifest_paths:
        if path.is_symlink() or not path.is_file():
            errors.append(f"manifest is not a regular file: {path.name}")
            continue
        try:
            manifest = parse_installation_manifest(path.read_bytes())
        except (OSError, ManifestError) as exc:
            errors.append(f"manifest is invalid: {path.name}: {exc}")
            continue
        if manifest["schema_version"] == 1:
            legacy = True
        elif manifest["manifest_path"] != path.relative_to(target).as_posix():
            errors.append(f"manifest path declaration does not match filename: {path.name}")
        key = (manifest["profile"], manifest["stage"])
        if key in seen_stage:
            errors.append(f"conflicting duplicate manifest for {key[0]} {key[1]}")
        seen_stage.add(key)
        manifests.append(manifest)
    profiles = sorted({manifest["profile"] for manifest in manifests})
    if len(profiles) > 1:
        errors.append("Minimal and Standard installation manifests conflict")
    if ("standard", "workflow") in seen_stage and ("standard", "support") not in seen_stage:
        errors.append("Standard workflow is present without a Standard support manifest")
    declared_paths = {
        item if manifest["schema_version"] == 1 else item["path"]
        for manifest in manifests for item in manifest["installed_files"]
    }
    if profiles == ["minimal"]:
        if "policy/baseline.json" not in declared_paths or "policy/standard-baseline.json" in declared_paths:
            errors.append("Minimal installation has a missing or wrong profile baseline")
    elif profiles == ["standard"]:
        if "policy/standard-baseline.json" not in declared_paths or "policy/baseline.json" in declared_paths:
            errors.append("Standard installation has a missing or wrong profile baseline")
    file_results: list[dict[str, Any]] = []
    observed_paths: dict[str, str] = {}
    versions = {manifest.get("development_version") or manifest.get("source_version") for manifest in manifests}
    sources = {manifest.get("source_type", "legacy") for manifest in manifests}
    if len(versions) > 1:
        errors.append("installation manifests declare conflicting versions")
    if len(sources) > 1:
        errors.append("installation manifests declare conflicting source types")
    catalog: dict[str, Any] | None = None
    if any(manifest["schema_version"] == 2 for manifest in manifests):
        try:
            catalog_path = _safe_target_file(target, "config/adoption-files.json")
            if catalog_path.is_symlink() or not catalog_path.is_file():
                raise InstallationError("installed adoption catalog is missing or unsafe")
            catalog = validate_catalog(loads_strict(catalog_path.read_bytes()))
            installed_version = parse_version_bytes(_safe_target_file(target, "VERSION").read_bytes())
            if len(versions) == 1 and installed_version != next(iter(versions)):
                errors.append("installed VERSION differs from installation manifests")
        except (OSError, BundleError, InstallationError, StrictJSONError, UnsafePath, VersionError) as exc:
            errors.append(f"installed adoption metadata is invalid: {exc}")
    if catalog is not None:
        for manifest in manifests:
            if manifest["schema_version"] != 2:
                continue
            config = catalog["profiles"][manifest["profile"]]
            expected: set[str] = set()
            if manifest["stage"] in {"all", "support"}:
                expected.update(catalog["common"])
                expected.update(config["support"])
            if manifest["stage"] in {"all", "workflow"}:
                expected.add(config["workflow_destination"])
            declared = {item["path"] for item in manifest["installed_files"]}
            if declared != expected:
                errors.append(f"{manifest['profile']} {manifest['stage']} manifest does not declare its exact support set")
    for manifest in manifests:
        if manifest["schema_version"] == 1:
            records = [{"path": item, "sha256": None, "mode": None} for item in manifest["installed_files"] if item != manifest_paths[0].relative_to(target).as_posix()]
        else:
            records = manifest["installed_files"]
        for record in records:
            relative = record["path"]
            key = collision_key(relative)
            if key in observed_paths and observed_paths[key] != relative:
                errors.append(f"case or Unicode path collision: {observed_paths[key]} and {relative}")
            observed_paths[key] = relative
            try:
                path = _safe_target_file(target, relative)
            except (InstallationError, UnsafePath) as exc:
                errors.append(str(exc))
                file_results.append({"path": relative, "state": "unsafe_path"})
                continue
            if path.is_symlink():
                errors.append(f"installed file was replaced by a symlink: {relative}")
                file_results.append({"path": relative, "state": "symlink"})
                continue
            if not path.exists():
                errors.append(f"installed file is missing: {relative}")
                file_results.append({"path": relative, "state": "missing"})
                continue
            details = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(details.st_mode):
                errors.append(f"installed path is not a regular file: {relative}")
                file_results.append({"path": relative, "state": "invalid_type"})
                continue
            mode = stat.S_IMODE(details.st_mode) & 0o777
            actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            state = "verified"
            if record["mode"] is not None and mode != record["mode"]:
                errors.append(f"installed mode differs: {relative}")
                state = "wrong_mode"
            elif record["sha256"] is not None and actual_hash != record["sha256"]:
                state = "locally_modified"
                warnings.append(f"installed file has local changes: {relative}")
            file_results.append({
                "path": relative, "state": state, "expected_sha256": record["sha256"],
                "actual_sha256": actual_hash, "expected_mode": record["mode"], "actual_mode": mode,
                "preservation_sensitive": relative in PRESERVATION_SENSITIVE or relative.startswith("policy/") or relative.startswith("config/") and "ignore" in relative,
            })
            if relative.startswith(".github/workflows/"):
                _workflow_checks(path, relative, errors, warnings)
            if relative in {"policy/baseline.json", "policy/standard-baseline.json"}:
                try:
                    baseline = loads_strict(path.read_bytes())
                    expected_profile = "standard" if relative == "policy/standard-baseline.json" else "minimal"
                    if not isinstance(baseline, dict) or baseline.get("profile") != expected_profile or not isinstance(baseline.get("fingerprints"), list):
                        errors.append(f"wrong or malformed profile baseline: {relative}")
                except (OSError, StrictJSONError):
                    errors.append(f"wrong or malformed profile baseline: {relative}")
    if legacy and not errors:
        status = "unverifiable_legacy_installation"
        warnings.append("Legacy manifests do not contain file hashes or modes.")
    elif errors:
        status = "conflict" if any("conflict" in item or "without" in item for item in errors) else "partial" if any("missing" in item for item in errors) else "invalid"
    elif warnings:
        status = "valid_with_local_changes"
    else:
        status = "valid"
    information.append("Installation verification checks VibeSec configuration, not application security.")
    return InstallationState(
        status, target, manifests, errors, warnings, information, sorted(file_results, key=lambda item: item["path"]),
        profiles, next(iter(versions)) if len(versions) == 1 else None,
        next(iter(sources)) if len(sources) == 1 else None,
    )
