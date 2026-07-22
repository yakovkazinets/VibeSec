#!/usr/bin/env python3
"""Safely preview or initialize VibeSec from source or a verified local bundle.

Exit codes: 0 success, 2 conflict/bundle verification, 3 invalid target or
configuration, and 4 infrastructure failure. No network, Git, package manager,
scanner, or application code is invoked.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import unicodedata
from typing import Any, Protocol

SCRIPT_DIRECTORY = str(Path(__file__).resolve().parent)
_remove_script_path = SCRIPT_DIRECTORY not in sys.path
if _remove_script_path:
    sys.path.insert(0, SCRIPT_DIRECTORY)
from vibesec.bundle import BundleError, VerifiedBundle, validate_catalog, verify_bundle  # noqa: E402
from vibesec.capabilities import (  # noqa: E402
    MANIFEST_PATH as CAPABILITY_MANIFEST_PATH,
    CapabilityError,
    all_capabilities,
    ask_capabilities,
    capability_bytes,
    load_capabilities_file,
)
from vibesec.exit_codes import INFRASTRUCTURE_FAILURE, INVALID_INPUT, SUCCESS, VERIFICATION_FAILED  # noqa: E402
from vibesec.manifest import file_record, installation_manifest_bytes  # noqa: E402
from vibesec.paths import UnsafePath, safe_posix_path  # noqa: E402
from vibesec.strict_json import StrictJSONError, loads_strict  # noqa: E402
from vibesec.version import VersionError, read_version  # noqa: E402
if _remove_script_path:
    sys.path.remove(SCRIPT_DIRECTORY)

SOURCE_ROOT = Path(__file__).resolve().parents[1]
MAX_WORKFLOW_BYTES = 1_000_000
COMMIT = re.compile(r"^[0-9a-f]{40}$")
OVERLAP_MARKERS = (
    "semgrep", "codeql", "snyk", "dependabot", "renovate", "trivy",
    "gitleaks", "osv-scanner", "checkov", "grype", "anchore",
)


class InvalidTarget(ValueError):
    """The target, source, or adoption catalog violates safety constraints."""


class ConflictError(ValueError):
    """One or more destination files already exist."""


class ConsumerSource(Protocol):
    source_type: str
    version: str
    source_commit: str | None
    bundle_manifest_sha256: str | None

    def read(self, relative: str) -> bytes: ...
    def mode(self, relative: str) -> int: ...


@dataclass(frozen=True)
class TreeSource:
    root: Path
    version: str
    source_commit: str | None = None
    source_type: str = "source_tree"
    bundle_manifest_sha256: str | None = None

    def _path(self, relative: str) -> Path:
        safe_posix_path(relative)
        source = self.root / relative
        try:
            resolved = source.resolve(strict=True)
            resolved.relative_to(self.root.resolve(strict=True))
            details = source.stat(follow_symlinks=False)
        except (OSError, ValueError) as exc:
            raise InvalidTarget(f"required source file is unavailable: {relative}") from exc
        if source.is_symlink() or not stat.S_ISREG(details.st_mode):
            raise InvalidTarget(f"required source must be a regular file: {relative}")
        return source

    def read(self, relative: str) -> bytes:
        try:
            return self._path(relative).read_bytes()
        except OSError as exc:
            raise InvalidTarget(f"required source cannot be read: {relative}") from exc

    def mode(self, relative: str) -> int:
        return stat.S_IMODE(self._path(relative).stat(follow_symlinks=False).st_mode) & 0o755


@dataclass(frozen=True)
class BundleSource:
    bundle: VerifiedBundle
    source_type: str = "bundle"

    @property
    def version(self) -> str:
        return self.bundle.version

    @property
    def source_commit(self) -> str | None:
        return self.bundle.source_commit

    @property
    def bundle_manifest_sha256(self) -> str:
        return self.bundle.manifest_sha256

    def read(self, relative: str) -> bytes:
        safe_posix_path(relative)
        try:
            return self.bundle.entries[relative]
        except KeyError as exc:
            raise InvalidTarget(f"verified bundle is missing required source: {relative}") from exc

    def mode(self, relative: str) -> int:
        try:
            return self.bundle.modes[relative]
        except KeyError as exc:
            raise InvalidTarget(f"verified bundle is missing source mode: {relative}") from exc


@dataclass(frozen=True)
class PlanEntry:
    source_path: str | None
    destination: Path
    mode: int
    data: bytes


def result() -> dict[str, Any]:
    return {
        "schema_version": 1, "would_create": [], "created": [], "conflict": [],
        "skipped": [], "warning": [], "error": [], "source": {}, "project_capabilities": None,
    }


def tree_source(source_commit: str | None = None) -> TreeSource:
    if source_commit is not None and not COMMIT.fullmatch(source_commit):
        raise InvalidTarget("source commit must be a full lowercase 40-character SHA")
    try:
        version = read_version(SOURCE_ROOT)
    except VersionError as exc:
        raise InvalidTarget(str(exc)) from exc
    return TreeSource(SOURCE_ROOT, version, source_commit)


def load_catalog(source: ConsumerSource | None = None) -> dict[str, Any]:
    provider = source or tree_source()
    try:
        return validate_catalog(loads_strict(provider.read("config/adoption-files.json")))
    except (BundleError, StrictJSONError, UnsafePath) as exc:
        raise InvalidTarget(f"invalid VibeSec adoption catalog: {exc}") from exc


def safe_relative(value: object) -> Path:
    try:
        return Path(safe_posix_path(value))
    except UnsafePath as exc:
        raise InvalidTarget(f"adoption catalog path is unsafe: {value!r}") from exc


def validate_target(raw_target: Path, source_root: Path | None = SOURCE_ROOT) -> Path:
    if raw_target.is_symlink():
        raise InvalidTarget("target root must not be a symbolic link")
    try:
        target = raw_target.resolve(strict=True)
    except OSError as exc:
        raise InvalidTarget(f"target directory is unavailable: {exc}") from exc
    if not target.is_dir():
        raise InvalidTarget("target must be an existing directory")
    if source_root is not None and target == source_root:
        raise InvalidTarget("the VibeSec source repository cannot initialize itself")
    return target


def source_entry(relative: Path, source: ConsumerSource | None = None,
                 executable: set[str] | None = None) -> tuple[bytes, int]:
    provider = source or tree_source()
    name = relative.as_posix()
    data = provider.read(name)
    mode = 0o755 if executable is not None and name in executable else provider.mode(name)
    if mode not in {0o644, 0o755}:
        mode = 0o755 if mode & 0o111 else 0o644
    return data, mode


def ensure_safe_parent(target: Path, destination: Path) -> None:
    try:
        destination.relative_to(target)
    except ValueError as exc:
        raise InvalidTarget("destination escapes target") from exc
    current = target
    for part in destination.relative_to(target).parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise InvalidTarget(f"destination parent is a symbolic link: {current.relative_to(target)}")
        if current.exists() and not current.is_dir():
            raise InvalidTarget(f"destination parent is not a directory: {current.relative_to(target)}")


def existing_name_index(target: Path) -> dict[str, str]:
    index: dict[str, str] = {}
    for directory, names, files in os.walk(target, topdown=True, followlinks=False):
        base = Path(directory)
        names[:] = sorted(name for name in names if not (base / name).is_symlink())
        for name in sorted([*names, *files]):
            relative = (base / name).relative_to(target).as_posix()
            key = unicodedata.normalize("NFC", relative).casefold()
            prior = index.get(key)
            if prior is not None and prior != relative:
                raise InvalidTarget(f"target contains Unicode or case-colliding paths: {prior!r}, {relative!r}")
            index[key] = relative
    return index


def overlap_warnings(target: Path) -> list[str]:
    workflow_root = target / ".github/workflows"
    if not workflow_root.is_dir() or workflow_root.is_symlink():
        return []
    detected: set[str] = set()
    for path in sorted(workflow_root.glob("*.y*ml")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            if path.stat().st_size > MAX_WORKFLOW_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace").casefold()
        except OSError:
            continue
        detected.update(marker for marker in OVERLAP_MARKERS if marker in text)
    return [] if not detected else [
        "existing security workflow markers detected (" + ", ".join(sorted(detected))
        + "); review docs/profile-selection.md before adding overlapping controls"
    ]


def build_plan(catalog: dict[str, Any], profile: str, stage: str,
               source: ConsumerSource | None = None,
               project_capabilities: bytes | None = None) -> list[PlanEntry]:
    provider = source or tree_source()
    config = catalog["profiles"].get(profile)
    if not isinstance(config, dict):
        raise InvalidTarget(f"unknown profile: {profile}")
    executable = set(catalog["executable_files"])
    mappings: list[tuple[str, Path]] = []
    if stage in {"all", "support"}:
        mappings.extend((value, safe_relative(value)) for value in [*catalog["common"], *config["support"]])
    if stage in {"all", "workflow"}:
        mappings.append((safe_relative(config["workflow_source"]).as_posix(), safe_relative(config["workflow_destination"])))
    entries: list[PlanEntry] = []
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for source_path, destination in sorted(mappings, key=lambda item: item[1].as_posix()):
        if destination.as_posix() in seen:
            continue
        seen.add(destination.as_posix())
        data, source_mode = source_entry(Path(source_path), provider, executable)
        mode = 0o755 if source_path in executable else 0o644
        if source_mode != mode:
            raise InvalidTarget(f"source mode does not match reviewed catalog: {source_path}")
        entries.append(PlanEntry(source_path, destination, mode, data))
        records.append(file_record(destination.as_posix(), data, mode))
    if project_capabilities is not None:
        capability_destination = Path(CAPABILITY_MANIFEST_PATH)
        entries.append(PlanEntry(None, capability_destination, 0o644, project_capabilities))
        records.append(file_record(CAPABILITY_MANIFEST_PATH, project_capabilities, 0o644))
    manifest_relative = Path(f".vibesec/install-{profile}-{stage}.json")
    manifest_data = installation_manifest_bytes(
        profile=profile, stage=stage, source_type=provider.source_type,
        development_version=provider.version, source_commit=provider.source_commit,
        bundle_manifest_sha256=provider.bundle_manifest_sha256,
        manifest_path=manifest_relative.as_posix(), installed=records,
    )
    entries.append(PlanEntry(None, manifest_relative, 0o644, manifest_data))
    return sorted(entries, key=lambda item: item.destination.as_posix())


def build_addon_plan(catalog: dict[str, Any], addon: str,
                     source: ConsumerSource | None = None) -> list[PlanEntry]:
    provider = source or tree_source()
    config = catalog["addons"].get(addon)
    if not isinstance(config, dict):
        raise InvalidTarget(f"unknown add-on: {addon}")
    executable = set(catalog["executable_files"])
    mappings = [(value, safe_relative(value)) for value in config["support"]]
    mappings.append((config["workflow_source"], safe_relative(config["workflow_destination"])))
    entries: list[PlanEntry] = []
    records: list[dict[str, Any]] = []
    for source_path, destination in sorted(mappings, key=lambda item: item[1].as_posix()):
        data, source_mode = source_entry(Path(source_path), provider, executable)
        mode = 0o755 if source_path in executable else 0o644
        if source_mode != mode:
            raise InvalidTarget(f"source mode does not match reviewed catalog: {source_path}")
        entries.append(PlanEntry(source_path, destination, mode, data))
        records.append(file_record(destination.as_posix(), data, mode))
    manifest_relative = Path(f".vibesec/install-addon-{addon}.json")
    manifest_data = installation_manifest_bytes(
        profile=addon, stage="addon", source_type=provider.source_type,
        development_version=provider.version, source_commit=provider.source_commit,
        bundle_manifest_sha256=provider.bundle_manifest_sha256,
        manifest_path=manifest_relative.as_posix(), installed=records,
    )
    entries.append(PlanEntry(None, manifest_relative, 0o644, manifest_data))
    return sorted(entries, key=lambda item: item.destination.as_posix())


def verify_addon_prerequisites(target: Path, catalog: dict[str, Any]) -> None:
    required = [safe_relative(value) for value in catalog["common"]]
    missing = [path.as_posix() for path in required if not (target / path).is_file() or (target / path).is_symlink()]
    if missing:
        raise InvalidTarget("DAST add-on requires an existing VibeSec installation: " + ", ".join(missing))


def verify_standard_workflow_prerequisites(target: Path, catalog: dict[str, Any]) -> None:
    required = [safe_relative(value) for value in [*catalog["common"], *catalog["profiles"]["standard"]["support"]]]
    missing = [path.as_posix() for path in required if not (target / path).is_file() or (target / path).is_symlink()]
    if missing:
        raise InvalidTarget("Standard workflow stage requires support files already present: " + ", ".join(missing))


def preflight(target: Path, plan: list[PlanEntry], output: dict[str, Any]) -> None:
    names = existing_name_index(target)
    for entry in plan:
        relative = entry.destination
        destination = target / relative
        ensure_safe_parent(target, destination)
        key = unicodedata.normalize("NFC", relative.as_posix()).casefold()
        parent_conflict = None
        for length in range(1, len(relative.parts)):
            parent = Path(*relative.parts[:length]).as_posix()
            existing = names.get(unicodedata.normalize("NFC", parent).casefold())
            if existing is not None and existing != parent:
                parent_conflict = existing
                break
        if destination.exists() or destination.is_symlink() or key in names or parent_conflict:
            conflict = parent_conflict or names.get(key, relative.as_posix())
            if conflict not in output["conflict"]:
                output["conflict"].append(conflict)
        else:
            output["would_create"].append(relative.as_posix())
    if output["conflict"]:
        raise ConflictError("initialization refused because destination files already exist")


def write_plan(target: Path, plan: list[PlanEntry], output: dict[str, Any]) -> None:
    created_files: list[tuple[Path, tuple[int, int]]] = []
    created_dirs: list[Path] = []
    try:
        for entry in plan:
            destination = target / entry.destination
            ensure_safe_parent(target, destination)
            missing_parents: list[Path] = []
            parent = destination.parent
            while parent != target and not parent.exists():
                missing_parents.append(parent)
                parent = parent.parent
            for directory in reversed(missing_parents):
                directory.mkdir(mode=0o755)
                created_dirs.append(directory)
            if destination.exists() or destination.is_symlink():
                raise FileExistsError(f"destination appeared during initialization: {entry.destination.as_posix()}")
            descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(entry.data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temporary, entry.mode)
                os.link(temporary, destination, follow_symlinks=False)
                details = destination.stat(follow_symlinks=False)
                created_files.append((destination, (details.st_dev, details.st_ino)))
            finally:
                temporary.unlink(missing_ok=True)
            output["created"].append(entry.destination.as_posix())
    except BaseException:
        for path, identity in reversed(created_files):
            try:
                details = path.stat(follow_symlinks=False)
                if (details.st_dev, details.st_ino) == identity:
                    path.unlink()
            except FileNotFoundError:
                pass
        for directory in reversed(created_dirs):
            try:
                directory.rmdir()
            except OSError:
                pass
        output["created"].clear()
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--profile", choices=("minimal", "standard"))
    selection.add_argument("--addon", choices=("dast-baseline",))
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--stage", choices=("support", "workflow"), help="Standard only; defaults to support")
    parser.add_argument("--bundle", type=Path, help="verified local consumer ZIP")
    parser.add_argument("--source-commit", help="optional source-tree full commit SHA")
    capabilities = parser.add_mutually_exclusive_group()
    capabilities.add_argument("--capabilities-file", type=Path, help="trusted local project capability JSON")
    capabilities.add_argument("--all-capabilities", action="store_true", help="non-interactively answer Yes to every capability")
    parser.add_argument("--write", action="store_true", help="create files after a conflict-free preview")
    return parser.parse_args()


def requested_capabilities(args: argparse.Namespace, target: Path, stage: str) -> dict[str, Any]:
    existing = target / CAPABILITY_MANIFEST_PATH
    if args.addon or stage == "workflow":
        if args.capabilities_file or args.all_capabilities:
            raise InvalidTarget("capability options are only valid when creating the project capability manifest")
        try:
            return load_capabilities_file(existing)
        except CapabilityError as exc:
            raise InvalidTarget(f"an existing valid project capability manifest is required: {exc}") from exc
    if args.capabilities_file:
        return load_capabilities_file(args.capabilities_file)
    if args.all_capabilities:
        return all_capabilities()
    if not sys.stdin.isatty():
        raise InvalidTarget("non-interactive initialization requires --capabilities-file or --all-capabilities")
    return ask_capabilities(sys.stdin, sys.stderr)


def main() -> int:
    args = parse_args()
    output = result()
    try:
        if args.bundle and args.source_commit:
            raise InvalidTarget("--source-commit cannot be combined with --bundle")
        if args.bundle:
            try:
                source: ConsumerSource = BundleSource(verify_bundle(args.bundle))
            except BundleError as exc:
                output["error"].append(f"bundle verification failed: {exc}")
                print(json.dumps(output, indent=2, sort_keys=True))
                return VERIFICATION_FAILED
        else:
            source = tree_source(args.source_commit)
        output["source"] = {
            "type": source.source_type, "development_version": source.version,
            "source_commit": source.source_commit,
            "bundle_manifest_sha256": source.bundle_manifest_sha256,
        }
        target = validate_target(args.target, SOURCE_ROOT if source.source_type == "source_tree" else None)
        catalog = load_catalog(source)
        if args.addon and args.stage is not None:
            raise InvalidTarget("--stage cannot be combined with --addon")
        if args.profile == "minimal" and args.stage is not None:
            raise InvalidTarget("--stage is only valid with --profile standard")
        if args.addon:
            verify_addon_prerequisites(target, catalog)
            stage = "addon"
        else:
            stage = args.stage or ("all" if args.profile == "minimal" else "support")
            if args.profile == "standard" and stage == "workflow":
                verify_standard_workflow_prerequisites(target, catalog)
        capabilities = requested_capabilities(args, target, stage)
        output["project_capabilities"] = capabilities
        if args.addon:
            if not capabilities["capabilities"]["dast_target"]:
                output["skipped"].append(
                    "dast-baseline = not_applicable: project capability manifest declares no runnable web application target"
                )
                print(json.dumps(output, indent=2, sort_keys=True))
                return SUCCESS
            plan = build_addon_plan(catalog, args.addon, source)
        else:
            manifest_data = None if stage == "workflow" else capability_bytes(capabilities)
            plan = build_plan(catalog, args.profile, stage, source, manifest_data)
        output["warning"].extend(overlap_warnings(target))
        if args.profile == "standard" and stage == "support":
            output["warning"].append("Standard uses a two-stage bootstrap: merge support files before initializing the workflow stage.")
        preflight(target, plan, output)
        if args.write:
            write_plan(target, plan, output)
        else:
            output["skipped"].append("dry-run: pass --write to create the listed files")
    except ConflictError as exc:
        output["error"].append(str(exc))
        print(json.dumps(output, indent=2, sort_keys=True))
        return VERIFICATION_FAILED
    except (InvalidTarget, CapabilityError, VersionError, UnsafePath) as exc:
        output["error"].append(str(exc))
        print(json.dumps(output, indent=2, sort_keys=True))
        return INVALID_INPUT
    except (OSError, UnicodeError, KeyboardInterrupt) as exc:
        output["error"].append(f"initialization infrastructure failure: {type(exc).__name__}: {exc}")
        print(json.dumps(output, indent=2, sort_keys=True))
        return INFRASTRUCTURE_FAILURE
    print(json.dumps(output, indent=2, sort_keys=True))
    return SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
