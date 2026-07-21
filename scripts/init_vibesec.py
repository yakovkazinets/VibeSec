#!/usr/bin/env python3
"""Safely preview or initialize VibeSec in an unrelated repository.

Exit codes: 0 success, 2 conflict, 3 invalid target/configuration, 4 infrastructure failure.
This helper performs no network, package-management, Git, or application execution.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unicodedata
from typing import Any

SOURCE_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = SOURCE_ROOT / "config/adoption-files.json"
MAX_WORKFLOW_BYTES = 1_000_000
OVERLAP_MARKERS = (
    "semgrep", "codeql", "snyk", "dependabot", "renovate", "trivy",
    "gitleaks", "osv-scanner", "checkov", "grype", "anchore",
)


class InvalidTarget(ValueError):
    """The target or source catalog violates initialization constraints."""


class ConflictError(ValueError):
    """One or more destination files already exist."""


def result() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "would_create": [],
        "created": [],
        "conflict": [],
        "skipped": [],
        "warning": [],
        "error": [],
    }


def load_catalog() -> dict[str, Any]:
    try:
        payload = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InvalidTarget(f"invalid VibeSec adoption catalog: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise InvalidTarget("invalid VibeSec adoption catalog schema")
    profiles = payload.get("profiles")
    common = payload.get("common")
    if not isinstance(profiles, dict) or not isinstance(common, list):
        raise InvalidTarget("VibeSec adoption catalog is missing profiles or common files")
    return payload


def safe_relative(value: object) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise InvalidTarget("adoption catalog contains an invalid path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or path == Path("."):
        raise InvalidTarget(f"adoption catalog path is unsafe: {value!r}")
    return path


def validate_target(raw_target: Path) -> Path:
    if raw_target.is_symlink():
        raise InvalidTarget("target root must not be a symbolic link")
    try:
        target = raw_target.resolve(strict=True)
    except OSError as exc:
        raise InvalidTarget(f"target directory is unavailable: {exc}") from exc
    if not target.is_dir():
        raise InvalidTarget("target must be an existing directory")
    if target == SOURCE_ROOT:
        raise InvalidTarget("the VibeSec source repository cannot initialize itself")
    return target


def source_entry(relative: Path) -> tuple[Path, int]:
    source = SOURCE_ROOT / relative
    try:
        source_resolved = source.resolve(strict=True)
        source_resolved.relative_to(SOURCE_ROOT)
    except (OSError, ValueError) as exc:
        raise InvalidTarget(f"required VibeSec source file is unavailable: {relative.as_posix()}") from exc
    if source.is_symlink() or not source_resolved.is_file():
        raise InvalidTarget(f"required VibeSec source must be a regular file: {relative.as_posix()}")
    mode = stat.S_IMODE(source_resolved.stat().st_mode) & 0o755
    return source_resolved, mode


def ensure_safe_parent(target: Path, destination: Path) -> None:
    try:
        destination.relative_to(target)
    except ValueError as exc:
        raise InvalidTarget(f"destination escapes target: {destination}") from exc
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
            path = base / name
            relative = path.relative_to(target).as_posix()
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
        for marker in OVERLAP_MARKERS:
            if marker in text:
                detected.add(marker)
    if not detected:
        return []
    return [
        "existing security workflow markers detected ("
        + ", ".join(sorted(detected))
        + "); review docs/profile-selection.md before adding overlapping controls"
    ]


def manifest_bytes(profile: str, stage: str, version: str, paths: list[str]) -> bytes:
    payload = {
        "schema_version": 1,
        "profile": profile,
        "stage": stage,
        "source_version": version,
        "installed_files": sorted(paths),
        "enforcement": "observe",
        "network_used_by_initializer": False,
    }
    if profile == "standard" and stage == "support":
        payload["next_step"] = "After merging support files to the default branch, run --profile standard --stage workflow --write."
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build_plan(catalog: dict[str, Any], profile: str, stage: str) -> list[tuple[Path | None, Path, int, bytes | None]]:
    config = catalog["profiles"].get(profile)
    if not isinstance(config, dict):
        raise InvalidTarget(f"unknown profile: {profile}")
    items: list[tuple[Path | None, Path, int, bytes | None]] = []
    paths: list[Path] = []
    if stage in {"all", "support"}:
        for value in [*catalog["common"], *config.get("support", [])]:
            relative = safe_relative(value)
            paths.append(relative)
    if stage in {"all", "workflow"}:
        source_relative = safe_relative(config.get("workflow_source"))
        destination_relative = safe_relative(config.get("workflow_destination"))
        source, mode = source_entry(source_relative)
        items.append((source, destination_relative, mode, None))
        paths.append(destination_relative)
    for relative in sorted(set(paths), key=lambda item: item.as_posix()):
        if any(destination == relative for _, destination, _, _ in items):
            continue
        source, mode = source_entry(relative)
        items.append((source, relative, mode, None))
    manifest_relative = Path(f".vibesec/install-{profile}-{stage}.json")
    installed = [destination.as_posix() for _, destination, _, _ in items] + [manifest_relative.as_posix()]
    content = manifest_bytes(profile, stage, str(catalog.get("source_version", "unknown")), installed)
    items.append((None, manifest_relative, 0o644, content))
    return sorted(items, key=lambda item: item[1].as_posix())


def verify_standard_workflow_prerequisites(target: Path, catalog: dict[str, Any]) -> None:
    required = [safe_relative(value) for value in [*catalog["common"], *catalog["profiles"]["standard"]["support"]]]
    missing = [path.as_posix() for path in required if not (target / path).is_file() or (target / path).is_symlink()]
    if missing:
        raise InvalidTarget("Standard workflow stage requires support files already present: " + ", ".join(missing))


def preflight(target: Path, plan: list[tuple[Path | None, Path, int, bytes | None]], output: dict[str, Any]) -> None:
    names = existing_name_index(target)
    for _, relative, _, _ in plan:
        destination = target / relative
        ensure_safe_parent(target, destination)
        key = unicodedata.normalize("NFC", relative.as_posix()).casefold()
        parent_conflict = None
        for length in range(1, len(relative.parts)):
            parent = Path(*relative.parts[:length]).as_posix()
            parent_key = unicodedata.normalize("NFC", parent).casefold()
            existing = names.get(parent_key)
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


def write_plan(target: Path, plan: list[tuple[Path | None, Path, int, bytes | None]], output: dict[str, Any]) -> None:
    created_files: list[tuple[Path, tuple[int, int]]] = []
    created_dirs: list[Path] = []
    try:
        for source, relative, mode, generated in plan:
            destination = target / relative
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
                raise FileExistsError(f"destination appeared during initialization: {relative.as_posix()}")
            data = generated if generated is not None else source.read_bytes() if source else b""
            file_descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
            temporary = Path(temporary_name)
            try:
                with os.fdopen(file_descriptor, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temporary, mode)
                os.link(temporary, destination, follow_symlinks=False)
                details = destination.stat(follow_symlinks=False)
                created_files.append((destination, (details.st_dev, details.st_ino)))
            finally:
                temporary.unlink(missing_ok=True)
            output["created"].append(relative.as_posix())
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
    parser.add_argument("--profile", required=True, choices=("minimal", "standard"))
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--stage", choices=("support", "workflow"), help="Standard only; defaults to support")
    parser.add_argument("--write", action="store_true", help="create files after a conflict-free preview")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output = result()
    try:
        target = validate_target(args.target)
        catalog = load_catalog()
        if args.profile == "minimal" and args.stage is not None:
            raise InvalidTarget("--stage is only valid with --profile standard")
        stage = args.stage or ("all" if args.profile == "minimal" else "support")
        if args.profile == "standard" and stage == "workflow":
            verify_standard_workflow_prerequisites(target, catalog)
        plan = build_plan(catalog, args.profile, stage)
        output["warning"].extend(overlap_warnings(target))
        if args.profile == "standard" and stage == "support":
            output["warning"].append(
                "Standard uses a two-stage bootstrap: merge support files before initializing the workflow stage."
            )
        preflight(target, plan, output)
        if args.write:
            write_plan(target, plan, output)
        else:
            output["skipped"].append("dry-run: pass --write to create the listed files")
    except ConflictError as exc:
        output["error"].append(str(exc))
        print(json.dumps(output, indent=2, sort_keys=True))
        return 2
    except InvalidTarget as exc:
        output["error"].append(str(exc))
        print(json.dumps(output, indent=2, sort_keys=True))
        return 3
    except (OSError, UnicodeError, KeyboardInterrupt) as exc:
        output["error"].append(f"initialization infrastructure failure: {type(exc).__name__}: {exc}")
        print(json.dumps(output, indent=2, sort_keys=True))
        return 4
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
