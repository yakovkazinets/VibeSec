"""Build and validate the trusted product-only VibeSec self-scan view."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
from typing import Any

from .paths import UnsafePath, collision_key, safe_posix_path, validate_unique_paths
from .strict_json import StrictJSONError, loads_strict

EXPECTED_EXCLUDED_ROOTS = (
    "examples/reports",
    "tests/consumer-fixtures",
    "tests/security-fixtures",
)
SCOPE_FIELDS = {"schema_version", "excluded_fixture_roots"}
ENTRY_FIELDS = {"path", "capability_ids", "test_modules", "ci_enforcement"}
MANDATORY_ACCOUNTABILITY_JOBS = {"scanner-accountability", "security-artifacts"}


class SelfScanError(ValueError):
    """Trusted self-scan scope or view construction failed closed."""


def _git_environment(home: Path) -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update({
        "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
    })
    return environment


def _strings(value: Any, field: str) -> list[str]:
    if (not isinstance(value, list) or not value or len(value) > 32
            or any(not isinstance(item, str) or not item or len(item) > 240 for item in value)):
        raise SelfScanError(f"{field} must be a bounded nonempty string array")
    if value != sorted(set(value)):
        raise SelfScanError(f"{field} must be sorted and unique")
    return value


def _workflow_job(workflow: str, job: str) -> str:
    marker = f"  {job}:\n"
    start = workflow.find(marker)
    if start < 0:
        raise SelfScanError(f"self-scan accountability job is missing: {job}")
    following = [
        position for position in (
            workflow.find(f"  {candidate}:\n", start + len(marker))
            for candidate in ("self-scan-minimal", "self-scan-standard", "scanner-accountability", "security-artifacts", "validate")
        ) if position >= 0
    ]
    return workflow[start:min(following) if following else len(workflow)]


def load_scope(root: Path) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Load the fixed trusted scope and prove each exclusion has independent CI evidence."""
    try:
        payload = loads_strict((root / "config/self-scan-scope.json").read_bytes())
    except (OSError, StrictJSONError) as exc:
        raise SelfScanError(f"trusted self-scan scope is invalid: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != SCOPE_FIELDS or payload.get("schema_version") != 1:
        raise SelfScanError("trusted self-scan scope schema is invalid")
    entries = payload["excluded_fixture_roots"]
    if not isinstance(entries, list) or not entries or len(entries) > 16:
        raise SelfScanError("excluded fixture roots must be a bounded nonempty array")
    try:
        paths = [safe_posix_path(entry.get("path") if isinstance(entry, dict) else None) for entry in entries]
        validate_unique_paths(paths)
    except UnsafePath as exc:
        raise SelfScanError(f"excluded fixture root is unsafe: {exc}") from exc
    if tuple(paths) != EXPECTED_EXCLUDED_ROOTS:
        raise SelfScanError("trusted self-scan exclusions differ from the reviewed roots")

    try:
        capabilities = loads_strict((root / "config/security-capabilities.json").read_bytes())
        capability_ids = {item["id"] for item in capabilities["capabilities"]}
        workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    except (OSError, KeyError, TypeError, StrictJSONError) as exc:
        raise SelfScanError("self-scan accountability sources are invalid") from exc
    validate_line = next((line for line in workflow.splitlines() if line.strip().startswith("needs: [")), "")

    for entry, relative in zip(entries, paths, strict=True):
        if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
            raise SelfScanError("excluded fixture root entry fields are invalid")
        source = root / relative
        try:
            resolved = source.resolve(strict=True)
            resolved.relative_to(root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise SelfScanError(f"excluded fixture root is unavailable: {relative}") from exc
        if source.is_symlink() or not resolved.is_dir():
            raise SelfScanError(f"excluded fixture root must be a real directory: {relative}")

        linked_capabilities = _strings(entry["capability_ids"], f"{relative}.capability_ids")
        if not set(linked_capabilities) <= capability_ids:
            raise SelfScanError(f"excluded fixture root references an unknown capability: {relative}")
        modules = _strings(entry["test_modules"], f"{relative}.test_modules")
        for module in modules:
            module_path = root / (module.replace(".", "/") + ".py")
            if not module_path.is_file() or relative not in module_path.read_text(encoding="utf-8"):
                raise SelfScanError(f"excluded fixture root lacks its declared test reference: {relative}")
        jobs = _strings(entry["ci_enforcement"], f"{relative}.ci_enforcement")
        if not set(jobs) <= MANDATORY_ACCOUNTABILITY_JOBS:
            raise SelfScanError(f"excluded fixture root references a non-accountability job: {relative}")
        for job in jobs:
            block = _workflow_job(workflow, job)
            if not any(module in block or (job == "scanner-accountability" and "run_security_accountability.py" in block) for module in modules):
                raise SelfScanError(f"excluded fixture root test is not enforced by {job}: {relative}")
            if job not in validate_line:
                raise SelfScanError(f"excluded fixture root job is not mandatory: {relative}: {job}")
    return payload, tuple(paths)


def _tracked_files(root: Path) -> list[str]:
    try:
        completed = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}",
             "-C", str(root), "ls-files", "-z"],
            env=_git_environment(Path("/nonexistent-vibesec-self-scan-home")), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SelfScanError(f"could not enumerate tracked product files: {type(exc).__name__}") from exc
    if completed.returncode != 0:
        raise SelfScanError("could not enumerate tracked product files")
    try:
        values = [item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]
        validate_unique_paths(values)
    except (UnicodeDecodeError, UnsafePath) as exc:
        raise SelfScanError(f"tracked product path is unsafe: {exc}") from exc
    return sorted(values)


def build_product_view(root: Path, destination: Path, excluded_roots: tuple[str, ...]) -> list[str]:
    """Copy tracked product files, excluding only the fixed synthetic roots."""
    destination.mkdir(parents=True, exist_ok=False)
    included: list[str] = []
    collision_map: dict[str, str] = {}
    resolved_root = root.resolve(strict=True)
    for relative in _tracked_files(resolved_root):
        if any(relative == excluded or relative.startswith(excluded + "/") for excluded in excluded_roots):
            continue
        key = collision_key(relative)
        if key in collision_map and collision_map[key] != relative:
            raise SelfScanError(f"tracked product paths collide: {collision_map[key]} and {relative}")
        collision_map[key] = relative
        source = resolved_root / relative
        try:
            resolved = source.resolve(strict=True)
            resolved.relative_to(resolved_root)
        except (OSError, ValueError) as exc:
            raise SelfScanError(f"tracked product file escapes the repository: {relative}") from exc
        if source.is_symlink() or not resolved.is_file():
            raise SelfScanError(f"tracked product path is not a regular file: {relative}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target, follow_symlinks=False)
        included.append(relative)
    if not included:
        raise SelfScanError("trusted product scan view would be empty")
    return included


def initialize_snapshot_repository(view: Path) -> None:
    """Create an inert one-commit repository so Gitleaks can scan the product snapshot."""
    environment = _git_environment(view.parent / ".git-home")
    commands = (
        ["git", "-c", f"core.hooksPath={os.devnull}", "init", "--quiet", "--template=", "--initial-branch=main"],
        ["git", "-c", f"core.hooksPath={os.devnull}", "add", "--all"],
        ["git", "-c", f"core.hooksPath={os.devnull}", "-c", "user.name=VibeSec Self Scan",
         "-c", "user.email=self-scan@invalid", "commit", "--quiet", "--no-gpg-sign",
         "-m", "VibeSec product snapshot"],
    )
    for command in commands:
        try:
            completed = subprocess.run(
                command, cwd=view, env=environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SelfScanError(f"could not create inert self-scan snapshot: {type(exc).__name__}") from exc
        if completed.returncode != 0:
            raise SelfScanError("could not create inert self-scan snapshot")


def make_read_only(view: Path) -> None:
    for path in sorted(view.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        mode = stat.S_IMODE(path.stat().st_mode)
        path.chmod((mode & 0o555) if path.is_file() else 0o555)
    view.chmod(0o555)


def make_removable(view: Path) -> None:
    if not view.exists():
        return
    view.chmod(0o755)
    for path in view.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
