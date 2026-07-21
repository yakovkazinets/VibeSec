"""Deterministic, bounded, read-only repository inventory for scanner routing."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

MAX_FILES = 100_000
MAX_DEPTH = 40
MAX_YAML_BYTES = 1_000_000
SKIP_DIRS = {value.casefold() for value in (
    ".git", ".tools", ".cache", "node_modules", "vendor", "dist", "build",
    "results", "reports", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
)}
LANGUAGE_SUFFIXES = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".py": "python", ".java": "java", ".go": "go",
}
MANIFESTS = {
    "package.json": "npm", "package-lock.json": "npm", "npm-shrinkwrap.json": "npm",
    "yarn.lock": "yarn", "pnpm-lock.yaml": "pnpm", "bun.lock": "bun", "bun.lockb": "bun",
    "requirements.txt": "pip", "uv.lock": "uv", "poetry.lock": "poetry",
    "Pipfile.lock": "pipenv", "pyproject.toml": "python", "pom.xml": "maven",
    "build.gradle": "gradle", "build.gradle.kts": "gradle", "gradle.lockfile": "gradle",
    "go.mod": "go", "go.sum": "go",
}
LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lock", "bun.lockb", "uv.lock", "poetry.lock", "Pipfile.lock", "gradle.lockfile", "go.sum",
}


class DetectionError(ValueError):
    """Inventory could not complete within its explicit safety bounds."""


def _yaml_mappings(path: Path) -> list[dict[str, Any]]:
    try:
        size = path.stat().st_size
        if size > MAX_YAML_BYTES:
            return []
        text = path.read_text(encoding="utf-8")
        values = list(yaml.safe_load_all(text))
    except (UnicodeError, yaml.YAMLError):
        return []
    except OSError as exc:
        raise DetectionError(f"could not inspect {path.name}: {exc}") from exc
    return [value for value in values if isinstance(value, dict)]


def _manifest_manager(name: str) -> str | None:
    if name in MANIFESTS:
        return MANIFESTS[name]
    lowered = name.casefold()
    if lowered.startswith("requirements") and lowered.endswith(".txt"):
        return "pip"
    return None


def inventory(root: Path) -> dict[str, Any]:
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise DetectionError(f"repository root is unavailable: {exc}") from exc
    if not root.is_dir():
        raise DetectionError("repository root must be a directory")
    languages: set[str] = set()
    package_managers: set[str] = set()
    source_files: list[str] = []
    manifests: list[str] = []
    lockfiles: list[str] = []
    dockerfiles: list[str] = []
    workflows: list[str] = []
    ci_configs: list[str] = []
    iac: dict[str, list[str]] = {key: [] for key in ("terraform", "kubernetes", "helm", "kustomize", "cloudformation", "bicep", "arm")}
    file_count = 0

    def walk_error(exc: OSError) -> None:
        raise DetectionError(f"repository traversal failed: {exc}")

    for directory, directory_names, file_names in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
        current = Path(directory)
        try:
            relative_directory = current.relative_to(root)
        except ValueError as exc:
            raise DetectionError("repository traversal escaped its root") from exc
        depth = len(relative_directory.parts)
        directory_names[:] = sorted(
            name for name in directory_names
            if name.casefold() not in SKIP_DIRS and not (current / name).is_symlink()
        )
        if depth >= MAX_DEPTH and directory_names:
            raise DetectionError(f"repository traversal exceeds maximum depth {MAX_DEPTH}")
        for name in sorted(file_names):
            path = current / name
            if path.is_symlink():
                continue
            try:
                if not path.is_file():
                    continue
            except OSError as exc:
                raise DetectionError(f"could not classify {name}: {exc}") from exc
            file_count += 1
            if file_count > MAX_FILES:
                raise DetectionError(f"repository contains more than {MAX_FILES} inspectable files")
            relative = path.relative_to(root)
            rel = relative.as_posix()
            suffix = path.suffix.casefold()
            if suffix in LANGUAGE_SUFFIXES:
                languages.add(LANGUAGE_SUFFIXES[suffix])
                source_files.append(rel)
            manager = _manifest_manager(name)
            if manager:
                manifests.append(rel)
                package_managers.add(manager)
                if name in LOCKFILES or name.casefold().startswith("requirements"):
                    lockfiles.append(rel)
            if name == "Dockerfile" or name.startswith("Dockerfile."):
                dockerfiles.append(rel)
            if len(relative.parts) >= 3 and tuple(part.casefold() for part in relative.parts[-3:-1]) == (".github", "workflows") and suffix in {".yml", ".yaml"}:
                workflows.append(rel)
                ci_configs.append(rel)
            if name in {".gitlab-ci.yml", "Jenkinsfile"} or rel.startswith(".circleci/"):
                ci_configs.append(rel)
            if suffix == ".tf":
                iac["terraform"].append(rel)
            elif suffix == ".bicep":
                iac["bicep"].append(rel)
            elif suffix in {".yaml", ".yml", ".json"}:
                payloads = _yaml_mappings(path)
                if name == "Chart.yaml" and any(
                    isinstance(value.get("apiVersion"), str) and isinstance(value.get("name"), str) and isinstance(value.get("version"), (str, int, float))
                    for value in payloads
                ):
                    iac["helm"].append(rel)
                if name.casefold() in {"kustomization.yaml", "kustomization.yml"} and any(
                    any(isinstance(value.get(key), list) for key in ("resources", "bases", "components"))
                    for value in payloads
                ):
                    iac["kustomize"].append(rel)
                if any(isinstance(value.get("apiVersion"), str) and isinstance(value.get("kind"), str) for value in payloads):
                    iac["kubernetes"].append(rel)
                if any("AWSTemplateFormatVersion" in value and isinstance(value.get("Resources"), dict) for value in payloads):
                    iac["cloudformation"].append(rel)
                if any(isinstance(value.get("$schema"), str) and "deploymentTemplate.json" in value["$schema"] for value in payloads):
                    iac["arm"].append(rel)
    manifest_dirs = {str(Path(path).parent) for path in manifests}
    return {
        "schema_version": 1, "files_inspected": file_count,
        "languages": sorted(languages), "source_files": sorted(source_files),
        "package_managers": sorted(package_managers), "manifests": sorted(manifests),
        "lockfiles": sorted(lockfiles), "monorepo": len(manifest_dirs) > 1,
        "dockerfiles": sorted(dockerfiles),
        "iac": {key: sorted(value) for key, value in sorted(iac.items())},
        "workflows": sorted(workflows), "ci_configs": sorted(set(ci_configs)),
    }
