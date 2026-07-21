"""Deterministic, read-only repository inventory for Standard profile routing."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

SKIP_DIRS = {".git", ".tools", ".cache", "node_modules", "vendor", "dist", "build", "results", "reports", ".venv", "venv"}
LANGUAGE_SUFFIXES = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".py": "python",
    ".java": "java", ".go": "go",
}
MANIFESTS = {
    "package.json": "npm", "package-lock.json": "npm", "npm-shrinkwrap.json": "npm",
    "yarn.lock": "yarn", "pnpm-lock.yaml": "pnpm", "requirements.txt": "pip",
    "poetry.lock": "poetry", "Pipfile.lock": "pipenv", "pyproject.toml": "python",
    "pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle",
    "go.mod": "go", "go.sum": "go",
}
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "go.sum"}


def _yaml_mapping(path: Path) -> dict[str, Any] | None:
    if path.stat().st_size > 1_000_000:
        return None
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError):
        return None
    return value if isinstance(value, dict) else None


def inventory(root: Path) -> dict[str, Any]:
    root = root.resolve()
    languages: set[str] = set()
    package_managers: set[str] = set()
    manifests: list[str] = []
    lockfiles: list[str] = []
    dockerfiles: list[str] = []
    workflows: list[str] = []
    iac: dict[str, list[str]] = {key: [] for key in ("terraform", "kubernetes", "helm", "kustomize", "cloudformation", "bicep", "arm")}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root)
        if any(part in SKIP_DIRS for part in relative.parts) or path.is_symlink() or not path.is_file():
            continue
        rel = relative.as_posix()
        name = path.name
        suffix = path.suffix.lower()
        if suffix in LANGUAGE_SUFFIXES:
            languages.add(LANGUAGE_SUFFIXES[suffix])
        if name in MANIFESTS:
            manifests.append(rel)
            package_managers.add(MANIFESTS[name])
            if name in LOCKFILES:
                lockfiles.append(rel)
        if name == "Dockerfile" or name.startswith("Dockerfile."):
            dockerfiles.append(rel)
        if len(relative.parts) >= 3 and relative.parts[-3:-1] == (".github", "workflows") and suffix in {".yml", ".yaml"}:
            workflows.append(rel)
        if suffix == ".tf":
            iac["terraform"].append(rel)
        elif suffix == ".bicep":
            iac["bicep"].append(rel)
        elif name == "Chart.yaml":
            iac["helm"].append(rel)
        elif name.lower() in {"kustomization.yaml", "kustomization.yml"}:
            iac["kustomize"].append(rel)
        elif suffix in {".yaml", ".yml", ".json"}:
            payload = _yaml_mapping(path)
            if payload and "apiVersion" in payload and "kind" in payload:
                iac["kubernetes"].append(rel)
            if payload and "AWSTemplateFormatVersion" in payload and "Resources" in payload:
                iac["cloudformation"].append(rel)
            if payload and "$schema" in payload and "deploymentTemplate.json" in str(payload.get("$schema")):
                iac["arm"].append(rel)
    manifest_dirs = {str(Path(path).parent) for path in manifests}
    return {
        "schema_version": 1,
        "languages": sorted(languages),
        "package_managers": sorted(package_managers),
        "manifests": sorted(manifests),
        "lockfiles": sorted(lockfiles),
        "monorepo": len(manifest_dirs) > 1,
        "dockerfiles": sorted(dockerfiles),
        "iac": {key: sorted(value) for key, value in sorted(iac.items())},
        "workflows": sorted(workflows),
    }
