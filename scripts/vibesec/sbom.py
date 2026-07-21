"""Fail-closed structural validation for generated SBOM artifacts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any

MAX_SBOM_BYTES = 50 * 1024 * 1024
MAX_DEPTH = 100


def _load(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_SBOM_BYTES:
            raise ValueError("SBOM exceeds the accepted size limit")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid SBOM {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"invalid SBOM {path}: expected an object")
    return payload


def validate_cyclonedx(path: Path) -> dict[str, Any]:
    payload = _load(path)
    if payload.get("bomFormat") != "CycloneDX" or not isinstance(payload.get("specVersion"), str):
        raise ValueError("invalid CycloneDX SBOM metadata")
    if not isinstance(payload.get("components"), list) or not payload["components"]:
        raise ValueError("CycloneDX SBOM contains no components")
    return payload


def validate_spdx(path: Path) -> dict[str, Any]:
    payload = _load(path)
    if not str(payload.get("spdxVersion", "")).startswith("SPDX-") or payload.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ValueError("invalid SPDX SBOM metadata")
    if not isinstance(payload.get("packages"), list) or not payload["packages"]:
        raise ValueError("SPDX SBOM contains no packages")
    return payload


def sanitize_repository_paths(path: Path, repository_root: Path) -> None:
    """Remove an absolute checkout prefix from strings in a generated SBOM."""
    payload = _load(path)
    roots = sorted({
        repository_root.absolute().as_posix().rstrip("/"),
        repository_root.resolve().as_posix().rstrip("/"),
    }, key=len, reverse=True)

    def sanitize(value: Any, depth: int = 0) -> Any:
        if depth > MAX_DEPTH:
            raise ValueError("SBOM exceeds the accepted nesting depth")
        if isinstance(value, str):
            normalized = value.replace("\\", "/")
            for root in roots:
                if normalized == root:
                    return "."
                if normalized.startswith(root + "/"):
                    return normalized[len(root) + 1:]
            return value
        if isinstance(value, list):
            return [sanitize(item, depth + 1) for item in value]
        if isinstance(value, dict):
            return {key: sanitize(item, depth + 1) for key, item in value.items()}
        return value

    sanitized = sanitize(payload)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(sanitized, stream, separators=(",", ":"), sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
