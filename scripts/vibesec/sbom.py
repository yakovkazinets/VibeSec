"""Fail-closed structural validation for generated SBOM artifacts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any

from .strict_json import StrictJSONError, loads_strict

MAX_SBOM_BYTES = 50 * 1024 * 1024
MAX_DEPTH = 100
MAX_SBOM_ITEMS = 250_000
CYCLONEDX_SPEC_VERSION = "1.6"
SPDX_SPEC_VERSION = "SPDX-2.3"


def _load(path: Path) -> dict[str, Any]:
    try:
        if (path.is_symlink() or not path.is_file()
                or path.stat(follow_symlinks=False).st_size > MAX_SBOM_BYTES):
            raise ValueError("SBOM is unsafe or exceeds the accepted size limit")
        payload = loads_strict(
            path.read_bytes(), maximum_bytes=MAX_SBOM_BYTES,
            maximum_depth=MAX_DEPTH, maximum_items=MAX_SBOM_ITEMS,
            maximum_string=MAX_SBOM_BYTES,
        )
    except (OSError, UnicodeError, StrictJSONError) as exc:
        raise ValueError(f"invalid SBOM {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"invalid SBOM {path}: expected an object")
    return payload


def validate_cyclonedx(path: Path) -> dict[str, Any]:
    payload = _load(path)
    if (payload.get("bomFormat") != "CycloneDX"
            or payload.get("specVersion") != CYCLONEDX_SPEC_VERSION):
        raise ValueError("invalid CycloneDX SBOM metadata")
    if not isinstance(payload.get("components"), list) or not payload["components"]:
        raise ValueError("CycloneDX SBOM contains no components")
    return payload


def validate_spdx(path: Path) -> dict[str, Any]:
    payload = _load(path)
    if (payload.get("spdxVersion") != SPDX_SPEC_VERSION
            or payload.get("SPDXID") != "SPDXRef-DOCUMENT"):
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
            json.dump(
                sanitized, stream, allow_nan=False, ensure_ascii=False,
                separators=(",", ":"), sort_keys=True,
            )
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
