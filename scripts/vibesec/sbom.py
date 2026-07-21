"""Fail-closed structural validation for generated SBOM artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_SBOM_BYTES = 50 * 1024 * 1024


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
