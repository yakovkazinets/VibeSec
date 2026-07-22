"""Strict installation-manifest schemas and canonical creation."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .paths import UnsafePath, safe_posix_path, validate_unique_paths
from .strict_json import StrictJSONError, canonical_json, loads_strict
from .version import VersionError, validate_version

INSTALLATION_SCHEMA = 2
HASH = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
MAX_INSTALLED_FILES = 128


class ManifestError(ValueError):
    """An installation manifest is malformed or unsupported."""


def installation_manifest_bytes(*, profile: str, stage: str, source_type: str,
                                development_version: str, source_commit: str | None,
                                bundle_manifest_sha256: str | None, manifest_path: str,
                                installed: list[dict[str, Any]]) -> bytes:
    payload: dict[str, Any] = {
        "schema_version": INSTALLATION_SCHEMA,
        "creation_tool_schema_version": 1,
        "profile": profile,
        "stage": stage,
        "source_type": source_type,
        "development_version": validate_version(development_version),
        "source_commit": source_commit,
        "bundle_manifest_sha256": bundle_manifest_sha256,
        "manifest_path": safe_posix_path(manifest_path),
        "installed_files": sorted(installed, key=lambda item: item["path"]),
        "enforcement_default": "observe",
        "initializer_network_behavior": "none",
    }
    if profile == "standard" and stage == "support":
        payload["next_step"] = "Merge support to the default branch, then initialize the Standard workflow stage."
    validate_installation_manifest(payload)
    return canonical_json(payload)


def _validate_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "mode"}:
        raise ManifestError("installation file record is malformed")
    path = safe_posix_path(value["path"])
    if not isinstance(value["sha256"], str) or not HASH.fullmatch(value["sha256"]):
        raise ManifestError(f"installation file hash is invalid: {path}")
    if value["mode"] not in {0o644, 0o755}:
        raise ManifestError(f"installation file mode is invalid: {path}")
    return value


def validate_installation_manifest(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ManifestError("installation manifest must be an object")
    schema = payload.get("schema_version")
    if schema == 1:
        allowed = {
            "schema_version", "profile", "stage", "source_version", "installed_files",
            "enforcement", "network_used_by_initializer", "next_step",
        }
        if not set(payload).issubset(allowed) or not allowed - {"next_step"} <= set(payload):
            raise ManifestError("legacy installation manifest fields are invalid")
        if payload.get("profile") not in {"minimal", "standard"} or payload.get("stage") not in {"all", "support", "workflow"}:
            raise ManifestError("legacy installation profile or stage is invalid")
        if (payload["profile"], payload["stage"]) not in {("minimal", "all"), ("standard", "support"), ("standard", "workflow")}:
            raise ManifestError("legacy installation profile/stage combination is invalid")
        source_version = payload.get("source_version")
        if not isinstance(source_version, str) or not source_version or len(source_version.encode("utf-8")) > 64:
            raise ManifestError("legacy source version is invalid")
        if payload.get("enforcement") != "observe" or payload.get("network_used_by_initializer") is not False:
            raise ManifestError("legacy installation safety declarations are invalid")
        paths = payload.get("installed_files")
        if not isinstance(paths, list) or len(paths) > MAX_INSTALLED_FILES or not all(isinstance(item, str) for item in paths):
            raise ManifestError("legacy installed_files is invalid")
        try:
            validate_unique_paths(paths)
        except UnsafePath as exc:
            raise ManifestError(str(exc)) from exc
        return payload
    required = {
        "schema_version", "creation_tool_schema_version", "profile", "stage", "source_type",
        "development_version", "source_commit", "bundle_manifest_sha256", "manifest_path",
        "installed_files", "enforcement_default", "initializer_network_behavior",
    }
    allowed = required | {"next_step"}
    if schema != INSTALLATION_SCHEMA or not required <= set(payload) or not set(payload) <= allowed:
        raise ManifestError("installation manifest schema or fields are unsupported")
    profile = payload["profile"]
    stage = payload["stage"]
    if (profile, stage) not in {("minimal", "all"), ("standard", "support"), ("standard", "workflow")}:
        raise ManifestError("installation profile/stage combination is invalid")
    if payload["source_type"] not in {"source_tree", "bundle"}:
        raise ManifestError("installation source type is invalid")
    validate_version(payload["development_version"])
    if payload["source_commit"] is not None and (not isinstance(payload["source_commit"], str) or not COMMIT.fullmatch(payload["source_commit"])):
        raise ManifestError("installation source commit is invalid")
    bundle_hash = payload["bundle_manifest_sha256"]
    if payload["source_type"] == "bundle":
        if not isinstance(bundle_hash, str) or not HASH.fullmatch(bundle_hash):
            raise ManifestError("bundle installation requires a manifest SHA-256")
    elif bundle_hash is not None:
        raise ManifestError("source-tree installation cannot declare a bundle hash")
    safe_posix_path(payload["manifest_path"])
    records = payload["installed_files"]
    if not isinstance(records, list) or len(records) > MAX_INSTALLED_FILES:
        raise ManifestError("installed_files is invalid")
    validated = [_validate_record(item) for item in records]
    validate_unique_paths([item["path"] for item in validated])
    if payload["enforcement_default"] != "observe" or payload["initializer_network_behavior"] != "none":
        raise ManifestError("installation safety declarations are invalid")
    return payload


def parse_installation_manifest(data: bytes) -> dict[str, Any]:
    try:
        return validate_installation_manifest(loads_strict(data))
    except (StrictJSONError, VersionError, UnsafePath) as exc:
        raise ManifestError(str(exc)) from exc


def file_record(path: str, data: bytes, mode: int) -> dict[str, Any]:
    safe_posix_path(path)
    if mode not in {0o644, 0o755}:
        raise ManifestError("installed file mode is unsafe")
    return {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "mode": mode}
