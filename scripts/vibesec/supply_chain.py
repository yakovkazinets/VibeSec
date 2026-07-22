"""Strict, bounded release-artifact preparation and verification.

The trust root for signature verification is deliberately external to the
artifact directory.  This module never treats files inside a release set as
executable authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any

from .bundle import verify_bundle
from .sbom import validate_cyclonedx, validate_spdx
from .strict_json import StrictJSONError, canonical_json, loads_strict
from .version import validate_version

RELEASE_SCHEMA = 1
PROVENANCE_SCHEMA = 1
RECORD_SCHEMA = 1
MAX_RELEASE_FILE_BYTES = 50 * 1024 * 1024
MAX_SIGNATURE_BYTES = 2 * 1024 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = "https://github.com/yakovkazinets/VibeSec"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
WORKFLOW_IDENTITY = (
    "https://github.com/yakovkazinets/VibeSec/.github/workflows/"
    "release-candidate.yml@refs/heads/main"
)
LOCAL_BUILDER_IDENTITY = "https://github.com/yakovkazinets/VibeSec/builders/local-preparation/v1"
BUNDLE_NAME = "vibesec-consumer-bundle.zip"
CYCLONEDX_NAME = "sbom.cyclonedx.json"
SPDX_NAME = "sbom.spdx.json"
PROVENANCE_NAME = "provenance.intoto.jsonl"
MANIFEST_NAME = "release-manifest.json"
CHECKSUMS_NAME = "SHA256SUMS"
SIGNATURE_NAME = "SHA256SUMS.sigstore.json"
CORE_NAMES = (BUNDLE_NAME, CYCLONEDX_NAME, SPDX_NAME)
CHECKSUM_NAMES = (*CORE_NAMES, PROVENANCE_NAME, MANIFEST_NAME)
UNSIGNED_NAMES = (*CHECKSUM_NAMES, CHECKSUMS_NAME)
SIGNED_NAMES = (*UNSIGNED_NAMES, SIGNATURE_NAME)
MEDIA_TYPES = {
    BUNDLE_NAME: "application/zip",
    CYCLONEDX_NAME: "application/vnd.cyclonedx+json",
    SPDX_NAME: "application/spdx+json",
}


class SupplyChainError(ValueError):
    """Release metadata or verification violates the reviewed contract."""


@dataclass(frozen=True)
class VerifiedRelease:
    directory: Path
    manifest: dict[str, Any]
    provenance: dict[str, Any]
    checksums: dict[str, str]
    signature_verified: bool


def verification_record(release: VerifiedRelease, *, release_reference: str | None,
                        verification_tool: str | None) -> dict[str, Any]:
    if release_reference is not None and not re.fullmatch(
        r"https://github\.com/yakovkazinets/VibeSec/releases/download/v[0-9]+\.[0-9]+\.[0-9]+/[A-Za-z0-9._-]+",
        release_reference,
    ):
        raise SupplyChainError("release reference must be an immutable official versioned asset URL")
    if release.signature_verified:
        if verification_tool is None or not re.fullmatch(r"cosign/[0-9]+\.[0-9]+\.[0-9]+", verification_tool):
            raise SupplyChainError("signed verification requires a supported Cosign version record")
    elif verification_tool is not None:
        raise SupplyChainError("checksum-only verification must not claim a signature tool")
    bundle = verify_bundle(release.directory / BUNDLE_NAME)
    return {
        "schema_version": RECORD_SCHEMA,
        "status": "verified",
        "version": release.manifest["version"],
        "source_commit": release.manifest["source"]["commit"],
        "bundle_sha256": release.checksums[BUNDLE_NAME],
        "bundle_manifest_sha256": bundle.manifest_sha256,
        "release_manifest_sha256": release.checksums[MANIFEST_NAME],
        "provenance_sha256": release.checksums[PROVENANCE_NAME],
        "signature_verified": release.signature_verified,
        "verification_tool": verification_tool,
        "certificate_identity": WORKFLOW_IDENTITY if release.signature_verified else None,
        "certificate_oidc_issuer": OIDC_ISSUER if release.signature_verified else None,
        "release_reference": release_reference,
    }


def validate_verification_record(value: Any) -> dict[str, Any]:
    required = {
        "schema_version", "status", "version", "source_commit", "bundle_sha256",
        "bundle_manifest_sha256", "release_manifest_sha256", "provenance_sha256",
        "signature_verified", "verification_tool", "certificate_identity",
        "certificate_oidc_issuer", "release_reference",
    }
    if (not isinstance(value, dict) or set(value) != required
            or value.get("schema_version") != RECORD_SCHEMA or value.get("status") != "verified"):
        raise SupplyChainError("release verification record fields or schema are invalid")
    try:
        validate_version(value["version"])
    except (TypeError, ValueError) as exc:
        raise SupplyChainError("release verification record version is invalid") from exc
    if not isinstance(value.get("source_commit"), str) or not COMMIT.fullmatch(value["source_commit"]):
        raise SupplyChainError("release verification record commit is invalid")
    for field in ("bundle_sha256", "bundle_manifest_sha256", "release_manifest_sha256", "provenance_sha256"):
        if not isinstance(value.get(field), str) or not SHA256.fullmatch(value[field]):
            raise SupplyChainError("release verification record digest is invalid")
    signed = value.get("signature_verified")
    if not isinstance(signed, bool):
        raise SupplyChainError("release verification signature state is invalid")
    expected_identity = WORKFLOW_IDENTITY if signed else None
    expected_issuer = OIDC_ISSUER if signed else None
    if value.get("certificate_identity") != expected_identity or value.get("certificate_oidc_issuer") != expected_issuer:
        raise SupplyChainError("release verification identity is invalid")
    tool = value.get("verification_tool")
    if signed and (not isinstance(tool, str) or not re.fullmatch(r"cosign/[0-9]+\.[0-9]+\.[0-9]+", tool)):
        raise SupplyChainError("release verification tool is invalid")
    if not signed and tool is not None:
        raise SupplyChainError("unsigned verification record claims a signature tool")
    reference = value.get("release_reference")
    if reference is not None and not re.fullmatch(
        r"https://github\.com/yakovkazinets/VibeSec/releases/download/v[0-9]+\.[0-9]+\.[0-9]+/[A-Za-z0-9._-]+",
        reference,
    ):
        raise SupplyChainError("release verification reference is mutable or invalid")
    return value


def _regular_file(path: Path, maximum: int = MAX_RELEASE_FILE_BYTES) -> bytes:
    try:
        details = path.stat(follow_symlinks=False)
        if path.is_symlink() or not path.is_file() or details.st_size > maximum:
            raise SupplyChainError(f"release artifact is unsafe or oversized: {path.name}")
        data = path.read_bytes()
    except OSError as exc:
        raise SupplyChainError(f"release artifact is unavailable: {path.name}") from exc
    if len(data) > maximum:
        raise SupplyChainError(f"release artifact grew beyond its limit: {path.name}")
    return data


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _artifact_records(directory: Path) -> list[dict[str, Any]]:
    records = []
    for name in CORE_NAMES:
        data = _regular_file(directory / name)
        records.append({
            "name": name,
            "sha256": _digest(data),
            "size": len(data),
            "media_type": MEDIA_TYPES[name],
        })
    return records


def create_release_manifest(*, directory: Path, version: str, source_commit: str,
                            tool_versions: dict[str, str], creation_mode: str) -> dict[str, Any]:
    validate_version(version)
    if not COMMIT.fullmatch(source_commit):
        raise SupplyChainError("source commit must be a full lowercase SHA")
    if creation_mode not in {"local-preparation", "trusted-github-workflow"}:
        raise SupplyChainError("release creation mode is unsupported")
    if (not isinstance(tool_versions, dict) or not tool_versions
            or any(not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", key)
                   or not isinstance(value, str) or not value or len(value) > 64
                   for key, value in tool_versions.items())):
        raise SupplyChainError("tool version map is invalid")
    return {
        "schema_version": RELEASE_SCHEMA,
        "version": version,
        "source": {"repository": REPOSITORY, "commit": source_commit},
        "artifacts": _artifact_records(directory),
        "schema_versions": {
            "release_manifest": RELEASE_SCHEMA,
            "provenance": PROVENANCE_SCHEMA,
            "cyclonedx": "1.7",
            "spdx": "SPDX-2.3",
        },
        "tool_versions": dict(sorted(tool_versions.items())),
        "creation_mode": creation_mode,
        "provenance": {
            "name": PROVENANCE_NAME,
            "predicate_type": "https://slsa.dev/provenance/v1",
        },
        "checksum_file": CHECKSUMS_NAME,
        "signature_bundle": SIGNATURE_NAME,
    }


def validate_release_manifest(value: Any) -> dict[str, Any]:
    required = {
        "schema_version", "version", "source", "artifacts", "schema_versions",
        "tool_versions", "creation_mode", "provenance", "checksum_file",
        "signature_bundle",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != RELEASE_SCHEMA:
        raise SupplyChainError("release manifest fields or schema are invalid")
    try:
        validate_version(value["version"])
    except (TypeError, ValueError) as exc:
        raise SupplyChainError("release manifest version is invalid") from exc
    source = value["source"]
    if (not isinstance(source, dict) or set(source) != {"repository", "commit"}
            or source.get("repository") != REPOSITORY
            or not isinstance(source.get("commit"), str) or not COMMIT.fullmatch(source["commit"])):
        raise SupplyChainError("release manifest source identity is invalid")
    expected_schema = {
        "release_manifest": RELEASE_SCHEMA, "provenance": PROVENANCE_SCHEMA,
        "cyclonedx": "1.7", "spdx": "SPDX-2.3",
    }
    if value.get("schema_versions") != expected_schema:
        raise SupplyChainError("release manifest schema declarations are invalid")
    if value.get("creation_mode") not in {"local-preparation", "trusted-github-workflow"}:
        raise SupplyChainError("release manifest creation mode is invalid")
    if value.get("checksum_file") != CHECKSUMS_NAME or value.get("signature_bundle") != SIGNATURE_NAME:
        raise SupplyChainError("release manifest linkage is invalid")
    if value.get("provenance") != {"name": PROVENANCE_NAME, "predicate_type": "https://slsa.dev/provenance/v1"}:
        raise SupplyChainError("release manifest provenance reference is invalid")
    tools = value.get("tool_versions")
    if (not isinstance(tools, dict) or not tools or list(tools) != sorted(tools)
            or any(not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", key)
                   or not isinstance(version, str) or not version or len(version) > 64
                   for key, version in tools.items())):
        raise SupplyChainError("release manifest tool versions are invalid")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(CORE_NAMES):
        raise SupplyChainError("release manifest artifact list is invalid")
    names = []
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {"name", "sha256", "size", "media_type"}:
            raise SupplyChainError("release manifest artifact record is malformed")
        name = item.get("name")
        if name not in CORE_NAMES or item.get("media_type") != MEDIA_TYPES.get(name):
            raise SupplyChainError("release manifest artifact identity is invalid")
        if not isinstance(item.get("sha256"), str) or not SHA256.fullmatch(item["sha256"]):
            raise SupplyChainError("release manifest artifact digest is invalid")
        if not isinstance(item.get("size"), int) or isinstance(item["size"], bool) or not 0 <= item["size"] <= MAX_RELEASE_FILE_BYTES:
            raise SupplyChainError("release manifest artifact size is invalid")
        names.append(name)
    if names != list(CORE_NAMES):
        raise SupplyChainError("release manifest artifacts are missing, duplicated, or out of order")
    return value


def create_provenance(manifest: dict[str, Any], *, workflow_identity: str,
                      invocation_id: str) -> dict[str, Any]:
    validate_release_manifest(manifest)
    expected_builder = (WORKFLOW_IDENTITY if manifest["creation_mode"] == "trusted-github-workflow"
                        else LOCAL_BUILDER_IDENTITY)
    if workflow_identity != expected_builder:
        raise SupplyChainError("builder identity does not match the release creation mode")
    if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,200}", invocation_id):
        raise SupplyChainError("invocation ID is invalid")
    source = manifest["source"]
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": item["name"], "digest": {"sha256": item["sha256"]}}
                    for item in manifest["artifacts"]],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/yakovkazinets/VibeSec/buildtypes/release-candidate/v1",
                "externalParameters": {"source": source, "version": manifest["version"]},
                "internalParameters": {"creation_mode": manifest["creation_mode"]},
                "resolvedDependencies": [
                    {"uri": f"pkg:generic/{name}@{version}"}
                    for name, version in manifest["tool_versions"].items()
                ],
            },
            "runDetails": {
                "builder": {"id": workflow_identity},
                "metadata": {"invocationId": invocation_id},
            },
        },
    }


def validate_provenance(value: Any, manifest: dict[str, Any]) -> dict[str, Any]:
    validate_release_manifest(manifest)
    if not isinstance(value, dict) or set(value) != {"_type", "subject", "predicateType", "predicate"}:
        raise SupplyChainError("provenance statement fields are invalid")
    if value.get("_type") != "https://in-toto.io/Statement/v1" or value.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise SupplyChainError("provenance statement type is invalid")
    expected_subject = [{"name": item["name"], "digest": {"sha256": item["sha256"]}}
                        for item in manifest["artifacts"]]
    if value.get("subject") != expected_subject:
        raise SupplyChainError("provenance subjects do not match release artifacts")
    predicate = value.get("predicate")
    if not isinstance(predicate, dict) or set(predicate) != {"buildDefinition", "runDetails"}:
        raise SupplyChainError("provenance predicate fields are invalid")
    definition = predicate.get("buildDefinition")
    expected_dependencies = [
        {"uri": f"pkg:generic/{name}@{version}"}
        for name, version in manifest["tool_versions"].items()
    ]
    if (not isinstance(definition, dict)
            or set(definition) != {"buildType", "externalParameters", "internalParameters", "resolvedDependencies"}
            or definition.get("buildType") != "https://github.com/yakovkazinets/VibeSec/buildtypes/release-candidate/v1"
            or definition.get("externalParameters") != {"source": manifest["source"], "version": manifest["version"]}
            or definition.get("internalParameters") != {"creation_mode": manifest["creation_mode"]}
            or definition.get("resolvedDependencies") != expected_dependencies):
        raise SupplyChainError("provenance build definition is invalid")
    run = predicate.get("runDetails")
    expected_builder = (WORKFLOW_IDENTITY if manifest["creation_mode"] == "trusted-github-workflow"
                        else LOCAL_BUILDER_IDENTITY)
    if (not isinstance(run, dict) or set(run) != {"builder", "metadata"}
            or run.get("builder") != {"id": expected_builder}
            or not isinstance(run.get("metadata"), dict)
            or set(run["metadata"]) != {"invocationId"}
            or not isinstance(run["metadata"]["invocationId"], str)
            or not re.fullmatch(r"[A-Za-z0-9._:/-]{1,200}", run["metadata"]["invocationId"])):
        raise SupplyChainError("provenance run details are invalid")
    return value


def checksum_bytes(directory: Path) -> bytes:
    return "".join(
        f"{_digest(_regular_file(directory / name))}  {name}\n" for name in CHECKSUM_NAMES
    ).encode("ascii")


def parse_checksums(data: bytes) -> dict[str, str]:
    if len(data) > 4096 or not data.endswith(b"\n"):
        raise SupplyChainError("checksum file is oversized or non-canonical")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SupplyChainError("checksum file must be ASCII") from exc
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if match is None or match.group(2) not in CHECKSUM_NAMES or match.group(2) in result:
            raise SupplyChainError("checksum entry is malformed, unknown, or duplicated")
        result[match.group(2)] = match.group(1)
    if list(result) != list(CHECKSUM_NAMES):
        raise SupplyChainError("checksum entries are missing or out of canonical order")
    return result


def _copy_regular(source: Path, destination: Path) -> None:
    data = _regular_file(source)
    destination.write_bytes(data)
    destination.chmod(0o644)


def prepare_release(directory: Path, *, bundle: Path, cyclonedx: Path, spdx: Path,
                    version: str, source_commit: str, tool_versions: dict[str, str],
                    creation_mode: str, invocation_id: str) -> dict[str, Any]:
    if directory.exists() or directory.is_symlink():
        raise SupplyChainError("output directory already exists")
    parent = directory.parent.resolve(strict=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{directory.name}.", dir=parent))
    try:
        for source, name in ((bundle, BUNDLE_NAME), (cyclonedx, CYCLONEDX_NAME), (spdx, SPDX_NAME)):
            _copy_regular(source, temporary / name)
        verified_bundle = verify_bundle(temporary / BUNDLE_NAME)
        if verified_bundle.version != version or verified_bundle.source_commit != source_commit:
            raise SupplyChainError("bundle version or source commit does not match release request")
        _load_strict_json(temporary / CYCLONEDX_NAME)
        _load_strict_json(temporary / SPDX_NAME)
        validate_cyclonedx(temporary / CYCLONEDX_NAME)
        validate_spdx(temporary / SPDX_NAME)
        manifest = create_release_manifest(
            directory=temporary, version=version, source_commit=source_commit,
            tool_versions=tool_versions, creation_mode=creation_mode,
        )
        provenance = create_provenance(
            manifest,
            workflow_identity=(WORKFLOW_IDENTITY if creation_mode == "trusted-github-workflow" else LOCAL_BUILDER_IDENTITY),
            invocation_id=invocation_id,
        )
        (temporary / PROVENANCE_NAME).write_bytes(canonical_json(provenance))
        (temporary / MANIFEST_NAME).write_bytes(canonical_json(manifest))
        (temporary / CHECKSUMS_NAME).write_bytes(checksum_bytes(temporary))
        os.rename(temporary, directory)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return manifest


def _load_canonical_json(path: Path, maximum: int = MAX_RELEASE_FILE_BYTES) -> dict[str, Any]:
    data = _regular_file(path, maximum)
    value = _load_strict_json(path, maximum)
    if canonical_json(value) != data:
        raise SupplyChainError(f"{path.name} is not canonical JSON")
    return value


def _load_strict_json(path: Path, maximum: int = MAX_RELEASE_FILE_BYTES) -> dict[str, Any]:
    data = _regular_file(path, maximum)
    try:
        value = loads_strict(data, maximum_bytes=maximum)
    except StrictJSONError as exc:
        raise SupplyChainError(f"{path.name} is invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise SupplyChainError(f"{path.name} must contain a JSON object")
    return value


def verify_release(directory: Path, *, require_signature: bool = False,
                   cosign: Path | None = None, certificate_identity: str = WORKFLOW_IDENTITY,
                   certificate_oidc_issuer: str = OIDC_ISSUER) -> VerifiedRelease:
    try:
        resolved = directory.resolve(strict=True)
    except OSError as exc:
        raise SupplyChainError("release directory is unavailable") from exc
    if directory.is_symlink() or not resolved.is_dir():
        raise SupplyChainError("release path must be a regular directory")
    names = sorted(path.name for path in resolved.iterdir())
    accepted = [sorted(SIGNED_NAMES)] if require_signature else [sorted(UNSIGNED_NAMES), sorted(SIGNED_NAMES)]
    if names not in accepted:
        raise SupplyChainError("release directory does not contain the exact reviewed artifact set")
    manifest_data = _regular_file(resolved / MANIFEST_NAME)
    manifest = validate_release_manifest(_load_canonical_json(resolved / MANIFEST_NAME))
    provenance = _load_canonical_json(resolved / PROVENANCE_NAME)
    validate_provenance(provenance, manifest)
    checksums_data = _regular_file(resolved / CHECKSUMS_NAME, 4096)
    checksums = parse_checksums(checksums_data)
    for name, expected_digest in checksums.items():
        if _digest(_regular_file(resolved / name)) != expected_digest:
            raise SupplyChainError(f"checksum mismatch: {name}")
    records = {item["name"]: item for item in manifest["artifacts"]}
    for name in CORE_NAMES:
        data = _regular_file(resolved / name)
        if records[name]["sha256"] != _digest(data) or records[name]["size"] != len(data):
            raise SupplyChainError(f"release manifest mismatch: {name}")
    bundle = verify_bundle(resolved / BUNDLE_NAME)
    if bundle.version != manifest["version"] or bundle.source_commit != manifest["source"]["commit"]:
        raise SupplyChainError("bundle identity does not match release manifest")
    _load_strict_json(resolved / CYCLONEDX_NAME)
    _load_strict_json(resolved / SPDX_NAME)
    validate_cyclonedx(resolved / CYCLONEDX_NAME)
    validate_spdx(resolved / SPDX_NAME)
    signature_verified = False
    if SIGNATURE_NAME in names:
        _load_strict_json(resolved / SIGNATURE_NAME, MAX_SIGNATURE_BYTES)
    if require_signature:
        if cosign is None or cosign.is_symlink() or not cosign.is_file():
            raise SupplyChainError("a trusted external Cosign executable is required")
        if certificate_identity != WORKFLOW_IDENTITY or certificate_oidc_issuer != OIDC_ISSUER:
            raise SupplyChainError("signature identity or issuer differs from reviewed policy")
        completed = subprocess.run(
            [str(cosign), "verify-blob", "--bundle", str(resolved / SIGNATURE_NAME),
             "--certificate-identity", certificate_identity,
             "--certificate-oidc-issuer", certificate_oidc_issuer,
             str(resolved / CHECKSUMS_NAME)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, timeout=120, check=False,
        )
        if completed.returncode != 0:
            raise SupplyChainError("keyless signature verification failed")
        signature_verified = True
    # Keep an explicit digest calculation for metadata consumers and to ensure
    # the canonical manifest used above is exactly the checked file.
    if checksums[MANIFEST_NAME] != _digest(manifest_data):
        raise SupplyChainError("release manifest checksum mismatch")
    return VerifiedRelease(resolved, manifest, provenance, checksums, signature_verified)
