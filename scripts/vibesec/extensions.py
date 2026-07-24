"""Strict local extension manifests, lifecycle inventory, and isolated adapters."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any

from .model import RESULT_TYPES, SEVERITIES
from .paths import UnsafePath, safe_posix_path, validate_unique_paths
from .portable import SUPPORTED_PLATFORMS
from .results import REQUIRED_RESULT_FIELDS, ResultDocumentError, _validate_document
from .strict_json import StrictJSONError, canonical_json, loads_strict

MANIFEST_NAME = "vibesec-extension.json"
INVENTORY_PATH = ".vibesec/extensions.json"
STORE_PATH = ".vibesec/extensions"
MANIFEST_FIELDS = {
    "schema_version", "extension_id", "version", "kind", "entrypoint", "capabilities",
    "supported_profiles", "supported_platforms", "execution_mode", "network", "artifacts", "permissions",
}
PERMISSION_FIELDS = {"repository_read", "repository_write", "network", "docker", "secrets", "host_process"}
EXTENSION_ID = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
CAPABILITY = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
MAX_MANIFEST_BYTES = 128_000
MAX_FILES = 128
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 5_000_000
MAX_ADAPTER_OUTPUT = 64 * 1024
MAX_DIAGNOSTIC = 4_096
BEARER_VALUE = re.compile(r"(?i)(authorization\s*:\s*bearer\s+|bearer\s+)[^\s,;]+")
CORE_CAPABILITIES = {
    "source_code", "dependencies", "infrastructure_as_code", "container_image", "dast_target",
    "api", "api_security_target", "authenticated_security_testing",
}


class ExtensionError(ValueError):
    """An extension violates a structural, trust, or lifecycle boundary."""


@dataclass(frozen=True)
class ExtensionSource:
    root: Path
    manifest: dict[str, Any]
    files: list[dict[str, Any]]
    content_digest: str


def validate_manifest(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != MANIFEST_FIELDS or payload.get("schema_version") != 1:
        raise ExtensionError("extension manifest fields or schema are invalid")
    extension_id = payload["extension_id"]
    if not isinstance(extension_id, str) or not 3 <= len(extension_id) <= 100 or not EXTENSION_ID.fullmatch(extension_id):
        raise ExtensionError("extension_id is invalid")
    if not isinstance(payload["version"], str) or not SEMVER.fullmatch(payload["version"]):
        raise ExtensionError("extension version must be a stable semantic version")
    if payload["kind"] != "scanner":
        raise ExtensionError("only the scanner extension kind is supported in v1")
    try:
        entrypoint = safe_posix_path(payload["entrypoint"])
    except UnsafePath as exc:
        raise ExtensionError(f"extension entrypoint is unsafe: {exc}") from exc
    if not entrypoint.endswith(".py"):
        raise ExtensionError("extension entrypoint must be a Python file")
    capabilities = payload["capabilities"]
    prefix = f"extension.{extension_id}."
    if (not isinstance(capabilities, list) or not 1 <= len(capabilities) <= 32
            or capabilities != sorted(set(capabilities))):
        raise ExtensionError("extension capabilities must be a sorted unique bounded list")
    for value in capabilities:
        suffix = value[len(prefix):] if isinstance(value, str) and value.startswith(prefix) else ""
        if not suffix or not CAPABILITY.fullmatch(suffix) or value in CORE_CAPABILITIES:
            raise ExtensionError("extension capability does not use its required namespace")
    profiles = payload["supported_profiles"]
    platforms = payload["supported_platforms"]
    if not isinstance(profiles, list) or profiles != sorted(set(profiles)) or not profiles or not set(profiles) <= {"minimal", "standard"}:
        raise ExtensionError("supported profiles are invalid")
    if not isinstance(platforms, list) or platforms != sorted(set(platforms)) or not platforms or not set(platforms) <= SUPPORTED_PLATFORMS:
        raise ExtensionError("supported platforms are invalid")
    if payload["execution_mode"] != "native" or payload["network"] != "none":
        raise ExtensionError("v1 extensions must use native execution with no network")
    artifacts = payload["artifacts"]
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 16 or artifacts != sorted(set(artifacts)):
        raise ExtensionError("declared artifacts must be a sorted unique bounded list")
    try:
        validate_unique_paths(artifacts)
    except UnsafePath as exc:
        raise ExtensionError(f"declared artifact path is unsafe: {exc}") from exc
    if "normalized.json" not in artifacts:
        raise ExtensionError("scanner extensions must declare normalized.json")
    permissions = payload["permissions"]
    expected_permissions = {
        "repository_read": True, "repository_write": False, "network": False,
        "docker": False, "secrets": False, "host_process": True,
    }
    if not isinstance(permissions, dict) or set(permissions) != PERMISSION_FIELDS or permissions != expected_permissions:
        raise ExtensionError("extension requests an unsupported permission combination")
    return payload


def parse_manifest(data: bytes) -> dict[str, Any]:
    try:
        payload = loads_strict(data, maximum_bytes=MAX_MANIFEST_BYTES)
    except StrictJSONError as exc:
        raise ExtensionError(f"extension manifest JSON is invalid: {exc}") from exc
    return validate_manifest(payload)


def _source_root(raw: Path) -> Path:
    if raw.is_symlink():
        raise ExtensionError("extension source root must not be a symlink")
    try:
        root = raw.resolve(strict=True)
    except OSError as exc:
        raise ExtensionError(f"extension source is unavailable: {exc}") from exc
    if not root.is_dir():
        raise ExtensionError("extension source must be a directory")
    return root


def collect_source(raw: Path) -> ExtensionSource:
    root = _source_root(raw)
    paths: list[Path] = []
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        for name in sorted([*names, *files]):
            candidate = base / name
            if candidate.is_symlink():
                raise ExtensionError(f"extension source contains a symlink: {candidate.relative_to(root)}")
            if name in {".git", "__pycache__"}:
                raise ExtensionError(f"extension source contains prohibited development content: {candidate.relative_to(root)}")
        names[:] = sorted(names)
        for name in sorted(files):
            candidate = base / name
            relative = candidate.relative_to(root).as_posix()
            try:
                safe_posix_path(relative)
                details = candidate.stat(follow_symlinks=False)
            except (OSError, UnsafePath) as exc:
                raise ExtensionError(f"extension source path is invalid: {relative}") from exc
            if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_FILE_BYTES:
                raise ExtensionError(f"extension source file is unsafe or oversized: {relative}")
            paths.append(candidate)
    if not paths or len(paths) > MAX_FILES:
        raise ExtensionError("extension source file count is invalid")
    total = sum(path.stat(follow_symlinks=False).st_size for path in paths)
    if total > MAX_TOTAL_BYTES:
        raise ExtensionError("extension source exceeds total size limit")
    relative_paths = [path.relative_to(root).as_posix() for path in paths]
    try:
        validate_unique_paths(relative_paths)
    except UnsafePath as exc:
        raise ExtensionError(f"extension source paths are ambiguous: {exc}") from exc
    manifest_path = root / MANIFEST_NAME
    if manifest_path not in paths:
        raise ExtensionError(f"extension source is missing {MANIFEST_NAME}")
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest = parse_manifest(manifest_bytes)
    except OSError as exc:
        raise ExtensionError("extension manifest cannot be read") from exc
    entrypoint = root / manifest["entrypoint"]
    if entrypoint not in paths:
        raise ExtensionError("declared extension entrypoint is missing or unsafe")
    records: list[dict[str, Any]] = []
    for path in sorted(paths):
        data = path.read_bytes()
        records.append({
            "path": path.relative_to(root).as_posix(), "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data), "mode": 0o755 if path == entrypoint else 0o644,
        })
    digest = hashlib.sha256(canonical_json(records)).hexdigest()
    return ExtensionSource(root, manifest, records, digest)


def _empty_inventory() -> dict[str, Any]:
    return {"schema_version": 1, "extensions": []}


def validate_inventory(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "extensions"} or payload.get("schema_version") != 1:
        raise ExtensionError("extension inventory fields or schema are invalid")
    extensions = payload["extensions"]
    if not isinstance(extensions, list) or len(extensions) > 128:
        raise ExtensionError("extension inventory list is invalid")
    ids: set[str] = set()
    for record in extensions:
        required = {"extension_id", "version", "manifest_sha256", "content_sha256", "install_source", "installed_files", "enabled", "granted_permissions", "capabilities", "signature"}
        if not isinstance(record, dict) or set(record) != required:
            raise ExtensionError("extension inventory record is malformed")
        if record["extension_id"] in ids:
            raise ExtensionError("extension inventory contains a duplicate ID")
        ids.add(record["extension_id"])
        if (not isinstance(record["extension_id"], str) or not EXTENSION_ID.fullmatch(record["extension_id"])
                or not isinstance(record["version"], str) or not SEMVER.fullmatch(record["version"])
                or not isinstance(record["manifest_sha256"], str) or not HASH.fullmatch(record["manifest_sha256"])
                or not isinstance(record["content_sha256"], str) or not HASH.fullmatch(record["content_sha256"])
                or not isinstance(record["install_source"], str) or not record["install_source"] or len(record["install_source"]) > 1000
                or not isinstance(record["enabled"], bool) or record["signature"] is not None):
            raise ExtensionError("extension inventory identity is invalid")
        if record["granted_permissions"] != {"repository_read": True, "repository_write": False, "network": False, "docker": False, "secrets": False, "host_process": True}:
            raise ExtensionError("extension inventory contains unsafe permissions")
        files = record["installed_files"]
        if not isinstance(files, list) or not files or len(files) > MAX_FILES:
            raise ExtensionError("extension inventory file list is invalid")
        paths: list[str] = []
        for item in files:
            if (not isinstance(item, dict) or set(item) != {"path", "sha256", "size", "mode"}
                    or not isinstance(item["sha256"], str) or not HASH.fullmatch(item["sha256"])
                    or not isinstance(item["size"], int) or isinstance(item["size"], bool) or not 0 <= item["size"] <= MAX_FILE_BYTES
                    or item["mode"] not in {0o644, 0o755}):
                raise ExtensionError("extension inventory file record is invalid")
            paths.append(safe_posix_path(item["path"]))
        validate_unique_paths(paths)
        if paths != sorted(paths):
            raise ExtensionError("extension inventory files are not sorted")
        capabilities = record["capabilities"]
        prefix = f"extension.{record['extension_id']}."
        if not isinstance(capabilities, list) or capabilities != sorted(set(capabilities)) or not capabilities or any(not isinstance(value, str) or not value.startswith(prefix) for value in capabilities):
            raise ExtensionError("extension inventory capability registration is invalid")
    if [item["extension_id"] for item in extensions] != sorted(ids):
        raise ExtensionError("extension inventory is not sorted")
    return payload


def load_inventory(target: Path) -> dict[str, Any]:
    path = target / INVENTORY_PATH
    if not path.exists():
        return _empty_inventory()
    if path.is_symlink() or not path.is_file():
        raise ExtensionError("extension inventory is not a regular file")
    try:
        return validate_inventory(loads_strict(path.read_bytes(), maximum_bytes=1_000_000))
    except (OSError, StrictJSONError, UnsafePath) as exc:
        raise ExtensionError(f"extension inventory is invalid: {exc}") from exc


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _record(source: ExtensionSource) -> dict[str, Any]:
    return {
        "extension_id": source.manifest["extension_id"], "version": source.manifest["version"],
        "manifest_sha256": hashlib.sha256((source.root / MANIFEST_NAME).read_bytes()).hexdigest(),
        "content_sha256": source.content_digest, "install_source": str(source.root),
        "installed_files": source.files, "enabled": True,
        "signature": None,
        "granted_permissions": source.manifest["permissions"], "capabilities": source.manifest["capabilities"],
    }


def install_extension(target: Path, source_path: Path, *, write: bool) -> dict[str, Any]:
    target = target.resolve(strict=True)
    if not target.is_dir() or target.is_symlink():
        raise ExtensionError("extension target must be a regular directory")
    source = collect_source(source_path)
    inventory = load_inventory(target)
    extension_id = source.manifest["extension_id"]
    if any(item["extension_id"] == extension_id for item in inventory["extensions"]):
        raise ExtensionError(f"extension is already installed and will not be overwritten: {extension_id}")
    destination = target / STORE_PATH / extension_id / source.manifest["version"]
    if destination.exists() or destination.is_symlink():
        raise ExtensionError("extension destination already exists and will not be overwritten")
    result = {"action": "install", "write": write, "extension": _record(source), "destination": destination.relative_to(target).as_posix()}
    if not write:
        return result
    store = target / STORE_PATH
    if store.is_symlink() or target.joinpath(".vibesec").is_symlink():
        raise ExtensionError("extension storage traverses a symlink")
    store.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{extension_id}.", dir=store))
    published = False
    try:
        for record in source.files:
            output = temporary / record["path"]
            output.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            descriptor = os.open(output, flags, record["mode"])
            with os.fdopen(descriptor, "wb") as stream:
                stream.write((source.root / record["path"]).read_bytes())
            output.chmod(record["mode"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(temporary, destination)
        published = True
        updated = {"schema_version": 1, "extensions": sorted([*inventory["extensions"], _record(source)], key=lambda item: item["extension_id"])}
        validate_inventory(updated)
        _atomic_write(target / INVENTORY_PATH, canonical_json(updated))
    except OSError as exc:
        if published:
            shutil.rmtree(destination, ignore_errors=True)
        raise ExtensionError(f"extension installation failed atomically: {type(exc).__name__}") from exc
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
    return result


def list_extensions(target: Path) -> list[dict[str, Any]]:
    return load_inventory(target.resolve(strict=True))["extensions"]


def describe_extension(target: Path, extension_id: str) -> dict[str, Any]:
    for record in list_extensions(target):
        if record["extension_id"] == extension_id:
            return record
    raise ExtensionError(f"extension is not installed: {extension_id}")


def verify_extensions(target: Path) -> dict[str, Any]:
    target = target.resolve(strict=True)
    inventory = load_inventory(target)
    errors: list[str] = []
    verified: list[str] = []
    for record in inventory["extensions"]:
        extension_id = record["extension_id"]
        root = target / STORE_PATH / extension_id / record["version"]
        try:
            if root.is_symlink() or not root.is_dir():
                raise ExtensionError("installed extension directory is missing or unsafe")
            observed: list[dict[str, Any]] = []
            for expected in record["installed_files"]:
                path = root / expected["path"]
                details = path.stat(follow_symlinks=False)
                if path.is_symlink() or not stat.S_ISREG(details.st_mode):
                    raise ExtensionError(f"installed file is missing or unsafe: {expected['path']}")
                data = path.read_bytes()
                current = {"path": expected["path"], "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "mode": stat.S_IMODE(details.st_mode) & 0o777}
                observed.append(current)
                if current != expected:
                    raise ExtensionError(f"installed file was modified: {expected['path']}")
            actual_paths = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
            if actual_paths != [item["path"] for item in record["installed_files"]]:
                raise ExtensionError("installed extension contains missing or untracked files")
            if hashlib.sha256(canonical_json(observed)).hexdigest() != record["content_sha256"]:
                raise ExtensionError("installed extension content digest is inconsistent")
            manifest = parse_manifest((root / MANIFEST_NAME).read_bytes())
            if hashlib.sha256((root / MANIFEST_NAME).read_bytes()).hexdigest() != record["manifest_sha256"]:
                raise ExtensionError("installed manifest digest is inconsistent")
            if manifest["extension_id"] != extension_id or manifest["version"] != record["version"] or manifest["capabilities"] != record["capabilities"] or manifest["permissions"] != record["granted_permissions"]:
                raise ExtensionError("installed manifest differs from registered identity or grants")
            verified.append(extension_id)
        except (OSError, ExtensionError, ResultDocumentError) as exc:
            errors.append(f"{extension_id}: {exc}")
    return {"status": "valid" if not errors else "invalid", "verified": verified, "errors": errors, "extensions": inventory["extensions"]}


def set_enabled(target: Path, extension_id: str, *, enabled: bool, write: bool) -> dict[str, Any]:
    target = target.resolve(strict=True)
    inventory = load_inventory(target)
    found = False
    updated_records = []
    for record in inventory["extensions"]:
        item = dict(record)
        if item["extension_id"] == extension_id:
            item["enabled"] = enabled
            found = True
        updated_records.append(item)
    if not found:
        raise ExtensionError(f"extension is not installed: {extension_id}")
    result = {"action": "enable" if enabled else "disable", "write": write, "extension_id": extension_id}
    if write:
        updated = {"schema_version": 1, "extensions": updated_records}
        validate_inventory(updated)
        _atomic_write(target / INVENTORY_PATH, canonical_json(updated))
    return result


def remove_extension(target: Path, extension_id: str, *, write: bool) -> dict[str, Any]:
    target = target.resolve(strict=True)
    inventory = load_inventory(target)
    matching = [item for item in inventory["extensions"] if item["extension_id"] == extension_id]
    if not matching:
        raise ExtensionError(f"extension is not installed: {extension_id}")
    record = matching[0]
    root = target / STORE_PATH / extension_id / record["version"]
    result = {"action": "remove", "write": write, "extension_id": extension_id, "version": record["version"]}
    if not write:
        return result
    if root.is_symlink() or not root.is_dir():
        raise ExtensionError("installed extension directory is missing or unsafe")
    tombstone = root.parent / f".{record['version']}.remove"
    if tombstone.exists():
        raise ExtensionError("extension removal staging path already exists")
    os.replace(root, tombstone)
    try:
        updated = {"schema_version": 1, "extensions": [item for item in inventory["extensions"] if item["extension_id"] != extension_id]}
        _atomic_write(target / INVENTORY_PATH, canonical_json(updated))
    except OSError:
        os.replace(tombstone, root)
        raise
    shutil.rmtree(tombstone)
    try:
        root.parent.rmdir()
    except OSError:
        pass
    return result


def plan_extension_upgrade(target: Path, source_path: Path) -> dict[str, Any]:
    source = collect_source(source_path)
    installed = describe_extension(target, source.manifest["extension_id"])
    changed = source.content_digest != installed["content_sha256"] or source.manifest["version"] != installed["version"]
    return {
        "action": "upgrade-plan", "extension_id": installed["extension_id"],
        "installed_version": installed["version"], "candidate_version": source.manifest["version"],
        "content_changed": source.content_digest != installed["content_sha256"],
        "status": "review_required" if changed else "no_changes", "automatic_apply": False,
    }


def _adapter_failure(code: int, diagnostic: str) -> dict[str, Any]:
    return {"schema_version": 1, "exit_code": code, "coverage": "tool_error", "normalized_findings_path": None, "artifacts": [], "diagnostics": [_redact(diagnostic)]}


def _redact(value: str) -> str:
    bounded = value.encode("utf-8", errors="replace")[:MAX_DIAGNOSTIC].decode("utf-8", errors="replace")
    return BEARER_VALUE.sub(lambda match: match.group(1) + "[REDACTED]", bounded)


def _validate_adapter_output(payload: Any, process_code: int, manifest: dict[str, Any]) -> dict[str, Any]:
    fields = {"schema_version", "exit_code", "coverage", "normalized_findings_path", "artifacts", "diagnostics"}
    if not isinstance(payload, dict) or set(payload) != fields or payload.get("schema_version") != 1:
        raise ExtensionError("adapter response fields or schema are invalid")
    if payload["exit_code"] != process_code or process_code not in {0, 1, 2, 3}:
        raise ExtensionError("adapter response did not preserve the exact process exit code")
    if payload["coverage"] not in {"ran", "not_applicable", "not_configured", "tool_error"}:
        raise ExtensionError("adapter coverage state is invalid")
    if process_code in {2, 3} and payload["coverage"] != "tool_error":
        raise ExtensionError("adapter failure cannot be represented as clean coverage")
    if process_code in {0, 1} and payload["coverage"] == "tool_error":
        raise ExtensionError("adapter tool_error must use a failure exit code")
    path = payload["normalized_findings_path"]
    if path is not None and path != "normalized.json":
        raise ExtensionError("adapter normalized findings path is invalid")
    artifacts = payload["artifacts"]
    if not isinstance(artifacts, list) or artifacts != sorted(set(artifacts)) or not set(artifacts) <= set(manifest["artifacts"]):
        raise ExtensionError("adapter returned undeclared or ambiguous artifacts")
    diagnostics = payload["diagnostics"]
    if not isinstance(diagnostics, list) or len(diagnostics) > 32 or any(not isinstance(item, str) or len(item.encode("utf-8")) > MAX_DIAGNOSTIC for item in diagnostics):
        raise ExtensionError("adapter diagnostics are invalid or unbounded")
    return payload


def execute_adapter(target: Path, extension_id: str, *, repository: Path, results: Path,
                    profile: str, current_platform: str, timeout_seconds: int = 300) -> dict[str, Any]:
    verification = verify_extensions(target)
    if verification["status"] != "valid":
        raise ExtensionError("extension verification failed before execution: " + "; ".join(verification["errors"]))
    record = describe_extension(target, extension_id)
    if not record["enabled"]:
        raise ExtensionError("extension is disabled")
    root = target.resolve(strict=True) / STORE_PATH / extension_id / record["version"]
    manifest = parse_manifest((root / MANIFEST_NAME).read_bytes())
    if profile not in manifest["supported_profiles"] or current_platform not in manifest["supported_platforms"]:
        raise ExtensionError("extension does not support the requested profile or platform")
    repository = repository.resolve(strict=True)
    if repository.is_symlink() or not repository.is_dir():
        raise ExtensionError("adapter repository must be a regular directory")
    results = results.resolve()
    if results.exists() or results.is_symlink():
        raise ExtensionError("adapter results destination must not already exist")
    results.parent.mkdir(parents=True, exist_ok=True)
    request = {
        "schema_version": 1, "repository_root": str(repository), "results_dir": "RESULTS_DIR",
        "profile": profile, "capabilities": record["capabilities"], "execution_mode": "native",
    }
    with tempfile.TemporaryDirectory(prefix="vibesec-extension-") as temporary_name:
        temporary = Path(temporary_name)
        private_results = temporary / "results"
        private_results.mkdir(mode=0o700)
        request["results_dir"] = str(private_results)
        environment = {"PATH": os.defpath, "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(temporary), "LC_ALL": "C.UTF-8"}
        try:
            completed = subprocess.run(
                [sys.executable, "-I", str(root / manifest["entrypoint"])], cwd=root,
                input=canonical_json(request), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment, timeout=timeout_seconds, check=False,
            )
        except subprocess.TimeoutExpired:
            return _adapter_failure(2, "extension adapter exceeded its bounded runtime")
        stderr = completed.stderr[:MAX_DIAGNOSTIC].decode("utf-8", errors="replace")
        if len(completed.stdout) > MAX_ADAPTER_OUTPUT or len(completed.stderr) > MAX_ADAPTER_OUTPUT:
            return _adapter_failure(2, "extension adapter output exceeded its bounded limit")
        try:
            response = _validate_adapter_output(loads_strict(completed.stdout, maximum_bytes=MAX_ADAPTER_OUTPUT), completed.returncode, manifest)
        except (StrictJSONError, ExtensionError) as exc:
            detail = stderr or str(exc)
            return _adapter_failure(2, detail)
        if response["coverage"] == "tool_error":
            response["diagnostics"] = [_redact(item) for item in [*(response["diagnostics"]), *([stderr] if stderr else [])][:32]]
            return response
        for relative in response["artifacts"]:
            source = private_results / safe_posix_path(relative)
            if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_FILE_BYTES:
                raise ExtensionError(f"adapter artifact is missing, unsafe, or oversized: {relative}")
        normalized = private_results / "normalized.json"
        try:
            normalized_bytes = normalized.read_bytes()
            if BEARER_VALUE.search(normalized_bytes.decode("utf-8", errors="replace")):
                raise ExtensionError("adapter normalized findings contain bearer-shaped material")
            document = _validate_document(loads_strict(normalized_bytes, maximum_bytes=MAX_FILE_BYTES))
        except (OSError, StrictJSONError, ResultDocumentError) as exc:
            raise ExtensionError(f"adapter normalized findings are invalid: {exc}") from exc
        if len(document["results"]) > 1_000:
            raise ExtensionError("adapter normalized finding count exceeds its bound")
        for item in document["results"]:
            try:
                if (set(item) != REQUIRED_RESULT_FIELDS or item["tool"] != extension_id
                        or item["result_type"] not in RESULT_TYPES or item["severity"] not in SEVERITIES
                        or item["confidence"] not in {"confirmed", "possible", "unknown"}
                        or not isinstance(item["description"], str) or len(item["description"]) > 500
                        or not isinstance(item["fingerprint"], str) or not HASH.fullmatch(item["fingerprint"])
                        or item["line"] is not None and (not isinstance(item["line"], int) or isinstance(item["line"], bool) or item["line"] < 1)
                        or item["file"] and safe_posix_path(item["file"]) != item["file"]):
                    raise ExtensionError("adapter normalized finding violates the strict v1 schema")
            except UnsafePath as exc:
                raise ExtensionError("adapter normalized finding contains an unsafe path") from exc
        staging = Path(tempfile.mkdtemp(prefix=f".{results.name}.", dir=results.parent))
        try:
            for relative in response["artifacts"]:
                destination = staging / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((private_results / relative).read_bytes())
            os.replace(staging, results)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        return response
