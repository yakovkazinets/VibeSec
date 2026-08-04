"""Verified, platform-aware scanner installation and cache management."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from typing import Any
import urllib.error
import urllib.request

try:
    import extract_tool_archive as _tool_archive
except ModuleNotFoundError:
    from scripts import extract_tool_archive as _tool_archive

from .portable import PROFILE_TOOLS, SUPPORTED_PLATFORMS
from .strict_json import StrictJSONError, loads_strict

MAX_DOWNLOAD_BYTES = 600 * 1024 * 1024
MANIFEST_NAME = "toolchain.json"
MANIFEST_SCHEMA = 1
TOOL_METADATA_SCHEMA = 2
OFFICIAL_DOWNLOAD_HOST = "github.com"
PROFILE_STORAGE_ESTIMATES = {
    "minimal": "100-400 MB, plus scanner databases",
    "standard": "500 MB-1 GB, plus scanner databases and any Checkov image; may exceed 600 MB",
}
ProgressCallback = Callable[[str], None]


class ToolchainError(ValueError):
    """A managed toolchain could not be installed or verified."""


def _report(progress: ProgressCallback | None, message: str) -> None:
    if progress is not None:
        progress(message)


def _display_cache_directory(cache_home: Path) -> str:
    value = str(cache_home)
    if len(value) > 2048 or any(ord(character) < 0x20 or ord(character) == 0x7f for character in value):
        return "<configured cache directory omitted>"
    return value


def managed_toolchain_disclosure(
    *,
    profile: str,
    platform_name: str,
    cache_home: Path,
    cache_reused: bool,
    network_mode: str,
) -> tuple[str, ...]:
    """Return bounded, human-readable disclosure lines for a managed install."""
    if profile not in PROFILE_TOOLS or platform_name not in SUPPORTED_PLATFORMS:
        raise ToolchainError("managed platform or profile is unsupported")
    if network_mode not in {"online", "offline"}:
        raise ToolchainError("managed network mode is unsupported")
    tools = ", ".join(PROFILE_TOOLS[profile])
    cache_state = (
        "yes; the complete cache was verified and will be reused"
        if cache_reused
        else "no; the complete verified toolchain will be downloaded"
    )
    checkov = (
        "not part of Minimal"
        if profile == "minimal"
        else "applicable IaC scanning additionally requires trusted Docker and a separately downloaded Checkov image"
    )
    privacy = (
        "Trivy may download its official vulnerability database; scanners otherwise operate locally."
        if profile == "minimal"
        else (
            "Trivy may download its official vulnerability database; Standard online OSV may send "
            "package names, versions, ecosystems, and file hashes to OSV.dev or deps.dev; SBOMs "
            "may disclose internal package names and versions."
            if network_mode == "online"
            else (
                "Trivy may require a separately provisioned database; Standard offline OSV uses "
                "only the explicitly supplied validated local database; SBOMs may disclose internal "
                "package names and versions."
            )
        )
    )
    return (
        "Managed toolchain disclosure:",
        f"  Profile: {profile}",
        f"  Platform: {platform_name}",
        f"  Tools: {tools}",
        f"  Cache directory: {_display_cache_directory(cache_home)}",
        f"  Existing verified cache reused: {cache_state}",
        f"  Estimated download/cache storage: {PROFILE_STORAGE_ESTIMATES[profile]}",
        f"  Docker/Checkov: {checkov}",
        (
            "  Download hosts: reviewed GitHub release asset hosts; scanner-managed databases "
            "and services only as disclosed below."
        ),
        f"  Network/privacy: {privacy}",
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def default_cache_home(environment: dict[str, str] | None = None) -> Path:
    env = os.environ if environment is None else environment
    explicit = env.get("VIBESEC_CACHE_HOME")
    if explicit:
        return Path(explicit).expanduser().resolve()
    if os.name == "posix" and os.uname().sysname == "Darwin":
        return (Path.home() / "Library" / "Caches" / "vibesec").resolve()
    xdg = env.get("XDG_CACHE_HOME")
    return ((Path(xdg).expanduser() if xdg else Path.home() / ".cache") / "vibesec").resolve()


def repository_id(target: Path) -> str:
    resolved = target.resolve(strict=True)
    return hashlib.sha256(os.fsencode(resolved)).hexdigest()[:24]


def managed_results_dir(cache_home: Path, target: Path) -> Path:
    return cache_home / "results" / repository_id(target) / "latest"


def prepare_managed_results_dir(cache_home: Path, target: Path) -> Path:
    _ensure_private_directory(cache_home)
    current = cache_home
    for component in ("results", repository_id(target), "latest"):
        current = current / component
        _ensure_private_directory(current)
    return current.resolve(strict=True)


def tool_cache_dir(cache_home: Path, version: str, platform_name: str, profile: str) -> Path:
    return cache_home / "tools" / version / platform_name / profile


def _ensure_private_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        try:
            details = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise ToolchainError("managed cache directory is unavailable") from exc
        if path.is_symlink() or not stat.S_ISDIR(details.st_mode):
            raise ToolchainError("managed cache hierarchy contains an unsafe path")
        return
    if path.parent == path:
        raise ToolchainError("managed cache directory has no creatable parent")
    _ensure_private_directory(path.parent)
    try:
        path.mkdir(mode=0o700)
    except OSError as exc:
        raise ToolchainError("managed cache directory could not be created") from exc


def _prepare_cache_parent(cache_home: Path, version: str, platform_name: str) -> Path:
    _ensure_private_directory(cache_home)
    current = cache_home
    for component in ("tools", version, platform_name):
        current = current / component
        _ensure_private_directory(current)
    return current


def load_tool_metadata(path: Path) -> dict[str, Any]:
    try:
        payload = loads_strict(path.read_bytes(), maximum_bytes=512_000)
    except (OSError, StrictJSONError) as exc:
        raise ToolchainError(f"tool metadata is invalid: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != TOOL_METADATA_SCHEMA:
        raise ToolchainError("tool metadata schema is unsupported")
    platforms = payload.get("supported_platforms")
    tools = payload.get("tools")
    if platforms != sorted(SUPPORTED_PLATFORMS) or not isinstance(tools, dict):
        raise ToolchainError("tool metadata platform inventory is invalid")
    for name, tool in tools.items():
        if not isinstance(name, str) or not isinstance(tool, dict):
            raise ToolchainError("tool metadata entry is malformed")
        required = {"kind", "version", "license", "official_repository", "verification_date"}
        if not required <= set(tool):
            raise ToolchainError(f"tool metadata is incomplete for {name}")
        if tool["kind"] == "native":
            assets = tool.get("platforms")
            if (not isinstance(tool.get("executable"), str) or not isinstance(assets, dict)
                    or not set(assets) <= SUPPORTED_PLATFORMS):
                raise ToolchainError(f"native tool metadata is malformed for {name}")
            for platform_name, asset in assets.items():
                _validate_asset(name, platform_name, asset)
        elif tool["kind"] == "container":
            if not isinstance(tool.get("image"), str) or not _sha256(tool.get("digest"), prefixed=True):
                raise ToolchainError(f"container metadata is malformed for {name}")
        else:
            raise ToolchainError(f"unsupported tool kind for {name}")
    return payload


def _sha256(value: object, *, prefixed: bool = False) -> bool:
    if not isinstance(value, str):
        return False
    candidate = value.removeprefix("sha256:") if prefixed else value
    return len(candidate) == 64 and all(character in "0123456789abcdef" for character in candidate)


def _validate_asset(name: str, platform_name: str, asset: object) -> None:
    if not isinstance(asset, dict):
        raise ToolchainError(f"asset metadata is malformed for {name} on {platform_name}")
    required = {"asset_name", "url", "sha256", "archive_type", "executable_name"}
    if not required <= set(asset) or asset["archive_type"] not in {"binary", "tar.gz"}:
        raise ToolchainError(f"asset metadata is incomplete for {name} on {platform_name}")
    if not _sha256(asset["sha256"]):
        raise ToolchainError(f"asset digest is invalid for {name} on {platform_name}")
    url = asset["url"]
    expected = f"https://github.com/"
    if (not isinstance(url, str) or not url.startswith(expected)
            or "/releases/download/" not in url or not url.endswith("/" + asset["asset_name"])):
        raise ToolchainError(f"asset URL is not an exact official release URL for {name} on {platform_name}")
    signature_keys = {"signature_url", "certificate_url", "certificate_identity", "certificate_oidc_issuer"}
    present = signature_keys & set(asset)
    if present and present != signature_keys:
        raise ToolchainError(f"signature metadata is incomplete for {name} on {platform_name}")
    if present:
        if not all(isinstance(asset[key], str) and asset[key] for key in signature_keys):
            raise ToolchainError(f"signature metadata is invalid for {name} on {platform_name}")
        if not asset["signature_url"].startswith(expected) or not asset["certificate_url"].startswith(expected):
            raise ToolchainError(f"signature URLs are not official release URLs for {name} on {platform_name}")


def _download_https(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "VibeSec-Guardian/1.1"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            final_url = response.geturl()
            if not final_url.startswith("https://github.com/") and not final_url.startswith(
                "https://release-assets.githubusercontent.com/"
            ):
                raise ToolchainError("release download redirected outside the reviewed GitHub asset hosts")
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > MAX_DOWNLOAD_BYTES:
                raise ToolchainError("release asset exceeds the download size limit")
            with destination.open("xb") as stream:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise ToolchainError("release asset exceeds the download size limit")
                    stream.write(chunk)
    except (OSError, urllib.error.URLError, ValueError) as exc:
        destination.unlink(missing_ok=True)
        if isinstance(exc, ToolchainError):
            raise
        raise ToolchainError(f"official release download failed: {type(exc).__name__}") from exc


def _extract(asset_path: Path, asset: dict[str, Any], destination: Path) -> None:
    try:
        if asset["archive_type"] == "binary":
            shutil.copyfile(asset_path, destination, follow_symlinks=False)
        else:
            _tool_archive.extract_executable(
                asset_path, asset["executable_name"], destination,
            )
    except (OSError, ValueError) as exc:
        raise ToolchainError("release archive failed safe extraction") from exc
    destination.chmod(0o755)


def _atomic_json(path: Path, payload: object) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _verify_signature(
    cosign: Path, artifact: Path, signature: Path, certificate: Path, asset: dict[str, Any]
) -> None:
    completed = subprocess.run(
        [
            str(cosign), "verify-blob", "--certificate", str(certificate),
            "--signature", str(signature), "--certificate-identity",
            asset["certificate_identity"], "--certificate-oidc-issuer",
            asset["certificate_oidc_issuer"], str(artifact),
        ],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=120, check=False,
    )
    if completed.returncode != 0:
        raise ToolchainError("Opengrep release signature verification failed")


def _manifest_payload(
    version: str, platform_name: str, profile: str, records: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "schema_version": MANIFEST_SCHEMA,
        "development_version": version,
        "platform": platform_name,
        "profile": profile,
        "tools": sorted(records, key=lambda item: item["name"]),
    }


def validate_tool_cache(
    directory: Path, metadata: dict[str, Any], version: str, platform_name: str, profile: str
) -> Path:
    expected_names = set(PROFILE_TOOLS[profile])
    manifest_path = directory / MANIFEST_NAME
    bin_dir = directory / "bin"
    try:
        directory_details = directory.stat(follow_symlinks=False)
        bin_details = bin_dir.stat(follow_symlinks=False)
        manifest_details = manifest_path.stat(follow_symlinks=False)
        if (
            directory.is_symlink()
            or bin_dir.is_symlink()
            or manifest_path.is_symlink()
            or not stat.S_ISDIR(directory_details.st_mode)
            or not stat.S_ISDIR(bin_details.st_mode)
            or not stat.S_ISREG(manifest_details.st_mode)
        ):
            raise ToolchainError("managed tool cache directories are unsafe")
        payload = loads_strict(manifest_path.read_bytes(), maximum_bytes=256_000)
    except (OSError, StrictJSONError) as exc:
        raise ToolchainError("managed tool cache is missing, partial, or malformed") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != MANIFEST_SCHEMA
        or payload.get("development_version") != version
        or payload.get("platform") != platform_name
        or payload.get("profile") != profile
        or not isinstance(payload.get("tools"), list)
    ):
        raise ToolchainError("managed tool cache metadata does not match this scan")
    records = payload["tools"]
    record_fields = {
        "name", "version", "asset_name", "artifact_sha256", "executable_sha256",
    }
    if (
        len(records) != len(expected_names)
        or any(not isinstance(item, dict) or set(item) != record_fields for item in records)
        or {item["name"] for item in records} != expected_names
    ):
        raise ToolchainError("managed tool cache is incomplete")
    try:
        actual_names = set(path.name for path in bin_dir.iterdir())
    except OSError as exc:
        raise ToolchainError("managed tool cache executable inventory is unavailable") from exc
    if actual_names != expected_names:
        raise ToolchainError("managed tool cache contains missing or unexpected executables")
    for record in records:
        name = record["name"]
        configured = metadata["tools"].get(name)
        asset = configured.get("platforms", {}).get(platform_name) if isinstance(configured, dict) else None
        executable = bin_dir / name
        try:
            details = executable.stat(follow_symlinks=False)
        except OSError as exc:
            raise ToolchainError(f"managed tool cache is missing {name}") from exc
        if (
            executable.is_symlink()
            or not stat.S_ISREG(details.st_mode)
            or not os.access(executable, os.X_OK)
            or not isinstance(asset, dict)
            or record.get("version") != configured.get("version")
            or record.get("artifact_sha256") != asset.get("sha256")
            or record.get("executable_sha256") != sha256_file(executable)
        ):
            raise ToolchainError(f"managed tool cache verification failed for {name}")
    return bin_dir


def inspect_profile_cache(
    *,
    metadata_path: Path,
    cache_home: Path,
    version: str,
    platform_name: str,
    profile: str,
) -> bool:
    """Return whether the exact complete cache exists and validates."""
    if platform_name not in SUPPORTED_PLATFORMS or profile not in PROFILE_TOOLS:
        raise ToolchainError("managed platform or profile is unsupported")
    metadata = load_tool_metadata(metadata_path)
    destination = tool_cache_dir(cache_home, version, platform_name, profile)
    if not destination.exists() and not destination.is_symlink():
        return False
    validate_tool_cache(destination, metadata, version, platform_name, profile)
    return True


def install_profile_tools(
    *,
    metadata_path: Path,
    cache_home: Path,
    version: str,
    platform_name: str,
    profile: str,
    download: Callable[[str, Path], None] = _download_https,
    progress: ProgressCallback | None = None,
) -> tuple[Path, bool]:
    if platform_name not in SUPPORTED_PLATFORMS or profile not in PROFILE_TOOLS:
        raise ToolchainError("managed platform or profile is unsupported")
    metadata = load_tool_metadata(metadata_path)
    destination = tool_cache_dir(cache_home, version, platform_name, profile)
    if destination.exists() or destination.is_symlink():
        _report(progress, f"Revalidating cached {profile} toolchain")
        cached = validate_tool_cache(destination, metadata, version, platform_name, profile)
        _report(progress, f"Reusing verified {profile} toolchain cache")
        _report(progress, f"Completed {profile} toolchain verification")
        return cached, True
    for name in PROFILE_TOOLS[profile]:
        tool = metadata["tools"].get(name)
        if not isinstance(tool, dict) or platform_name not in tool.get("platforms", {}):
            raise ToolchainError(f"{name} has no verified asset for {platform_name}")
    _prepare_cache_parent(cache_home, version, platform_name)
    staging_root = Path(tempfile.mkdtemp(prefix=f".{profile}.", dir=destination.parent))
    try:
        staging_root.chmod(0o700)
        bin_dir = staging_root / "bin"
        downloads = staging_root / "downloads"
        bin_dir.mkdir(mode=0o700)
        downloads.mkdir(mode=0o700)
        records: list[dict[str, Any]] = []
        total = len(PROFILE_TOOLS[profile])
        for index, name in enumerate(PROFILE_TOOLS[profile], start=1):
            tool = metadata["tools"][name]
            asset = tool["platforms"][platform_name]
            artifact = downloads / asset["asset_name"]
            _report(progress, f"[{index}/{total}] Downloading {name}")
            download(asset["url"], artifact)
            _report(progress, f"[{index}/{total}] Verifying {name} checksum")
            actual = sha256_file(artifact)
            if actual != asset["sha256"]:
                raise ToolchainError(f"release checksum mismatch for {name}")
            executable = bin_dir / name
            _report(progress, f"[{index}/{total}] Installing {name}")
            _extract(artifact, asset, executable)
            if "signature_url" in asset:
                signature = downloads / f"{name}.sig"
                certificate = downloads / f"{name}.cert"
                _report(progress, f"[{index}/{total}] Downloading {name} signature evidence")
                download(asset["signature_url"], signature)
                download(asset["certificate_url"], certificate)
                cosign = bin_dir / "cosign"
                if not cosign.is_file():
                    raise ToolchainError("signature verification dependency is unavailable")
                _report(progress, f"[{index}/{total}] Verifying {name} signature")
                _verify_signature(cosign, artifact, signature, certificate, asset)
            records.append({
                "name": name,
                "version": tool["version"],
                "asset_name": asset["asset_name"],
                "artifact_sha256": asset["sha256"],
                "executable_sha256": sha256_file(executable),
            })
            _report(progress, f"[{index}/{total}] Installed {name}")
        _atomic_json(
            staging_root / MANIFEST_NAME,
            _manifest_payload(version, platform_name, profile, records),
        )
        shutil.rmtree(downloads)
        os.replace(staging_root, destination)
        _report(progress, f"Verifying complete {profile} toolchain")
        installed = validate_tool_cache(destination, metadata, version, platform_name, profile)
        _report(progress, f"Completed {profile} toolchain installation")
        return installed, False
    except BaseException:
        shutil.rmtree(staging_root, ignore_errors=True)
        raise


def validate_profile_tools(
    *, metadata_path: Path, cache_home: Path, version: str, platform_name: str, profile: str
) -> Path:
    metadata = load_tool_metadata(metadata_path)
    return validate_tool_cache(
        tool_cache_dir(cache_home, version, platform_name, profile),
        metadata, version, platform_name, profile,
    )
