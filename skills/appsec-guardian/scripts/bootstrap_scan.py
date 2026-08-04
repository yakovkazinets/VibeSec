#!/usr/bin/env python3
"""Acquire a pinned VibeSec Guardian runtime and execute a managed local scan."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable
import urllib.error
import urllib.request
import zipfile

SKILL_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_METADATA = SKILL_ROOT / "runtime.json"
BUNDLE_MANIFEST = "vibesec-bundle-manifest.json"
MAX_BUNDLE_BYTES = 25_000_000
MAX_ENTRIES = 256
MAX_FILE_BYTES = 5_000_000
MAX_TOTAL_BYTES = 25_000_000
MAX_COMPRESSION_RATIO = 200


class BootstrapError(ValueError):
    """The skill runtime could not be verified or executed safely."""


def _progress(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _cache_home() -> Path:
    if value := os.getenv("VIBESEC_CACHE_HOME"):
        return Path(value).expanduser().resolve()
    if sys.platform == "darwin":
        return (Path.home() / "Library" / "Caches" / "vibesec").resolve()
    return (Path(os.getenv("XDG_CACHE_HOME", Path.home() / ".cache")).expanduser() / "vibesec").resolve()


def _ensure_cache_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        try:
            details = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise BootstrapError("runtime cache directory is unavailable") from exc
        if path.is_symlink() or not stat.S_ISDIR(details.st_mode):
            raise BootstrapError("runtime cache hierarchy contains an unsafe path")
        return
    if path.parent == path:
        raise BootstrapError("runtime cache directory has no creatable parent")
    _ensure_cache_directory(path.parent)
    try:
        path.mkdir(mode=0o700)
    except OSError as exc:
        raise BootstrapError("runtime cache directory could not be created") from exc


def _load_metadata() -> dict[str, Any]:
    try:
        payload = json.loads(RUNTIME_METADATA.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BootstrapError("trusted skill runtime metadata is malformed") from exc
    required = {
        "schema_version", "release_version", "development_version", "bundle_url",
        "bundle_sha256", "bundle_name",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != required
        or payload["schema_version"] != 1
        or payload["release_version"] != "1.1.0"
        or payload["development_version"] != "1.1.0-dev"
        or payload["bundle_name"] != "vibesec-consumer-bundle.zip"
        or payload["bundle_url"]
        != "https://github.com/yakovkazinets/VibeSec/releases/download/v1.1.0/vibesec-consumer-bundle.zip"
        or not _is_sha256(payload["bundle_sha256"])
    ):
        raise BootstrapError("trusted skill runtime metadata does not match the reviewed v1.1.0 release")
    return payload


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _download(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "VibeSec-Guardian-Skill/1.1"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            final_url = response.geturl()
            if not (
                final_url.startswith("https://github.com/")
                or final_url.startswith("https://release-assets.githubusercontent.com/")
            ):
                raise BootstrapError("runtime download redirected outside reviewed GitHub asset hosts")
            with destination.open("xb") as stream:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_BUNDLE_BYTES:
                        raise BootstrapError("runtime bundle exceeds its size limit")
                    stream.write(chunk)
    except (OSError, urllib.error.URLError) as exc:
        destination.unlink(missing_ok=True)
        raise BootstrapError(f"runtime download failed: {type(exc).__name__}") from exc


def _safe_name(value: str) -> str:
    if "\\" in value or "\x00" in value:
        raise BootstrapError("runtime bundle contains a non-canonical path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise BootstrapError("runtime bundle contains an unsafe path")
    return value


def _verified_entries(bundle: Path, expected_version: str) -> tuple[dict[str, bytes], dict[str, int]]:
    if bundle.is_symlink() or not bundle.is_file() or bundle.stat().st_size > MAX_BUNDLE_BYTES:
        raise BootstrapError("runtime bundle is missing, linked, or oversized")
    try:
        with zipfile.ZipFile(bundle) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ENTRIES:
                raise BootstrapError("runtime bundle entry count is invalid")
            names = [_safe_name(item.filename) for item in infos]
            if len(names) != len(set(names)) or BUNDLE_MANIFEST not in names:
                raise BootstrapError("runtime bundle has duplicate entries or no manifest")
            entries: dict[str, bytes] = {}
            modes: dict[str, int] = {}
            total_size = 0
            for info in infos:
                mode = (info.external_attr >> 16) & 0o177777
                if stat.S_IFMT(mode) != stat.S_IFREG or stat.S_ISLNK(mode):
                    raise BootstrapError("runtime bundle contains a link or non-regular entry")
                if info.file_size < 0 or info.file_size > MAX_FILE_BYTES:
                    raise BootstrapError("runtime bundle contains an oversized entry")
                total_size += info.file_size
                if total_size > MAX_TOTAL_BYTES:
                    raise BootstrapError("runtime bundle expanded size exceeds its limit")
                if info.file_size > MAX_COMPRESSION_RATIO * max(1, info.compress_size):
                    raise BootstrapError("runtime bundle contains an excessive compression ratio")
                data = archive.read(info)
                if len(data) != info.file_size:
                    raise BootstrapError("runtime bundle entry is truncated")
                entries[info.filename] = data
                modes[info.filename] = stat.S_IMODE(mode)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise BootstrapError("runtime bundle is malformed") from exc
    try:
        manifest = json.loads(entries[BUNDLE_MANIFEST])
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BootstrapError("runtime bundle manifest is malformed") from exc
    records = manifest.get("files") if isinstance(manifest, dict) else None
    if (
        manifest.get("schema_version") != 1
        or manifest.get("development_version") != expected_version
        or not isinstance(records, list)
    ):
        raise BootstrapError("runtime bundle version or manifest schema is invalid")
    expected_names = {record.get("path") for record in records if isinstance(record, dict)}
    if expected_names != set(entries) - {BUNDLE_MANIFEST}:
        raise BootstrapError("runtime bundle file inventory is incomplete or unexpected")
    for record in records:
        name = record["path"]
        if (
            not _is_sha256(record.get("sha256"))
            or record.get("size") != len(entries[name])
            or record.get("sha256") != _sha256_bytes(entries[name])
            or record.get("mode") != modes[name]
            or modes[name] not in {0o644, 0o755}
        ):
            raise BootstrapError("runtime bundle file verification failed")
    if entries.get("VERSION") not in {f"{expected_version}\n".encode(), expected_version.encode()}:
        raise BootstrapError("runtime VERSION differs from trusted metadata")
    return entries, modes


def _validate_cached_runtime(
    destination: Path, bundle_sha256: str, expected_version: str,
) -> Path:
    marker = destination / ".vibesec-runtime.json"
    try:
        destination_details = destination.stat(follow_symlinks=False)
        marker_details = marker.stat(follow_symlinks=False)
        manifest_path = destination / BUNDLE_MANIFEST
        manifest_details = manifest_path.stat(follow_symlinks=False)
    except OSError as exc:
        raise BootstrapError("cached runtime is partial or malformed") from exc
    if (
        destination.is_symlink()
        or marker.is_symlink()
        or manifest_path.is_symlink()
        or not stat.S_ISDIR(destination_details.st_mode)
        or not stat.S_ISREG(marker_details.st_mode)
        or not stat.S_ISREG(manifest_details.st_mode)
        or any(path.is_symlink() for path in destination.rglob("*"))
    ):
        raise BootstrapError("cached runtime contains an unsafe path")
    try:
        record = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BootstrapError("cached runtime is partial or malformed") from exc
    if record != {
        "schema_version": 1,
        "bundle_sha256": bundle_sha256,
        "development_version": expected_version,
    }:
        raise BootstrapError("cached runtime metadata does not match the trusted release")
    try:
        manifest = json.loads((destination / BUNDLE_MANIFEST).read_text(encoding="utf-8"))
        records = manifest["files"]
    except (OSError, KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise BootstrapError("cached runtime bundle manifest is missing or malformed") from exc
    expected = {item.get("path") for item in records if isinstance(item, dict)}
    actual = {
        path.relative_to(destination).as_posix()
        for path in destination.rglob("*") if path.is_file()
    } - {BUNDLE_MANIFEST, ".vibesec-runtime.json"}
    if expected != actual or manifest.get("development_version") != expected_version:
        raise BootstrapError("cached runtime file inventory does not match the trusted release")
    for item in records:
        path = destination / item["path"]
        try:
            details = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise BootstrapError("cached runtime file is missing") from exc
        if (
            path.is_symlink()
            or not stat.S_ISREG(details.st_mode)
            or stat.S_IMODE(details.st_mode) != item.get("mode")
            or path.stat().st_size != item.get("size")
            or _sha256_file(path) != item.get("sha256")
        ):
            raise BootstrapError("cached runtime file verification failed")
    executable = destination / "vibesec"
    if executable.is_symlink() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise BootstrapError("cached runtime executable is missing or unsafe")
    return executable


def _install_runtime(
    *, metadata: dict[str, Any], cache: Path, local_bundle: Path | None,
    local_sha256: str | None, progress: Callable[[str], None] | None = None,
) -> tuple[Path, bool]:
    expected_digest = metadata["bundle_sha256"]
    if local_bundle is not None:
        if not _is_sha256(local_sha256):
            raise BootstrapError("trusted local bundle override requires an explicit SHA-256")
        expected_digest = str(local_sha256)
    destination = cache / "runtime" / metadata["release_version"]
    if destination.exists() or destination.is_symlink():
        if progress is not None:
            progress("Revalidating cached VibeSec Guardian runtime")
        executable = _validate_cached_runtime(
            destination, expected_digest, metadata["development_version"],
        )
        if progress is not None:
            progress("Reusing verified VibeSec Guardian runtime cache")
        return executable, True
    _ensure_cache_directory(cache)
    _ensure_cache_directory(cache / "runtime")
    staging = Path(tempfile.mkdtemp(prefix=".runtime-", dir=destination.parent))
    try:
        bundle = staging / metadata["bundle_name"]
        if local_bundle is None:
            if progress is not None:
                progress("Downloading verified VibeSec Guardian runtime")
            _download(metadata["bundle_url"], bundle)
        else:
            if progress is not None:
                progress("Loading trusted local VibeSec Guardian runtime bundle")
            requested_source = local_bundle.expanduser()
            if requested_source.is_symlink():
                raise BootstrapError("trusted local bundle override must be a regular file")
            source = requested_source.resolve(strict=True)
            if not source.is_file():
                raise BootstrapError("trusted local bundle override must be a regular file")
            shutil.copyfile(source, bundle, follow_symlinks=False)
        if progress is not None:
            progress("Verifying VibeSec Guardian runtime checksum")
        if _sha256_file(bundle) != expected_digest:
            raise BootstrapError("runtime bundle checksum mismatch")
        entries, modes = _verified_entries(bundle, metadata["development_version"])
        bundle.unlink()
        if progress is not None:
            progress("Installing verified VibeSec Guardian runtime")
        for name, data in entries.items():
            path = staging / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o644 if name == BUNDLE_MANIFEST else modes[name])
        marker = {
            "schema_version": 1,
            "bundle_sha256": expected_digest,
            "development_version": metadata["development_version"],
        }
        (staging / ".vibesec-runtime.json").write_text(
            json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8", newline="\n",
        )
        os.replace(staging, destination)
        executable = _validate_cached_runtime(
            destination, expected_digest, metadata["development_version"],
        )
        if progress is not None:
            progress("Installed verified VibeSec Guardian runtime")
        return executable, False
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("minimal", "standard"), required=True)
    parser.add_argument("--target", type=Path, default=Path("."))
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--network-mode", choices=("online", "offline"), default="online")
    parser.add_argument("--acknowledge-downloads", action="store_true")
    parser.add_argument("--trusted-local-bundle", type=Path)
    parser.add_argument("--trusted-local-sha256")
    args = parser.parse_args()
    try:
        if not args.acknowledge_downloads:
            raise BootstrapError(
                "explicit approval is required before runtime/tool downloads and scanner network access"
            )
        metadata = _load_metadata()
        target = args.target.expanduser().resolve(strict=True)
        if args.target.is_symlink() or not target.is_dir():
            raise BootstrapError("scan target must be a regular directory")
        cache = (args.cache_dir or _cache_home()).expanduser().resolve()
        try:
            cache.relative_to(target)
        except ValueError:
            pass
        else:
            raise BootstrapError("runtime and tool cache must be outside the application repository")
        runtime, reused = _install_runtime(
            metadata=metadata, cache=cache,
            local_bundle=args.trusted_local_bundle,
            local_sha256=args.trusted_local_sha256,
            progress=_progress,
        )
        _progress(f"Starting managed {args.profile} scan")
        command = [
            str(runtime), "scan", "--profile", args.profile, "--target",
            str(target), "--install-tools", "--cache-dir",
            str(cache), "--network-mode", args.network_mode, "--json",
        ]
        if args.results:
            command.extend(["--results", str(args.results.expanduser().resolve())])
        completed = subprocess.run(
            command, stdin=subprocess.DEVNULL, check=False,
        )
        return completed.returncode if completed.returncode in {0, 1, 2, 3, 4} else 4
    except BootstrapError as exc:
        print(json.dumps({
            "schema_version": 1,
            "status": "bootstrap_error",
            "errors": [" ".join(str(exc).split())[:300]],
        }, sort_keys=True))
        return 2
    except (OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({
            "schema_version": 1,
            "status": "infrastructure_failure",
            "errors": [type(exc).__name__],
        }, sort_keys=True))
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
