"""Deterministic platform detection and local execution-mode selection."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import platform
import stat
from typing import Any

from .strict_json import StrictJSONError, loads_strict

SUPPORTED_PLATFORMS = {"linux-amd64", "linux-arm64", "macos-amd64", "macos-arm64"}
PROFILES = {"minimal", "standard"}
MODES = {"native", "container", "auto"}
PROFILE_TOOLS = {
    "minimal": ("trivy", "gitleaks", "actionlint"),
    "standard": ("trivy", "gitleaks", "actionlint", "opengrep", "osv-scanner", "syft"),
}


class PortableExecutionError(ValueError):
    """Portable execution configuration or selection failed closed."""


@dataclass(frozen=True)
class ExecutionDecision:
    platform: str
    requested_mode: str
    selected_mode: str
    profile: str
    reason: str

    def result(self) -> dict[str, str]:
        return {
            "platform": self.platform,
            "requested_mode": self.requested_mode,
            "selected_mode": self.selected_mode,
            "profile": self.profile,
            "reason": self.reason,
        }


def platform_id(system: str | None = None, machine: str | None = None) -> str:
    system_value = (system or platform.system()).casefold()
    machine_value = (machine or platform.machine()).casefold()
    operating_system = {"linux": "linux", "darwin": "macos"}.get(system_value)
    architecture = {
        "x86_64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
    }.get(machine_value)
    if operating_system is None or architecture is None:
        raise PortableExecutionError(
            f"unsupported native platform: {system_value or 'unknown'}-{machine_value or 'unknown'}"
        )
    value = f"{operating_system}-{architecture}"
    if value not in SUPPORTED_PLATFORMS:
        raise PortableExecutionError(f"unsupported native platform: {value}")
    return value


def load_support(path: Path) -> dict[str, Any]:
    try:
        payload = loads_strict(path.read_bytes(), maximum_bytes=128_000)
    except (OSError, StrictJSONError) as exc:
        raise PortableExecutionError(f"portable execution metadata is invalid: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "platforms", "scanner_support"}:
        raise PortableExecutionError("portable execution metadata fields are invalid")
    if payload["schema_version"] != 1 or not isinstance(payload["platforms"], dict) or set(payload["platforms"]) != SUPPORTED_PLATFORMS:
        raise PortableExecutionError("portable execution metadata schema or platforms are invalid")
    for name, entry in payload["platforms"].items():
        if not isinstance(entry, dict) or set(entry) != {"native_profiles", "container_profiles", "unsupported_reason"}:
            raise PortableExecutionError(f"portable platform entry is invalid: {name}")
        for field in ("native_profiles", "container_profiles"):
            values = entry[field]
            if not isinstance(values, list) or values != sorted(set(values)) or not set(values) <= PROFILES:
                raise PortableExecutionError(f"portable platform {field} is invalid: {name}")
        reason = entry["unsupported_reason"]
        if reason is not None and (not isinstance(reason, str) or not reason or len(reason) > 500):
            raise PortableExecutionError(f"portable platform limitation is invalid: {name}")
    scanners = payload["scanner_support"]
    if not isinstance(scanners, dict) or not scanners:
        raise PortableExecutionError("scanner support metadata is invalid")
    for scanner, platforms in scanners.items():
        if (not isinstance(scanner, str) or not scanner or not isinstance(platforms, list)
                or platforms != sorted(set(platforms)) or not set(platforms) <= SUPPORTED_PLATFORMS):
            raise PortableExecutionError("scanner support declaration is invalid")
    return payload


def _regular_executables(tool_dir: Path, profile: str) -> tuple[bool, list[str]]:
    missing: list[str] = []
    for tool in PROFILE_TOOLS[profile]:
        candidate = tool_dir / tool
        try:
            details = candidate.stat(follow_symlinks=False)
        except OSError:
            missing.append(tool)
            continue
        if candidate.is_symlink() or not stat.S_ISREG(details.st_mode) or not os.access(candidate, os.X_OK):
            missing.append(tool)
    return not missing, missing


def select_execution_mode(*, requested: str, profile: str, current_platform: str,
                          tool_dir: Path, support: dict[str, Any]) -> ExecutionDecision:
    if requested not in MODES or profile not in PROFILES or current_platform not in SUPPORTED_PLATFORMS:
        raise PortableExecutionError("execution mode, profile, or platform is invalid")
    platform_support = support["platforms"][current_platform]
    native_supported = profile in platform_support["native_profiles"]
    container_supported = profile in platform_support["container_profiles"]
    tools_ready, missing = _regular_executables(tool_dir, profile)

    if requested == "native":
        if not native_supported:
            raise PortableExecutionError(
                platform_support["unsupported_reason"] or f"native {profile} execution is unsupported on {current_platform}"
            )
        if not tools_ready:
            raise PortableExecutionError("native verified tool set is incomplete: " + ", ".join(missing))
        return ExecutionDecision(current_platform, requested, "native", profile,
                                 "complete native profile support and executable boundaries verified")
    if requested == "container":
        if not container_supported:
            raise PortableExecutionError(
                f"complete container {profile} execution is not distributed for {current_platform}; no unverified fallback was attempted"
            )
        return ExecutionDecision(current_platform, requested, "container", profile,
                                 "complete immutable container profile is supported")
    if native_supported and tools_ready:
        return ExecutionDecision(current_platform, requested, "native", profile,
                                 "auto selected the complete verified native tool set")
    if container_supported:
        return ExecutionDecision(current_platform, requested, "container", profile,
                                 "auto selected the complete immutable container profile")
    detail = ("missing native tools: " + ", ".join(missing)) if native_supported else (
        platform_support["unsupported_reason"] or "native profile unsupported"
    )
    raise PortableExecutionError(
        f"no complete verified execution mode for {profile} on {current_platform} ({detail}); no fallback was attempted"
    )
