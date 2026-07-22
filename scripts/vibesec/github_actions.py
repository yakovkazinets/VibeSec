"""Strict offline inventory and policy checks for GitHub Actions references."""

from __future__ import annotations

from datetime import date
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Iterable

from .strict_json import StrictJSONError, loads_strict

INVENTORY_PATH = "config/github-actions.json"
MAX_INVENTORY_BYTES = 16_384
MAX_AUDIT_FILE_BYTES = 1_000_000
MINIMUM_RUNNER_VERSION = "2.327.1"
ACTION_FIELDS = {"version", "commit", "kind", "runtime", "verified_on"}
APPROVED_ACTIONS = {"actions/checkout", "actions/upload-artifact"}
KNOWN_NODE20_PINS = {
    "11bd71901bbe5b1630ceea73d27597364c9af683": "actions/checkout v4.2.2",
    "ea165f8d65b6e75b540449e92b4886f43607fa02": "actions/upload-artifact v4.6.2",
}
PROHIBITED_OVERRIDES = {
    "ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION",
    "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24",
}
OVERRIDE_USAGE = re.compile(
    r"(?m)^[ \t]*(?:export[ \t]+)?(?:ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION|"
    r"FORCE_JAVASCRIPT_ACTIONS_TO_NODE24)[ \t]*(?::|=)"
)
VERSION = re.compile(r"^v[1-9][0-9]*\.[0-9]+\.[0-9]+$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
RUNNER_VERSION = re.compile(r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")
USES_LINE = re.compile(
    r"^(?P<indent>[ \t]*)(?:-[ \t]*)?uses:[ \t]*(?P<action>[^@#\s]+)@(?P<ref>[^#\s]+)"
    r"(?:[ \t]+#[ \t]*(?P<comment>[^\r\n]*))?[ \t]*$",
    re.MULTILINE,
)


class GitHubActionsError(ValueError):
    """The action inventory or a workflow violates the reviewed contract."""


def validate_inventory(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "minimum_runner_version", "actions"}:
        raise GitHubActionsError("GitHub Actions inventory contains missing or unknown fields")
    if payload.get("schema_version") != 1 or isinstance(payload.get("schema_version"), bool):
        raise GitHubActionsError("GitHub Actions inventory schema is unsupported")
    minimum = payload.get("minimum_runner_version")
    if not isinstance(minimum, str) or not RUNNER_VERSION.fullmatch(minimum) or minimum != MINIMUM_RUNNER_VERSION:
        raise GitHubActionsError(f"GitHub Actions inventory must require runner {MINIMUM_RUNNER_VERSION}")
    actions = payload.get("actions")
    if not isinstance(actions, dict) or set(actions) != APPROVED_ACTIONS:
        raise GitHubActionsError("GitHub Actions inventory must define exactly the approved actions")
    validated: dict[str, dict[str, str]] = {}
    for name in sorted(actions):
        record = actions[name]
        if not isinstance(record, dict) or set(record) != ACTION_FIELDS:
            raise GitHubActionsError(f"GitHub Actions inventory record is malformed: {name}")
        if not isinstance(record["version"], str) or not VERSION.fullmatch(record["version"]):
            raise GitHubActionsError(f"GitHub Actions version is invalid: {name}")
        if not isinstance(record["commit"], str) or not COMMIT.fullmatch(record["commit"]):
            raise GitHubActionsError(f"GitHub Actions commit is not a full lowercase SHA: {name}")
        if record["kind"] != "javascript" or record["runtime"] != "node24":
            raise GitHubActionsError(f"GitHub Action is not an approved Node 24 JavaScript action: {name}")
        try:
            verified = date.fromisoformat(record["verified_on"])
        except (TypeError, ValueError) as exc:
            raise GitHubActionsError(f"GitHub Actions verification date is invalid: {name}") from exc
        if verified.isoformat() != record["verified_on"]:
            raise GitHubActionsError(f"GitHub Actions verification date is not canonical: {name}")
        validated[name] = {field: record[field] for field in sorted(ACTION_FIELDS)}
    return {
        "schema_version": 1,
        "minimum_runner_version": minimum,
        "actions": validated,
    }


def parse_inventory(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_INVENTORY_BYTES:
        raise GitHubActionsError("GitHub Actions inventory exceeds its size limit")
    if data.startswith(b"\xef\xbb\xbf"):
        raise GitHubActionsError("GitHub Actions inventory must be UTF-8 without a byte-order mark")
    try:
        return validate_inventory(loads_strict(data))
    except (StrictJSONError, UnicodeError) as exc:
        raise GitHubActionsError(f"GitHub Actions inventory is invalid: {exc}") from exc


def load_inventory(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise GitHubActionsError("GitHub Actions inventory must not be a symbolic link")
    try:
        details = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(details.st_mode):
            raise GitHubActionsError("GitHub Actions inventory must be a regular file")
        if details.st_size > MAX_INVENTORY_BYTES:
            raise GitHubActionsError("GitHub Actions inventory exceeds its size limit")
        return parse_inventory(path.read_bytes())
    except OSError as exc:
        raise GitHubActionsError(f"GitHub Actions inventory cannot be read: {type(exc).__name__}") from exc


def expected_comment(record: dict[str, str]) -> str:
    return f"{record['version']}, Node 24, verified {record['verified_on']}"


def _step_text(text: str, match: re.Match[str]) -> str:
    lines = text[match.start():].splitlines()
    base = len(match.group("indent").expandtabs(8))
    selected = [lines[0]]
    for line in lines[1:]:
        if not line.strip():
            selected.append(line)
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        if indent <= base and re.match(r"^[ \t]*-[ \t]+", line):
            break
        selected.append(line)
    return "\n".join(selected)


def audit_workflow_text(text: str, relative: str, inventory: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    records = inventory["actions"]
    matches = list(USES_LINE.finditer(text))
    if "uses:" in text and not matches:
        errors.append(f"workflow contains an unparseable uses reference: {relative}")
    for match in matches:
        action = match.group("action")
        reference = match.group("ref")
        record = records.get(action)
        if record is None:
            errors.append(f"workflow action is absent from the approved inventory: {relative}: {action}")
            continue
        if reference != record["commit"]:
            errors.append(f"workflow action does not match the approved immutable pin: {relative}: {action}")
        if (match.group("comment") or "").strip() != expected_comment(record):
            errors.append(f"workflow action review comment is missing or inconsistent: {relative}: {action}")
        step = _step_text(text, match)
        if action == "actions/checkout" and not re.search(r"(?m)^[ \t]+persist-credentials:[ \t]+false[ \t]*$", step):
            errors.append(f"checkout must explicitly disable persisted credentials: {relative}")
        if action == "actions/upload-artifact":
            required = {
                "if-no-files-found": "error",
                "include-hidden-files": "false",
                "archive": "true",
            }
            for key, value in required.items():
                if not re.search(rf"(?m)^[ \t]+{re.escape(key)}:[ \t]+{value}[ \t]*$", step):
                    errors.append(f"artifact upload must set {key}: {value}: {relative}")
    for match in OVERRIDE_USAGE.finditer(text):
        errors.append(f"prohibited JavaScript action runtime override is present: {relative}: {match.group(0).strip()}")
    return errors


def tracked_paths(root: Path) -> list[str]:
    try:
        completed = subprocess.run(
            ["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GitHubActionsError("tracked file inventory is unavailable") from exc
    return sorted(item.decode("utf-8") for item in completed.stdout.split(b"\0") if item)


def audit_tracked_files(root: Path, inventory: dict[str, Any], paths: Iterable[str] | None = None) -> list[str]:
    errors: list[str] = []
    for relative in paths if paths is not None else tracked_paths(root):
        path = root / relative
        try:
            details = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(details.st_mode):
                continue
            if details.st_size > MAX_AUDIT_FILE_BYTES:
                data = path.read_bytes()
                if b"uses:" in data or any(marker.encode() in data for marker in PROHIBITED_OVERRIDES):
                    errors.append(f"oversized tracked file may contain an unaudited action reference: {relative}")
                continue
            data = path.read_bytes()
        except OSError as exc:
            errors.append(f"tracked file cannot be audited: {relative}: {type(exc).__name__}")
            continue
        if b"uses:" not in data and not any(marker.encode() in data for marker in PROHIBITED_OVERRIDES):
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeError:
            errors.append(f"tracked file containing an action marker is not UTF-8: {relative}")
            continue
        if USES_LINE.search(text) or OVERRIDE_USAGE.search(text):
            errors.extend(audit_workflow_text(text, relative, inventory))
    return errors
