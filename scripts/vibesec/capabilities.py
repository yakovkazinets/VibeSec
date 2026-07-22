"""Strict project capability manifests and questionnaire metadata."""

from __future__ import annotations

from pathlib import Path
import stat
from typing import Any, TextIO

from .strict_json import StrictJSONError, canonical_json, loads_strict

SCHEMA_VERSION = 1
MANIFEST_PATH = ".vibesec/project-capabilities.json"
MAX_MANIFEST_BYTES = 16_384

QUESTIONS: tuple[tuple[str, str], ...] = (
    ("web_application", "Does this project run a web application?"),
    ("api", "Does this project expose an API?"),
    ("container_image", "Does this project produce a container image?"),
    ("kubernetes", "Does this project use Kubernetes?"),
    ("infrastructure_as_code", "Does this project use Terraform or other Infrastructure as Code?"),
    ("github_actions", "Does this project use GitHub Actions?"),
    ("javascript_typescript", "Does this project contain JavaScript or TypeScript?"),
    ("python", "Does this project contain Python?"),
    ("java", "Does this project contain Java?"),
    ("public_runtime", "Is the application publicly reachable?"),
    ("authentication", "Does the application use authentication?"),
    ("database", "Does the application use a database?"),
    ("secrets_configuration", "Does the project use secrets or environment configuration?"),
    ("dast_target", "Should VibeSec configure a runtime DAST target?"),
)
CAPABILITY_KEYS = tuple(key for key, _ in QUESTIONS)


class CapabilityError(ValueError):
    """A capability manifest or questionnaire response is unsafe or invalid."""


def all_capabilities(value: bool = True) -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "capabilities": {key: value for key in CAPABILITY_KEYS}}


def validate_capabilities(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "capabilities"}:
        raise CapabilityError("project capability manifest contains missing or unknown fields")
    if payload.get("schema_version") != SCHEMA_VERSION or isinstance(payload.get("schema_version"), bool):
        raise CapabilityError("project capability manifest schema is unsupported")
    values = payload.get("capabilities")
    if not isinstance(values, dict) or set(values) != set(CAPABILITY_KEYS):
        raise CapabilityError("project capability manifest contains missing or unknown capabilities")
    if any(type(values[key]) is not bool for key in CAPABILITY_KEYS):
        raise CapabilityError("project capability values must be Boolean")
    if values["dast_target"] and not values["web_application"]:
        raise CapabilityError("dast_target=true requires web_application=true")
    if values["public_runtime"] and not (values["web_application"] or values["api"]):
        raise CapabilityError("public_runtime=true requires web_application=true or api=true")
    if values["authentication"] and not (values["web_application"] or values["api"]):
        raise CapabilityError("authentication=true requires web_application=true or api=true")
    return {"schema_version": SCHEMA_VERSION, "capabilities": {key: values[key] for key in CAPABILITY_KEYS}}


def parse_capabilities(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_MANIFEST_BYTES:
        raise CapabilityError("project capability manifest exceeds its size limit")
    if data.startswith(b"\xef\xbb\xbf"):
        raise CapabilityError("project capability manifest must be UTF-8 without a byte-order mark")
    try:
        return validate_capabilities(loads_strict(data))
    except (StrictJSONError, UnicodeError) as exc:
        raise CapabilityError(f"project capability manifest is invalid: {exc}") from exc


def capability_bytes(payload: Any) -> bytes:
    return canonical_json(validate_capabilities(payload))


def load_capabilities_file(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise CapabilityError("project capability manifest must not be a symbolic link")
    try:
        details = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(details.st_mode):
            raise CapabilityError("project capability manifest must be a regular file")
        if details.st_size > MAX_MANIFEST_BYTES:
            raise CapabilityError("project capability manifest exceeds its size limit")
        return parse_capabilities(path.read_bytes())
    except OSError as exc:
        raise CapabilityError(f"project capability manifest cannot be read: {type(exc).__name__}") from exc


def parse_answer(value: str) -> bool | None:
    normalized = value.strip().casefold()
    if normalized in {"", "y", "yes"}:
        return True
    if normalized in {"n", "no"}:
        return False
    return None


def ask_capabilities(input_stream: TextIO, prompt_stream: TextIO) -> dict[str, Any]:
    values: dict[str, bool] = {}
    for key, question in QUESTIONS:
        while True:
            prompt_stream.write(f"{question} [Y/n] ")
            prompt_stream.flush()
            line = input_stream.readline()
            if line == "":
                raise CapabilityError("questionnaire ended before every capability was answered")
            answer = parse_answer(line)
            if answer is not None:
                values[key] = answer
                break
            prompt_stream.write("Please answer Yes or No.\n")
    return validate_capabilities({"schema_version": SCHEMA_VERSION, "capabilities": values})


def scanner_applicability(payload: Any) -> dict[str, dict[str, str]]:
    capabilities = validate_capabilities(payload)["capabilities"]
    mapping = {
        "gitleaks": True,
        "actionlint": capabilities["github_actions"],
        "checkov": capabilities["infrastructure_as_code"],
        "trivy-image": capabilities["container_image"],
        "dast-baseline": capabilities["dast_target"] and capabilities["web_application"],
    }
    return {
        name: ({"state": "applicable", "reason": "project capability manifest enables this scanner scope"}
               if enabled else {"state": "not_applicable", "reason": "project capability manifest excludes this scanner scope"})
        for name, enabled in mapping.items()
    }
