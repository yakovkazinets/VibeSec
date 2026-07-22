"""Safe deterministic JSON envelopes and concise human output."""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
MAX_MESSAGE = 500
ENVELOPE_FIELDS = {"schema_version", "command", "development_version", "status", "errors", "warnings", "information", "result"}


def safe_text(value: object) -> str:
    text = CONTROL.sub("?", str(value)).replace("\x1b", "?")
    return "".join("?" if unicodedata.category(character) in {"Cc", "Cs"} else character for character in text)[:MAX_MESSAGE]


def envelope(command: str, version: str, status: str, *, result: Any = None,
             errors: list[str] | None = None, warnings: list[str] | None = None,
             information: list[str] | None = None) -> dict[str, Any]:
    payload = {
        "schema_version": 1,
        "command": safe_text(command),
        "development_version": safe_text(version),
        "status": safe_text(status),
        "errors": [safe_text(item) for item in (errors or [])],
        "warnings": [safe_text(item) for item in (warnings or [])],
        "information": [safe_text(item) for item in (information or [])],
        "result": result if result is not None else {},
    }
    validate_envelope(payload)
    return payload


def validate_envelope(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != ENVELOPE_FIELDS or payload.get("schema_version") != 1:
        raise ValueError("command envelope schema or fields are invalid")
    if any(not isinstance(payload[field], str) or not payload[field] or len(payload[field]) > MAX_MESSAGE
           for field in ("command", "development_version", "status")):
        raise ValueError("command envelope identity fields are invalid")
    for field in ("errors", "warnings", "information"):
        values = payload[field]
        if not isinstance(values, list) or len(values) > 1_000 or any(not isinstance(item, str) or len(item) > MAX_MESSAGE for item in values):
            raise ValueError(f"command envelope {field} is invalid")
    if not isinstance(payload["result"], dict):
        raise ValueError("command envelope result must be an object")
    return payload


def emit(payload: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return
    print(f"{payload['command']}: {payload['status']}")
    for label, key in (("error", "errors"), ("warning", "warnings"), ("info", "information")):
        for item in payload[key]:
            print(f"{label}: {safe_text(item)}")
