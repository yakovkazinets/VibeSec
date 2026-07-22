"""Strict bounded JSON parsing and canonical serialization."""

from __future__ import annotations

import json
import math
import unicodedata
from typing import Any

MAX_JSON_BYTES = 5_000_000
MAX_DEPTH = 24
MAX_ITEMS = 10_000
MAX_STRING = 20_000


class StrictJSONError(ValueError):
    """JSON is malformed, ambiguous, or exceeds explicit bounds."""


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _validate(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise StrictJSONError("JSON nesting exceeds limit")
    if isinstance(value, str):
        if len(value) > MAX_STRING or any(unicodedata.category(character) in {"Cc", "Cs"} for character in value):
            raise StrictJSONError("JSON string is oversized or contains controls")
    elif isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise StrictJSONError("JSON array exceeds limit")
        for item in value:
            _validate(item, depth + 1)
    elif isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise StrictJSONError("JSON object exceeds limit")
        for key, item in value.items():
            _validate(key, depth + 1)
            _validate(item, depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise StrictJSONError("JSON number must be finite")
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise StrictJSONError("JSON contains an unsupported value")


def loads_strict(data: bytes, *, maximum_bytes: int = MAX_JSON_BYTES) -> Any:
    if len(data) > maximum_bytes:
        raise StrictJSONError("JSON input exceeds size limit")
    if data.startswith(b"\xef\xbb\xbf"):
        raise StrictJSONError("JSON must not contain a UTF-8 BOM")
    try:
        text = data.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_object, parse_constant=lambda item: (_ for _ in ()).throw(StrictJSONError(f"invalid number: {item}")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StrictJSONError(f"invalid JSON: {exc}") from exc
    _validate(value)
    return value


def canonical_json(value: Any) -> bytes:
    _validate(value)
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
