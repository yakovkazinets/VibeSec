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


def _validate(
    value: Any,
    depth: int = 0,
    *,
    maximum_depth: int = MAX_DEPTH,
    maximum_items: int = MAX_ITEMS,
    maximum_string: int = MAX_STRING,
    reject_controls: bool = True,
) -> None:
    if depth > maximum_depth:
        raise StrictJSONError("JSON nesting exceeds limit")
    if isinstance(value, str):
        prohibited_categories = {"Cc", "Cs"} if reject_controls else {"Cs"}
        has_prohibited_character = any(
            unicodedata.category(character) in prohibited_categories
            for character in value
        )
        if len(value) > maximum_string or has_prohibited_character:
            raise StrictJSONError("JSON string is oversized or contains controls")
    elif isinstance(value, list):
        if len(value) > maximum_items:
            raise StrictJSONError("JSON array exceeds limit")
        for item in value:
            _validate(
                item,
                depth + 1,
                maximum_depth=maximum_depth,
                maximum_items=maximum_items,
                maximum_string=maximum_string,
                reject_controls=reject_controls,
            )
    elif isinstance(value, dict):
        if len(value) > maximum_items:
            raise StrictJSONError("JSON object exceeds limit")
        for key, item in value.items():
            _validate(
                key,
                depth + 1,
                maximum_depth=maximum_depth,
                maximum_items=maximum_items,
                maximum_string=maximum_string,
                reject_controls=reject_controls,
            )
            _validate(
                item,
                depth + 1,
                maximum_depth=maximum_depth,
                maximum_items=maximum_items,
                maximum_string=maximum_string,
                reject_controls=reject_controls,
            )
    elif isinstance(value, float) and not math.isfinite(value):
        raise StrictJSONError("JSON number must be finite")
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise StrictJSONError("JSON contains an unsupported value")


def loads_strict(
    data: bytes,
    *,
    maximum_bytes: int = MAX_JSON_BYTES,
    maximum_depth: int = MAX_DEPTH,
    maximum_items: int = MAX_ITEMS,
    maximum_string: int = MAX_STRING,
    reject_controls: bool = True,
) -> Any:
    if min(maximum_bytes, maximum_depth, maximum_items, maximum_string) < 1:
        raise StrictJSONError("JSON parser bounds must be positive")
    if len(data) > maximum_bytes:
        raise StrictJSONError("JSON input exceeds size limit")
    if data.startswith(b"\xef\xbb\xbf"):
        raise StrictJSONError("JSON must not contain a UTF-8 BOM")
    try:
        text = data.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_object, parse_constant=lambda item: (_ for _ in ()).throw(StrictJSONError(f"invalid number: {item}")))
    except StrictJSONError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise StrictJSONError(f"invalid JSON: {exc}") from exc
    _validate(
        value,
        maximum_depth=maximum_depth,
        maximum_items=maximum_items,
        maximum_string=maximum_string,
        reject_controls=reject_controls,
    )
    return value


def canonical_json(value: Any) -> bytes:
    _validate(value)
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
