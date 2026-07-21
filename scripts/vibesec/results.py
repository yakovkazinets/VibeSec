"""Safe mutation helpers for normalized VibeSec result documents."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any


class ResultDocumentError(ValueError):
    """A normalized result document or appended result is malformed."""


REQUIRED_RESULT_FIELDS = {
    "tool", "category", "rule_id", "severity", "file", "line", "description",
    "confidence", "fingerprint", "result_type",
}


def _validate_document(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ResultDocumentError("normalized result document must be a schema-version 1 object")
    if not isinstance(payload.get("results"), list):
        raise ResultDocumentError("normalized result document must contain a results array")
    for item in payload["results"]:
        if not isinstance(item, dict) or item.get("result_type") not in ("finding", "tool_error", "pass"):
            raise ResultDocumentError("each existing result must be an object with a valid result_type")
        missing = REQUIRED_RESULT_FIELDS - set(item)
        if missing:
            raise ResultDocumentError(f"existing result is missing required fields: {', '.join(sorted(missing))}")
    return payload


def _validate_tool_errors(tool_errors: Any) -> list[dict[str, Any]]:
    if not isinstance(tool_errors, list):
        raise ResultDocumentError("tool errors must be an array")
    for item in tool_errors:
        if not isinstance(item, dict) or item.get("result_type") != "tool_error":
            raise ResultDocumentError("each appended item must be a tool_error object")
        missing = REQUIRED_RESULT_FIELDS - set(item)
        if missing:
            raise ResultDocumentError(f"tool error is missing required fields: {', '.join(sorted(missing))}")
    return tool_errors


def append_tool_errors_atomic(path: Path, tool_errors: list[dict[str, Any]]) -> None:
    """Validate, append, and atomically rewrite JSON with one real trailing newline."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ResultDocumentError(f"normalized result document is malformed: {exc}") from exc
    document = _validate_document(payload)
    errors = _validate_tool_errors(tool_errors)
    updated = dict(document)
    updated["results"] = [*document["results"], *errors]
    serialized = json.dumps(updated, indent=2) + "\n"

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(serialized)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    except OSError as exc:
        raise ResultDocumentError(f"could not atomically write normalized results: {exc}") from exc
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
