"""Bounded canonical paths shared by bundles and installation tooling."""

from __future__ import annotations

from pathlib import PurePosixPath
import re
import unicodedata

MAX_PATH_LENGTH = 240
DRIVE = re.compile(r"^[A-Za-z]:")


class UnsafePath(ValueError):
    """A path is ambiguous, unbounded, or can escape its root."""


def safe_posix_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise UnsafePath("path must be nonempty bounded text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise UnsafePath("path must be valid Unicode") from exc
    if len(encoded) > MAX_PATH_LENGTH:
        raise UnsafePath("path must be nonempty bounded text")
    if "\x00" in value or "\\" in value or value.startswith("/") or DRIVE.match(value):
        raise UnsafePath("path contains an absolute, NUL, drive, or backslash form")
    if any(unicodedata.category(character) in {"Cc", "Cs"} for character in value):
        raise UnsafePath("path contains control characters")
    if unicodedata.normalize("NFC", value) != value:
        raise UnsafePath("path must use Unicode NFC")
    path = PurePosixPath(value)
    if value != path.as_posix() or any(part in {"", ".", ".."} for part in path.parts):
        raise UnsafePath("path is non-canonical or traverses its root")
    return value


def collision_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def validate_unique_paths(values: list[str]) -> None:
    exact: set[str] = set()
    folded: dict[str, str] = {}
    for value in values:
        safe_posix_path(value)
        if value in exact:
            raise UnsafePath(f"duplicate path: {value}")
        exact.add(value)
        key = collision_key(value)
        if key in folded and folded[key] != value:
            raise UnsafePath(f"case or Unicode collision: {folded[key]} and {value}")
        folded[key] = value
