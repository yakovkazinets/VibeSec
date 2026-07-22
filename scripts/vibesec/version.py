"""Canonical development-version parsing without Git or network access."""

from __future__ import annotations

from pathlib import Path
import re
import unicodedata

MAX_VERSION_BYTES = 65
DEVELOPMENT_VERSION = re.compile(
    r"^(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})-dev(?:[.+][0-9A-Za-z][0-9A-Za-z.-]{0,31})?$"
)


class VersionError(ValueError):
    """The canonical version file or value is malformed."""


def validate_version(value: object) -> str:
    if not isinstance(value, str):
        raise VersionError("development version must be text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise VersionError("development version must be valid Unicode") from exc
    if not value or len(encoded) > MAX_VERSION_BYTES - 1:
        raise VersionError("development version must be nonempty and at most 64 UTF-8 bytes")
    if value != value.strip() or any(unicodedata.category(character) in {"Cc", "Cs"} for character in value):
        raise VersionError("development version must not contain surrounding whitespace or controls")
    if not DEVELOPMENT_VERSION.fullmatch(value):
        raise VersionError("development version must use MAJOR.MINOR.PATCH-dev syntax")
    return value


def parse_version_bytes(data: bytes) -> str:
    if len(data) > MAX_VERSION_BYTES:
        raise VersionError("VERSION is oversized")
    if data.startswith(b"\xef\xbb\xbf"):
        raise VersionError("VERSION must not contain a UTF-8 BOM")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VersionError("VERSION must be valid UTF-8") from exc
    if text.endswith("\r\n"):
        value = text[:-2]
    elif text.endswith("\n"):
        value = text[:-1]
    else:
        value = text
    if "\n" in value or "\r" in value:
        raise VersionError("VERSION allows at most one trailing newline")
    return validate_version(value)


def read_version(root: Path) -> str:
    try:
        return parse_version_bytes((root / "VERSION").read_bytes())
    except OSError as exc:
        raise VersionError(f"VERSION is unavailable: {exc}") from exc
