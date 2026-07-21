"""Fail-closed validation and canonicalization for imported skill text."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import unicodedata
from urllib.parse import unquote, urlparse

import yaml
from yaml.events import AliasEvent, NodeEvent

MAX_SKILL_BYTES = 256 * 1024
MAX_REFERENCED_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_FILES = 128
MAX_PATH_DEPTH = 12
MAX_METADATA_DEPTH = 6

PROHIBITED_BIDI = {
    "\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}
PROHIBITED_ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
NAME_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
LINK_PATTERN = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
SECOND_FRONT_MATTER = re.compile(
    r"(?ms)^---[ \t]*\n(?:(?!^---[ \t]*$).)*?^(?:name|description)[ \t]*:.*?^---[ \t]*$"
)
FENCE_START = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")


class SkillValidationError(ValueError):
    """The skill is ambiguous, unsafe to consume, or outside the strict schema."""


class StrictSafeLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys."""


def _construct_unique_mapping(loader: StrictSafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise SkillValidationError("metadata keys must be strings")
        if key in mapping:
            raise SkillValidationError(f"duplicate metadata key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


@dataclass(frozen=True)
class ValidatedSkill:
    root: Path
    metadata: dict[str, str]
    body: str
    references: tuple[str, ...]
    reference_hashes: dict[str, str]
    canonical: str
    fingerprint: str

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "valid",
            "metadata": self.metadata,
            "references": list(self.references),
            "reference_hashes": self.reference_hashes,
            "fingerprint": self.fingerprint,
        }


def _decode_and_normalize(data: bytes, *, label: str, maximum: int) -> str:
    if len(data) > maximum:
        raise SkillValidationError(f"{label} exceeds the {maximum}-byte limit")
    if data.startswith(b"\xef\xbb\xbf"):
        raise SkillValidationError(f"{label} contains a UTF-8 BOM")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SkillValidationError(f"{label} is not valid UTF-8") from exc
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = unicodedata.normalize("NFC", text)
    for character in text:
        if character in PROHIBITED_BIDI:
            raise SkillValidationError(f"{label} contains a prohibited bidirectional control U+{ord(character):04X}")
        if character in PROHIBITED_ZERO_WIDTH:
            raise SkillValidationError(f"{label} contains a prohibited zero-width character U+{ord(character):04X}")
    return text


def _metadata_depth(value: object, depth: int = 0) -> int:
    if depth > MAX_METADATA_DEPTH:
        return depth
    if isinstance(value, dict):
        return max((_metadata_depth(item, depth + 1) for item in value.values()), default=depth)
    if isinstance(value, list):
        return max((_metadata_depth(item, depth + 1) for item in value), default=depth)
    return depth


def _parse_metadata(source: str) -> tuple[dict[str, str], str]:
    if not source.startswith("---\n"):
        raise SkillValidationError("SKILL.md must begin with exactly one YAML front-matter block")
    closing = source.find("\n---\n", 4)
    if closing < 0:
        raise SkillValidationError("front matter is unclosed or ambiguous")
    yaml_text = source[4:closing]
    body = source[closing + 5 :]
    if SECOND_FRONT_MATTER.search(body):
        raise SkillValidationError("multiple or competing front-matter blocks are prohibited")
    try:
        for event in yaml.parse(yaml_text, Loader=StrictSafeLoader):
            if isinstance(event, AliasEvent) or (isinstance(event, NodeEvent) and event.anchor is not None):
                raise SkillValidationError("YAML anchors and aliases are prohibited")
        metadata = yaml.load(yaml_text, Loader=StrictSafeLoader)
    except SkillValidationError:
        raise
    except yaml.YAMLError as exc:
        raise SkillValidationError(f"metadata YAML is invalid or uses a prohibited tag: {exc}") from exc
    if not isinstance(metadata, dict):
        raise SkillValidationError("metadata must be a mapping")
    if _metadata_depth(metadata) > MAX_METADATA_DEPTH:
        raise SkillValidationError("metadata is too deeply nested")
    allowed = {"name", "description"}
    unknown = set(metadata) - allowed
    missing = allowed - set(metadata)
    if unknown:
        raise SkillValidationError(f"unknown metadata fields are prohibited: {', '.join(sorted(unknown))}")
    if missing:
        raise SkillValidationError(f"required metadata fields are missing: {', '.join(sorted(missing))}")
    if type(metadata["name"]) is not str or type(metadata["description"]) is not str:
        raise SkillValidationError("name and description metadata must be strings")
    if not NAME_PATTERN.fullmatch(metadata["name"]):
        raise SkillValidationError("name must use lowercase hyphen-case")
    if not metadata["description"].strip() or len(metadata["description"]) > 2048:
        raise SkillValidationError("description must be a non-empty string of at most 2048 characters")
    canonical_metadata = {"description": metadata["description"].strip(), "name": metadata["name"]}
    round_trip = yaml.load(yaml.safe_dump(canonical_metadata, sort_keys=True), Loader=StrictSafeLoader)
    if round_trip != canonical_metadata:
        raise SkillValidationError("metadata parser round-trip was materially inconsistent")
    return canonical_metadata, body


def _classify_markdown(body: str) -> tuple[list[bool], list[bool]]:
    lines = body.splitlines(keepends=True)
    in_fence: tuple[str, int] | None = None
    in_comment = False
    fenced: list[bool] = []
    commented: list[bool] = []
    for line in lines:
        stripped = line.rstrip("\n")
        match = FENCE_START.match(stripped)
        current_fenced = in_fence is not None
        if match:
            marker, suffix = match.groups()
            if in_fence is None:
                in_fence = (marker[0], len(marker))
                current_fenced = True
            elif marker[0] == in_fence[0] and len(marker) >= in_fence[1] and not suffix.strip():
                current_fenced = True
                in_fence = None
            else:
                raise SkillValidationError("nested or malformed Markdown code fence")
        fenced.append(current_fenced)
        if not current_fenced:
            opens = line.count("<!--")
            closes = line.count("-->")
            if closes > opens and not in_comment:
                raise SkillValidationError("Markdown contains an unmatched HTML comment close")
            was_comment = in_comment or opens > 0
            if opens > closes:
                in_comment = True
            elif closes >= opens and closes > 0:
                in_comment = False
            commented.append(was_comment)
        else:
            commented.append(False)
    if in_fence is not None:
        raise SkillValidationError("Markdown code fence is unclosed")
    if in_comment:
        raise SkillValidationError("Markdown HTML comment is unclosed")
    return fenced, commented


def _validate_tree(root: Path) -> None:
    seen: dict[str, str] = {}
    file_count = 0
    total_bytes = 0
    for directory, names, files in os.walk(root, followlinks=False):
        for name in names + files:
            path = Path(directory, name)
            relative = path.relative_to(root).as_posix()
            if any(ord(character) > 127 for character in relative):
                raise SkillValidationError(f"non-ASCII skill path is prohibited in v0.1: {relative}")
            collision_key = unicodedata.normalize("NFC", relative).casefold()
            if collision_key in seen and seen[collision_key] != relative:
                raise SkillValidationError(f"case- or normalization-colliding paths: {seen[collision_key]} and {relative}")
            seen[collision_key] = relative
            if len(Path(relative).parts) > MAX_PATH_DEPTH:
                raise SkillValidationError(f"path nesting exceeds {MAX_PATH_DEPTH}: {relative}")
            if path.is_symlink():
                try:
                    resolved = path.resolve(strict=True)
                except OSError as exc:
                    raise SkillValidationError(f"broken symlink is prohibited: {relative}") from exc
                if not resolved.is_relative_to(root):
                    raise SkillValidationError(f"symlink escapes the skill root: {relative}")
        for name in files:
            path = Path(directory, name)
            if not path.is_symlink():
                file_count += 1
                total_bytes += path.stat().st_size
    if file_count > MAX_FILES or total_bytes > MAX_TOTAL_BYTES:
        raise SkillValidationError("skill package exceeds file-count or total-size limits")


def _local_references(root: Path, body: str, fenced: list[bool], commented: list[bool]) -> dict[str, str]:
    references: dict[str, str] = {}
    for index, line in enumerate(body.splitlines()):
        if fenced[index] or commented[index] or line.lstrip().startswith(">"):
            continue
        for raw_target in LINK_PATTERN.findall(line):
            target = raw_target.strip().strip("<>").split("#", 1)[0]
            if not target:
                continue
            parsed = urlparse(target)
            if parsed.scheme or parsed.netloc:
                continue
            decoded = unquote(target)
            candidate = root.joinpath(decoded)
            try:
                resolved = candidate.resolve(strict=True)
            except OSError as exc:
                raise SkillValidationError(f"referenced path does not exist: {decoded}") from exc
            if not resolved.is_relative_to(root):
                raise SkillValidationError(f"referenced path escapes the skill root: {decoded}")
            if candidate.is_symlink() and not resolved.is_relative_to(root):
                raise SkillValidationError(f"referenced symlink escapes the skill root: {decoded}")
            if not resolved.is_file():
                raise SkillValidationError(f"referenced path is not a file: {decoded}")
            data = resolved.read_bytes()
            normalized = _decode_and_normalize(data, label=decoded, maximum=MAX_REFERENCED_BYTES)
            relative = resolved.relative_to(root).as_posix()
            references[relative] = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return dict(sorted(references.items()))


def validate_skill(root: Path) -> ValidatedSkill:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise SkillValidationError("skill root must be a directory")
    _validate_tree(root)
    skill_path = root / "SKILL.md"
    if skill_path.is_symlink():
        raise SkillValidationError("SKILL.md must not be a symlink")
    try:
        source = _decode_and_normalize(skill_path.read_bytes(), label="SKILL.md", maximum=MAX_SKILL_BYTES)
    except OSError as exc:
        raise SkillValidationError("SKILL.md is missing or unreadable") from exc
    metadata, body = _parse_metadata(source)
    fenced, commented = _classify_markdown(body)
    reference_hashes = _local_references(root, body, fenced, commented)
    references = tuple(reference_hashes)
    canonical_object = {
        "body": body,
        "metadata": metadata,
        "references": reference_hashes,
        "schema_version": 1,
    }
    canonical = json.dumps(canonical_object, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return ValidatedSkill(root, metadata, body, references, reference_hashes, canonical, fingerprint)
