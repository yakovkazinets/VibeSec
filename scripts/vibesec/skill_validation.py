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
FENCE_START = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
HEADING = re.compile(r"^(#{1,6})[ \t]+(.+?)\s*$")
MAPPING_LIKE = re.compile(r"^[ \t]*[A-Za-z_][A-Za-z0-9_-]*[ \t]*:")


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
class ContentSegment:
    segment_type: str
    start_line: int
    end_line: int
    text: str

    def to_dict(self) -> dict[str, object]:
        return {
            "type": self.segment_type,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "text": self.text,
        }


@dataclass(frozen=True)
class ValidatedSkill:
    root: Path
    metadata: dict[str, str]
    body: str
    references: tuple[str, ...]
    reference_hashes: dict[str, str]
    authoritative_body: str
    authoritative_segments: tuple[ContentSegment, ...]
    non_authoritative_segments: tuple[ContentSegment, ...]
    canonical: str
    fingerprint: str

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "valid",
            "metadata": self.metadata,
            "references": list(self.references),
            "reference_hashes": self.reference_hashes,
            "authoritative_body": self.authoritative_body,
            "authoritative_segments": [segment.to_dict() for segment in self.authoritative_segments],
            "non_authoritative_segments": [segment.to_dict() for segment in self.non_authoritative_segments],
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


def _segment_markdown(body: str) -> tuple[ContentSegment, ...]:
    lines = body.splitlines(keepends=True)
    in_fence: tuple[str, int] | None = None
    in_comment = False
    example_level: int | None = None
    classified: list[tuple[str, int, str]] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.rstrip("\n")
        match = FENCE_START.match(stripped)
        if in_fence is not None:
            if match:
                marker, suffix = match.groups()
                if marker[0] == in_fence[0] and len(marker) >= in_fence[1] and not suffix.strip():
                    in_fence = None
                else:
                    raise SkillValidationError("nested or malformed Markdown code fence")
            classified.append(("code_fence", line_number, line))
            continue
        if match:
            marker, suffix = match.groups()
            in_fence = (marker[0], len(marker))
            classified.append(("code_fence", line_number, line))
            continue
        if in_comment:
            if "<!--" in line:
                raise SkillValidationError("nested Markdown HTML comment")
            if "-->" in line:
                before, after = line.split("-->", 1)
                del before
                if after.strip():
                    raise SkillValidationError("HTML comment mixed with authoritative prose is ambiguous")
                in_comment = False
            classified.append(("html_comment", line_number, line))
            continue
        if "-->" in line and "<!--" not in line:
            raise SkillValidationError("Markdown contains an unmatched HTML comment close")
        if "<!--" in line:
            before, after_open = line.split("<!--", 1)
            if before.strip():
                raise SkillValidationError("HTML comment mixed with authoritative prose is ambiguous")
            if "-->" in after_open:
                _, after_close = after_open.split("-->", 1)
                if after_close.strip():
                    raise SkillValidationError("HTML comment mixed with authoritative prose is ambiguous")
            else:
                in_comment = True
            classified.append(("html_comment", line_number, line))
            continue
        heading = HEADING.match(stripped)
        if heading:
            level = len(heading.group(1))
            title = heading.group(2).strip().casefold().rstrip(":")
            if example_level is not None and level <= example_level:
                example_level = None
            if title == "example" or title == "examples" or title.startswith("example "):
                example_level = level
        if example_level is not None:
            classified.append(("example", line_number, line))
        elif line.lstrip().startswith(">"):
            classified.append(("block_quote", line_number, line))
        else:
            classified.append(("prose", line_number, line))
    if in_fence is not None:
        raise SkillValidationError("Markdown code fence is unclosed")
    if in_comment:
        raise SkillValidationError("Markdown HTML comment is unclosed")
    segments: list[ContentSegment] = []
    for segment_type, line_number, line in classified:
        if segments and segments[-1].segment_type == segment_type and segments[-1].end_line + 1 == line_number:
            previous = segments[-1]
            segments[-1] = ContentSegment(segment_type, previous.start_line, line_number, previous.text + line)
        else:
            segments.append(ContentSegment(segment_type, line_number, line_number, line))
    return tuple(segments)


def _reject_competing_front_matter(segments: tuple[ContentSegment, ...]) -> None:
    authoritative_lines: list[tuple[int, str]] = []
    for segment in segments:
        if segment.segment_type == "prose":
            authoritative_lines.extend(
                (segment.start_line + offset, line)
                for offset, line in enumerate(segment.text.splitlines())
            )
    delimiter_positions = [index for index, (_, line) in enumerate(authoritative_lines) if line.strip() == "---"]
    for position_index, opening in enumerate(delimiter_positions):
        for closing in delimiter_positions[position_index + 1 :]:
            if closing <= opening + 1:
                continue
            candidate_lines = authoritative_lines[opening + 1 : closing]
            if any(candidate_lines[index][0] + 1 != candidate_lines[index + 1][0] for index in range(len(candidate_lines) - 1)):
                continue
            candidate = "\n".join(line for _, line in candidate_lines)
            try:
                parsed = yaml.load(candidate, Loader=StrictSafeLoader)
            except (yaml.YAMLError, SkillValidationError) as exc:
                if any(MAPPING_LIKE.match(line) for _, line in candidate_lines):
                    raise SkillValidationError("ambiguous later YAML-like metadata block") from exc
                continue
            if isinstance(parsed, dict):
                raise SkillValidationError("multiple or competing front-matter blocks are prohibited")


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


def _local_references(root: Path, segments: tuple[ContentSegment, ...]) -> dict[str, str]:
    references: dict[str, str] = {}
    for segment in segments:
        if segment.segment_type != "prose":
            continue
        for raw_target in LINK_PATTERN.findall(segment.text):
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
    segments = _segment_markdown(body)
    _reject_competing_front_matter(segments)
    authoritative_segments = tuple(segment for segment in segments if segment.segment_type == "prose")
    non_authoritative_segments = tuple(segment for segment in segments if segment.segment_type != "prose")
    authoritative_body = "".join(segment.text for segment in authoritative_segments)
    reference_hashes = _local_references(root, segments)
    references = tuple(reference_hashes)
    canonical_object = {
        "segments": [segment.to_dict() for segment in segments],
        "metadata": metadata,
        "references": reference_hashes,
        "schema_version": 1,
    }
    canonical = json.dumps(canonical_object, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return ValidatedSkill(
        root, metadata, body, references, reference_hashes, authoritative_body,
        authoritative_segments, non_authoritative_segments, canonical, fingerprint,
    )
