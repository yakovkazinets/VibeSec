#!/usr/bin/env python3
"""Validate the local, non-autofixing VibeSec Opengrep rule pack."""

from __future__ import annotations

from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_LANGUAGES = {"javascript", "typescript", "python", "java", "go"}
REQUIRED_METADATA = {
    "category", "confidence", "cwe", "framework", "language", "owasp",
    "remediation", "false_positive_notes", "license", "provenance",
}


class StrictLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader: StrictLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def validate(directory: Path) -> list[str]:
    identifiers: list[str] = []
    for path in sorted(directory.glob("*.yml")):
        try:
            payload = yaml.load(path.read_text(encoding="utf-8"), Loader=StrictLoader)
        except (OSError, UnicodeError, yaml.YAMLError, ValueError) as exc:
            raise ValueError(f"invalid rule file {path.name}: {exc}") from exc
        if not isinstance(payload, dict) or set(payload) != {"rules"} or not isinstance(payload["rules"], list):
            raise ValueError(f"{path.name} must contain only a rules array")
        for rule in payload["rules"]:
            if not isinstance(rule, dict):
                raise ValueError(f"{path.name} contains a non-object rule")
            if "fix" in rule or "fix-regex" in rule:
                raise ValueError(f"{path.name} contains a prohibited autofix")
            identifier = rule.get("id")
            languages = rule.get("languages")
            metadata = rule.get("metadata")
            if not isinstance(identifier, str) or not identifier.startswith("vibesec.") or identifier in identifiers:
                raise ValueError(f"{path.name} contains an invalid or duplicate rule id")
            if not isinstance(languages, list) or not languages or not set(languages) <= ALLOWED_LANGUAGES:
                raise ValueError(f"{identifier} contains unsupported languages")
            if not isinstance(metadata, dict) or set(metadata) != REQUIRED_METADATA:
                raise ValueError(f"{identifier} must define the exact reviewed metadata fields")
            if metadata.get("license") != "Apache-2.0" or metadata.get("provenance") != "original-vibesec":
                raise ValueError(f"{identifier} has invalid license or provenance")
            for field in REQUIRED_METADATA:
                if not isinstance(metadata.get(field), str) or not metadata[field].strip():
                    raise ValueError(f"{identifier} metadata {field} must be a non-empty string")
            identifiers.append(identifier)
    if not identifiers:
        raise ValueError("no Opengrep rules found")
    return identifiers


def main() -> int:
    try:
        identifiers = validate(ROOT / "rules/opengrep")
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 3
    print(f"validated {len(identifiers)} VibeSec Opengrep rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
