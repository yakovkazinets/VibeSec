#!/usr/bin/env python3
"""Generate deterministic finding correlation and priority artifacts."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.finding_intelligence import (  # noqa: E402
    FindingIntelligenceError, SourceDocument, build, canonical_bytes,
)
from vibesec.strict_json import StrictJSONError, loads_strict  # noqa: E402


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def load(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise FindingIntelligenceError(f"input is not a regular file: {path}")
    payload = loads_strict(path.read_bytes(), maximum_bytes=25 * 1024 * 1024)
    if not isinstance(payload, dict):
        raise FindingIntelligenceError("input must be an object")
    return payload


def fingerprints(path: Path | None, field: str) -> set[str]:
    if path is None:
        return set()
    payload = load(path)
    values = payload.get(field)
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise FindingIntelligenceError(f"{field} must be an array of strings")
    return set(values)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--source-artifact", default="normalized.json")
    parser.add_argument("--authentication-context", choices=("authenticated", "unauthenticated", "both", "unknown"), default="unknown")
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--suppressions", type=Path)
    parser.add_argument("--groups", type=Path, required=True)
    parser.add_argument("--prioritized", type=Path, required=True)
    args = parser.parse_args()
    try:
        document = load(args.input)
        groups, priorities = build([
            SourceDocument(args.profile, args.source_artifact, document, args.authentication_context),
        ], baseline=fingerprints(args.baseline, "fingerprints"),
           suppressions={item["finding_fingerprint"] for item in load(args.suppressions).get("suppressions", [])} if args.suppressions else set())
        atomic_write(args.groups, canonical_bytes(groups))
        atomic_write(args.prioritized, canonical_bytes(priorities))
    except (OSError, StrictJSONError, FindingIntelligenceError, KeyError, TypeError) as exc:
        print(f"finding intelligence failed: {exc}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
