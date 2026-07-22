#!/usr/bin/env python3
"""Harmless reference adapter that checks one repository metadata marker."""

import hashlib
import json
from pathlib import Path
import sys


def main() -> int:
    try:
        request = json.loads(sys.stdin.buffer.read(64 * 1024))
        if set(request) != {"schema_version", "repository_root", "results_dir", "profile", "capabilities", "execution_mode"} or request["schema_version"] != 1:
            raise ValueError("request schema is invalid")
        repository = Path(request["repository_root"])
        results = Path(request["results_dir"])
        marker = repository / ".vibesec-example-positive"
        findings = []
        if marker.is_file() and not marker.is_symlink():
            description = "The reference extension found its controlled repository metadata marker."
            stable = "\0".join(["vibesec.repository-metadata-example", "metadata", "controlled-marker", ".vibesec-example-positive", "1", description.lower()])
            findings.append({
                "tool": "vibesec.repository-metadata-example", "category": "metadata",
                "rule_id": "controlled-marker", "severity": "low", "file": ".vibesec-example-positive",
                "line": 1, "description": description, "confidence": "confirmed",
                "fingerprint": hashlib.sha256(stable.encode("utf-8")).hexdigest(), "result_type": "finding",
            })
        results.mkdir(parents=True, exist_ok=True)
        (results / "normalized.json").write_text(json.dumps({"schema_version": 1, "results": findings}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        response = {"schema_version": 1, "exit_code": 0, "coverage": "ran", "normalized_findings_path": "normalized.json", "artifacts": ["normalized.json"], "diagnostics": []}
        sys.stdout.write(json.dumps(response, sort_keys=True) + "\n")
        return 0
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        response = {"schema_version": 1, "exit_code": 2, "coverage": "tool_error", "normalized_findings_path": None, "artifacts": [], "diagnostics": [type(exc).__name__]}
        sys.stdout.write(json.dumps(response, sort_keys=True) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
