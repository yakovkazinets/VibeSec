#!/usr/bin/env python3
"""Exercise every local Opengrep rule against positive and negative fixtures."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "vibesec.javascript.dangerous-eval", "vibesec.python.subprocess-shell-true",
    "vibesec.java.runtime-exec", "vibesec.go.shell-command",
}


def scan(binary: Path, source: Path, output: Path, environment: dict[str, str]) -> list[dict]:
    completed = subprocess.run([
        str(binary), "scan", "--config", str(ROOT / "rules/opengrep"),
        "--json-output", str(output), "--disable-version-check", "--no-git-ignore", str(source),
    ], cwd=ROOT, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=300, check=False)
    if completed.returncode != 0:
        raise ValueError(f"Opengrep fixture scan exited with status {completed.returncode}")
    try:
        payload = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Opengrep fixture output is malformed: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("Opengrep fixture output has no results array")
    return payload["results"]


def main() -> int:
    binary = Path(sys.argv[1]) if len(sys.argv) == 2 else ROOT / ".tools/bin/opengrep"
    try:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            positive = base / "positive"
            negative = base / "negative"
            shutil.copytree(ROOT / "tests/fixtures/opengrep/positive", positive, ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(ROOT / "tests/fixtures/opengrep/negative", negative, ignore=shutil.ignore_patterns("__pycache__"))
            environment = os.environ.copy()
            environment.update({"HOME": str(base / "home"), "XDG_CACHE_HOME": str(base / "cache"), "OPENGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"})
            positive_results = scan(binary, positive, base / "positive.json", environment)
            negative_results = scan(binary, negative, base / "negative.json", environment)
            observed = {identifier for result in positive_results for identifier in EXPECTED if str(result.get("check_id", "")).endswith(identifier)}
            if observed != EXPECTED or len(positive_results) != len(EXPECTED):
                raise ValueError(f"positive fixtures did not produce exactly the expected rules: {sorted(observed)}")
            if negative_results:
                raise ValueError("negative fixtures produced unexpected findings")
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 2
    print(f"exercised {len(EXPECTED)} Opengrep rules against positive and negative fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
