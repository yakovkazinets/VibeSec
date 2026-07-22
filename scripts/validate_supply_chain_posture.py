#!/usr/bin/env python3
"""Offline, deterministic repository supply-chain posture validation."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
FULL_SHA = re.compile(r"@[0-9a-f]{40}(?:\s|$)")
WORKFLOW = ROOT / ".github/workflows/release-candidate.yml"


def validate(root: Path = ROOT) -> dict[str, object]:
    controls: list[dict[str, object]] = []

    def check(name: str, passed: bool, evidence: str) -> None:
        controls.append({"control": name, "passed": bool(passed), "evidence": evidence})

    workflow = (root / ".github/workflows/release-candidate.yml").read_text(encoding="utf-8")
    signer = (root / "scripts/sign_release_artifacts.py").read_text(encoding="utf-8")
    workflows = sorted((root / ".github/workflows").glob("*.y*ml")) + sorted((root / "templates/github-actions").glob("*.y*ml"))
    all_workflow_text = "\n".join(path.read_text(encoding="utf-8") for path in workflows)
    action_lines = [line.strip() for line in all_workflow_text.splitlines() if "uses:" in line]
    check("pinned-actions", bool(action_lines) and all(FULL_SHA.search(line) for line in action_lines), "all action uses are full commits")
    check("least-permissions", "permissions:\n  contents: read" in workflow and "id-token: write" in workflow, "read-only workflow with job-scoped OIDC")
    check("trusted-trigger", "workflow_dispatch:" in workflow and "pull_request:" not in workflow and "pull_request_target" not in workflow and "push:" not in workflow, "manual only")
    check("trusted-source", "github.ref == 'refs/heads/main'" in workflow and "github.repository == 'yakovkazinets/VibeSec'" in workflow, "repository and main ref constrained")
    check("no-publication", all(marker not in workflow for marker in ("gh release", "git tag", "git push", "npm publish", "twine upload")), "release candidate upload only")
    check("security-policy", (root / "SECURITY.md").is_file(), "SECURITY.md")
    check("dependency-policy", "dependency" in (root / "CONTRIBUTING.md").read_text(encoding="utf-8").casefold(), "CONTRIBUTING.md")
    check("release-process", (root / "docs/release-signing.md").is_file() and (root / "docs/provenance.md").is_file(), "reviewed release documentation")
    check("provenance", "prepare_release_artifacts.py" in workflow and "verify_release_artifacts.py" in workflow, "provenance generated and verified")
    check("signed-artifacts", "sign_release_artifacts.py" in workflow and "sign-blob" in signer and "--require-signature" in workflow, "keyless checksum signature")
    check("binary-policy", "binary" in (root / "docs/software-supply-chain-assurance.md").read_text(encoding="utf-8").casefold(), "binary artifact policy documented")
    return {"schema_version": 1, "offline": True, "controls": controls, "passed": all(item["passed"] for item in controls)}


def main() -> int:
    try:
        payload = validate()
    except (OSError, UnicodeError) as exc:
        print(json.dumps({"schema_version": 1, "passed": False, "error": type(exc).__name__}, sort_keys=True))
        return 3
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0 if payload["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
