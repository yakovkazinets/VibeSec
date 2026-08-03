#!/usr/bin/env python3
"""Validate v1 human/machine documentation parity, links, examples, and drift."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from vibesec.agents import ADAPTER_IDS, TASK_IDS  # noqa: E402
from vibesec.strict_json import StrictJSONError, loads_strict  # noqa: E402
from vibesec.v1_contract import (  # noqa: E402
    V1ContractError, validate_catalogs, validate_examples,
)

LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
ABSOLUTE_RUNNER = re.compile(r"(?:/home/runner/|[A-Za-z]:\\(?:actions|runner)\\)", re.IGNORECASE)
SECRET_LIKE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|Bearer [A-Za-z0-9._-]{20,})"
)
MAP_FIELDS = {
    "schema_version", "stable_id", "status", "source_of_truth",
    "generated_reference", "curated_index", "domain_catalogs", "curated_documents",
}


def _slug(value: str) -> str:
    value = re.sub(r"<[^>]+>", "", value.strip().casefold())
    value = re.sub(r"[^\w\- ]", "", value, flags=re.UNICODE)
    return re.sub(r" +", "-", value)


def _anchors(path: Path) -> set[str]:
    result: set[str] = set()
    counts: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not re.match(r"^#{1,6} ", line):
            continue
        base = _slug(line.lstrip("#").strip())
        count = counts.get(base, 0)
        result.add(base if count == 0 else f"{base}-{count}")
        counts[base] = count + 1
    return result


def _validate_links(documents: list[Path]) -> None:
    for document in documents:
        text = document.read_text(encoding="utf-8")
        if ABSOLUTE_RUNNER.search(text):
            raise V1ContractError(f"{document.relative_to(ROOT)} contains an absolute runner path")
        if SECRET_LIKE.search(text):
            raise V1ContractError(f"{document.relative_to(ROOT)} contains credential-like material")
        for raw in LINK.findall(text):
            target = unquote(raw.split(maxsplit=1)[0].strip("<>"))
            if target.startswith(("https://", "http://", "mailto:")):
                continue
            path_text, _, anchor = target.partition("#")
            candidate = document if not path_text else (document.parent / path_text).resolve()
            try:
                candidate.relative_to(ROOT)
            except ValueError as exc:
                raise V1ContractError(f"{document.relative_to(ROOT)} link escapes repository: {target}") from exc
            if not candidate.exists():
                raise V1ContractError(f"{document.relative_to(ROOT)} link is missing: {target}")
            if anchor and candidate.suffix == ".md" and anchor not in _anchors(candidate):
                raise V1ContractError(f"{document.relative_to(ROOT)} anchor is missing: {target}")


def _load_map() -> dict:
    path = ROOT / "machine/documentation-map.json"
    try:
        value = loads_strict(path.read_bytes())
    except (OSError, StrictJSONError) as exc:
        raise V1ContractError(f"documentation map is invalid: {exc}") from exc
    if (not isinstance(value, dict) or set(value) != MAP_FIELDS
            or value.get("schema_version") != 1
            or value.get("stable_id") != "vibesec.documentation-map.v1"
            or value.get("status") != "stable"):
        raise V1ContractError("documentation map has unknown, missing, or invalid fields")
    return value


def _parity(catalogs: dict[str, dict]) -> None:
    capabilities = json.loads((ROOT / "config/security-capabilities.json").read_text(encoding="utf-8"))
    expected_capabilities = {item["id"] for item in capabilities["capabilities"]}
    if set(catalogs["capabilities"]["members"]) != expected_capabilities | {"vibesec.capabilities.registry"}:
        raise V1ContractError("capability documentation differs from the capability matrix")
    tools = json.loads((ROOT / "config/tools.json").read_text(encoding="utf-8"))["tools"]
    if set(catalogs["scanners"]["members"]) != set(tools) | {"vibesec.scanners.registry"}:
        raise V1ContractError("scanner documentation differs from the tool inventory")
    templates = {str(path.relative_to(ROOT)) for path in (ROOT / "templates/github-actions").glob("*.yml")}
    workflows = {str(path.relative_to(ROOT)) for path in (ROOT / ".github/workflows").glob("*.yml")}
    if set(catalogs["workflows"]["members"]) != templates | workflows | {"vibesec.workflows.contract"}:
        raise V1ContractError("workflow documentation differs from distributed workflows")
    schemas = {
        str(path.relative_to(ROOT))
        for base in (ROOT / "config", ROOT / "machine/schemas")
        for path in base.glob("*schema*.json")
    }
    if not schemas.issubset(catalogs["artifacts"]["statuses"]):
        raise V1ContractError("artifact documentation omits a public schema")
    extension_schema = json.loads((ROOT / "config/extension-manifest-schema.json").read_text(encoding="utf-8"))
    kinds = set(extension_schema["properties"]["kind"]["enum"])
    documented_kinds = {
        member.removeprefix("extension.kind.")
        for member in catalogs["extensions"]["members"] if member.startswith("extension.kind.")
    }
    if kinds != documented_kinds:
        raise V1ContractError("extension-kind documentation differs from its schema")
    expected_agents = (
        {f"agent.adapter.{item}" for item in ADAPTER_IDS}
        | {f"agent.task.{item}" for item in TASK_IDS}
    )
    if not expected_agents.issubset(catalogs["agents"]["statuses"]):
        raise V1ContractError("agent adapter or task documentation is incomplete")
    help_result = subprocess.run(
        [sys.executable, str(ROOT / "vibesec"), "--help"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=10, check=False,
    )
    if help_result.returncode != 0:
        raise V1ContractError("CLI help failed")
    commands = {"scan", "doctor", "verify", "init", "upgrade-plan", "extensions", "agents"}
    if any(command not in help_result.stdout for command in commands):
        raise V1ContractError("CLI documentation omits an implemented root command")


def main() -> int:
    try:
        inventory, catalogs = validate_catalogs(ROOT)
        validate_examples(ROOT)
        mapping = _load_map()
        documents = [ROOT / path for path in mapping["curated_documents"]]
        catalogs_paths = [ROOT / path for path in mapping["domain_catalogs"]]
        if any(not path.is_file() for path in documents + catalogs_paths):
            raise V1ContractError("documentation map references a missing file")
        if set(catalogs_paths) != {ROOT / f"machine/{name}.json" for name in catalogs}:
            raise V1ContractError("documentation map does not exactly cover domain catalogs")
        referenced_docs = {
            item.split("#", 1)[0]
            for interface in inventory["interfaces"]
            for item in interface["human_documentation"]
        }
        index_text = (ROOT / mapping["curated_index"]).read_text(encoding="utf-8")
        for path in mapping["curated_documents"]:
            if path == mapping["curated_index"]:
                continue
            if path not in referenced_docs and Path(path).name not in index_text:
                raise V1ContractError(f"human document is not mapped from machine metadata or index: {path}")
        _parity(catalogs)
        _validate_links(documents)
        generated = subprocess.run(
            [sys.executable, str(ROOT / "scripts/generate_v1_reference.py"), "--check"],
            cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=30, check=False,
        )
        if generated.returncode != 0:
            raise V1ContractError(generated.stderr.strip() or "generated documentation is stale")
        machine_text = "\n".join(
            path.read_text(encoding="utf-8") for path in catalogs_paths + [ROOT / "machine/interfaces.json"]
        )
        if ABSOLUTE_RUNNER.search(machine_text):
            raise V1ContractError("machine documentation contains an absolute runner path")
        print(
            f"validated {len(documents)} human documents, {len(catalogs)} catalogs, "
            f"{len(inventory['interfaces'])} interfaces, and 11 examples"
        )
        return 0
    except (OSError, UnicodeError, ValueError, V1ContractError) as exc:
        print(f"documentation contract invalid: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
