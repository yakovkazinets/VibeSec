"""Strict v1 public-interface, documentation, migration, and readiness contracts."""

from __future__ import annotations

from pathlib import Path
import re
import unicodedata
from typing import Any

from .strict_json import StrictJSONError, canonical_json, loads_strict

SCHEMA_VERSION = 1
STATUSES = {"stable", "experimental", "conditionally_enforced", "deprecated", "internal"}
COVERAGE_STATES = ("ran", "not_applicable", "not_configured", "tool_error")
REQUIRED_STATUS = "validate"
MAX_DOCUMENT_BYTES = 1_000_000
ID = re.compile(r"^vibesec\.[a-z0-9]+(?:[._-][a-z0-9]+)*$")
RELATIVE = re.compile(r"^(?!/)(?![A-Za-z]:[\\/])(?!.*(?:^|/)\.\.(?:/|$))[^\x00-\x1f\\]+$")

INTERFACE_FIELDS = {
    "schema_version", "stable_id", "status", "summary", "owning_component",
    "dependencies", "configuration", "inputs", "outputs", "artifacts",
    "coverage_states", "exit_behavior", "security_boundaries", "limitations",
    "human_documentation", "owning_source_files", "machine_schema",
    "compatibility_guarantees", "deprecation_policy", "migration_notes",
}
DOMAIN_FIELDS = {
    "schema_version", "stable_id", "status", "summary", "source",
    "human_documentation", "members", "statuses",
}
CATALOGS = (
    "project", "capabilities", "profiles", "scanners", "workflows", "cli",
    "configuration", "policies", "artifacts", "findings", "extensions",
    "agents", "release", "compatibility",
)


class V1ContractError(ValueError):
    """A v1 contract document is ambiguous, incomplete, or inconsistent."""


def _load(path: Path) -> Any:
    try:
        return loads_strict(path.read_bytes(), maximum_bytes=MAX_DOCUMENT_BYTES)
    except (OSError, StrictJSONError) as exc:
        raise V1ContractError(f"{path}: {exc}") from exc


def _text(value: Any, field: str, *, maximum: int = 500) -> str:
    if (not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum
            or value != unicodedata.normalize("NFC", value)
            or any(unicodedata.category(character) in {"Cc", "Cs"} for character in value)):
        raise V1ContractError(f"{field} must be bounded NFC text without controls")
    return value


def _string_list(value: Any, field: str, *, paths: bool = False,
                 maximum: int = 256) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise V1ContractError(f"{field} must be a bounded array")
    result: list[str] = []
    for index, item in enumerate(value):
        text = _text(item, f"{field}[{index}]", maximum=1000)
        if paths and not RELATIVE.fullmatch(text):
            raise V1ContractError(f"{field}[{index}] must be a repository-relative POSIX path")
        result.append(text)
    if len(set(result)) != len(result):
        raise V1ContractError(f"{field} contains duplicates")
    return result


def _existing_paths(root: Path, values: list[str], field: str) -> None:
    for value in values:
        path, _, anchor = value.partition("#")
        candidate = root / path
        if not candidate.is_file():
            raise V1ContractError(f"{field} references missing file: {path}")
        if anchor and candidate.suffix == ".md":
            headings = {
                re.sub(r"[^a-z0-9 -]", "", line.lstrip("#").strip().casefold()).replace(" ", "-")
                for line in candidate.read_text(encoding="utf-8").splitlines()
                if line.startswith("#")
            }
            if anchor not in headings:
                raise V1ContractError(f"{field} references missing anchor: {value}")


def validate_interface(value: Any, root: Path) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != INTERFACE_FIELDS:
        raise V1ContractError("public interface has unknown or missing fields")
    if value.get("schema_version") != SCHEMA_VERSION or isinstance(value["schema_version"], bool):
        raise V1ContractError("public interface schema_version must be 1")
    stable_id = _text(value.get("stable_id"), "stable_id")
    if not ID.fullmatch(stable_id):
        raise V1ContractError(f"invalid stable ID: {stable_id}")
    if value.get("status") not in STATUSES:
        raise V1ContractError(f"{stable_id} has an invalid status")
    for field in (
        "summary", "owning_component", "exit_behavior", "deprecation_policy",
    ):
        _text(value.get(field), f"{stable_id}.{field}", maximum=2000)
    for field in (
        "dependencies", "configuration", "inputs", "outputs", "artifacts",
        "security_boundaries", "limitations", "compatibility_guarantees",
        "migration_notes",
    ):
        _string_list(value.get(field), f"{stable_id}.{field}")
    states = _string_list(value.get("coverage_states"), f"{stable_id}.coverage_states")
    if any(state not in COVERAGE_STATES for state in states):
        raise V1ContractError(f"{stable_id} declares an unknown coverage state")
    docs = _string_list(
        value.get("human_documentation"), f"{stable_id}.human_documentation", paths=True,
    )
    sources = _string_list(
        value.get("owning_source_files"), f"{stable_id}.owning_source_files", paths=True,
    )
    schemas = _string_list(
        value.get("machine_schema"), f"{stable_id}.machine_schema", paths=True,
    )
    if value["status"] == "stable" and (not docs or not schemas):
        raise V1ContractError(f"stable interface {stable_id} requires documentation and schema")
    _existing_paths(root, docs, f"{stable_id}.human_documentation")
    _existing_paths(root, sources, f"{stable_id}.owning_source_files")
    _existing_paths(root, schemas, f"{stable_id}.machine_schema")
    return value


def validate_interfaces(root: Path) -> dict[str, Any]:
    path = root / "machine/interfaces.json"
    value = _load(path)
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "stable_id", "status", "summary", "required_status",
        "coverage_states", "interfaces",
    }:
        raise V1ContractError("machine/interfaces.json has unknown or missing fields")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise V1ContractError("interface inventory schema_version must be 1")
    if value.get("stable_id") != "vibesec.interfaces.v1" or value.get("status") != "stable":
        raise V1ContractError("interface inventory identity is invalid")
    _text(value.get("summary"), "interfaces.summary", maximum=2000)
    if value.get("required_status") != REQUIRED_STATUS:
        raise V1ContractError("required aggregate status must remain exactly validate")
    if value.get("coverage_states") != list(COVERAGE_STATES):
        raise V1ContractError("coverage-state order or meaning changed")
    interfaces = value.get("interfaces")
    if not isinstance(interfaces, list) or not interfaces or len(interfaces) > 256:
        raise V1ContractError("interface inventory must contain a bounded nonempty array")
    seen: set[str] = set()
    for item in interfaces:
        validate_interface(item, root)
        stable_id = item["stable_id"]
        if stable_id in seen:
            raise V1ContractError(f"duplicate interface ID: {stable_id}")
        seen.add(stable_id)
    return value


def validate_domain(root: Path, name: str) -> dict[str, Any]:
    path = root / f"machine/{name}.json"
    value = _load(path)
    if not isinstance(value, dict) or set(value) != DOMAIN_FIELDS:
        raise V1ContractError(f"machine/{name}.json has unknown or missing fields")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise V1ContractError(f"machine/{name}.json schema_version must be 1")
    stable_id = _text(value.get("stable_id"), f"{name}.stable_id")
    if stable_id != f"vibesec.catalog.{name}" or value.get("status") not in STATUSES:
        raise V1ContractError(f"machine/{name}.json identity or status is invalid")
    _text(value.get("summary"), f"{name}.summary", maximum=2000)
    source = _text(value.get("source"), f"{name}.source", maximum=1000)
    if not RELATIVE.fullmatch(source) or not (root / source).is_file():
        raise V1ContractError(f"machine/{name}.json source is missing or unsafe")
    docs = _string_list(
        value.get("human_documentation"), f"{name}.human_documentation", paths=True,
    )
    _existing_paths(root, docs, f"{name}.human_documentation")
    members = _string_list(value.get("members"), f"{name}.members", maximum=1000)
    statuses = value.get("statuses")
    if (not isinstance(statuses, dict) or set(statuses) != set(members)
            or any(status not in STATUSES for status in statuses.values())):
        raise V1ContractError(f"machine/{name}.json status map must exactly cover members")
    if list(statuses) != sorted(statuses):
        raise V1ContractError(f"machine/{name}.json status map must be sorted")
    return value


def validate_catalogs(root: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    inventory = validate_interfaces(root)
    catalogs = {name: validate_domain(root, name) for name in CATALOGS}
    inventory_ids = {item["stable_id"] for item in inventory["interfaces"]}
    domain_ids = {member for catalog in catalogs.values() for member in catalog["members"]}
    missing = sorted(inventory_ids - domain_ids)
    if missing:
        raise V1ContractError(f"public interfaces missing from domain catalogs: {', '.join(missing)}")
    return inventory, catalogs


def validate_examples(root: Path) -> dict[str, Any]:
    value = _load(root / "machine/examples.json")
    fields = {"schema_version", "stable_id", "status", "examples"}
    example_fields = {"stable_id", "summary", "fixture", "commands", "human_documentation"}
    if not isinstance(value, dict) or set(value) != fields or value.get("schema_version") != 1:
        raise V1ContractError("example catalog has unknown or missing fields")
    if value.get("stable_id") != "vibesec.examples.v1" or value.get("status") != "stable":
        raise V1ContractError("example catalog identity is invalid")
    examples = value.get("examples")
    if not isinstance(examples, list) or len(examples) != 11:
        raise V1ContractError("example catalog must contain exactly eleven adoption patterns")
    for item in examples:
        if not isinstance(item, dict) or set(item) != example_fields:
            raise V1ContractError("example has unknown or missing fields")
        _text(item["stable_id"], "example.stable_id")
        _text(item["summary"], "example.summary")
        fixture = _text(item["fixture"], "example.fixture")
        if not RELATIVE.fullmatch(fixture) or not (root / fixture).exists():
            raise V1ContractError(f"example fixture is missing or unsafe: {fixture}")
        commands = _string_list(item["commands"], "example.commands")
        if not commands or any(
            token in command
            for command in commands
            for token in ("curl http://", "curl https://", "Authorization:", "Bearer ", "password=")
        ):
            raise V1ContractError("examples must use non-secret, non-public-target commands")
        docs = _string_list(item["human_documentation"], "example.human_documentation", paths=True)
        _existing_paths(root, docs, "example.human_documentation")
    return value


def validate_migrations(root: Path) -> dict[str, Any]:
    value = _load(root / "machine/migrations.json")
    fields = {"schema_version", "stable_id", "status", "preservation_contract", "records"}
    record_fields = {
        "stable_id", "from", "installation", "fixture", "fixture_id", "preserves",
        "conflict_behavior", "secret_handling", "expected_exit",
    }
    if not isinstance(value, dict) or set(value) != fields or value.get("schema_version") != 1:
        raise V1ContractError("migration catalog has unknown or missing fields")
    if value.get("stable_id") != "vibesec.migrations.v1" or value.get("status") != "stable":
        raise V1ContractError("migration catalog identity is invalid")
    preservation = _string_list(value.get("preservation_contract"), "migration.preservation_contract")
    required = {
        "explicit_answers", "explicit_no_answers", "baselines", "suppressions",
        "local_workflow_customizations", "user_agent_files", "extension_states",
        "disabled_adapters", "secret_names_only", "unrelated_files",
    }
    if set(preservation) != required:
        raise V1ContractError("migration preservation contract is incomplete")
    records = value.get("records")
    if not isinstance(records, list) or len(records) != 11:
        raise V1ContractError("migration catalog must cover exactly eleven representative paths")
    fixture_ids: set[str] = set()
    fixture_paths: set[Path] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != record_fields:
            raise V1ContractError("migration record has unknown or missing fields")
        _text(record["stable_id"], "migration.stable_id")
        _text(record["from"], "migration.from")
        _text(record["installation"], "migration.installation")
        fixture = _text(record["fixture"], "migration.fixture")
        if not RELATIVE.fullmatch(fixture) or not (root / fixture).is_file():
            raise V1ContractError(f"migration fixture is missing or unsafe: {fixture}")
        _text(record["fixture_id"], "migration.fixture_id")
        fixture_ids.add(record["fixture_id"])
        fixture_paths.add(root / fixture)
        if not required.issuperset(_string_list(record["preserves"], "migration.preserves")):
            raise V1ContractError("migration record contains an unknown preservation claim")
        if record["conflict_behavior"] != "report_without_overwrite":
            raise V1ContractError("migration conflicts must never be silently overwritten")
        if record["secret_handling"] != "preserve_name_never_value":
            raise V1ContractError("migration secret contract changed")
        if record["expected_exit"] not in {0, 1, 2, 3, 4} or isinstance(record["expected_exit"], bool):
            raise V1ContractError("migration expected exit is invalid")
    if len(fixture_paths) != 1:
        raise V1ContractError("migration records must use the reviewed fixture catalog")
    fixture = _load(next(iter(fixture_paths)))
    fixture_fields = {
        "id", "source_version", "installation", "explicit_answers", "baselines",
        "suppressions", "local_workflows", "user_agent_files", "extension_states",
        "disabled_adapters", "secret_names", "secret_values_present", "unrelated_files",
    }
    if not isinstance(fixture, dict) or set(fixture) != {"schema_version", "fixtures"} or fixture.get("schema_version") != 1:
        raise V1ContractError("migration fixture catalog fields or schema are invalid")
    fixtures = fixture.get("fixtures")
    if not isinstance(fixtures, list) or len(fixtures) != 11:
        raise V1ContractError("migration fixture catalog must contain exactly eleven installations")
    seen: set[str] = set()
    for item in fixtures:
        if not isinstance(item, dict) or set(item) != fixture_fields:
            raise V1ContractError("migration fixture has unknown or missing fields")
        identifier = _text(item["id"], "migration.fixture.id")
        if identifier in seen:
            raise V1ContractError("migration fixture IDs must be unique")
        seen.add(identifier)
        answers = item["explicit_answers"]
        if (not isinstance(answers, dict) or not answers
                or not all(isinstance(key, str) and type(answer) is bool for key, answer in answers.items())
                or False not in answers.values()):
            raise V1ContractError("migration fixture must preserve explicit answers including No")
        for field in (
            "baselines", "suppressions", "local_workflows", "user_agent_files",
            "disabled_adapters", "secret_names", "unrelated_files",
        ):
            if not _string_list(item[field], f"migration.fixture.{field}", paths=field not in {"disabled_adapters", "secret_names"}):
                raise V1ContractError(f"migration fixture {field} must be nonempty")
        if not isinstance(item["extension_states"], dict) or not item["extension_states"]:
            raise V1ContractError("migration fixture extension state must be explicit")
        if item["secret_values_present"] is not False:
            raise V1ContractError("migration fixtures must never contain secret values")
    if seen != fixture_ids:
        raise V1ContractError("migration records and fixture IDs differ")
    return value


def validate_readiness(value: Any, *, source_commit: str | None = None) -> dict[str, Any]:
    fields = {
        "schema_version", "stable_id", "status", "version", "main_commit",
        "schema_versions", "interface_statuses", "test_totals", "platform_support",
        "known_limitations", "deferred_features", "experimental_features",
        "threat_model_review", "release_artifact_verification",
        "migration_coverage", "documentation_coverage", "unresolved_risks",
        "release_blockers",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise V1ContractError("release readiness report has unknown or missing fields")
    if value.get("schema_version") != 1 or value.get("stable_id") != "vibesec.release-readiness.v1":
        raise V1ContractError("release readiness identity is invalid")
    if value.get("status") not in {"ready", "ready_with_known_limitations", "blocked"}:
        raise V1ContractError("release readiness status is invalid")
    if not isinstance(value.get("main_commit"), str) or not re.fullmatch(r"[0-9a-f]{40}", value["main_commit"]):
        raise V1ContractError("release readiness main commit is invalid")
    if source_commit is not None and value["main_commit"] != source_commit:
        raise V1ContractError("release readiness main commit differs from requested source")
    _text(value.get("version"), "readiness.version")
    for field in ("schema_versions", "interface_statuses", "test_totals", "platform_support"):
        mapping = value.get(field)
        if not isinstance(mapping, dict) or not mapping:
            raise V1ContractError(f"release readiness {field} must be a nonempty object")
    for field in (
        "known_limitations", "deferred_features", "experimental_features",
        "unresolved_risks", "release_blockers",
    ):
        _string_list(value.get(field), f"readiness.{field}")
    for field in (
        "threat_model_review", "release_artifact_verification",
        "migration_coverage", "documentation_coverage",
    ):
        _text(value.get(field), f"readiness.{field}", maximum=2000)
    if value["status"] != "blocked" and value["release_blockers"]:
        raise V1ContractError("non-blocked readiness cannot contain release blockers")
    if value["status"] == "blocked" and not value["release_blockers"]:
        raise V1ContractError("blocked readiness requires release blockers")
    return value


def load_readiness(path: Path, *, source_commit: str | None = None) -> dict[str, Any]:
    return validate_readiness(_load(path), source_commit=source_commit)


def canonical_readiness(value: dict[str, Any]) -> bytes:
    validate_readiness(value)
    return canonical_json(value)


def build_readiness(root: Path, *, main_commit: str, test_total: int,
                    test_evidence: str) -> dict[str, Any]:
    inventory, catalogs = validate_catalogs(root)
    validate_examples(root)
    migrations = validate_migrations(root)
    if not re.fullmatch(r"[0-9a-f]{40}", main_commit):
        raise V1ContractError("release readiness requires a full lowercase main commit")
    if not isinstance(test_total, int) or isinstance(test_total, bool) or test_total < 1:
        raise V1ContractError("release readiness requires a positive automated test total")
    _text(test_evidence, "readiness.test_evidence")
    statuses = {status: 0 for status in sorted(STATUSES)}
    for item in inventory["interfaces"]:
        statuses[item["status"]] += 1
    value = {
        "schema_version": 1,
        "stable_id": "vibesec.release-readiness.v1",
        "status": "ready_with_known_limitations",
        "version": (root / "VERSION").read_text(encoding="utf-8").strip(),
        "main_commit": main_commit,
        "schema_versions": {
            "agent_contract": 1,
            "domain_catalog": 1,
            "public_interface": 1,
            "release_manifest": 1,
            "release_readiness": 1,
        },
        "interface_statuses": statuses,
        "test_totals": {
            "automated_tests": test_total,
            "evidence": test_evidence,
            "migration_paths": len(migrations["records"]),
            "machine_catalogs": len(catalogs),
        },
        "platform_support": {
            member: catalogs["compatibility"]["statuses"][member]
            for member in catalogs["compatibility"]["members"]
        },
        "known_limitations": [
            "Scanner coverage is incomplete and a clean result is not proof of security.",
            "Complete native Minimal and Standard scanning is currently validated only on Linux x86_64.",
            "Live Docker targets and GitHub OIDC signing require separately controlled environments.",
            "Installed extension code and external agent behavior remain maintainer trust decisions.",
        ],
        "deferred_features": [
            "Complete profile container runners.",
            "Native Windows profile execution.",
            "Comprehensive DAST, general-purpose fuzzing, IAST, and runtime protection.",
        ],
        "experimental_features": [
            "Portable container and auto mode availability beyond validated native combinations.",
            "GitHub Enterprise Server integration.",
        ],
        "threat_model_review": "Complete for documented v1 boundaries; residual risks are listed and no security guarantee is made.",
        "release_artifact_verification": "Deterministic bundle, manifest, SBOM, readiness, provenance, checksum, tampering, and controlled signature paths are verified.",
        "migration_coverage": "Eleven representative paths cover v0.1.0, v0.2.0, current pre-v1, profiles, runtime add-ons, extensions, and agents.",
        "documentation_coverage": "Strict machine catalogs map to curated documentation and reproducible generated reference tables.",
        "unresolved_risks": [
            "Live platform and third-party service behavior can differ from controlled offline tests.",
            "Security scanners and maintained rules can miss vulnerabilities or report false positives.",
        ],
        "release_blockers": [],
    }
    return validate_readiness(value, source_commit=main_commit)
