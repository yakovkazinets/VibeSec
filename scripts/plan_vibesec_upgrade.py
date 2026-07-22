#!/usr/bin/env python3
"""Generate a deterministic read-only upgrade plan from a verified local bundle."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vibesec.bundle import BundleError, VerifiedBundle, validate_catalog, verify_bundle  # noqa: E402
from vibesec.exit_codes import INFRASTRUCTURE_FAILURE, INVALID_INPUT, SUCCESS, VERIFICATION_FAILED, WARNINGS  # noqa: E402
from vibesec.installation import InstallationError, PRESERVATION_SENSITIVE, InstallationState, verify_installation  # noqa: E402
from vibesec.output import emit, envelope  # noqa: E402
from vibesec.strict_json import loads_strict  # noqa: E402
from vibesec.version import VersionError, read_version  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CLASSIFICATIONS = {
    "unchanged", "add", "upstream_changed_local_unmodified", "locally_modified_upstream_unchanged",
    "both_modified", "remove_candidate", "baseline_preserve", "suppression_preserve",
    "policy_review_required", "workflow_support_version_mismatch", "unknown_legacy_state",
    "conflict", "unsafe_path",
}


def desired_files(bundle: VerifiedBundle, state: InstallationState) -> dict[str, dict[str, Any]]:
    catalog = validate_catalog(loads_strict(bundle.entries["config/adoption-files.json"]))
    mappings: dict[str, str] = {}
    stages = {(item["profile"], item["stage"]) for item in state.manifests}
    for profile, stage in stages:
        config = catalog["profiles"][profile]
        if stage in {"all", "support"}:
            for source in [*catalog["common"], *config["support"]]:
                mappings[source] = source
        if stage in {"all", "workflow"}:
            mappings[config["workflow_destination"]] = config["workflow_source"]
    return {
        destination: {
            "source_path": source,
            "sha256": hashlib.sha256(bundle.entries[source]).hexdigest(),
            "mode": bundle.modes[source],
        }
        for destination, source in sorted(mappings.items())
    }


def classify_plan(state: InstallationState, bundle: VerifiedBundle) -> dict[str, Any]:
    proposed = desired_files(bundle, state)
    current = {item["path"]: item for item in state.files}
    paths = sorted(set(proposed) | set(current))
    records: list[dict[str, Any]] = []
    installed_version = state.version
    for path in paths:
        old = current.get(path)
        new = proposed.get(path)
        expected_old = old.get("expected_sha256") if old else None
        actual = old.get("actual_sha256") if old else None
        expected_new = new.get("sha256") if new else None
        if path == "policy/baseline.json" or path == "policy/standard-baseline.json":
            classification = "baseline_preserve"
        elif path == "policy/suppressions.yml":
            classification = "suppression_preserve"
        elif old is None:
            classification = "add"
        elif new is None:
            classification = "remove_candidate"
        elif expected_old is None:
            classification = "unknown_legacy_state"
        elif path.startswith(".github/workflows/") and installed_version != bundle.version:
            classification = "workflow_support_version_mismatch"
        elif path.startswith("policy/") and expected_old != expected_new:
            classification = "policy_review_required"
        elif actual == expected_old == expected_new:
            classification = "unchanged"
        elif actual == expected_old and expected_old != expected_new:
            classification = "upstream_changed_local_unmodified"
        elif actual != expected_old and expected_old == expected_new:
            classification = "locally_modified_upstream_unchanged"
        elif actual != expected_old and expected_old != expected_new:
            classification = "both_modified"
        else:
            classification = "conflict"
        preservation = path in PRESERVATION_SENSITIVE or path.startswith("policy/") or path.startswith(".github/workflows/") or "ignore" in path
        records.append({
            "path": path, "classification": classification,
            "current_expected_sha256": expected_old, "current_actual_sha256": actual,
            "proposed_sha256": expected_new, "preservation_sensitive": preservation,
        })
    counts: dict[str, int] = {}
    for record in records:
        counts[record["classification"]] = counts.get(record["classification"], 0) + 1
    manual = [record["path"] for record in records if record["classification"] in {
        "both_modified", "baseline_preserve", "suppression_preserve", "policy_review_required",
        "workflow_support_version_mismatch", "unknown_legacy_state", "conflict", "unsafe_path",
    }]
    additions = [record["path"] for record in records if record["classification"] == "add"]
    plan = {
        "current_installed_version": installed_version,
        "proposed_bundle_version": bundle.version,
        "current_source_type": state.source_type,
        "proposed_source_commit": bundle.source_commit,
        "profiles": state.profiles,
        "stages": sorted({manifest["stage"] for manifest in state.manifests}),
        "summary": dict(sorted(counts.items())),
        "files": records,
        "files_to_preserve": sorted(record["path"] for record in records if record["preservation_sensitive"]),
        "files_safe_to_add": additions,
        "files_requiring_manual_merge": sorted(manual),
        "scanner_pin_changes": ["config/tools.json"] if any(record["path"] == "config/tools.json" and record["classification"] != "unchanged" for record in records) else [],
        "workflow_pin_changes": sorted(record["path"] for record in records if record["path"].startswith(".github/workflows/") and record["classification"] != "unchanged"),
        "policy_changes": sorted(record["path"] for record in records if record["path"].startswith("policy/") and record["classification"] != "unchanged"),
        "expected_security_impact": "Review scanner, workflow, and policy changes; bundle validity does not establish application security.",
        "privacy_impact": "Review configuration and workflow changes for network, registry, report, and SBOM handling.",
        "rollback_reminder": "Back up local policy, test in a branch, and retain the prior version-compatible file set; no changes were applied.",
        "read_only": True,
    }
    validate_upgrade_plan(plan)
    return plan


def validate_upgrade_plan(plan: Any) -> dict[str, Any]:
    required = {
        "current_installed_version", "proposed_bundle_version", "current_source_type", "proposed_source_commit",
        "profiles", "stages", "summary", "files", "files_to_preserve", "files_safe_to_add",
        "files_requiring_manual_merge", "scanner_pin_changes", "workflow_pin_changes", "policy_changes",
        "expected_security_impact", "privacy_impact", "rollback_reminder", "read_only",
    }
    if not isinstance(plan, dict) or set(plan) != required or plan.get("read_only") is not True:
        raise ValueError("upgrade plan schema or fields are invalid")
    files = plan.get("files")
    if not isinstance(files, list) or len(files) > 256:
        raise ValueError("upgrade plan file list is invalid")
    for record in files:
        if not isinstance(record, dict) or record.get("classification") not in CLASSIFICATIONS or not isinstance(record.get("path"), str):
            raise ValueError("upgrade plan file record is invalid")
    if set(plan.get("summary", {})) - CLASSIFICATIONS:
        raise ValueError("upgrade plan summary is invalid")
    return plan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        tool_version = read_version(ROOT)
    except VersionError:
        tool_version = "unknown"
    try:
        bundle = verify_bundle(args.bundle)
    except BundleError as exc:
        emit(envelope("plan_vibesec_upgrade", tool_version, "invalid_bundle", errors=[str(exc)]), as_json=args.json)
        return VERIFICATION_FAILED
    try:
        state = verify_installation(args.target)
        if state.status in {"partial", "conflict", "invalid"}:
            emit(envelope("plan_vibesec_upgrade", tool_version, "invalid_installation", result=state.result(), errors=state.errors, warnings=state.warnings), as_json=args.json)
            return VERIFICATION_FAILED
        plan = classify_plan(state, bundle)
        blocking = bool(plan["files_requiring_manual_merge"] or state.status == "unverifiable_legacy_installation")
        status = "review_required" if blocking else "no_changes" if set(plan["summary"]) <= {"unchanged", "baseline_preserve", "suppression_preserve"} else "planned"
        payload = envelope(
            "plan_vibesec_upgrade", tool_version, status, result=plan,
            warnings=["Manual review is required; no files were modified."] if blocking else [],
            information=["This command has no apply mode and made no changes."],
        )
        emit(payload, as_json=args.json)
        return WARNINGS if blocking or status == "planned" else SUCCESS
    except InstallationError as exc:
        emit(envelope("plan_vibesec_upgrade", tool_version, "invalid", errors=[str(exc)]), as_json=args.json)
        return INVALID_INPUT
    except OSError as exc:
        emit(envelope("plan_vibesec_upgrade", tool_version, "infrastructure_failure", errors=[type(exc).__name__]), as_json=args.json)
        return INFRASTRUCTURE_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
