"""Deterministic, bounded correlation and priority for normalized findings.

The original normalized finding and scanner fingerprint remain authoritative.
Correlation is an additional explainable view and never removes a finding.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any, Iterable

from .model import normalize_path

SCHEMA_VERSION = 1
FINGERPRINT_VERSION = 1
MAX_FINDINGS = 5_000
MAX_GROUPS = 5_000
MAX_MEMBERS_PER_GROUP = 256
MAX_REASONS = 16
MAX_CANDIDATE_PAIRS = 100_000
MAX_TEXT = 500
KNOWN_SCANNERS = {
    "actionlint", "checkov", "gitleaks", "opengrep", "osv-scanner",
    "schemathesis", "trivy", "trivy-image", "zap-baseline",
}
SEVERITIES = ("low", "medium", "high", "critical")
PRIORITIES = ("informational", "low", "medium", "high", "critical")
CONFIDENCES = ("unknown", "possible", "confirmed")
AUTH_CONTEXTS = ("authenticated", "unauthenticated", "both", "unknown")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
METHOD = re.compile(r"^[A-Z]{3,10}$")
FAMILY_BY_CATEGORY = {
    "command-injection": "command-injection", "code-injection": "code-injection",
    "cross-site-scripting": "cross-site-scripting", "dependency": "dependency-vulnerability",
    "insecure-deserialization": "insecure-deserialization", "open-redirect": "open-redirect",
    "path-traversal": "path-traversal", "permissive-cors": "cors-misconfiguration",
    "secret": "secret-exposure", "secret-exposure": "secret-exposure",
    "sql-injection": "sql-injection", "template-injection": "template-injection",
}
FAMILY_BY_CWE = {
    "CWE-22": "path-traversal", "CWE-78": "command-injection", "CWE-79": "cross-site-scripting",
    "CWE-89": "sql-injection", "CWE-95": "code-injection", "CWE-200": "information-exposure",
    "CWE-352": "csrf", "CWE-502": "insecure-deserialization", "CWE-601": "open-redirect",
    "CWE-942": "cors-misconfiguration", "CWE-1336": "template-injection",
}


class FindingIntelligenceError(ValueError):
    """Input cannot be safely or deterministically interpreted."""


@dataclass(frozen=True)
class SourceDocument:
    profile: str
    artifact: str
    payload: dict[str, Any]
    authentication_context: str = "unknown"


def _text(value: Any, field: str, *, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise FindingIntelligenceError(f"{field} must be a string")
    result = " ".join(value.split())
    if len(result) > MAX_TEXT or any(ord(character) < 32 or ord(character) == 127 for character in result):
        raise FindingIntelligenceError(f"{field} is oversized or contains controls")
    if required and not result:
        raise FindingIntelligenceError(f"{field} is required")
    return result


def _canonical_hash(parts: Iterable[str]) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def _authentication_context(item: dict[str, Any], source: SourceDocument) -> str:
    unauthenticated = item.get("observed_unauthenticated")
    authenticated = item.get("observed_authenticated")
    if unauthenticated is not None or authenticated is not None:
        if type(unauthenticated) is not bool or type(authenticated) is not bool:
            raise FindingIntelligenceError("authentication observation flags must both be Boolean")
        if unauthenticated and authenticated:
            return "both"
        if authenticated:
            return "authenticated"
        if unauthenticated:
            return "unauthenticated"
        return "unknown"
    if source.authentication_context not in AUTH_CONTEXTS:
        raise FindingIntelligenceError("source authentication context is unsupported")
    return source.authentication_context


def _family(item: dict[str, Any]) -> tuple[str | None, str | None]:
    cwe = item.get("cwe")
    if cwe is not None:
        cwe = _text(cwe, "cwe", required=True).upper()
        if not re.fullmatch(r"CWE-[1-9][0-9]{0,5}", cwe):
            raise FindingIntelligenceError("CWE identifier is malformed")
    category = _text(item.get("vulnerability_family") or item.get("category"), "category", required=True).lower()
    return FAMILY_BY_CWE.get(cwe) or FAMILY_BY_CATEGORY.get(category), cwe


def _optional_identity(item: dict[str, Any], field: str) -> str | None:
    value = item.get(field)
    if value is None:
        return None
    return _text(value, field, required=True).casefold()


def _validate_finding(item: Any, source: SourceDocument, index: int) -> dict[str, Any]:
    if not isinstance(item, dict) or item.get("result_type") != "finding":
        raise FindingIntelligenceError("finding intelligence accepts finding results only")
    tool = _text(item.get("tool"), "tool", required=True).lower()
    if tool not in KNOWN_SCANNERS:
        raise FindingIntelligenceError(f"unknown scanner: {tool}")
    severity = _text(item.get("severity"), "severity", required=True).lower()
    confidence = _text(item.get("confidence"), "confidence", required=True).lower()
    fingerprint = _text(item.get("fingerprint"), "fingerprint", required=True).lower()
    if severity not in SEVERITIES or confidence not in CONFIDENCES or not HEX64.fullmatch(fingerprint):
        raise FindingIntelligenceError("finding severity, confidence, or fingerprint is invalid")
    line = item.get("line")
    if line is not None and (type(line) is not int or line < 1 or line > 10_000_000):
        raise FindingIntelligenceError("finding line is invalid")
    end_line = item.get("end_line", line)
    if end_line is not None and (type(end_line) is not int or end_line < (line or 1) or end_line > 10_000_000):
        raise FindingIntelligenceError("finding end_line is invalid")
    file = normalize_path(_text(item.get("file", ""), "file"))
    if file and ((PurePosixPath(file).is_absolute() and not item.get("path_template"))
                 or ".." in PurePosixPath(file).parts):
        raise FindingIntelligenceError("finding file is not repository relative")
    family, cwe = _family(item)
    method = _optional_identity(item, "method")
    if method is not None:
        method = method.upper()
        if not METHOD.fullmatch(method):
            raise FindingIntelligenceError("runtime method is invalid")
    path_template = _optional_identity(item, "path_template")
    if path_template is not None and not path_template.startswith("/"):
        raise FindingIntelligenceError("runtime path template must start with slash")
    profile = _text(source.profile, "source profile", required=True)
    artifact = normalize_path(_text(source.artifact, "source artifact", required=True))
    if PurePosixPath(artifact).is_absolute() or ".." in PurePosixPath(artifact).parts:
        raise FindingIntelligenceError("source artifact is not repository relative")
    source_reference = _canonical_hash((profile, artifact, str(index), fingerprint))
    return {
        "source_reference": source_reference,
        "source_profile": profile,
        "source_artifact": artifact,
        "original_scanner": tool,
        "original_rule_id": _text(item.get("rule_id"), "rule_id", required=True),
        "original_normalized_severity": severity,
        "confidence": confidence,
        "scanner_fingerprint": fingerprint,
        "scanner_fingerprint_version": FINGERPRINT_VERSION,
        "category": _text(item.get("category"), "category", required=True),
        "vulnerability_family": family,
        "cwe": cwe,
        "sink_category": _optional_identity(item, "sink_category") or family,
        "file": file,
        "start_line": line,
        "end_line": end_line,
        "method": method,
        "path_template": path_template,
        "authentication_context": _authentication_context(item, source),
        "package_ecosystem": _optional_identity(item, "package_ecosystem"),
        "package_name": _optional_identity(item, "package_name"),
        "installed_version": _optional_identity(item, "installed_version"),
        "advisory_id": _optional_identity(item, "advisory_id") or _optional_identity(item, "rule_id"),
        "direct_dependency": item.get("direct_dependency") if type(item.get("direct_dependency")) is bool else None,
        "confirmed_runtime": bool(item.get("confirmed_runtime", tool in {"zap-baseline", "schemathesis"})),
        "reachable_sink": item.get("reachable_sink") is True,
        "known_exploited": item.get("known_exploited") is True,
        "baseline_state": "suppressed" if fingerprint in source.payload.get("_suppressions", []) else (
            "baseline" if fingerprint in source.payload.get("_baseline", []) else "new"
        ),
    }


def _overlaps_or_adjacent(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if left["start_line"] is None or right["start_line"] is None:
        return False
    return left["start_line"] <= right["end_line"] + 1 and right["start_line"] <= left["end_line"] + 1


def _correlation(left: dict[str, Any], right: dict[str, Any]) -> tuple[str, str, list[dict[str, str]]] | None:
    if (left["original_scanner"] == right["original_scanner"]
            and left["scanner_fingerprint"] == right["scanner_fingerprint"]):
        return "scanner-exact", "exact", [{"factor": "scanner_fingerprint", "evidence": "identical scanner fingerprint"}]
    if (left["file"] and left["file"] == right["file"] and _overlaps_or_adjacent(left, right)
            and left["vulnerability_family"] is not None
            and left["vulnerability_family"] == right["vulnerability_family"]
            and left["sink_category"] == right["sink_category"]):
        return "code-location", "heuristic", [
            {"factor": "repository_location", "evidence": "same file with overlapping or adjacent reviewed lines"},
            {"factor": "vulnerability_family", "evidence": left["vulnerability_family"]},
            {"factor": "sink_category", "evidence": str(left["sink_category"])},
        ]
    dependency_fields = ("package_ecosystem", "package_name", "installed_version", "advisory_id")
    if all(left[field] is not None and left[field] == right[field] for field in dependency_fields):
        return "dependency", "exact", [
            {"factor": field, "evidence": str(left[field])} for field in dependency_fields
        ]
    if (left["method"] is not None and left["method"] == right["method"]
            and left["path_template"] is not None and left["path_template"] == right["path_template"]
            and left["vulnerability_family"] is not None
            and left["vulnerability_family"] == right["vulnerability_family"]
            and left["authentication_context"] == right["authentication_context"]):
        return "runtime-route", "heuristic", [
            {"factor": "route", "evidence": f"{left['method']} {left['path_template']}"},
            {"factor": "vulnerability_family", "evidence": left["vulnerability_family"]},
            {"factor": "authentication_context", "evidence": left["authentication_context"]},
        ]
    return None


def _priority(members: list[dict[str, Any]]) -> tuple[str, list[dict[str, str]]]:
    highest = max(SEVERITIES.index(item["original_normalized_severity"]) for item in members)
    score = highest + 1
    reasons = [{"factor": "normalized_severity", "effect": "base", "evidence": SEVERITIES[highest]}]
    confidence = CONFIDENCES[max(CONFIDENCES.index(item["confidence"]) for item in members)]
    reasons.append({"factor": "confidence", "effect": "context", "evidence": confidence})
    scanners = sorted({item["original_scanner"] for item in members})
    if len(scanners) > 1:
        score += 1
        reasons.append({"factor": "independent_scanners", "effect": "increase", "evidence": str(len(scanners))})
    if any(item["confirmed_runtime"] for item in members):
        score += 1
        reasons.append({"factor": "confirmed_runtime", "effect": "increase", "evidence": "scanner runtime observation"})
    if any(item["reachable_sink"] for item in members):
        score += 1
        reasons.append({"factor": "reachable_sink", "effect": "increase", "evidence": "statically proven sink evidence"})
    if any(item["known_exploited"] for item in members):
        score = 4
        reasons.append({"factor": "known_exploited", "effect": "set-critical", "evidence": "offline reviewed metadata"})
    if all(item["authentication_context"] == "authenticated" for item in members):
        reasons.append({"factor": "authenticated_only", "effect": "context", "evidence": "observed only with authentication"})
    if any(item["direct_dependency"] is True for item in members):
        reasons.append({"factor": "direct_dependency", "effect": "context", "evidence": "direct dependency metadata"})
    states = {item["baseline_state"] for item in members}
    if "suppressed" in states:
        score = 0
        reasons.append({"factor": "suppression", "effect": "set-informational", "evidence": "active fingerprint suppression"})
    elif states == {"baseline"}:
        score = max(0, score - 1)
        reasons.append({"factor": "baseline", "effect": "decrease", "evidence": "all members are baselined"})
    priority = PRIORITIES[min(score, len(PRIORITIES) - 1)]
    return priority, reasons[:MAX_REASONS]


def build(documents: list[SourceDocument], *, baseline: set[str] | None = None,
          suppressions: set[str] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return group and priority documents while retaining every source finding."""
    findings: list[dict[str, Any]] = []
    baseline = baseline or set()
    suppressions = suppressions or set()
    for source in documents:
        payload = source.payload
        if not isinstance(payload, dict) or payload.get("schema_version") != 1 or not isinstance(payload.get("results"), list):
            raise FindingIntelligenceError("normalized source must be a schema-version 1 result document")
        local = dict(payload)
        local["_baseline"] = sorted(baseline)
        local["_suppressions"] = sorted(suppressions)
        source = SourceDocument(source.profile, source.artifact, local, source.authentication_context)
        source_findings = [item for item in payload["results"]
                           if not isinstance(item, dict) or item.get("result_type") == "finding"]
        source_findings.sort(key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                            if isinstance(item, dict) else repr(item))
        for index, item in enumerate(source_findings):
            findings.append(_validate_finding(item, source, index))
            if len(findings) > MAX_FINDINGS:
                raise FindingIntelligenceError("finding count exceeds limit")
    findings.sort(key=lambda item: item["source_reference"])
    parent = list(range(len(findings)))
    decisions: dict[tuple[int, int], tuple[str, str, list[dict[str, str]]]] = {}

    def root(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    buckets: dict[tuple[str, ...], list[int]] = {}
    for index, item in enumerate(findings):
        identities = [("fingerprint", item["original_scanner"], item["scanner_fingerprint"])]
        if item["file"]:
            identities.append(("file", item["file"]))
        dependency = tuple(str(item[field]) for field in (
            "package_ecosystem", "package_name", "installed_version", "advisory_id"
        ))
        if "None" not in dependency:
            identities.append(("dependency", *dependency))
        if item["method"] is not None and item["path_template"] is not None:
            identities.append(("route", item["method"], item["path_template"], item["authentication_context"]))
        for identity in identities:
            buckets.setdefault(identity, []).append(index)
    candidates: set[tuple[int, int]] = set()
    for indexes in buckets.values():
        for position, left_index in enumerate(indexes):
            for right_index in indexes[position + 1:]:
                candidates.add((left_index, right_index))
                if len(candidates) > MAX_CANDIDATE_PAIRS:
                    raise FindingIntelligenceError("correlation candidate count exceeds limit")
    for left_index, right_index in sorted(candidates):
        decision = _correlation(findings[left_index], findings[right_index])
        if decision is None:
            continue
        left_root, right_root = root(left_index), root(right_index)
        if left_root != right_root:
            parent[right_root] = left_root
        decisions[(left_index, right_index)] = decision

    components: dict[int, list[int]] = {}
    for index in range(len(findings)):
        components.setdefault(root(index), []).append(index)
    if len(components) > MAX_GROUPS:
        raise FindingIntelligenceError("group count exceeds limit")
    groups: list[dict[str, Any]] = []
    prioritized: list[dict[str, Any]] = []
    for indexes in components.values():
        if len(indexes) > MAX_MEMBERS_PER_GROUP:
            raise FindingIntelligenceError("group member count exceeds limit")
        members = [findings[index] for index in indexes]
        applied = [decision for pair, decision in decisions.items() if pair[0] in indexes and pair[1] in indexes]
        kinds = sorted({decision[0] for decision in applied}) or ["singleton"]
        accuracy = "exact" if applied and all(decision[1] == "exact" for decision in applied) else (
            "heuristic" if applied else "none"
        )
        identity = sorted(item["source_reference"] for item in members)
        correlation_key = _canonical_hash(("v1", *identity))
        provenance: list[dict[str, Any]] = []
        for (left_index, right_index), decision in sorted(decisions.items()):
            if left_index in indexes and right_index in indexes:
                provenance.append({
                    "left": findings[left_index]["source_reference"],
                    "right": findings[right_index]["source_reference"],
                    "rule": decision[0], "classification": decision[1], "evidence": decision[2],
                })
        if not provenance:
            reason = "missing compatible correlation evidence"
            if any(item["vulnerability_family"] is None for item in members):
                reason = "unknown vulnerability family remains separate"
            elif any(not item["file"] and item["method"] is None for item in members):
                reason = "missing location remains separate"
            provenance = [{"left": identity[0], "right": None, "rule": "singleton", "classification": "none",
                           "evidence": [{"factor": "separation", "evidence": reason}]}]
        priority, reasons = _priority(members)
        scanners = sorted({item["original_scanner"] for item in members})
        group = {
            "correlation_key": correlation_key,
            "correlation_key_version": 1,
            "correlation_rules": kinds,
            "correlation_classification": accuracy,
            "member_count": len(members),
            "member_references": identity,
            "contributing_scanners": scanners,
            "decision_provenance": provenance,
        }
        groups.append(group)
        prioritized.append({
            "correlation_key": correlation_key, "priority": priority,
            "priority_reasons": reasons, "member_count": len(members),
            "contributing_scanners": scanners, "independent_scanner_count": len(scanners),
            "confirmed_runtime": any(item["confirmed_runtime"] for item in members),
            "member_references": identity,
        })
        for member in members:
            member["correlation_key"] = correlation_key
    group_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    prioritized.sort(key=lambda item: (group_order[item["priority"]], item["correlation_key"]))
    groups.sort(key=lambda item: item["correlation_key"])
    findings.sort(key=lambda item: item["source_reference"])
    group_document = {
        "schema_version": SCHEMA_VERSION,
        "model": "vibesec-finding-groups",
        "fingerprint_compatibility": "scanner fingerprints remain version 1 and unchanged",
        "findings": findings,
        "groups": groups,
    }
    priority_document = {
        "schema_version": SCHEMA_VERSION,
        "model": "vibesec-prioritized-findings",
        "priority_is_separate_from_scanner_severity": True,
        "groups": prioritized,
    }
    validate_documents(group_document, priority_document)
    return group_document, priority_document


def validate_documents(groups: Any, priorities: Any) -> None:
    if (not isinstance(groups, dict) or set(groups) != {"schema_version", "model", "fingerprint_compatibility", "findings", "groups"}
            or groups.get("schema_version") != 1 or groups.get("model") != "vibesec-finding-groups"
            or not isinstance(groups.get("findings"), list) or len(groups["findings"]) > MAX_FINDINGS
            or not isinstance(groups.get("groups"), list) or len(groups["groups"]) > MAX_GROUPS):
        raise FindingIntelligenceError("finding group document schema is invalid")
    if (not isinstance(priorities, dict) or set(priorities) != {"schema_version", "model", "priority_is_separate_from_scanner_severity", "groups"}
            or priorities.get("schema_version") != 1 or priorities.get("model") != "vibesec-prioritized-findings"
            or priorities.get("priority_is_separate_from_scanner_severity") is not True
            or not isinstance(priorities.get("groups"), list) or len(priorities["groups"]) > MAX_GROUPS):
        raise FindingIntelligenceError("priority document schema is invalid")
    keys = [item.get("correlation_key") for item in groups["groups"] if isinstance(item, dict)]
    priority_keys = [item.get("correlation_key") for item in priorities["groups"] if isinstance(item, dict)]
    if (len(keys) != len(groups["groups"]) or len(set(keys)) != len(keys) or set(keys) != set(priority_keys)
            or any(not isinstance(key, str) or not HEX64.fullmatch(key) for key in keys)):
        raise FindingIntelligenceError("group identities are invalid or inconsistent")
    references = [item.get("source_reference") for item in groups["findings"] if isinstance(item, dict)]
    if len(references) != len(groups["findings"]) or len(references) != len(set(references)):
        raise FindingIntelligenceError("source finding references are invalid or duplicated")
    reference_set = set(references)
    for item in groups["groups"]:
        if (not isinstance(item.get("member_references"), list) or not item["member_references"]
                or not set(item["member_references"]) <= reference_set
                or item.get("member_count") != len(item["member_references"])):
            raise FindingIntelligenceError("group membership is invalid")
    for item in priorities["groups"]:
        if item.get("priority") not in PRIORITIES or not isinstance(item.get("priority_reasons"), list):
            raise FindingIntelligenceError("priority or reasons are invalid")


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    validate = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    return validate.encode("utf-8")
