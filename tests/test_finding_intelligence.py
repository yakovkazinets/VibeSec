import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.vibesec.finding_intelligence import (
    FindingIntelligenceError, SourceDocument, build, validate_documents,
)

ROOT = Path(__file__).resolve().parents[1]


def finding(tool="opengrep", fingerprint="1" * 64, *, rule="RULE-1", severity="high",
            confidence="confirmed", file="src/app.py", line=10, category="command-injection", **extra):
    result = {
        "tool": tool, "category": category, "rule_id": rule, "severity": severity,
        "file": file, "line": line, "description": "Harmless controlled finding",
        "confidence": confidence, "fingerprint": fingerprint, "result_type": "finding",
    }
    result.update(extra)
    return result


def source(*findings, profile="standard", artifact="normalized.json", authentication="unknown"):
    return SourceDocument(profile, artifact, {"schema_version": 1, "results": list(findings)}, authentication)


class FindingIntelligenceTests(unittest.TestCase):
    def test_exact_deduplication_preserves_both_original_findings(self):
        groups, priorities = build([source(finding(), finding())])
        self.assertEqual(len(groups["findings"]), 2)
        self.assertEqual(len(groups["groups"]), 1)
        self.assertEqual(groups["groups"][0]["member_count"], 2)
        self.assertEqual(groups["groups"][0]["correlation_classification"], "exact")
        self.assertEqual(priorities["groups"][0]["priority"], "high")

    def test_same_scanner_fingerprint_collision_with_conflicting_evidence_stays_separate(self):
        fingerprint = "a" * 64
        original = finding(fingerprint=fingerprint, rule="RULE-1", line=10, category="command-injection")
        collision = finding(fingerprint=fingerprint, rule="RULE-2", line=40, category="open-redirect")
        groups, priorities = build([source(original, collision)])
        self.assertEqual(len(groups["findings"]), 2)
        self.assertEqual(len(groups["groups"]), 2)
        self.assertTrue(all(group["correlation_classification"] == "none" for group in groups["groups"]))
        self.assertTrue(all(group["correlation_rules"] == ["singleton"] for group in groups["groups"]))
        for group in groups["groups"]:
            collision_decisions = [
                item for item in group["decision_provenance"]
                if item["rule"] == "scanner-fingerprint-collision"
            ]
            self.assertEqual(len(collision_decisions), 1)
            evidence = {item["factor"]: item["evidence"] for item in collision_decisions[0]["evidence"]}
            self.assertIn("original_rule_id", evidence["conflicting_fields"])
            self.assertIn("category", evidence["conflicting_fields"])
        self.assertEqual(len(priorities["groups"]), 2)

    def test_same_scanner_fingerprint_missing_vs_present_identity_stays_separate(self):
        fingerprint = "b" * 64
        missing = finding(fingerprint=fingerprint)
        present = finding(fingerprint=fingerprint, cwe="CWE-78")
        groups, _ = build([source(missing, present)])
        self.assertEqual(len(groups["groups"]), 2)
        for group in groups["groups"]:
            collision = next(item for item in group["decision_provenance"]
                             if item["rule"] == "scanner-fingerprint-collision")
            fields = next(item["evidence"] for item in collision["evidence"]
                          if item["factor"] == "conflicting_fields")
            self.assertEqual(fields, "cwe")

    def test_cross_scanner_code_location_requires_family_sink_and_adjacent_lines(self):
        left = finding(vulnerability_family="command-injection", sink_category="command-injection")
        right = finding("trivy", "2" * 64, line=11, rule="RULE-2",
                        vulnerability_family="command-injection", sink_category="command-injection")
        groups, priorities = build([source(left, right)])
        self.assertEqual(len(groups["groups"]), 1)
        self.assertEqual(groups["groups"][0]["correlation_classification"], "heuristic")
        self.assertEqual(groups["groups"][0]["correlation_rules"], ["code-location"])
        self.assertEqual(priorities["groups"][0]["independent_scanner_count"], 2)
        self.assertEqual(priorities["groups"][0]["priority"], "critical")

    def test_generic_cwe_alone_and_incompatible_sink_do_not_correlate(self):
        left = finding(cwe="CWE-78", sink_category="shell")
        right = finding("trivy", "2" * 64, cwe="CWE-78", sink_category="process")
        groups, _ = build([source(left, right)])
        self.assertEqual(len(groups["groups"]), 2)

    def test_dependency_identity_requires_all_reviewed_fields(self):
        evidence = {"package_ecosystem": "PyPI", "package_name": "fixture", "installed_version": "1.0", "advisory_id": "CVE-TEST"}
        left = finding("osv-scanner", "1" * 64, file="requirements.txt", line=None, category="dependency", **evidence)
        right = finding("trivy", "2" * 64, file="requirements.txt", line=None, category="dependency", **evidence)
        groups, _ = build([source(left, right)])
        self.assertEqual(groups["groups"][0]["correlation_rules"], ["dependency"])
        changed = copy.deepcopy(right)
        changed["installed_version"] = "2.0"
        separated, _ = build([source(left, changed)])
        self.assertEqual(len(separated["groups"]), 2)

    def test_runtime_route_requires_compatible_authentication_context(self):
        fields = {"method": "GET", "path_template": "/users/{id}", "vulnerability_family": "open-redirect"}
        left = finding("zap-baseline", "1" * 64, file="/users/{id}", line=None, category="open-redirect", **fields)
        right = finding("schemathesis", "2" * 64, file="openapi.yaml", line=None, category="open-redirect", **fields)
        grouped, _ = build([source(left, authentication="authenticated"), source(right, artifact="api.json", authentication="authenticated")])
        self.assertEqual(len(grouped["groups"]), 1)
        separated, _ = build([source(left, authentication="authenticated"), source(right, artifact="api.json", authentication="unauthenticated")])
        self.assertEqual(len(separated["groups"]), 2)

    def test_unknown_family_and_missing_location_remain_explained_singletons(self):
        unknown = finding(category="custom-review-family", file="", line=None)
        groups, _ = build([source(unknown)])
        evidence = groups["groups"][0]["decision_provenance"][0]["evidence"][0]["evidence"]
        self.assertIn("unknown vulnerability family", evidence)

    def test_unknown_scanner_and_malformed_cwe_fail_closed(self):
        with self.assertRaisesRegex(FindingIntelligenceError, "unknown scanner"):
            build([source(finding("mystery"))])
        with self.assertRaisesRegex(FindingIntelligenceError, "CWE"):
            build([source(finding(cwe="CWE-unknown"))])

    def test_stable_keys_ordering_and_line_ending_independence(self):
        findings = [finding(fingerprint="2" * 64, line=20), finding(fingerprint="1" * 64, line=1)]
        first = build([source(*findings)])
        second = build([source(*reversed(findings))])
        self.assertEqual(first, second)
        payload = json.loads((json.dumps(first[0]) + "\r\n"))
        validate_documents(payload, first[1])

    def test_priority_reasons_cover_confidence_runtime_reachability_and_offline_kev(self):
        item = finding(severity="medium", confidence="confirmed", reachable_sink=True,
                       known_exploited=True, confirmed_runtime=True)
        _, priorities = build([source(item)])
        factors = {reason["factor"] for reason in priorities["groups"][0]["priority_reasons"]}
        self.assertEqual(priorities["groups"][0]["priority"], "critical")
        self.assertTrue({"normalized_severity", "confirmed_runtime", "reachable_sink", "known_exploited"} <= factors)

    def test_baseline_and_suppression_are_explicit_and_deterministic(self):
        item = finding()
        baseline_groups, baseline_priority = build([source(item)], baseline={item["fingerprint"]})
        self.assertEqual(baseline_groups["findings"][0]["baseline_state"], "baseline")
        self.assertIn("baseline", {reason["factor"] for reason in baseline_priority["groups"][0]["priority_reasons"]})
        suppressed_groups, suppressed_priority = build([source(item)], suppressions={item["fingerprint"]})
        self.assertEqual(suppressed_groups["findings"][0]["baseline_state"], "suppressed")
        self.assertEqual(suppressed_priority["groups"][0]["priority"], "informational")

    def test_schema_files_validate_generated_documents(self):
        groups, priorities = build([source(finding())])
        validate_documents(groups, priorities)
        for name, payload in (("finding-groups-schema.json", groups), ("prioritized-findings-schema.json", priorities)):
            schema = json.loads((ROOT / "config" / name).read_text(encoding="utf-8"))
            self.assertEqual(schema["properties"]["schema_version"]["const"], payload["schema_version"])
            self.assertTrue(set(schema["required"]) <= set(payload))

    def test_malformed_and_oversized_documents_fail_closed(self):
        with self.assertRaises(FindingIntelligenceError):
            build([SourceDocument("standard", "normalized.json", {"schema_version": 1, "results": "wrong"})])
        many = [finding(fingerprint=f"{index:064x}") for index in range(5001)]
        with self.assertRaisesRegex(FindingIntelligenceError, "count"):
            build([source(*many)])

    def test_pathological_correlation_candidate_count_is_bounded(self):
        crowded = [finding(fingerprint=f"{index:064x}", line=index + 1) for index in range(450)]
        with self.assertRaisesRegex(FindingIntelligenceError, "candidate count"):
            build([source(*crowded)])

    def test_cli_rejects_duplicate_keys_and_does_not_publish(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            malformed = root / "input.json"
            malformed.write_text('{"schema_version":1,"schema_version":1,"results":[]}', encoding="utf-8")
            completed = subprocess.run([
                sys.executable, str(ROOT / "scripts/generate_finding_intelligence.py"),
                "--input", str(malformed), "--profile", "standard",
                "--groups", str(root / "groups.json"), "--prioritized", str(root / "priority.json"),
            ], text=True, capture_output=True, check=False)
            self.assertEqual(completed.returncode, 3)
            self.assertFalse((root / "groups.json").exists())


if __name__ == "__main__":
    unittest.main()
