from datetime import date
import unittest

from scripts.vibesec.policy import ConfigurationError, active_suppressions, evaluate, evaluate_priority


def finding(fingerprint="new", severity="high", result_type="finding"):
    return {
        "tool": "test", "category": "test", "rule_id": "TEST-1", "severity": severity,
        "file": "fixture.txt", "line": 1, "description": "Harmless test result",
        "confidence": "confirmed", "fingerprint": fingerprint, "result_type": result_type,
    }


class PolicyTests(unittest.TestCase):
    def test_baseline_comparison_only_blocks_new_findings(self):
        result = evaluate([finding("old"), finding("new")], minimum_severity="high", enforcement="new", baseline={"old"}, suppressions=set(), today=date(2026, 7, 20))
        self.assertEqual([item["fingerprint"] for item in result["violations"]], ["new"])

    def test_observe_mode_does_not_block_historical_unknowns(self):
        result = evaluate([finding()], minimum_severity="high", enforcement="observe", baseline=set(), suppressions=set(), today=date(2026, 7, 20))
        self.assertEqual(result["status"], "pass")

    def test_tool_failure_is_not_a_clean_scan(self):
        result = evaluate([finding("failure", result_type="tool_error")], minimum_severity="high", enforcement="observe", baseline=set(), suppressions=set(), today=date(2026, 7, 20))
        self.assertEqual(result["status"], "tool_error")

    def test_expired_suppression_is_inactive(self):
        active, expired = active_suppressions({"suppressions": [{"finding_fingerprint": "old", "reason": "reviewed", "owner": "maintainer", "expiration_date": "2026-07-19"}]}, date(2026, 7, 20))
        self.assertEqual(active, set())
        self.assertEqual(expired, ["old"])

    def test_suppression_requires_audit_fields(self):
        with self.assertRaises(ConfigurationError):
            active_suppressions({"suppressions": [{"finding_fingerprint": "x"}]}, date(2026, 7, 20))

    def test_invalid_result_type_is_rejected(self):
        with self.assertRaises(ConfigurationError):
            evaluate([{"result_type": "clean"}], minimum_severity="high", enforcement="observe", baseline=set(), suppressions=set(), today=date(2026, 7, 20))

    def test_finding_intelligence_policy_is_optional_and_deterministic(self):
        group = {"priority": "high", "independent_scanner_count": 2, "confirmed_runtime": True}
        disabled = {"enabled": False, "minimum_priority": "high", "minimum_independent_scanners": None, "require_confirmed_runtime": False}
        enabled = {**disabled, "enabled": True, "minimum_independent_scanners": 2, "require_confirmed_runtime": True}
        self.assertEqual(evaluate_priority([group], disabled), [])
        self.assertEqual(evaluate_priority([group], enabled), [group])
        self.assertEqual(evaluate_priority([{**group, "confirmed_runtime": False}], enabled), [])

    def test_malformed_priority_policy_fails_closed(self):
        with self.assertRaises(ConfigurationError):
            evaluate_priority([], {"enabled": True})


if __name__ == "__main__":
    unittest.main()
