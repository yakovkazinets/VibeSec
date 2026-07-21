from datetime import date
import unittest

from scripts.vibesec.policy import ConfigurationError, active_suppressions, evaluate


def finding(fingerprint="new", severity="high", result_type="finding"):
    return {"fingerprint": fingerprint, "severity": severity, "result_type": result_type}


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


if __name__ == "__main__":
    unittest.main()
