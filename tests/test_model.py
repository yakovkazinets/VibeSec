import unittest

from scripts.vibesec.model import Finding, fingerprint_for, normalize_severity


class ModelTests(unittest.TestCase):
    def test_severity_normalization(self):
        self.assertEqual(normalize_severity("CRITICAL"), "critical")
        self.assertEqual(normalize_severity("moderate"), "medium")
        self.assertEqual(normalize_severity("informational"), "low")

    def test_fingerprint_is_stable_across_path_separators(self):
        first = fingerprint_for("Trivy", "dependency", "CVE-1", "./src\\app.py", 4, " Example  issue ")
        second = fingerprint_for("trivy", "dependency", "cve-1", "src/app.py", 4, "example issue")
        self.assertEqual(first, second)

    def test_result_types_remain_distinct(self):
        finding = Finding.create(tool="trivy", category="dependency", rule_id="CVE-1", severity="high", description="finding")
        failure = Finding.create(tool="trivy", category="execution", rule_id="tool-error", severity="low", description="failure", result_type="tool_error", confidence="unknown")
        self.assertEqual(finding.result_type, "finding")
        self.assertEqual(failure.result_type, "tool_error")


if __name__ == "__main__":
    unittest.main()
