from pathlib import Path
import tempfile
import unittest

from scripts.policy_gate import safe_markdown_cell, write_markdown


class ReportTests(unittest.TestCase):
    def test_untrusted_markdown_is_escaped(self):
        self.assertEqual(safe_markdown_cell("<script>|x`\x00"), "&lt;script&gt;\\|x'")

    def test_report_contains_finding_and_tool_error_details(self):
        evaluation = {
            "status": "tool_error",
            "findings": [{
                "tool": "trivy", "severity": "high", "rule_id": "CVE-TEST", "file": "requirements.txt",
                "line": 4, "confidence": "confirmed", "description": "Harmless test finding",
            }],
            "new_findings": [], "violations": [],
            "tool_errors": [{"tool": "actionlint", "description": "execution failed"}],
        }
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.md"
            write_markdown(report, evaluation, ["a" * 64])
            text = report.read_text(encoding="utf-8")
        self.assertIn("CVE-TEST", text)
        self.assertIn("requirements.txt:4", text)
        self.assertIn("actionlint", text)
        self.assertIn("Expired suppressions", text)


if __name__ == "__main__":
    unittest.main()
