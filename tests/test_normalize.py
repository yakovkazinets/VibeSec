import json
from pathlib import Path
import tempfile
import unittest

from scripts.vibesec.normalize import normalize_checkov, normalize_gitleaks, normalize_opengrep, normalize_osv, normalize_trivy, normalize_trivy_image


class NormalizeTests(unittest.TestCase):
    def write_json(self, payload):
        temporary = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(payload, temporary)
        temporary.close()
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        return Path(temporary.name)

    def test_trivy_normalization(self):
        path = self.write_json({"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{"VulnerabilityID": "CVE-TEST-1", "Severity": "HIGH", "Title": "Harmless test finding"}]}]})
        result = normalize_trivy(path)
        self.assertEqual(result[0].tool, "trivy")
        self.assertEqual(result[0].severity, "high")
        self.assertEqual(result[0].file, "requirements.txt")

    def test_gitleaks_does_not_retain_secret_value(self):
        path = self.write_json([{"RuleID": "generic-api-key", "Description": "Fake fixture", "File": "tests/fixture.txt", "StartLine": 1, "Secret": "UNUSABLE-TEST-VALUE"}])
        result = normalize_gitleaks(path)[0].to_dict()
        self.assertNotIn("Secret", result)
        self.assertNotIn("UNUSABLE", json.dumps(result))

    def test_malformed_scanner_output(self):
        path = self.write_json({"unexpected": []})
        with self.assertRaises(ValueError):
            normalize_gitleaks(path)

    def test_opengrep_omits_source_snippets(self):
        path = self.write_json({"results": [{"check_id": "vibesec.python.test", "path": "app.py", "start": {"line": 7}, "extra": {"severity": "ERROR", "message": "Unsafe API", "lines": "TOP_SECRET_VALUE"}}]})
        result = normalize_opengrep(path)[0].to_dict()
        self.assertEqual(result["category"], "sast")
        self.assertNotIn("TOP_SECRET_VALUE", json.dumps(result))

    def test_osv_v2_normalization(self):
        path = self.write_json({"results": [{"source": {"path": "go.mod"}, "packages": [{"package": {"name": "example"}, "vulnerabilities": [{"id": "OSV-TEST", "summary": "Fixture advisory", "database_specific": {"severity": "HIGH"}}]}]}]})
        result = normalize_osv(path)[0]
        self.assertEqual((result.tool, result.severity, result.file), ("osv-scanner", "high", "go.mod"))

    def test_osv_ecosystem_severity_is_supported(self):
        path = self.write_json({"results": [{"source": {"path": "go.mod"}, "packages": [{"package": {"name": "example"}, "vulnerabilities": [{"id": "GO-TEST", "summary": "Fixture advisory", "ecosystem_specific": {"severity": "HIGH"}}]}]}]})
        self.assertEqual(normalize_osv(path)[0].severity, "high")

    def test_checkov_and_trivy_image_categories(self):
        checkov = self.write_json({"results": {"failed_checks": [{"check_id": "CKV_TEST", "check_name": "Fixture", "file_path": "/main.tf", "file_line_range": [2, 3]}]}})
        image = self.write_json({"Results": [{"Target": "fixture@sha256:abc", "Vulnerabilities": [{"VulnerabilityID": "CVE-TEST", "Severity": "CRITICAL", "Title": "Fixture"}]}]})
        self.assertEqual(normalize_checkov(checkov)[0].category, "iac")
        self.assertEqual(normalize_trivy_image(image)[0].category, "container")

    def test_invalid_line_and_oversized_shape_fail_closed(self):
        path = self.write_json({"results": [{"check_id": "x", "path": "a.py", "start": {"line": -1}, "extra": {"severity": "ERROR", "message": "x"}}]})
        with self.assertRaises(ValueError):
            normalize_opengrep(path)


if __name__ == "__main__":
    unittest.main()
