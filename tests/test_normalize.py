import json
from pathlib import Path
import tempfile
import unittest

from scripts.vibesec.normalize import normalize_actionlint, normalize_checkov, normalize_gitleaks, normalize_opengrep, normalize_osv, normalize_trivy, normalize_trivy_image


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

    def test_opengrep_retains_reviewed_correlation_metadata_without_snippets(self):
        path = self.write_json({"results": [{
            "check_id": "vibesec.python.test", "path": "app.py", "start": {"line": 7}, "end": {"line": 8},
            "extra": {"severity": "ERROR", "message": "Unsafe API", "lines": "TOP_SECRET_VALUE",
                      "metadata": {"category": "command-injection", "confidence": "high", "cwe": "CWE-78", "framework": "flask"}},
        }]})
        result = normalize_opengrep(path)[0].to_dict()
        self.assertEqual((result["cwe"], result["vulnerability_family"], result["framework"], result["end_line"]),
                         ("CWE-78", "command-injection", "flask", 8))
        self.assertEqual(result["confidence"], "confirmed")
        self.assertNotIn("TOP_SECRET_VALUE", json.dumps(result))

    def test_osv_v2_normalization(self):
        path = self.write_json({"results": [{"source": {"path": "go.mod"}, "packages": [{"package": {"name": "example"}, "vulnerabilities": [{"id": "OSV-TEST", "summary": "Fixture advisory", "database_specific": {"severity": "HIGH"}}]}]}]})
        result = normalize_osv(path)[0]
        self.assertEqual((result.tool, result.severity, result.file), ("osv-scanner", "high", "go.mod"))

    def test_dependency_correlation_metadata_is_retained_only_when_explicit(self):
        osv = self.write_json({"results": [{"source": {"path": "requirements.txt"}, "packages": [{
            "package": {"name": "fixture", "version": "1.0", "ecosystem": "PyPI"},
            "vulnerabilities": [{"id": "OSV-TEST", "aliases": ["CVE-2026-0001"], "database_specific": {"severity": "HIGH"}}],
        }]}]})
        trivy = self.write_json({"Results": [{"Target": "requirements.txt", "Type": "PyPI", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2026-0001", "PkgName": "fixture", "InstalledVersion": "1.0", "Severity": "HIGH",
        }]}]})
        left, right = normalize_osv(osv)[0].to_dict(), normalize_trivy(trivy)[0].to_dict()
        for field, expected in (("package_ecosystem", "PyPI"), ("package_name", "fixture"),
                                ("installed_version", "1.0"), ("advisory_id", "CVE-2026-0001")):
            self.assertEqual(left[field], expected)
            self.assertEqual(right[field], expected)

    def test_osv_ecosystem_severity_is_supported(self):
        path = self.write_json({"results": [{"source": {"path": "go.mod"}, "packages": [{"package": {"name": "example"}, "vulnerabilities": [{"id": "GO-TEST", "summary": "Fixture advisory", "ecosystem_specific": {"severity": "HIGH"}}]}]}]})
        self.assertEqual(normalize_osv(path)[0].severity, "high")

    def test_osv_null_results_is_a_valid_clean_v2_report(self):
        self.assertEqual(normalize_osv(self.write_json({"results": None, "experimental_config": {}})), [])

    def test_checkov_and_trivy_image_categories(self):
        checkov = self.write_json({"results": {"failed_checks": [{"check_id": "CKV_TEST", "check_name": "Fixture", "file_path": "/main.tf", "file_line_range": [2, 3]}]}})
        image = self.write_json({"Results": [{"Target": "fixture@sha256:abc", "Vulnerabilities": [{"VulnerabilityID": "CVE-TEST", "Severity": "CRITICAL", "Title": "Fixture"}]}]})
        self.assertEqual(normalize_checkov(checkov)[0].category, "iac")
        self.assertEqual(normalize_trivy_image(image)[0].category, "container")

    def test_invalid_line_and_oversized_shape_fail_closed(self):
        path = self.write_json({"results": [{"check_id": "x", "path": "a.py", "start": {"line": -1}, "extra": {"severity": "ERROR", "message": "x"}}]})
        with self.assertRaises(ValueError):
            normalize_opengrep(path)

    def test_trivy_requires_results_and_scalar_fields(self):
        with self.assertRaises(ValueError):
            normalize_trivy(self.write_json({}))
        self.assertEqual(normalize_trivy(self.write_json({"SchemaVersion": 2, "Trivy": {"Version": "0.72.0"}})), [])
        with self.assertRaises(ValueError):
            normalize_trivy(self.write_json({"Results": [{"Target": {}, "Vulnerabilities": []}]}))

    def test_absolute_container_paths_become_repository_relative(self):
        checkov = self.write_json({"results": {"failed_checks": [{"check_id": "CKV_TEST", "file_path": "/workspace/iac/main.tf", "check_name": "Fixture"}]}})
        self.assertEqual(normalize_checkov(checkov)[0].file, "iac/main.tf")

    def test_parent_traversal_and_non_array_findings_fail_closed(self):
        with self.assertRaises(ValueError):
            normalize_opengrep(self.write_json({"results": [{"check_id": "x", "path": "../escape.py", "start": {}, "extra": {"severity": "ERROR", "message": "x"}}]}))
        with self.assertRaises(ValueError):
            normalize_trivy(self.write_json({"Results": [{"Vulnerabilities": {}}]}))

    def test_actionlint_text_is_sanitized(self):
        temporary = tempfile.NamedTemporaryFile(mode="w", delete=False)
        temporary.write("/workspace/.github/workflows/ci.yml:2:3: Fixture [syntax-check]\n")
        temporary.close()
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        result = normalize_actionlint(Path(temporary.name))[0]
        self.assertEqual(result.file, ".github/workflows/ci.yml")


if __name__ == "__main__":
    unittest.main()
