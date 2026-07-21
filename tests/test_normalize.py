import json
from pathlib import Path
import tempfile
import unittest

from scripts.vibesec.normalize import normalize_gitleaks, normalize_trivy


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


if __name__ == "__main__":
    unittest.main()
