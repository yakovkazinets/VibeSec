import json
from pathlib import Path
import tempfile
import unittest

from scripts.vibesec.coverage import markdown, validate_coverage
from scripts.vibesec.detection import inventory
from scripts.vibesec.sbom import validate_cyclonedx, validate_spdx


class DetectionCoverageSbomTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_content_aware_inventory_and_monorepo(self):
        (self.root / "service").mkdir()
        (self.root / "service/package.json").write_text("{}\n", encoding="utf-8")
        (self.root / "requirements.txt").write_text("example==1\n", encoding="utf-8")
        (self.root / "main.py").write_text("print('ok')\n", encoding="utf-8")
        (self.root / "deployment.yml").write_text("apiVersion: v1\nkind: Pod\nmetadata: {}\n", encoding="utf-8")
        result = inventory(self.root)
        self.assertTrue(result["monorepo"])
        self.assertEqual(result["languages"], ["python"])
        self.assertEqual(result["iac"]["kubernetes"], ["deployment.yml"])

    def test_markdown_distinguishes_coverage_states(self):
        payload = {"schema_version": 1, "tools": [{"tool": "checkov", "version": "test", "scope": "iac", "state": "not_applicable", "reason": "none detected"}]}
        validate_coverage(payload)
        self.assertIn("not_applicable", markdown(payload))
        payload["tools"][0]["state"] = "clean"
        with self.assertRaises(ValueError):
            validate_coverage(payload)

    def test_sbom_structure_and_nonempty_requirements(self):
        cyclonedx = self.root / "cdx.json"
        spdx = self.root / "spdx.json"
        cyclonedx.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "fixture"}]}), encoding="utf-8")
        spdx.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": [{"name": "fixture"}]}), encoding="utf-8")
        validate_cyclonedx(cyclonedx)
        validate_spdx(spdx)
        cyclonedx.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}), encoding="utf-8")
        with self.assertRaises(ValueError):
            validate_cyclonedx(cyclonedx)


if __name__ == "__main__":
    unittest.main()
