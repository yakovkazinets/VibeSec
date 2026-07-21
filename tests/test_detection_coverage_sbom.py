import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.vibesec.coverage import markdown, validate_coverage
from scripts.vibesec.detection import DetectionError, inventory
from scripts.vibesec.sbom import sanitize_repository_paths, validate_cyclonedx, validate_spdx


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
        payload = {
            "schema_version": 1,
            "limitations": ["limited <coverage>"],
            "outside_coverage": ["runtime `behavior`"],
            "tools": [{
                "tool": "checkov", "version": "test", "scope": "iac",
                "state": "not_applicable", "reason": "none | detected",
                "relevant_artifacts": [], "output_files": [],
                "network_access": "none", "application_code_executed": False,
            }],
        }
        validate_coverage(payload)
        rendered = markdown(payload)
        self.assertIn("not_applicable", rendered)
        self.assertIn("&lt;coverage&gt;", rendered)
        self.assertIn("none \\| detected", rendered)
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

    def test_multidocument_yaml_and_specific_helm_kustomize_detection(self):
        (self.root / "objects.yml").write_text("---\nname: metadata\n---\napiVersion: v1\nkind: Service\n", encoding="utf-8")
        (self.root / "Chart.yaml").write_text("name: misleading\n", encoding="utf-8")
        (self.root / "kustomization.yaml").write_text("apiVersion: kustomize.config.k8s.io/v1beta1\n", encoding="utf-8")
        result = inventory(self.root)
        self.assertEqual(result["iac"]["kubernetes"], ["objects.yml"])
        self.assertEqual(result["iac"]["helm"], [])
        self.assertEqual(result["iac"]["kustomize"], [])

    def test_case_insensitive_skips_and_symlinks(self):
        skipped = self.root / "Node_Modules"
        skipped.mkdir()
        (skipped / "hidden.py").write_text("pass\n", encoding="utf-8")
        real = self.root / "real.py"
        real.write_text("pass\n", encoding="utf-8")
        (self.root / "linked.py").symlink_to(real)
        self.assertEqual(inventory(self.root)["source_files"], ["real.py"])

    def test_file_limit_fails_closed(self):
        (self.root / "one.py").write_text("pass\n", encoding="utf-8")
        (self.root / "two.py").write_text("pass\n", encoding="utf-8")
        with patch("scripts.vibesec.detection.MAX_FILES", 1), self.assertRaises(DetectionError):
            inventory(self.root)

    def test_sbom_absolute_repository_paths_are_removed(self):
        path = self.root / "sbom.json"
        absolute = str(self.root / "requirements.txt")
        path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": absolute}]}), encoding="utf-8")
        sanitize_repository_paths(path, self.root)
        self.assertNotIn(str(self.root), path.read_text(encoding="utf-8"))
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["components"][0]["name"], "requirements.txt")


if __name__ == "__main__":
    unittest.main()
