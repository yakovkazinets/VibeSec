import json
from pathlib import Path
import unittest

from scripts.validate_repository import EXPECTED_TOOLS, ROOT, SHA256, validate_policy, validate_references, validate_tools


class RepositoryValidationTests(unittest.TestCase):
    def test_tool_release_metadata_is_complete(self):
        tools = json.loads((ROOT / "config/tools.json").read_text(encoding="utf-8"))
        self.assertEqual(set(tools), EXPECTED_TOOLS)
        for name, config in tools.items():
            self.assertTrue(config["official_repository"].startswith("https://github.com/"))
            expected_date = "2026-07-22" if name in {"cosign", "schemathesis"} else "2026-07-21"
            self.assertEqual(config["verification_date"], expected_date)
            if config.get("kind") == "container":
                self.assertRegex(config["digest"].removeprefix("sha256:"), SHA256)
            else:
                self.assertRegex(config["sha256"], SHA256)
                self.assertTrue(config["url"].startswith("https://github.com/"))
                self.assertIn("/releases/download/", config["url"])

    def test_static_repository_validation(self):
        validate_tools()
        validate_policy()
        validate_references()

    def test_yaml_dependency_is_exactly_pinned(self):
        self.assertEqual((ROOT / "requirements.txt").read_text(encoding="utf-8"), "PyYAML==6.0.3\n")


if __name__ == "__main__":
    unittest.main()
