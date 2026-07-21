import json
from pathlib import Path
import unittest

from scripts.validate_repository import EXPECTED_TOOLS, ROOT, SHA256, validate_policy, validate_references, validate_tools


class RepositoryValidationTests(unittest.TestCase):
    def test_tool_release_metadata_is_complete(self):
        tools = json.loads((ROOT / "config/tools.json").read_text(encoding="utf-8"))
        self.assertEqual(set(tools), EXPECTED_TOOLS)
        for config in tools.values():
            self.assertRegex(config["sha256"], SHA256)
            self.assertTrue(config["url"].startswith("https://github.com/"))
            self.assertIn("/releases/download/", config["url"])

    def test_static_repository_validation(self):
        validate_tools()
        validate_policy()
        validate_references()


if __name__ == "__main__":
    unittest.main()
