import json
from pathlib import Path
import tempfile
import unittest

from scripts.validate_repository import (
    EXPECTED_TOOLS, ROOT, SHA256, load_object, validate_policy,
    validate_references, validate_tools,
)


class RepositoryValidationTests(unittest.TestCase):
    def test_tool_release_metadata_is_complete(self):
        metadata = json.loads((ROOT / "config/tools.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["schema_version"], 2)
        tools = metadata["tools"]
        self.assertEqual(set(tools), EXPECTED_TOOLS)
        for name, config in tools.items():
            self.assertTrue(config["official_repository"].startswith("https://github.com/"))
            self.assertEqual(config["verification_date"], "2026-08-03")
            if config.get("kind") == "container":
                self.assertRegex(config["digest"].removeprefix("sha256:"), SHA256)
            else:
                self.assertEqual(set(config["platforms"]), {
                    "linux-amd64", "macos-amd64", "macos-arm64",
                })
                for asset in config["platforms"].values():
                    self.assertRegex(asset["sha256"], SHA256)
                    self.assertTrue(asset["url"].startswith("https://github.com/"))
                    self.assertIn("/releases/download/", asset["url"])

    def test_static_repository_validation(self):
        validate_tools()
        validate_policy()
        validate_references()

    def test_static_json_configuration_rejects_duplicate_and_non_finite_values(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            path = Path(temporary) / "ambiguous.json"
            for payload in (
                b'{"mode":"observe","mode":"all"}',
                b'{"threshold":NaN}',
            ):
                with self.subTest(payload=payload):
                    path.write_bytes(payload)
                    with self.assertRaisesRegex(
                        ValueError, "duplicate JSON key|invalid number",
                    ):
                        load_object(path)

    def test_yaml_dependency_is_exactly_pinned(self):
        self.assertEqual((ROOT / "requirements.txt").read_text(encoding="utf-8"), "PyYAML==6.0.3\n")


if __name__ == "__main__":
    unittest.main()
