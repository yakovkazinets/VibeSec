from pathlib import Path
import unittest

from scripts.validate_opengrep_rules import ROOT, validate


class OpengrepRuleTests(unittest.TestCase):
    def test_rule_metadata_and_language_coverage(self):
        identifiers = validate(ROOT / "rules/opengrep")
        self.assertEqual(len(identifiers), 32)
        self.assertEqual(len(identifiers), len(set(identifiers)))
        for framework in ("express", "next", "react", "flask", "django", "fastapi", "spring"):
            self.assertTrue(any(framework in identifier for identifier in identifiers), framework)

    def test_positive_and_negative_fixtures_cover_each_language(self):
        for side in ("positive", "negative"):
            directory = ROOT / "tests/fixtures/opengrep" / side
            self.assertEqual({path.suffix for path in directory.iterdir() if path.is_file()}, {".js", ".py", ".java", ".go"})


if __name__ == "__main__":
    unittest.main()
