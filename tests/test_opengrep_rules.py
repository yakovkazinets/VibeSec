from pathlib import Path
import shutil
import tempfile
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

    def test_java_return_statement_pattern_requires_parser_terminator(self):
        with tempfile.TemporaryDirectory() as temporary:
            rules = Path(temporary) / "rules"
            shutil.copytree(ROOT / "rules/opengrep", rules)
            java = rules / "java.yml"
            java.write_text(
                java.read_text(encoding="utf-8").replace(
                    'return "redirect:" + $REQUEST.getParameter(...);',
                    'return "redirect:" + $REQUEST.getParameter(...)',
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "return-statement pattern must end with a semicolon"):
                validate(rules)


if __name__ == "__main__":
    unittest.main()
