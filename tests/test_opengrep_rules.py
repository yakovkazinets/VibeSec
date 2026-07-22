from pathlib import Path
import re
import shutil
import tempfile
import unittest
import yaml

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

    def test_next_public_secret_regex_matches_positive_identifier_only(self):
        javascript = yaml.safe_load((ROOT / "rules/opengrep/javascript.yml").read_text(encoding="utf-8"))
        rule = next(item for item in javascript["rules"] if item["id"] == "vibesec.javascript.next-public-secret")
        pattern = re.compile(rule["pattern-regex"])
        positive = (ROOT / "tests/security-fixtures/opengrep/positive/frameworks.jsx").read_text(encoding="utf-8")
        negative = (ROOT / "tests/security-fixtures/opengrep/negative/frameworks.jsx").read_text(encoding="utf-8")
        self.assertEqual(pattern.findall(positive), ["process.env.NEXT_PUBLIC_API_TOKEN"])
        self.assertFalse(pattern.search(negative))

    def test_fastapi_cors_rule_targets_add_middleware_call(self):
        python = yaml.safe_load((ROOT / "rules/opengrep/python.yml").read_text(encoding="utf-8"))
        rule = next(item for item in python["rules"] if item["id"] == "vibesec.python.fastapi-permissive-cors")
        self.assertEqual(
            rule["pattern"],
            '$APP.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, ...)',
        )
        positive = (ROOT / "tests/security-fixtures/opengrep/positive/frameworks.py").read_text(encoding="utf-8")
        negative = (ROOT / "tests/security-fixtures/opengrep/negative/frameworks.py").read_text(encoding="utf-8")
        self.assertIn('allow_origins=["*"]', positive)
        self.assertNotIn('allow_origins=["*"]', negative)


if __name__ == "__main__":
    unittest.main()
