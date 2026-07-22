import json
from pathlib import Path
import re
import tempfile
import unittest
import yaml

from scripts.run_security_accountability import run
from scripts.validate_opengrep_rules import validate as validate_opengrep_rules
from scripts.validate_security_capabilities import render_matrix, validate_evidence, validate_matrix
from scripts.vibesec.normalize import normalize_file


ROOT = Path(__file__).resolve().parents[1]
LIVE_SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


class SecurityAccountabilityTests(unittest.TestCase):
    def test_matrix_fixtures_tools_and_rendered_document_are_consistent(self):
        matrix = validate_matrix()
        self.assertEqual(len(matrix["capabilities"]), 45)
        rendered = render_matrix(matrix)
        self.assertEqual((ROOT / "docs/security-capability-matrix.md").read_text(encoding="utf-8"), rendered)
        self.assertEqual(
            set(matrix["claimed_scanners"]),
            {item["tool"] for item in matrix["capabilities"] if item["tool"] is not None},
        )

    def test_all_positive_and_negative_fixtures_produce_expected_evidence(self):
        matrix = validate_matrix()
        payload = run()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            validate_evidence(path, matrix)
        self.assertTrue(all(item["positive"]["fixture_ran"] and item["negative"]["fixture_ran"] for item in payload["capabilities"]))

    def test_opengrep_capability_expected_and_normalized_ids_exactly_match_rule_pack(self):
        rule_ids = sorted(validate_opengrep_rules(ROOT / "rules/opengrep"))
        matrix = validate_matrix()
        capability = next(item for item in matrix["capabilities"] if item["id"] == "standard.opengrep-sast")
        expected = json.loads((ROOT / capability["expected_metadata"]).read_text(encoding="utf-8"))
        raw = json.loads((ROOT / capability["positive_fixture"] / "raw.json").read_text(encoding="utf-8"))
        normalized = [item.to_dict() for item in normalize_file("opengrep", ROOT / capability["positive_fixture"] / "raw.json")]
        self.assertEqual(len(rule_ids), 32)
        self.assertEqual(capability["expected_finding_ids"], rule_ids)
        self.assertEqual(expected["positive"]["expected_finding_ids"], rule_ids)
        self.assertEqual(sorted(item["check_id"] for item in raw["results"]), rule_ids)
        self.assertEqual(sorted(item["rule_id"] for item in normalized), rule_ids)
        self.assertEqual(expected["positive"]["expected_count"], len(rule_ids))

        rules = {}
        for path in sorted((ROOT / "rules/opengrep").glob("*.yml")):
            for rule in yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]:
                rules[rule["id"]] = rule
        for item in normalized:
            rule = rules[item["rule_id"]]
            metadata = rule["metadata"]
            self.assertEqual(item["severity"], "medium" if rule["severity"] == "WARNING" else "high")
            self.assertEqual(item["confidence"], {"high": "confirmed", "medium": "possible", "low": "unknown"}[metadata["confidence"]])
            self.assertEqual(item["cwe"], metadata["cwe"])
            self.assertEqual(item["vulnerability_family"], metadata["category"])
            self.assertEqual(item["sink_category"], metadata["category"])
            self.assertEqual(item["framework"], metadata["framework"])

    def test_fixture_tree_contains_no_live_service_credential_format(self):
        root = ROOT / "tests/security-fixtures"
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for pattern in LIVE_SECRET_PATTERNS:
                self.assertIsNone(pattern.search(text), f"usable-looking credential pattern in {path.relative_to(ROOT)}")
        readme = (root / "README.md").read_text(encoding="utf-8")
        self.assertIn("VIBESEC_FAKE_SECRET_DO_NOT_USE_000000000000", readme)
        self.assertIn("not accepted by any service", readme)

    def test_every_scanner_parser_rejects_malformed_truncated_wrong_and_oversized_output(self):
        tools = ("trivy", "gitleaks", "actionlint", "opengrep", "osv-scanner", "checkov", "trivy-image")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for tool in tools:
                for label, content in (
                    ("malformed", b"not-json\n" if tool != "actionlint" else b"not actionlint output\n"),
                    ("truncated", b"{" if tool != "actionlint" else b"file.yml:1"),
                    ("wrong-schema", b"{}\n"),
                ):
                    path = root / f"{tool}-{label}"
                    path.write_bytes(content)
                    with self.subTest(tool=tool, label=label), self.assertRaises(ValueError):
                        normalize_file(tool, path)
                oversized = root / f"{tool}-oversized"
                with oversized.open("wb") as stream:
                    stream.truncate(25 * 1024 * 1024 + 1)
                with self.subTest(tool=tool, label="oversized"), self.assertRaises(ValueError):
                    normalize_file(tool, oversized)

    def test_actionlint_plain_text_and_json_forms_are_supported_without_snippets(self):
        fixture = ROOT / "tests/security-fixtures/actionlint"
        text_results = normalize_file("actionlint", fixture / "positive/raw.txt")
        json_results = normalize_file("actionlint", fixture / "positive/raw.json")
        self.assertEqual([item.rule_id for item in text_results], ["expression"])
        self.assertEqual([item.rule_id for item in json_results], ["expression"])
        self.assertNotIn("MUST_NOT_SURVIVE", json.dumps([item.to_dict() for item in json_results]))
        self.assertEqual(normalize_file("actionlint", fixture / "negative/raw.json"), [])
        with self.assertRaises(ValueError):
            normalize_file("actionlint", fixture / "malformed.json")

    def test_trusted_harness_shadow_files_are_data_not_executable_authority(self):
        fixture = ROOT / "tests/security-fixtures/trusted-harness/negative"
        script = (fixture / "scripts/run_standard_profile.py").read_text(encoding="utf-8")
        self.assertIn("MUST NEVER EXECUTE", script)
        harness = (ROOT / "scripts/run_standard_profile.py").read_text(encoding="utf-8")
        self.assertIn("--vibesec-root", harness)
        workflow = (ROOT / "templates/github-actions/security-standard.yml").read_text(encoding="utf-8")
        self.assertIn('git archive "$TRUSTED_SHA" scripts config policy rules', workflow)
        self.assertNotIn("pull_request_target", workflow)


if __name__ == "__main__":
    unittest.main()
