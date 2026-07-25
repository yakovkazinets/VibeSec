import copy
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))
from vibesec.strict_json import StrictJSONError, loads_strict  # noqa: E402
from vibesec.v1_contract import (  # noqa: E402
    V1ContractError, validate_catalogs, validate_interface, validate_readiness,
)


class V1ContractTests(unittest.TestCase):
    def test_every_public_interface_is_strict_inventoried_documented_and_schematized(self):
        inventory, catalogs = validate_catalogs(ROOT)
        self.assertGreaterEqual(len(inventory["interfaces"]), 25)
        self.assertEqual(inventory["required_status"], "validate")
        self.assertEqual(inventory["coverage_states"], [
            "ran", "not_applicable", "not_configured", "tool_error",
        ])
        self.assertEqual(len(catalogs), 14)
        for item in inventory["interfaces"]:
            if item["status"] == "stable":
                self.assertTrue(item["human_documentation"])
                self.assertTrue(item["machine_schema"])

    def test_unknown_interface_field_fails_closed(self):
        value = json.loads((ROOT / "machine/interfaces.json").read_text())["interfaces"][0]
        changed = copy.deepcopy(value)
        changed["future"] = True
        with self.assertRaisesRegex(V1ContractError, "unknown or missing"):
            validate_interface(changed, ROOT)

    def test_nonnormalized_interface_text_fails_closed(self):
        value = json.loads((ROOT / "machine/interfaces.json").read_text())["interfaces"][0]
        changed = copy.deepcopy(value)
        changed["summary"] = "Cafe\u0301"
        with self.assertRaisesRegex(V1ContractError, "NFC"):
            validate_interface(changed, ROOT)

    def test_duplicate_bom_invalid_utf8_trailing_and_number_ambiguity_fail(self):
        cases = [
            b'{"a":1,"a":2}\n',
            b"\xef\xbb\xbf{}\n",
            b'{"x":"\xff"}\n',
            b"{}\n{}\n",
            b'{"x":NaN}\n',
        ]
        for data in cases:
            with self.subTest(data=data), self.assertRaises(StrictJSONError):
                loads_strict(data)

    def test_deep_and_oversized_json_fail(self):
        with self.assertRaisesRegex(StrictJSONError, "nesting"):
            loads_strict(("[" * 30 + "0" + "]" * 30).encode())
        with self.assertRaisesRegex(StrictJSONError, "size"):
            loads_strict(b"{}" + b" " * 20, maximum_bytes=10)

    def test_readiness_missing_unknown_and_blocker_state_fail(self):
        value = json.loads((ROOT / "machine/release-readiness.json").read_text())
        for mutation in ("missing", "unknown", "blocker"):
            changed = copy.deepcopy(value)
            if mutation == "missing":
                changed.pop("documentation_coverage")
            elif mutation == "unknown":
                changed["extra"] = True
            else:
                changed["release_blockers"] = ["unresolved"]
            with self.subTest(mutation=mutation), self.assertRaises(V1ContractError):
                validate_readiness(changed)


if __name__ == "__main__":
    unittest.main()
