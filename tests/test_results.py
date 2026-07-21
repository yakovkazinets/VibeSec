import json
from pathlib import Path
import tempfile
import unittest

from scripts.vibesec.model import Finding
from scripts.vibesec.results import ResultDocumentError, append_tool_errors_atomic


def tool_error(tool: str) -> dict:
    return Finding.create(
        tool=tool,
        category="execution",
        rule_id="tool-error",
        severity="low",
        description=f"{tool} failed safely",
        confidence="unknown",
        result_type="tool_error",
    ).to_dict()


class ResultWriterTests(unittest.TestCase):
    def make_results(self, content: bytes = b'{"schema_version": 1, "results": []}\n') -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "normalized.json"
        path.write_bytes(content)
        return path

    def assert_valid_trailing_newline(self, path: Path) -> dict:
        data = path.read_bytes()
        self.assertTrue(data.endswith(b"\n"))
        self.assertFalse(data.endswith(b"\\n"))
        return json.loads(data)

    def test_empty_tool_error_input_remains_valid_json(self):
        path = self.make_results()
        append_tool_errors_atomic(path, [])
        payload = self.assert_valid_trailing_newline(path)
        self.assertEqual(payload["results"], [])

    def test_one_or_more_tool_errors_are_appended(self):
        path = self.make_results()
        append_tool_errors_atomic(path, [tool_error("trivy"), tool_error("actionlint")])
        payload = self.assert_valid_trailing_newline(path)
        self.assertEqual([item["tool"] for item in payload["results"]], ["trivy", "actionlint"])
        self.assertTrue(all(item["result_type"] == "tool_error" for item in payload["results"]))

    def test_malformed_input_fails_without_replacing_original(self):
        path = self.make_results(b'{"schema_version": 1, "results": []}\\n')
        original = path.read_bytes()
        with self.assertRaises(ResultDocumentError):
            append_tool_errors_atomic(path, [])
        self.assertEqual(path.read_bytes(), original)

    def test_malformed_existing_result_fails_closed(self):
        path = self.make_results(b'{"schema_version": 1, "results": [{"result_type": "finding"}]}\n')
        with self.assertRaises(ResultDocumentError):
            append_tool_errors_atomic(path, [])


if __name__ == "__main__":
    unittest.main()
