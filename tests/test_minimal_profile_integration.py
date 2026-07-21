import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


class MinimalProfileIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        temporary_root = Path(self.temporary.name)
        self.tool_dir = temporary_root / "tools"
        self.results_dir = temporary_root / "results"
        self.tool_dir.mkdir()
        self.write_tool("trivy", r'''#!/usr/bin/env bash
set -u
output=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then output="$2"; shift 2; else shift; fi
done
if [[ "${FAKE_TRIVY_MODE:-pass}" == "fail" ]]; then exit 7; fi
if [[ "${FAKE_TRIVY_MODE:-pass}" == "malformed" ]]; then printf 'not-json' > "$output"; exit 0; fi
printf '{"Results":[]}\n' > "$output"
''')
        self.write_tool("gitleaks", r'''#!/usr/bin/env bash
set -u
report=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--report-path" ]]; then report="$2"; shift 2; else shift; fi
done
if [[ "${FAKE_GITLEAKS_MODE:-pass}" == "finding" ]]; then
  printf '[{"RuleID":"fake-test-rule","Description":"Harmless synthetic finding","File":"fixture.txt","StartLine":1}]\n' > "$report"
  exit 1
fi
printf '[]\n' > "$report"
''')
        self.write_tool("actionlint", r'''#!/usr/bin/env bash
if [[ "${FAKE_ACTIONLINT_MODE:-pass}" == "fail" ]]; then exit 8; fi
exit 0
''')

    def write_tool(self, name: str, source: str) -> None:
        path = self.tool_dir / name
        path.write_text(textwrap.dedent(source), encoding="utf-8")
        path.chmod(0o755)

    def run_profile(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update({"VIBESEC_TOOL_DIR": str(self.tool_dir), **overrides})
        return subprocess.run(
            ["bash", "scripts/run_minimal_profile.sh", str(ROOT), str(self.results_dir)],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def load_final_results(self) -> dict:
        data = (self.results_dir / "normalized.json").read_bytes()
        self.assertTrue(data.endswith(b"\n"))
        self.assertFalse(data.endswith(b"\\n"))
        return json.loads(data)

    def test_complete_orchestration_writes_valid_results_and_report(self):
        completed = self.run_profile()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.load_final_results()["results"], [])
        report = (self.results_dir / "report.md").read_text(encoding="utf-8")
        self.assertIn("Status: **pass**", report)

    def test_tool_failure_is_appended_and_returns_two(self):
        completed = self.run_profile(FAKE_TRIVY_MODE="fail")
        self.assertEqual(completed.returncode, 2, completed.stderr)
        results = self.load_final_results()["results"]
        self.assertEqual(results[0]["tool"], "trivy")
        self.assertEqual(results[0]["result_type"], "tool_error")
        self.assertIn("Status: **tool_error**", (self.results_dir / "report.md").read_text(encoding="utf-8"))

    def test_policy_violation_returns_one(self):
        completed = self.run_profile(FAKE_GITLEAKS_MODE="finding", VIBESEC_ENFORCEMENT="all")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(self.load_final_results()["results"][0]["result_type"], "finding")
        self.assertIn("Status: **policy_violation**", (self.results_dir / "report.md").read_text(encoding="utf-8"))

    def test_malformed_scanner_output_returns_three_not_clean(self):
        completed = self.run_profile(FAKE_TRIVY_MODE="malformed")
        self.assertEqual(completed.returncode, 3)
        self.assertFalse((self.results_dir / "report.md").exists())
        self.assertIn("malformed scanner output", completed.stderr)


if __name__ == "__main__":
    unittest.main()
