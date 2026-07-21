import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StandardProfileIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.tools = base / "tools"
        self.results = base / "results"
        self.tools.mkdir()
        self.write_tool("opengrep", r'''#!/usr/bin/env python3
import json, os, sys
output = sys.argv[sys.argv.index("--json-output") + 1]
mode = os.getenv("FAKE_OPENGREP_MODE", "pass")
if mode == "fail": raise SystemExit(9)
if mode == "malformed": open(output, "w").write("not-json")
elif mode == "finding": json.dump({"results":[{"check_id":"vibesec.python.test","path":"fixture.py","start":{"line":1},"extra":{"severity":"ERROR","message":"Synthetic test finding","lines":"OMITTED_SECRET"}}]}, open(output, "w"))
else: json.dump({"results":[]}, open(output, "w"))
''')
        self.write_tool("osv-scanner", r'''#!/usr/bin/env python3
import json, os, sys
mode = os.getenv("FAKE_OSV_MODE", "pass")
if mode == "fail": raise SystemExit(8)
output = sys.argv[sys.argv.index("--output-file") + 1]
payload = {"results":[]}
if mode == "finding": payload = {"results":[{"source":{"path":"requirements.txt"},"packages":[{"package":{"name":"fixture"},"vulnerabilities":[{"id":"OSV-TEST","summary":"Synthetic advisory","database_specific":{"severity":"HIGH"}}]}]}]}
json.dump(payload, open(output, "w"))
if mode == "finding": raise SystemExit(1)
''')
        self.write_tool("syft", r'''#!/usr/bin/env python3
import json, sys
for index, value in enumerate(sys.argv):
    if value == "--output":
        form, path = sys.argv[index + 1].split("=", 1)
        payload = ({"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"fixture"}]} if form == "cyclonedx-json" else {"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[{"name":"fixture"}]})
        json.dump(payload, open(path, "w"))
''')
        self.write_tool("trivy", r'''#!/usr/bin/env python3
import json, sys
output = sys.argv[sys.argv.index("--output") + 1]
json.dump({"Results":[]}, open(output, "w"))
''')
        self.write_tool("gitleaks", r'''#!/usr/bin/env python3
import json, sys
output = sys.argv[sys.argv.index("--report-path") + 1]
json.dump([], open(output, "w"))
''')
        self.write_tool("actionlint", "#!/usr/bin/env bash\nexit 0\n")
        self.write_tool("docker", "#!/usr/bin/env bash\nprintf '{\"results\":{\"failed_checks\":[]}}\\n'\n")

    def write_tool(self, name: str, source: str) -> None:
        path = self.tools / name
        path.write_text(textwrap.dedent(source), encoding="utf-8")
        path.chmod(0o755)

    def run_profile(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update({"PATH": f"{self.tools}:{environment['PATH']}", **overrides})
        return subprocess.run(
            ["python3", "scripts/run_standard_profile.py", str(ROOT), str(self.results), "--tool-dir", str(self.tools)],
            cwd=ROOT, env=environment, text=True, capture_output=True, check=False,
        )

    def load_json(self, name: str) -> dict:
        data = (self.results / name).read_bytes()
        self.assertTrue(data.endswith(b"\n"))
        self.assertFalse(data.endswith(b"\\n"))
        return json.loads(data)

    def test_complete_orchestration_outputs_reports_coverage_and_sboms(self):
        completed = self.run_profile()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.load_json("normalized.json")["profile"], "standard")
        states = {entry["tool"]: entry["state"] for entry in self.load_json("coverage.json")["tools"]}
        self.assertEqual(states["opengrep"], "ran")
        self.assertEqual(states["checkov"], "ran")
        self.assertEqual(states["trivy-image"], "not_configured")
        self.assertTrue(all(entry["version"] for entry in self.load_json("coverage.json")["tools"]))
        self.assertIn("Standard profile coverage", (self.results / "report.md").read_text(encoding="utf-8"))
        self.assertTrue((self.results / "sbom.cyclonedx.json").is_file())
        self.assertTrue((self.results / "sbom.spdx.json").is_file())

    def test_tool_execution_failure_returns_two(self):
        completed = self.run_profile(FAKE_OSV_MODE="fail")
        self.assertEqual(completed.returncode, 2, completed.stderr)
        results = self.load_json("normalized.json")["results"]
        self.assertTrue(any(item["tool"] == "osv-scanner" and item["result_type"] == "tool_error" for item in results))

    def test_osv_finding_exit_is_not_misclassified_as_tool_failure(self):
        completed = self.run_profile(FAKE_OSV_MODE="finding", VIBESEC_ENFORCEMENT="all")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        results = self.load_json("normalized.json")["results"]
        self.assertTrue(any(item["tool"] == "osv-scanner" and item["result_type"] == "finding" for item in results))
        self.assertFalse(any(item["tool"] == "osv-scanner" and item["result_type"] == "tool_error" for item in results))

    def test_malformed_scanner_output_returns_three_not_clean(self):
        completed = self.run_profile(FAKE_OPENGREP_MODE="malformed")
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertIn("tool_error", json.dumps(self.load_json("normalized.json")))
        self.assertNotIn("Status: **pass**", (self.results / "report.md").read_text(encoding="utf-8"))

    def test_security_finding_returns_one_in_enforce_all_mode(self):
        completed = self.run_profile(FAKE_OPENGREP_MODE="finding", VIBESEC_ENFORCEMENT="all")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        serialized = json.dumps(self.load_json("normalized.json"))
        self.assertIn("Synthetic test finding", serialized)
        self.assertNotIn("OMITTED_SECRET", serialized)

    def test_tag_only_image_reference_is_invalid_configuration(self):
        completed = self.run_profile(VIBESEC_IMAGE_REFERENCE="example/image:latest")
        self.assertEqual(completed.returncode, 3)


if __name__ == "__main__":
    unittest.main()
