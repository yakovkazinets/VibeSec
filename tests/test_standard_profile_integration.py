import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
import zipfile
from datetime import date

ROOT = Path(__file__).resolve().parents[1]


class StandardProfileIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.tools = base / "tools"
        self.results = base / "results"
        self.target = base / "target"
        self.tools.mkdir()
        (self.target / ".git").mkdir(parents=True)
        (self.target / ".github/workflows").mkdir(parents=True)
        (self.target / "main.py").write_text("print('fixture')\n", encoding="utf-8")
        (self.target / "requirements.txt").write_text("fixture==1\n", encoding="utf-8")
        (self.target / ".github/workflows/test.yml").write_text("name: test\non: push\njobs: {}\n", encoding="utf-8")
        (self.target / "main.tf").write_text("resource \"test\" \"fixture\" {}\n", encoding="utf-8")
        # Target-controlled scanner configuration must never become authoritative.
        (self.target / ".gitleaks.toml").write_text("[[rules]]\nid='disable'\n", encoding="utf-8")
        (self.target / ".semgrepignore").write_text("**\n", encoding="utf-8")
        (self.target / ".syft.yaml").write_text("enrich: [all]\n", encoding="utf-8")
        expected = str(ROOT)
        self.write_tool("opengrep", r'''#!/usr/bin/env python3
import json, os, sys
expected = os.environ["VIBESEC_EXPECTED_ROOT"]
assert sys.argv[sys.argv.index("--config") + 1] == expected + "/rules/opengrep"
assert sys.argv[sys.argv.index("--semgrepignore-filename") + 1] == expected + "/config/opengrep-standard.ignore"
assert "--no-git-ignore" in sys.argv
output = sys.argv[sys.argv.index("--json-output") + 1]
mode = os.getenv("FAKE_OPENGREP_MODE", "pass")
if mode == "fail": raise SystemExit(9)
if mode == "malformed": open(output, "w").write("not-json")
elif mode == "finding": json.dump({"results":[{"check_id":"vibesec.python.test","path":"fixture.py","start":{"line":1},"extra":{"severity":"ERROR","message":"Synthetic test finding","lines":"OMITTED_SECRET"}}]}, open(output, "w"))
else: json.dump({"results":[]}, open(output, "w"))
''')
        self.write_tool("osv-scanner", r'''#!/usr/bin/env python3
import json, os, sys
assert sys.argv[sys.argv.index("--config") + 1] == "/dev/null"
assert "--no-call-analysis=go" in sys.argv and "--no-call-analysis=rust" in sys.argv
assert "--no-resolve" in sys.argv
assert sys.argv[1:3] == ["scan", "source"]
mode = os.getenv("FAKE_OSV_MODE", "pass")
if mode == "fail": raise SystemExit(8)
output = sys.argv[sys.argv.index("--output-file") + 1]
payload = {"results":[]}
if mode == "finding": payload = {"results":[{"source":{"path":"requirements.txt"},"packages":[{"package":{"name":"fixture"},"vulnerabilities":[{"id":"OSV-TEST","summary":"Synthetic advisory","database_specific":{"severity":"HIGH"}}]}]}]}
json.dump(payload, open(output, "w"))
if mode == "finding": raise SystemExit(1)
''')
        self.write_tool("syft", r'''#!/usr/bin/env python3
import json, os, sys
expected = os.environ["VIBESEC_EXPECTED_ROOT"]
assert sys.argv[sys.argv.index("--config") + 1] == expected + "/config/syft-standard.yaml"
assert "dir:." in sys.argv and sys.argv[sys.argv.index("--base-path") + 1] == "."
if os.getenv("FAKE_SYFT_MODE") == "fail": raise SystemExit(7)
for index, value in enumerate(sys.argv):
    if value == "--output":
        form, path = sys.argv[index + 1].split("=", 1)
        payload = ({"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"fixture"}]} if form == "cyclonedx-json" else {"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[{"name":"fixture"}]})
        json.dump(payload, open(path, "w"))
''')
        self.write_tool("trivy", r'''#!/usr/bin/env python3
import json, os, sys
expected = os.environ["VIBESEC_EXPECTED_ROOT"]
assert sys.argv[sys.argv.index("--config") + 1] == expected + "/config/trivy-standard.yaml"
output = sys.argv[sys.argv.index("--output") + 1]
json.dump({"Results":[]}, open(output, "w"))
''')
        self.write_tool("gitleaks", r'''#!/usr/bin/env python3
import json, os, sys
expected = os.environ["VIBESEC_EXPECTED_ROOT"]
assert sys.argv[sys.argv.index("--config") + 1] == expected + "/config/gitleaks-standard.toml"
assert sys.argv[sys.argv.index("--gitleaks-ignore-path") + 1] == expected + "/config/gitleaks-standard-ignore.txt"
output = sys.argv[sys.argv.index("--report-path") + 1]
json.dump([], open(output, "w"))
''')
        self.write_tool("actionlint", r'''#!/usr/bin/env python3
import os, sys
expected = os.environ["VIBESEC_EXPECTED_ROOT"]
assert sys.argv[sys.argv.index("-config-file") + 1] == expected + "/config/actionlint-standard.yaml"
assert sys.argv[sys.argv.index("-shellcheck") + 1] == ""
assert sys.argv[sys.argv.index("-pyflakes") + 1] == ""
''')
        self.write_tool("docker", r'''#!/usr/bin/env python3
import json, sys
assert sys.argv[sys.argv.index("--network") + 1] == "none"
assert sys.argv[sys.argv.index("--config-file") + 1] == "/dev/null"
assert "--read-only" in sys.argv and "ALL" in sys.argv and "/workspace:ro" in " ".join(sys.argv)
print(json.dumps({"results":{"failed_checks":[]}}))
''')

    def write_tool(self, name: str, source: str) -> None:
        path = self.tools / name
        path.write_text(textwrap.dedent(source), encoding="utf-8")
        path.chmod(0o755)

    def run_profile(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update({"PATH": f"{self.tools}:{environment['PATH']}", "VIBESEC_EXPECTED_ROOT": str(ROOT), **overrides})
        return subprocess.run(
            ["python3", "scripts/run_standard_profile.py", str(self.target), str(self.results), "--vibesec-root", str(ROOT), "--tool-dir", str(self.tools)],
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
        self.assertEqual(states["trivy-image"], "not_applicable")
        coverage = self.load_json("coverage.json")
        self.assertTrue(all(entry["version"] for entry in coverage["tools"]))
        self.assertTrue(all(entry["application_code_executed"] is False for entry in coverage["tools"]))
        self.assertEqual(len({entry["tool"] for entry in coverage["tools"]}), 8)
        self.assertEqual(coverage["sbom_formats"], ["CycloneDX 1.6", "SPDX-2.3"])
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

    def test_observe_mode_reports_finding_without_policy_failure(self):
        completed = self.run_profile(FAKE_OPENGREP_MODE="finding", VIBESEC_ENFORCEMENT="observe")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Synthetic test finding", json.dumps(self.load_json("normalized.json")))

    def test_new_mode_blocks_unbaselined_finding(self):
        completed = self.run_profile(FAKE_OPENGREP_MODE="finding", VIBESEC_ENFORCEMENT="new")
        self.assertEqual(completed.returncode, 1, completed.stderr)

    def test_offline_mode_requires_and_uses_explicit_fresh_database(self):
        database = self.target.parent / "osv-db"
        (database / "PyPI").mkdir(parents=True)
        with zipfile.ZipFile(database / "PyPI/all.zip", "w") as bundle:
            bundle.writestr("OSV-TEST.json", "{}")
        completed = self.run_profile(
            VIBESEC_NETWORK_MODE="offline", VIBESEC_OSV_DATABASE_DIR=str(database),
            VIBESEC_OSV_DATABASE_DATE=date.today().isoformat(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        coverage = self.load_json("coverage.json")
        osv = next(item for item in coverage["tools"] if item["tool"] == "osv-scanner")
        self.assertEqual(osv["network_access"], "local_database")
        self.assertEqual(coverage["osv_database"]["age_days"], 0)

    def test_offline_mode_without_database_is_invalid_configuration(self):
        completed = self.run_profile(VIBESEC_NETWORK_MODE="offline", VIBESEC_OSV_DATABASE_DATE=date.today().isoformat())
        self.assertEqual(completed.returncode, 3)

    def test_stale_sboms_are_removed_when_syft_fails(self):
        self.results.mkdir()
        for name in ("sbom.cyclonedx.json", "sbom.spdx.json"):
            (self.results / name).write_text("stale", encoding="utf-8")
        completed = self.run_profile(FAKE_SYFT_MODE="fail")
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertFalse((self.results / "sbom.cyclonedx.json").exists())
        self.assertFalse((self.results / "sbom.spdx.json").exists())

    def test_image_scan_is_disabled_for_unknown_github_events(self):
        completed = self.run_profile(
            GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="pull_request",
            VIBESEC_IMAGE_REFERENCE="registry.example/image@sha256:" + "a" * 64,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        entry = next(item for item in self.load_json("coverage.json")["tools"] if item["tool"] == "trivy-image")
        self.assertEqual(entry["state"], "not_configured")
        self.assertIn("untrusted", entry["reason"])

    def test_dockerfile_without_image_is_an_explicit_coverage_gap(self):
        (self.target / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        completed = self.run_profile()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        entry = next(item for item in self.load_json("coverage.json")["tools"] if item["tool"] == "trivy-image")
        self.assertEqual(entry["state"], "not_configured")
        self.assertEqual(entry["relevant_artifacts"], ["Dockerfile"])

    def test_digest_image_runs_only_on_trusted_event(self):
        completed = self.run_profile(
            GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="push",
            VIBESEC_IMAGE_REFERENCE="registry.example/image@sha256:" + "b" * 64,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        entry = next(item for item in self.load_json("coverage.json")["tools"] if item["tool"] == "trivy-image")
        self.assertEqual(entry["state"], "ran")
        self.assertEqual(entry["network_access"], "scanner_managed")

    def test_no_relevant_standard_artifacts_are_not_reported_as_clean_runs(self):
        for relative in ("main.py", "requirements.txt", "main.tf", ".github/workflows/test.yml"):
            (self.target / relative).unlink()
        completed = self.run_profile()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        states = {item["tool"]: item["state"] for item in self.load_json("coverage.json")["tools"]}
        for tool in ("opengrep", "osv-scanner", "syft", "checkov", "actionlint", "trivy-image"):
            self.assertEqual(states[tool], "not_applicable")


if __name__ == "__main__":
    unittest.main()
