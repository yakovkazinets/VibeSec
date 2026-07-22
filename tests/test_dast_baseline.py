import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.vibesec.dast import (
    DastError, load_config, normalize_zap_report, sanitize_url, trusted_event,
    validate_base_path, validate_image_reference, validate_port,
)
from scripts.test_dast_container import classify_zap_failure, zap_failure_summary


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/security-fixtures/zap-baseline"
IMAGE = "registry.example/application@sha256:" + "a" * 64


FAKE_DOCKER = r'''#!/usr/bin/env python3
import json,os,pathlib,sys
args=sys.argv[1:]
log=pathlib.Path(os.environ["FAKE_DOCKER_LOG"])
with log.open("a",encoding="utf-8") as stream: stream.write(json.dumps(args)+"\n")
mode=os.environ.get("FAKE_DAST_MODE", "success")
if args[:1] == ["pull"]: raise SystemExit(1 if mode == "pull_fail" else 0)
if args[:3] == ["image","inspect","--format"]:
 users={"root":"", "root_name":"root:root", "root_uid":"0:0"}
 print(json.dumps(users.get(mode,"1000"))); raise SystemExit(0)
if args[:2] == ["network","create"]: raise SystemExit(1 if mode == "network_fail" else 0)
if args[:2] == ["network","rm"]: raise SystemExit(1 if mode == "cleanup_fail" else 0)
if args[:2] == ["inspect","--format"]: print("false" if mode == "early_exit" else "true"); raise SystemExit(0)
if args[:2] == ["rm","-f"]: raise SystemExit(1 if mode == "cleanup_fail" else 0)
if args[:1] == ["run"]:
 if "--detach" in args: print("container-id"); raise SystemExit(1 if mode == "target_fail" else 0)
 if "python3" in args: raise SystemExit(1 if mode in {"early_exit", "not_ready"} else 0)
 if "zap-baseline.py" in args:
  config=args[args.index("-c")+1] if "-c" in args else ""
  report=args[args.index("-J")+1] if "-J" in args else ""
  policy_mount="dst=/zap/wrk/vibesec-zap-baseline.conf,readonly"
  if config != "vibesec-zap-baseline.conf" or report != "zap-report.json" or not any(policy_mount in value for value in args):
   print("packaged scan file argument contract failed",file=sys.stderr); raise SystemExit(3)
  if mode == "zap_fail": raise SystemExit(3)
  if mode != "missing_report":
   mount=next(value for value in args if value.startswith("type=bind,src=") and value.endswith(",dst=/zap/wrk"))
   directory=pathlib.Path(next(part.split("=",1)[1] for part in mount.split(",") if part.startswith("src=")))
   source=pathlib.Path(os.environ["FAKE_ZAP_REPORT"])
   (directory/"zap-report.json").write_bytes(source.read_bytes())
  raise SystemExit(int(os.environ.get("FAKE_ZAP_EXIT", "2")))
raise SystemExit(0)
'''


class DastBaselineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.docker = self.work / "docker"
        self.docker.write_text(FAKE_DOCKER, encoding="utf-8")
        self.docker.chmod(0o755)
        self.log = self.work / "docker.log"

    def run_profile(self, *, report="positive", event="workflow_dispatch", image=IMAGE, mode="success", zap_exit="2", enforcement="observe"):
        results = self.work / f"results-{len(list(self.work.glob('results-*')))}"
        environment = {key: value for key, value in os.environ.items() if not key.startswith(("VIBESEC_DAST_", "FAKE_DAST_", "FAKE_ZAP_"))}
        environment.update({"FAKE_DOCKER_LOG": str(self.log), "FAKE_DAST_MODE": mode,
                            "FAKE_ZAP_REPORT": str(FIXTURE / report / "raw.json"), "FAKE_ZAP_EXIT": zap_exit})
        completed = subprocess.run(
            [sys.executable, "scripts/run_dast_baseline.py", str(results), "--docker", str(self.docker),
             "--event", event, "--image-reference", image, "--container-port", "8080",
             "--base-path", "/positive", "--enforcement", enforcement, "--minimum-severity", "medium"],
            cwd=ROOT, env=environment, text=True, capture_output=True, check=False,
        )
        return completed, results

    def test_strict_configuration_and_inputs(self):
        config = load_config(ROOT)
        self.assertEqual(config["target_hostname"], "target")
        self.assertEqual(validate_image_reference(IMAGE), IMAGE)
        for value in ("image:latest", "http://example.com", "image@sha256:" + "A" * 64, "--privileged"):
            with self.subTest(value=value), self.assertRaises(DastError):
                validate_image_reference(value)
        self.assertEqual(validate_port("65535"), 65535)
        for value in (0, 65536, "08", "--publish"):
            with self.subTest(value=value), self.assertRaises(DastError):
                validate_port(value)
        self.assertEqual(validate_base_path("/safe/path"), "/safe/path")
        for value in ("http://host/", "../x", "/a/../b", "/x?secret=1", "/%2e%2e/x", "/a\\b"):
            with self.subTest(value=value), self.assertRaises(DastError):
                validate_base_path(value)

    def test_event_policy_fails_closed(self):
        self.assertTrue(trusted_event("workflow_dispatch"))
        self.assertTrue(trusted_event("schedule"))
        self.assertFalse(trusted_event("pull_request"))
        self.assertFalse(trusted_event("pull_request_target"))
        with self.assertRaises(DastError):
            trusted_event("push")

    def test_normalization_sanitizes_sensitive_fields(self):
        findings, urls = normalize_zap_report(FIXTURE / "positive/raw.json", port=8080, maximum_bytes=5_000_000, maximum_findings=100)
        self.assertEqual(urls, 1)
        self.assertEqual([(item["rule_id"], item["file"], item["severity"], item["confidence"]) for item in findings],
                         [("10020", "/positive", "medium", "possible")])
        serialized = json.dumps(findings)
        for prohibited in ("private=value", "fragment", "sensitive evidence", "Sensitive raw description", "param"):
            self.assertNotIn(prohibited, serialized)
        self.assertEqual(findings[0]["method"], "GET")
        clean, count = normalize_zap_report(FIXTURE / "negative/raw.json", port=8080, maximum_bytes=5_000_000, maximum_findings=100)
        self.assertEqual((clean, count), ([], 0))

    def test_unsafe_urls_and_unknown_scanner_values_fail(self):
        for url in ("https://target:8080/", "http://evil:8080/", "http://target:8080/%2e%2e/x", "http://target:8080/a\\b"):
            with self.subTest(url=url), self.assertRaises(DastError):
                sanitize_url(url, port=8080)
        payload = json.loads((FIXTURE / "positive/raw.json").read_text(encoding="utf-8"))
        for field, value in (("riskcode", "9"), ("confidence", "9")):
            changed = json.loads(json.dumps(payload))
            changed["site"][0]["alerts"][0][field] = value
            path = self.work / f"bad-{field}.json"
            path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaises(DastError):
                normalize_zap_report(path, port=8080, maximum_bytes=5_000_000, maximum_findings=100)

    def test_malformed_duplicate_oversized_and_missing_reports_fail(self):
        documents = {"malformed": b"{", "duplicate": b'{"site":[],"site":[]}', "schema": b'{"alerts":[]}'}
        for name, data in documents.items():
            path = self.work / f"{name}.json"
            path.write_bytes(data)
            with self.subTest(name=name), self.assertRaises(DastError):
                normalize_zap_report(path, port=8080, maximum_bytes=1000, maximum_findings=100)
        oversized = self.work / "oversized.json"
        oversized.write_bytes(b" " * 1001)
        with self.assertRaises(DastError):
            normalize_zap_report(oversized, port=8080, maximum_bytes=1000, maximum_findings=100)

    def test_zap_success_warning_and_fail_exits_are_completed_scans(self):
        for zap_exit in ("0", "1", "2"):
            with self.subTest(zap_exit=zap_exit):
                completed, results = self.run_profile(zap_exit=zap_exit)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                coverage = json.loads((results / "coverage.json").read_text(encoding="utf-8"))
                self.assertEqual(coverage["state"], "ran")
                self.assertEqual(coverage["target_digest"], "sha256:" + "a" * 64)
                self.assertNotIn("registry.example", json.dumps(coverage))
                self.assertFalse((results / "zap-report.json").exists())

    def test_policy_is_independent_from_zap_exit(self):
        completed, results = self.run_profile(zap_exit="2", enforcement="all")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        policy = json.loads((results / "policy-result.json").read_text(encoding="utf-8"))
        self.assertEqual(policy["exit_category"], "policy_violation")

    def test_negative_fixture_is_clean_and_stale_positive_does_not_survive(self):
        completed, results = self.run_profile(report="negative", zap_exit="0")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        normalized = json.loads((results / "normalized.json").read_text(encoding="utf-8"))
        self.assertEqual(normalized["results"], [])

    def test_runtime_commands_enforce_isolation(self):
        completed, _ = self.run_profile()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        commands = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        flattened = "\n".join(" ".join(command) for command in commands)
        self.assertIn("network create --internal", flattened)
        self.assertIn("--cap-drop ALL", flattened)
        self.assertIn("--security-opt no-new-privileges", flattened)
        self.assertIn("--read-only", flattened)
        self.assertIn("--cpus 1", flattened)
        self.assertIn("--memory 1024m", flattened)
        self.assertIn("--pids-limit 256", flattened)
        self.assertNotIn("--publish", flattened)
        self.assertNotIn("--privileged", flattened)
        self.assertNotIn("--network host", flattened)
        self.assertNotIn("docker.sock", flattened)
        target = next(command for command in commands if command[:1] == ["run"] and "--detach" in command)
        self.assertNotIn("--mount", target)
        scanner = next(command for command in commands if command[:1] == ["run"] and "zap-baseline.py" in command)
        self.assertEqual(scanner[scanner.index("-c") + 1], "vibesec-zap-baseline.conf")
        self.assertEqual(scanner[scanner.index("-J") + 1], "zap-report.json")
        self.assertFalse(scanner[scanner.index("-c") + 1].startswith("/"))
        self.assertFalse(scanner[scanner.index("-J") + 1].startswith("/"))
        mounts = [value for index, value in enumerate(scanner) if index and scanner[index - 1] == "--mount"]
        output_mount = next(value for value in mounts if value.endswith("dst=/zap/wrk"))
        policy_mount = next(value for value in mounts if "dst=/zap/wrk/vibesec-zap-baseline.conf" in value)
        self.assertNotIn("readonly", output_mount)
        self.assertTrue(policy_mount.endswith(",readonly"))
        self.assertIn(str(ROOT / "config/zap-baseline.conf"), policy_mount)
        private = Path(next(part.split("=", 1)[1] for part in output_mount.split(",") if part.startswith("src=")))
        self.assertFalse(private.exists(), "private raw-output directory survived cleanup")
        self.assertIn("-T", scanner)
        self.assertEqual(scanner[scanner.index("-T") + 1], "3")
        self.assertNotIn("-a", scanner)

    def test_live_harness_diagnostics_are_bounded_and_sanitized(self):
        marker = "MUST_NOT_APPEAR_IN_DIAGNOSTIC"
        completed = subprocess.CompletedProcess([], 3, "", "unable to open config file " + marker)
        report = self.work / "zap-report.json"
        report.write_bytes(b"{}")
        summary = zap_failure_summary("positive", completed, report)
        self.assertEqual(
            summary,
            "live ZAP scan failed: case=positive exit=3 report_exists=true report_bytes=2 category=config_file_unavailable",
        )
        self.assertNotIn(marker, summary)
        self.assertEqual(classify_zap_failure("permission denied " + marker), "filesystem_unavailable")
        self.assertEqual(classify_zap_failure(marker * 1000), "unknown_zap_exit")

    def test_live_harness_uses_packaged_scan_relative_file_contract(self):
        harness = (ROOT / "scripts/test_dast_container.py").read_text(encoding="utf-8")
        self.assertIn('"-c", "vibesec-zap-baseline.conf"', harness)
        self.assertIn('"-J", "zap-report.json"', harness)
        self.assertIn('dst=/zap/wrk/vibesec-zap-baseline.conf,readonly', harness)
        self.assertIn('dst=/zap/wrk"', harness)
        self.assertNotIn('"-c", "/zap/', harness)
        self.assertNotIn('"-J", "/zap/', harness)

    def test_fake_docker_rejects_absolute_packaged_scan_file_arguments(self):
        private = self.work / "private"
        private.mkdir()
        environment = os.environ.copy()
        environment.update({
            "FAKE_DOCKER_LOG": str(self.log),
            "FAKE_ZAP_REPORT": str(FIXTURE / "positive/raw.json"),
            "FAKE_ZAP_EXIT": "2",
        })
        mounts = [
            "--mount", f"type=bind,src={private},dst=/zap/wrk",
            "--mount", f"type=bind,src={ROOT / 'config/zap-baseline.conf'},dst=/zap/wrk/vibesec-zap-baseline.conf,readonly",
        ]
        absolute = subprocess.run(
            [str(self.docker), "run", *mounts, "pinned-zap", "zap-baseline.py",
             "-c", "/zap/policy/vibesec-zap-baseline.conf", "-J", "/zap/wrk/zap-report.json"],
            env=environment, text=True, capture_output=True, check=False,
        )
        self.assertEqual(absolute.returncode, 3)
        self.assertIn("packaged scan file argument contract failed", absolute.stderr)
        relative = subprocess.run(
            [str(self.docker), "run", *mounts, "pinned-zap", "zap-baseline.py",
             "-c", "vibesec-zap-baseline.conf", "-J", "zap-report.json"],
            env=environment, text=True, capture_output=True, check=False,
        )
        self.assertEqual(relative.returncode, 2)
        self.assertEqual((private / "zap-report.json").read_bytes(), (FIXTURE / "positive/raw.json").read_bytes())

    def test_untrusted_and_missing_configuration_never_invoke_docker(self):
        for event, image in (("pull_request", IMAGE), ("workflow_dispatch", "")):
            self.log.unlink(missing_ok=True)
            completed, results = self.run_profile(event=event, image=image)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(self.log.exists())
            coverage = json.loads((results / "coverage.json").read_text(encoding="utf-8"))
            self.assertEqual(coverage["state"], "not_configured")

    def test_tool_invalid_and_cleanup_failures_are_not_clean(self):
        for mode, expected in (("pull_fail", 2), ("root", 3), ("root_name", 3), ("root_uid", 3), ("target_fail", 2), ("zap_fail", 2),
                               ("missing_report", 3), ("cleanup_fail", 2)):
            with self.subTest(mode=mode):
                completed, results = self.run_profile(mode=mode)
                self.assertEqual(completed.returncode, expected, completed.stderr)
                coverage = json.loads((results / "coverage.json").read_text(encoding="utf-8"))
                self.assertEqual(coverage["state"], "tool_error")
                normalized = json.loads((results / "normalized.json").read_text(encoding="utf-8"))
                self.assertEqual(normalized["results"][0]["result_type"], "tool_error")

    def test_sanitized_artifact_validator_accepts_only_final_contract(self):
        completed, results = self.run_profile()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        valid = subprocess.run(
            [sys.executable, "scripts/validate_dast_artifacts.py", "--results", str(results), "--expect-state", "ran"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)
        (results / "raw-zap.json").write_text("{}\n", encoding="utf-8")
        rejected = subprocess.run(
            [sys.executable, "scripts/validate_dast_artifacts.py", "--results", str(results), "--expect-state", "ran"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(rejected.returncode, 3)


if __name__ == "__main__":
    unittest.main()
