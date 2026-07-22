import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.vibesec.dast import (
    DastError, load_config, normalize_zap_report, sanitize_url, trusted_event,
    validate_base_path, validate_image_reference, validate_port,
)
from scripts.test_dast_container import capture_zap_runtime_diagnostic
from scripts.vibesec.zap_automation import (
    CONTAINER_ZAP_HOME, JOB_TYPES, PLAN_FILENAME, REPORT_FILENAME, RUNTIME_ADDON_OPTIONS,
    build_passive_plan, load_passive_plan, trusted_zap_command,
    trusted_zap_container_command, validate_passive_plan, write_passive_plan,
)
from scripts.vibesec.zap_diagnostics import (
    ERROR_CODES, classify_zap_runtime, render_zap_runtime_diagnostic,
)


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
if args[:3] == ["inspect","--format","{{json .State}}"]:
 print(json.dumps({"Status":"exited","ExitCode":1,"OOMKilled":False,"Error":""})); raise SystemExit(0)
if args[:2] == ["inspect","--format"]: print("false" if mode == "early_exit" else "true"); raise SystemExit(0)
if args[:1] == ["logs"]: print(os.environ.get("FAKE_ZAP_RUNTIME_LOG", "")); raise SystemExit(0)
if args[:1] == ["cp"]:
 pathlib.Path(args[-1]).write_text(os.environ.get("FAKE_ZAP_RUNTIME_LOG", ""),encoding="utf-8"); raise SystemExit(0)
if args[:2] == ["rm","-f"]: raise SystemExit(1 if mode == "cleanup_fail" else 0)
if args[:1] == ["run"]:
 if "--detach" in args: print("container-id"); raise SystemExit(1 if mode == "target_fail" else 0)
 if "python3" in args: raise SystemExit(1 if mode in {"early_exit", "not_ready"} else 0)
 if "zap.sh" in args:
  tail=args[args.index("zap.sh"):]
  if tail not in (["zap.sh","-cmd","-silent","-dir","/zap/vibesec-home","-autorun","/zap/wrk/vibesec-zap-plan.yaml"],
                  ["zap.sh","-cmd","-silent","-dir","/zap/vibesec-home","-autocheck","/zap/wrk/vibesec-zap-plan.yaml"]):
   print("automation command contract failed",file=sys.stderr); raise SystemExit(3)
  mount=next(value for value in args if value.startswith("type=bind,src=") and value.endswith(",dst=/zap/wrk"))
  directory=pathlib.Path(next(part.split("=",1)[1] for part in mount.split(",") if part.startswith("src=")))
  plan=directory/"vibesec-zap-plan.yaml"
  payload=json.loads(plan.read_text(encoding="utf-8"))
  if os.environ.get("FAKE_ZAP_PLAN_LOG"): pathlib.Path(os.environ["FAKE_ZAP_PLAN_LOG"]).write_bytes(plan.read_bytes())
  if [job.get("type") for job in payload.get("jobs",[])] != ["spider","passiveScan-wait","report","exitStatus"]:
   print("automation plan contract failed",file=sys.stderr); raise SystemExit(3)
  if "-autocheck" in tail: raise SystemExit(1 if mode == "autocheck_fail" else 0)
  if mode == "zap_fail": raise SystemExit(3)
  if mode != "missing_report":
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
                            "FAKE_ZAP_REPORT": str(FIXTURE / report / "raw.json"), "FAKE_ZAP_EXIT": zap_exit,
                            "FAKE_ZAP_PLAN_LOG": str(self.work / "observed-plan.json")})
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
        completed, results = self.run_profile()
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
        scanner = next(command for command in commands if command[:1] == ["run"] and "zap.sh" in command)
        self.assertEqual(scanner[scanner.index("zap.sh"):], trusted_zap_command())
        self.assertEqual(scanner[scanner.index("--user") + 1], f"{os.getuid()}:{os.getgid()}")
        tmpfs_values = [value for index, value in enumerate(scanner) if index and scanner[index - 1] == "--tmpfs"]
        self.assertIn("/tmp:rw,noexec,nosuid,nodev,size=512m", tmpfs_values)
        self.assertIn(
            f"{CONTAINER_ZAP_HOME}:rw,noexec,nosuid,nodev,size=256m,uid={os.getuid()},gid={os.getgid()},mode=0700",
            tmpfs_values,
        )
        self.assertEqual(sum(value.startswith(CONTAINER_ZAP_HOME + ":") for value in tmpfs_values), 1)
        self.assertFalse(any(value.startswith("/home/zap:") for value in tmpfs_values))
        mounts = [value for index, value in enumerate(scanner) if index and scanner[index - 1] == "--mount"]
        self.assertEqual(len(mounts), 1)
        output_mount = mounts[0]
        self.assertTrue(output_mount.endswith("dst=/zap/wrk"))
        self.assertNotIn("readonly", output_mount)
        private = Path(next(part.split("=", 1)[1] for part in output_mount.split(",") if part.startswith("src=")))
        self.assertFalse(private.exists(), "private plan/report directory survived cleanup")
        self.assertFalse(RUNTIME_ADDON_OPTIONS.intersection(scanner))
        self.assertFalse(any("proxy" in value.casefold() for value in scanner[scanner.index("zap.sh"):]))
        for prohibited in ("zap-baseline.py", "zap-full-scan.py", "zap-api-scan.py", "activeScan", "spiderAjax", "spiderClient"):
            self.assertNotIn(prohibited, flattened)
        observed_plan = json.loads((self.work / "observed-plan.json").read_text(encoding="utf-8"))
        self.assertEqual(tuple(job["type"] for job in observed_plan["jobs"]), JOB_TYPES)
        self.assertEqual(observed_plan["env"]["contexts"][0]["urls"], ["http://target:8080/positive"])
        coverage = json.loads((results / "coverage.json").read_text(encoding="utf-8"))
        self.assertEqual(coverage["scanner_mode"], "automation_framework")
        self.assertEqual(coverage["report_template"], "traditional-json")
        self.assertFalse(coverage["runtime_addon_updates"])
        self.assertEqual(coverage["zap_home_mode"], "ephemeral_tmpfs")
        self.assertEqual(coverage["zap_home_path"], CONTAINER_ZAP_HOME)
        self.assertEqual(coverage["zap_home_tmpfs_megabytes"], 256)

    def test_trusted_plan_and_command_are_closed_to_caller_extensions(self):
        config = load_config(ROOT)
        command = trusted_zap_command()
        self.assertEqual(command, ["zap.sh", "-cmd", "-silent", "-dir", CONTAINER_ZAP_HOME,
                                   "-autorun", "/zap/wrk/vibesec-zap-plan.yaml"])
        self.assertEqual(
            trusted_zap_command("autocheck"),
            ["zap.sh", "-cmd", "-silent", "-dir", CONTAINER_ZAP_HOME,
             "-autocheck", "/zap/wrk/vibesec-zap-plan.yaml"],
        )
        self.assertEqual(command.count("-dir"), 1)
        self.assertEqual(command[command.index("-dir") + 1], CONTAINER_ZAP_HOME)
        self.assertNotIn("/home/zap", command)
        self.assertFalse(RUNTIME_ADDON_OPTIONS.intersection(command))
        self.assertFalse(any("proxy" in value.casefold() for value in command))
        with self.assertRaises(TypeError):
            trusted_zap_command("autorun", options="-addonupdate")  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            trusted_zap_command("autorun", directory="/target/controlled")  # type: ignore[call-arg]
        with self.assertRaises(DastError):
            trusted_zap_command("arbitrary")
        plan = build_passive_plan(
            port=8080, base_path="/positive", spider_minutes=config["spider_duration_minutes"],
            passive_wait_minutes=config["passive_scan_timeout_minutes"],
        )
        self.assertEqual(tuple(job["type"] for job in plan["jobs"]), JOB_TYPES)
        self.assertEqual(plan["env"]["contexts"][0]["urls"], ["http://target:8080/positive"])
        self.assertEqual(plan["jobs"][2]["parameters"]["template"], "traditional-json")
        self.assertNotIn("authentication", plan["env"]["contexts"][0])
        serialized = json.dumps(plan)
        for prohibited in ("activeScan", "spiderAjax", "spiderClient", "requestor", "script", "addOns", "proxy"):
            self.assertNotIn(prohibited, serialized)

    def test_plan_validator_rejects_origin_escape_plus_reports_and_forbidden_jobs(self):
        config = load_config(ROOT)
        original = build_passive_plan(port=8080, base_path="/positive", spider_minutes=1, passive_wait_minutes=3)
        mutations = []
        changed = json.loads(json.dumps(original)); changed["env"]["contexts"][0]["urls"] = ["https://example.invalid/"]; mutations.append(changed)
        changed = json.loads(json.dumps(original)); changed["env"]["contexts"][0]["authentication"] = {}; mutations.append(changed)
        changed = json.loads(json.dumps(original)); changed["env"]["proxy"] = {"hostname": "proxy"}; mutations.append(changed)
        changed = json.loads(json.dumps(original)); changed["jobs"][2]["parameters"]["template"] = "traditional-json-plus"; mutations.append(changed)
        for job in ("activeScan", "spiderAjax", "spiderClient", "script", "requestor", "openapi", "graphql", "soap", "addOns"):
            changed = json.loads(json.dumps(original)); changed["jobs"].insert(1, {"type": job, "parameters": {}}); mutations.append(changed)
        for changed in mutations:
            with self.subTest(plan=changed), self.assertRaises(DastError):
                validate_passive_plan(
                    changed, port=8080, base_path="/positive",
                    spider_minutes=config["spider_duration_minutes"],
                    passive_wait_minutes=config["passive_scan_timeout_minutes"],
                )

    def test_plan_is_restrictive_atomic_and_round_trips_strictly(self):
        path = self.work / PLAN_FILENAME
        write_passive_plan(path, port=8080, base_path="/positive", spider_minutes=1, passive_wait_minutes=3)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        loaded = load_passive_plan(path, port=8080, base_path="/positive", spider_minutes=1, passive_wait_minutes=3)
        self.assertEqual(tuple(job["type"] for job in loaded["jobs"]), JOB_TYPES)
        path.write_text(path.read_text(encoding="utf-8").replace("traditional-json", "traditional-json-plus"), encoding="utf-8")
        path.chmod(0o600)
        with self.assertRaises(DastError):
            load_passive_plan(path, port=8080, base_path="/positive", spider_minutes=1, passive_wait_minutes=3)

    def test_zap_home_tmpfs_has_independent_strict_bounds(self):
        workspace = self.work / "home-bound-workspace"
        workspace.mkdir(mode=0o700)
        config = load_config(ROOT)
        self.assertEqual(config["zap_home_tmpfs_megabytes"], 256)
        config_root = self.work / "config-bound-root"
        (config_root / "config").mkdir(parents=True)
        (config_root / "config/zap-baseline.conf").write_bytes((ROOT / "config/zap-baseline.conf").read_bytes())
        for value in (True, 127, 1025, "256"):
            changed = dict(config)
            changed["zap_home_tmpfs_megabytes"] = value
            (config_root / "config/dast-baseline.json").write_text(
                json.dumps(changed) + "\n", encoding="utf-8",
            )
            with self.subTest(config_value=value), self.assertRaises(DastError):
                load_config(config_root)
            with self.subTest(value=value), self.assertRaises(DastError):
                trusted_zap_container_command(
                    docker="docker", container_name="vibesec-zap-test", network="vibesec-zap-network",
                    workspace=workspace, image="pinned-image", config=changed,
                )

    def test_production_and_live_harness_share_the_command_builder(self):
        for relative in ("scripts/run_dast_baseline.py", "scripts/test_dast_container.py"):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("trusted_zap_container_command(", source)
            self.assertIn("write_passive_plan(", source)
            self.assertNotIn("zap-baseline.py", source)
            self.assertNotIn("zap-full-scan.py", source)

    def test_live_runtime_diagnostic_categories_are_precise(self):
        cases = (
            ("fatal Java heap space", {"OOMKilled": True, "ExitCode": 137}, "java_out_of_memory"),
            ("unable to create native thread", {"ExitCode": 1}, "java_thread_limit"),
            ("Unable to create home directory: /zap/.ZAP/", {"ExitCode": 1}, "zap_home_unwritable"),
            ("permission denied writing /zap/vibesec-home/config.xml", {"ExitCode": 1}, "zap_home_unwritable"),
            ("permission denied writing /zap/wrk/zap-report.json", {"ExitCode": 1}, "filesystem_permission_failed"),
            ("failed to access URL: connection refused", {"ExitCode": 1}, "target_unreachable"),
            ("report job failed: cannot write output", {"ExitCode": 1}, "report_generation_failed"),
            ("report job failed: template traditional-json unavailable", {"ExitCode": 1}, "report_template_unavailable"),
            ("passive scan rule add-on missing", {"ExitCode": 1}, "passive_rule_unavailable"),
            ("", {"ExitCode": 143, "Error": "killed"}, "container_killed"),
            ("Automation Framework job spider failed", {"ExitCode": 1}, "automation_job_error"),
            ("unclassified failure", {"ExitCode": 1}, "unknown_zap_runtime_error"),
        )
        for text, state, expected in cases:
            with self.subTest(expected=expected):
                classified = classify_zap_runtime(text, state)
                self.assertEqual(classified["code"], expected)
                self.assertIn(classified["code"], ERROR_CODES)
        self.assertEqual(classify_zap_runtime(cases[-2][0], cases[-2][1])["job"], "spider")

    def test_live_runtime_diagnostic_is_bounded_and_sanitized(self):
        report = self.work / REPORT_FILENAME
        raw = ("ERROR Automation Framework job report failed for https://target:8080/positive?secret=yes "
               "at /home/runner/work/VibeSec/private/0123456789abcdef\x00") * 20
        summary = render_zap_runtime_diagnostic(
            case="positive", exit_code=1,
            state={"Status": "exited", "ExitCode": 1, "OOMKilled": False, "Error": ""},
            report=report, runtime_text=raw,
        )
        self.assertLessEqual(len(summary), 512)
        self.assertIn("code=report_generation_failed", summary)
        self.assertIn("job=report", summary)
        for prohibited in ("https://", "/home/runner", "0123456789abcdef", "secret=yes", "\x00"):
            self.assertNotIn(prohibited, summary)

    def test_stopped_container_log_is_copied_parsed_and_deleted(self):
        private = self.work / "private-diagnostic"
        private.mkdir(mode=0o700)
        report = private / REPORT_FILENAME
        runtime_log = "ERROR Automation Framework job report failed: template traditional-json unavailable"
        scan = subprocess.CompletedProcess([], 1, "", "")
        with patch.dict(os.environ, {
            "FAKE_DOCKER_LOG": str(self.log),
            "FAKE_ZAP_RUNTIME_LOG": runtime_log,
        }):
            summary = capture_zap_runtime_diagnostic(
                docker=str(self.docker), container="vibesec-dast-live-zap-positive-deadbeef",
                private=private, case="positive", scan=scan, report=report,
            )
        self.assertIn("code=report_template_unavailable", summary)
        self.assertFalse((private / ".vibesec-zap-runtime.log").exists())
        commands = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(any(command[:3] == ["logs", "--tail", "200"] for command in commands))
        self.assertTrue(any(command[:1] == ["cp"] and
                            f":{CONTAINER_ZAP_HOME}/zap.log" in command[1] for command in commands))

    def test_live_harness_uses_controlled_fixture_and_pinned_autocheck(self):
        harness = (ROOT / "scripts/test_dast_container.py").read_text(encoding="utf-8")
        self.assertIn('ROOT / "tests/security-fixtures/zap-baseline/server.py"', harness)
        self.assertIn('operation="autocheck"', harness)
        self.assertIn('capture_zap_runtime_diagnostic(', harness)
        self.assertIn('[docker, "logs", "--tail", "200", container]', harness)
        self.assertIn('[docker, "cp", f"{container}:{CONTAINER_ZAP_HOME}/zap.log"', harness)
        production = (ROOT / "scripts/run_dast_baseline.py").read_text(encoding="utf-8")
        self.assertNotIn("capture_zap_runtime_diagnostic", production)
        self.assertNotIn('"logs", "--tail"', production)
        builder = (ROOT / "scripts/vibesec/zap_automation.py").read_text(encoding="utf-8")
        self.assertIn('dst={CONTAINER_WORKDIR}', builder)
        self.assertNotIn("run_dast_baseline.py .", harness)

    def test_vibesec_dast_self_state_is_not_applicable_and_consumer_addon_is_opt_in(self):
        matrix = json.loads((ROOT / "config/security-capabilities.json").read_text(encoding="utf-8"))
        states = {item["self_repository_scan"] for item in matrix["capabilities"] if item["profile"] == "dast-baseline"}
        self.assertEqual(states, {"not_applicable"})
        catalog = json.loads((ROOT / "config/adoption-files.json").read_text(encoding="utf-8"))
        self.assertEqual(set(catalog["addons"]), {"dast-baseline"})
        self.assertTrue(all("run_dast_baseline.py" not in profile["support"] for profile in catalog["profiles"].values()))

    def test_untrusted_and_missing_configuration_never_invoke_docker(self):
        for event, image in (("pull_request", IMAGE), ("workflow_dispatch", "")):
            self.log.unlink(missing_ok=True)
            completed, results = self.run_profile(event=event, image=image)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(self.log.exists())
            coverage = json.loads((results / "coverage.json").read_text(encoding="utf-8"))
            self.assertEqual(coverage["state"], "not_configured")

    def test_automation_exit_one_without_report_is_runtime_failure(self):
        completed, results = self.run_profile(mode="missing_report", zap_exit="1")
        self.assertEqual(completed.returncode, 2, completed.stderr)
        coverage = json.loads((results / "coverage.json").read_text(encoding="utf-8"))
        self.assertEqual(coverage["state"], "tool_error")

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
