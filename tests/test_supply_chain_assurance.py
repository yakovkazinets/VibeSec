import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from vibesec.bundle import build_bundle_bytes, verify_bundle  # noqa: E402
from vibesec.strict_json import canonical_json  # noqa: E402
from vibesec.supply_chain import (  # noqa: E402
    BUNDLE_NAME, CHECKSUMS_NAME, CYCLONEDX_NAME, MANIFEST_NAME,
    OIDC_ISSUER, PROVENANCE_NAME, SIGNATURE_NAME, SPDX_NAME,
    WORKFLOW_IDENTITY, SupplyChainError, checksum_bytes, prepare_release,
    validate_verification_record, verification_record, verify_release,
)


class SupplyChainAssuranceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.commit = "a" * 40
        self.bundle = self.root / "input.zip"
        self.bundle.write_bytes(build_bundle_bytes(ROOT, self.commit)[0])
        self.cyclonedx = self.root / "cyclonedx.json"
        self.spdx = self.root / "spdx.json"
        self.cyclonedx.write_bytes((ROOT / "examples/reports/sbom.cyclonedx.json").read_bytes())
        self.spdx.write_bytes((ROOT / "examples/reports/sbom.spdx.json").read_bytes())

    def prepare(self, name="release", creation_mode="local-preparation"):
        output = self.root / name
        prepare_release(
            output, bundle=self.bundle, cyclonedx=self.cyclonedx, spdx=self.spdx,
            version="0.3.0-dev", source_commit=self.commit,
            tool_versions={"cosign": "3.1.2", "syft": "1.49.0"},
            creation_mode=creation_mode, invocation_id="controlled-test",
        )
        return output

    def test_preparation_is_deterministic_and_closed(self):
        first = self.prepare("first")
        second = self.prepare("second")
        self.assertEqual(
            {path.name: path.read_bytes() for path in first.iterdir()},
            {path.name: path.read_bytes() for path in second.iterdir()},
        )
        result = verify_release(first)
        self.assertFalse(result.signature_verified)
        self.assertEqual(result.manifest["source"]["commit"], self.commit)
        self.assertEqual(list(result.checksums), [
            BUNDLE_NAME, CYCLONEDX_NAME, SPDX_NAME, PROVENANCE_NAME, MANIFEST_NAME,
        ])
        self.assertNotIn(str(self.root), json.dumps(result.manifest))

    def test_bundle_sbom_manifest_provenance_and_checksum_tampering_fail(self):
        cases = (BUNDLE_NAME, CYCLONEDX_NAME, SPDX_NAME, MANIFEST_NAME, PROVENANCE_NAME, CHECKSUMS_NAME)
        for name in cases:
            release = self.prepare(f"tamper-{name.replace('.', '-')}")
            path = release / name
            path.write_bytes(path.read_bytes() + b"x")
            with self.subTest(name=name), self.assertRaises(SupplyChainError):
                verify_release(release)

    def test_wrong_sbom_and_wrong_provenance_subject_fail_closed(self):
        wrong_sbom = self.prepare("wrong-sbom")
        (wrong_sbom / CYCLONEDX_NAME).write_bytes((wrong_sbom / SPDX_NAME).read_bytes())
        (wrong_sbom / CHECKSUMS_NAME).write_bytes(checksum_bytes(wrong_sbom))
        with self.assertRaises(SupplyChainError):
            verify_release(wrong_sbom)

        wrong_subject = self.prepare("wrong-subject")
        provenance = json.loads((wrong_subject / PROVENANCE_NAME).read_text())
        provenance["subject"][0]["digest"]["sha256"] = "0" * 64
        (wrong_subject / PROVENANCE_NAME).write_bytes(canonical_json(provenance))
        (wrong_subject / CHECKSUMS_NAME).write_bytes(checksum_bytes(wrong_subject))
        with self.assertRaisesRegex(SupplyChainError, "subjects"):
            verify_release(wrong_subject)

    def test_missing_extra_duplicate_key_and_oversized_inputs_fail(self):
        missing = self.prepare("missing")
        (missing / SPDX_NAME).unlink()
        with self.assertRaises(SupplyChainError):
            verify_release(missing)

        extra = self.prepare("extra")
        (extra / "unexpected").write_text("x")
        with self.assertRaises(SupplyChainError):
            verify_release(extra)

        duplicate = self.prepare("duplicate")
        data = (duplicate / MANIFEST_NAME).read_bytes()
        (duplicate / MANIFEST_NAME).write_bytes(data.replace(b'{"artifacts"', b'{"schema_version":1,"artifacts"', 1))
        with self.assertRaisesRegex(SupplyChainError, "duplicate JSON key"):
            verify_release(duplicate)

        oversized = self.prepare("oversized")
        (oversized / CYCLONEDX_NAME).write_bytes(b"x" * (50 * 1024 * 1024 + 1))
        with self.assertRaisesRegex(SupplyChainError, "oversized"):
            verify_release(oversized)

    def test_signature_bundle_is_structural_and_external_cosign_identity_is_exact(self):
        malformed = self.prepare("malformed-signature")
        (malformed / SIGNATURE_NAME).write_bytes(b'{"a":1,"a":2}\n')
        with self.assertRaises(SupplyChainError):
            verify_release(malformed, require_signature=True, cosign=Path("/bin/false"))

        signed = self.prepare("signed")
        (signed / SIGNATURE_NAME).write_bytes(b"{}\n")
        log = self.root / "cosign.log"
        fake = self.root / "cosign"
        fake.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FAKE_COSIGN_LOG\"\n", encoding="utf-8")
        fake.chmod(0o755)
        old = os.environ.get("FAKE_COSIGN_LOG")
        os.environ["FAKE_COSIGN_LOG"] = str(log)
        self.addCleanup(lambda: os.environ.pop("FAKE_COSIGN_LOG", None) if old is None else os.environ.__setitem__("FAKE_COSIGN_LOG", old))
        result = verify_release(signed, require_signature=True, cosign=fake)
        self.assertTrue(result.signature_verified)
        command = log.read_text()
        self.assertIn(WORKFLOW_IDENTITY, command)
        self.assertIn(OIDC_ISSUER, command)
        with self.assertRaises(SupplyChainError):
            verify_release(signed, require_signature=True, cosign=fake, certificate_identity="attacker")

    def test_signer_preserves_tool_failure_and_rejects_untrusted_context(self):
        release = self.prepare("trusted-signing", "trusted-github-workflow")
        fake = self.root / "cosign-signer"
        fake.write_text(
            "#!/bin/sh\n"
            "output=''\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  if [ \"$1\" = '--bundle' ]; then shift; output=$1; fi\n"
            "  shift\n"
            "done\n"
            "[ -z \"$output\" ] || printf '{}\\n' > \"$output\"\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        environment = os.environ.copy()
        environment.update({
            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "yakovkazinets/VibeSec", "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": self.commit,
        })
        untrusted = environment.copy()
        untrusted["GITHUB_EVENT_NAME"] = "pull_request"
        rejected = subprocess.run(
            ["python3", "scripts/sign_release_artifacts.py", str(release), "--cosign", str(fake)],
            cwd=ROOT, env=untrusted, text=True, capture_output=True, check=False,
        )
        self.assertEqual(rejected.returncode, 3)
        self.assertFalse((release / SIGNATURE_NAME).exists())
        signed = subprocess.run(
            ["python3", "scripts/sign_release_artifacts.py", str(release), "--cosign", str(fake)],
            cwd=ROOT, env=environment, text=True, capture_output=True, check=False,
        )
        self.assertEqual(signed.returncode, 0, signed.stderr)
        self.assertEqual((release / SIGNATURE_NAME).read_bytes(), b"{}\n")

        failure_release = self.prepare("tool-failure-signing", "trusted-github-workflow")
        failing = self.root / "cosign-failure"
        failing.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
        failing.chmod(0o755)
        failed = subprocess.run(
            ["python3", "scripts/sign_release_artifacts.py", str(failure_release), "--cosign", str(failing)],
            cwd=ROOT, env=environment, text=True, capture_output=True, check=False,
        )
        self.assertEqual(failed.returncode, 2)
        self.assertFalse((failure_release / SIGNATURE_NAME).exists())

    def test_verification_record_rejects_mutable_reference_and_unsupported_tool(self):
        release = self.prepare("record")
        unsigned = verify_release(release)
        record = verification_record(unsigned, release_reference=None, verification_tool=None)
        self.assertFalse(validate_verification_record(record)["signature_verified"])
        with self.assertRaisesRegex(SupplyChainError, "immutable"):
            verification_record(unsigned, release_reference="https://github.com/yakovkazinets/VibeSec/releases/latest", verification_tool=None)
        changed = dict(record)
        changed["verification_tool"] = "cosign/latest"
        with self.assertRaises(SupplyChainError):
            validate_verification_record(changed)

    def test_cli_reports_checksum_only_verification_without_claiming_identity(self):
        release = self.prepare("cli")
        completed = subprocess.run(
            ["python3", "scripts/verify_release_artifacts.py", str(release), "--json"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["result"]["checksums_verified"])
        self.assertFalse(payload["result"]["signature_verified"])
        self.assertFalse(payload["result"]["publisher_identity_verified"])

    def test_doctor_and_upgrade_preserve_verified_release_metadata(self):
        release = self.prepare("lifecycle-release")
        target = self.root / "consumer"
        target.mkdir()
        initialized = subprocess.run(
            ["python3", "scripts/init_vibesec.py", "--bundle", str(self.bundle),
             "--profile", "minimal", "--target", str(target), "--all-capabilities", "--write"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        doctor = subprocess.run(
            ["python3", "scripts/vibesec_doctor.py", "--target", str(target), "--json"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        codes = {item["code"] for item in json.loads(doctor.stdout)["result"]["diagnostics"]}
        self.assertIn("RELEASE_METADATA_MISSING", codes)

        record_path = target / ".vibesec/release-verification.json"
        recorded = subprocess.run(
            ["python3", "scripts/verify_release_artifacts.py", str(release),
             "--record", str(record_path), "--json"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(recorded.returncode, 0, recorded.stderr)
        shutil.copyfile(release / PROVENANCE_NAME, target / ".vibesec" / PROVENANCE_NAME)
        doctor = subprocess.run(
            ["python3", "scripts/vibesec_doctor.py", "--target", str(target), "--json"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        codes = {item["code"] for item in json.loads(doctor.stdout)["result"]["diagnostics"]}
        self.assertNotIn("RELEASE_METADATA_MISSING", codes)
        self.assertNotIn("RELEASE_METADATA_INVALID", codes)
        self.assertIn("RELEASE_SIGNATURE_UNVERIFIED", codes)

        planned = subprocess.run(
            ["python3", "scripts/plan_vibesec_upgrade.py", "--target", str(target),
             "--bundle", str(self.bundle), "--json"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertIn(planned.returncode, {0, 1}, planned.stderr)
        plan = json.loads(planned.stdout)["result"]
        self.assertIn(".vibesec/release-verification.json", plan["files_to_preserve"])
        self.assertIn(".vibesec/provenance.intoto.jsonl", plan["files_to_preserve"])
        self.assertEqual(
            {item["classification"] for item in plan["files"] if item["path"].startswith(".vibesec/release-") or item["path"].endswith("provenance.intoto.jsonl")},
            {"release_metadata_preserve"},
        )

        (target / ".vibesec" / PROVENANCE_NAME).write_text("{}\n", encoding="utf-8")
        malformed = subprocess.run(
            ["python3", "scripts/vibesec_doctor.py", "--target", str(target), "--json"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        malformed_codes = {item["code"] for item in json.loads(malformed.stdout)["result"]["diagnostics"]}
        self.assertIn("RELEASE_METADATA_INVALID", malformed_codes)

    def test_release_workflow_and_offline_posture_enforce_trust_boundary(self):
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("push:", workflow)
        self.assertIn("github.repository == 'yakovkazinets/VibeSec'", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertEqual(workflow.count("id-token: write"), 1)
        for prohibited in ("gh release", "git tag", "git push", "contents: write"):
            self.assertNotIn(prohibited, workflow)
        completed = subprocess.run(
            ["python3", "scripts/validate_supply_chain_posture.py"], cwd=ROOT,
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertTrue(json.loads(completed.stdout)["passed"])

    def test_accountability_catalog_lists_all_required_cases(self):
        catalog = json.loads((ROOT / "tests/security-fixtures/supply-chain/expected.json").read_text())
        self.assertEqual(catalog["schema_version"], 1)
        self.assertEqual(len(catalog["required_cases"]), 15)
        self.assertEqual(len(catalog["required_cases"]), len(set(catalog["required_cases"])))


if __name__ == "__main__":
    unittest.main()
