import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.vibesec.api_fuzzing import default_installed_config
from scripts.vibesec.authenticated import AUTH_ENVIRONMENT_VARIABLE, configuration_bytes
from scripts.vibesec.capabilities import all_capabilities, capability_bytes

ROOT = Path(__file__).resolve().parents[1]


class FuzzingExitContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)

    def test_missing_secret_and_invalid_authentication_modes_keep_distinct_exit_contracts(self):
        repository = self.work / "repository"
        (repository / ".vibesec").mkdir(parents=True)
        capabilities = all_capabilities(False)
        capabilities["capabilities"].update({
            "api": True, "container_image": True, "api_security_target": True,
            "api_fuzzing_target": True, "authentication": True,
            "authenticated_security_testing": True,
        })
        (repository / ".vibesec/project-capabilities.json").write_bytes(capability_bytes(capabilities))
        (repository / ".vibesec/authenticated-security-testing.json").write_bytes(
            configuration_bytes("MISSING_FUZZING_BEARER")
        )
        installed = default_installed_config()
        installed.update({"mode": "fuzz", "fuzzing_enabled": True})
        (repository / ".vibesec/api-fuzzing.json").write_text(
            json.dumps(installed) + "\n", encoding="utf-8"
        )
        environment = {
            key: value for key, value in os.environ.items()
            if key != AUTH_ENVIRONMENT_VARIABLE
        }
        environment.update({"VIBESEC_AUTH_MODE": "bearer", "GITHUB_EVENT_NAME": "push"})
        results = self.work / "missing-secret"
        completed = subprocess.run([
            sys.executable, "scripts/run_api_fuzzing.py", str(results),
            "--repository", str(repository),
        ], cwd=ROOT, env=environment, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        coverage = json.loads((results / "fuzzing-coverage.json").read_text())
        policy = json.loads((results / "fuzzing-policy-result.json").read_text())
        self.assertEqual(coverage["state"], "not_configured")
        self.assertFalse(coverage["authentication_applied"])
        self.assertFalse(policy["clean"])
        self.assertNotEqual(coverage["state"], "ran")
        for index, mode in enumerate(("digest", "")):
            with self.subTest(authentication_mode=mode):
                invalid_results = self.work / f"invalid-auth-{index}"
                invalid = subprocess.run([
                    sys.executable, "scripts/run_api_fuzzing.py", str(invalid_results),
                    "--repository", str(repository), "--authentication-mode", mode,
                ], cwd=ROOT, text=True, capture_output=True, check=False)
                self.assertEqual(invalid.returncode, 3)
                invalid_coverage = json.loads(
                    (invalid_results / "fuzzing-coverage.json").read_text()
                )
                self.assertEqual(invalid_coverage["state"], "tool_error")


if __name__ == "__main__":
    unittest.main()
