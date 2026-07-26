import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from vibesec.bundle import build_bundle_bytes  # noqa: E402
from vibesec.capabilities import all_capabilities, capability_bytes  # noqa: E402
from vibesec.strict_json import canonical_json  # noqa: E402
from vibesec.supply_chain import prepare_release  # noqa: E402
from vibesec.v1_contract import validate_examples  # noqa: E402


class V1ExecutableExamplesTests(unittest.TestCase):
    def test_all_eleven_examples_execute_with_harmless_materialized_prerequisites(self):
        catalog = validate_examples(ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            bundle = base / "vibesec-consumer-bundle.zip"
            commit = "b" * 40
            bundle.write_bytes(build_bundle_bytes(ROOT, commit)[0])
            capabilities = all_capabilities()
            capabilities["capabilities"]["java"] = False
            capability_file = base / "capabilities.json"
            capability_file.write_bytes(capability_bytes(capabilities))
            passive = all_capabilities(False)
            passive["capabilities"]["python"] = True
            passive_capability_file = base / "passive-capabilities.json"
            passive_capability_file.write_bytes(capability_bytes(passive))
            for item in catalog["examples"]:
                with self.subTest(example=item["stable_id"]):
                    target = base / item["stable_id"].removeprefix("vibesec.example.")
                    target.mkdir()
                    fixture = ROOT / item["fixture"]
                    if fixture.is_dir():
                        shutil.copytree(fixture, target, dirs_exist_ok=True)
                    command = shlex.split(item["commands"][0])
                    self._materialize_prerequisites(
                        item["stable_id"], target, bundle, capability_file,
                        passive_capability_file, commit, base,
                    )
                    command = self._bind_command(
                        command, target=target, bundle=bundle,
                        release=base / "release-candidate",
                    )
                    before = self._file_hashes(base)
                    completed = subprocess.run(
                        command, cwd=ROOT, text=True, capture_output=True, check=False,
                    )
                    expected_exit = 1 if item["stable_id"] in {
                        "vibesec.example.local-cli", "vibesec.example.upgrade",
                    } else 0
                    self.assertEqual(
                        completed.returncode, expected_exit,
                        completed.stderr + completed.stdout,
                    )
                    self.assertNotIn("fixture-secret-value", completed.stdout + completed.stderr)
                    if item["stable_id"] == "vibesec.example.authenticated-api":
                        configuration = (
                            target / ".vibesec/authenticated-security-testing.json"
                        ).read_text(encoding="utf-8")
                        self.assertIn("VIBESEC_TEST_TOKEN", configuration)
                        self.assertNotIn("fixture-secret-value", configuration)
                    self.assertEqual(before, self._file_hashes(base))

    def _materialize_prerequisites(
            self, example_id: str, target: Path, bundle: Path,
            capability_file: Path, passive_capability_file: Path,
            commit: str, base: Path) -> None:
        if example_id in {
            "vibesec.example.containerized-web",
            "vibesec.example.openapi-api",
            "vibesec.example.authenticated-api",
            "vibesec.example.api-fuzzing",
            "vibesec.example.local-cli",
            "vibesec.example.first-party-extension",
            "vibesec.example.multi-agent",
            "vibesec.example.upgrade",
        }:
            runtime = example_id in {
                "vibesec.example.containerized-web",
                "vibesec.example.openapi-api",
                "vibesec.example.authenticated-api",
                "vibesec.example.api-fuzzing",
            }
            setup = [
                sys.executable, "scripts/init_vibesec.py", "--bundle", str(bundle),
                "--profile", "minimal", "--target", str(target),
                "--capabilities-file", str(
                    capability_file if runtime else passive_capability_file
                ),
            ]
            if runtime:
                setup.extend(["--auth-secret-name", "VIBESEC_TEST_TOKEN"])
            setup.append("--write")
            self._run_setup(setup)
        if example_id in {
            "vibesec.example.openapi-api",
            "vibesec.example.authenticated-api",
            "vibesec.example.api-fuzzing",
        }:
            (target / "openapi.json").write_bytes(canonical_json({
                "openapi": "3.1.0",
                "info": {"title": "fixture", "version": "1.0.0"},
                "paths": {
                    "/health": {
                        "get": {
                            "operationId": "getHealth",
                            "responses": {"200": {"description": "ok"}},
                        },
                    },
                },
            }))
        if example_id == "vibesec.example.api-fuzzing":
            self._run_setup([
                sys.executable, "scripts/init_vibesec.py", "--bundle", str(bundle),
                "--addon", "api-security-baseline", "--target", str(target),
                "--api-schema", "openapi.json",
                "--write",
            ])
        if example_id == "vibesec.example.release-verification":
            readiness = json.loads((ROOT / "machine/release-readiness.json").read_text())
            readiness["main_commit"] = commit
            readiness_path = base / "example-readiness.json"
            readiness_path.write_bytes(canonical_json(readiness))
            prepare_release(
                base / "release-candidate",
                bundle=bundle,
                cyclonedx=ROOT / "examples/reports/sbom.cyclonedx.json",
                spdx=ROOT / "examples/reports/sbom.spdx.json",
                readiness=readiness_path,
                version=(ROOT / "VERSION").read_text().strip(),
                source_commit=commit,
                tool_versions={"cosign": "3.1.2", "syft": "1.49.0"},
                creation_mode="local-preparation",
                invocation_id="v1-example-validation",
            )

    def _run_setup(self, command: list[str]) -> None:
        completed = subprocess.run(
            command, cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)

    @staticmethod
    def _bind_command(
            command: list[str], *, target: Path, bundle: Path, release: Path) -> list[str]:
        bound = list(command)
        if "--target" in bound:
            bound[bound.index("--target") + 1] = str(target)
        if "--bundle" in bound:
            bound[bound.index("--bundle") + 1] = str(bundle)
        if len(bound) >= 3 and bound[1].endswith("verify_release_artifacts.py"):
            bound[2] = str(release)
        return bound

    @staticmethod
    def _file_hashes(root: Path) -> dict[str, str]:
        return {
            path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()
        }


if __name__ == "__main__":
    unittest.main()
