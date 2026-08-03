import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from vibesec.v1_contract import (  # noqa: E402
    V1ContractError, build_readiness, canonical_readiness, validate_readiness,
    validate_release_validation_evidence,
)


def validation_evidence(commit: str, total: int = 123):
    return {
        "schema_version": 1,
        "stable_id": "vibesec.release-validation-evidence.v1",
        "status": "passed",
        "source_commit": commit,
        "test_command": "python3 -m unittest discover -s tests -v",
        "test_total": total,
        "test_result": "passed",
        "repository_validation_command": "python3 scripts/validate_repository.py",
        "repository_validation_result": "passed",
    }


class V1ReleaseReadinessTests(unittest.TestCase):
    def test_committed_readiness_is_complete_and_non_publishing(self):
        value = json.loads((ROOT / "machine/release-readiness.json").read_text())
        validate_readiness(
            value, source_commit="990305e7c940bd714e0de7aaebd1df4722da3f2a",
        )
        self.assertEqual(value["status"], "ready_with_known_limitations")
        self.assertEqual(value["release_blockers"], [])
        self.assertEqual(value["test_totals"]["automated_tests"], 474)
        self.assertEqual(
            value["test_totals"]["evidence"],
            "exact-sha-validate:990305e7c940bd714e0de7aaebd1df4722da3f2a",
        )
        self.assertNotEqual(value["test_totals"]["evidence"], "required-validate")

    def test_readiness_generation_is_deterministic(self):
        evidence = validation_evidence("c" * 40)
        first = build_readiness(
            ROOT, main_commit="c" * 40, validation_evidence=evidence,
        )
        second = build_readiness(
            ROOT, main_commit="c" * 40, validation_evidence=evidence,
        )
        self.assertEqual(canonical_readiness(first), canonical_readiness(second))
        self.assertEqual(first["test_totals"]["automated_tests"], 123)
        self.assertEqual(first["test_totals"]["evidence"], f"exact-sha-validate:{'c' * 40}")

    def test_fresh_validation_evidence_and_readiness_are_exact_commit_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            tests_log = base / "tests.log"
            tests_log.write_text(
                "test_example ... ok\n\nRan 1 test in 0.001s\n\nOK\n",
                encoding="utf-8",
            )
            repository_log = base / "repository.log"
            repository_log.write_text("repository configuration is valid\n", encoding="utf-8")
            evidence_path = base / "evidence.json"
            current = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
                capture_output=True, check=True,
            ).stdout.strip()
            evidence_command = [
                sys.executable, "scripts/generate_release_validation_evidence.py",
                "--output", str(evidence_path), "--source-commit", current,
                "--test-log", str(tests_log),
                "--repository-validation-log", str(repository_log),
            ]
            generated = subprocess.run(
                evidence_command, cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)
            evidence = json.loads(evidence_path.read_text())
            validate_release_validation_evidence(evidence, source_commit=current)
            self.assertEqual(evidence["test_total"], 1)

            output = base / "readiness.json"
            readiness_command = [
                sys.executable, "scripts/generate_release_readiness.py",
                "--output", str(output), "--main-commit", current,
                "--validation-evidence", str(evidence_path),
            ]
            created = subprocess.run(
                readiness_command, cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            self.assertEqual(json.loads(output.read_text())["test_totals"], {
                "automated_tests": 1,
                "evidence": f"exact-sha-validate:{current}",
                "machine_catalogs": 14,
                "migration_paths": 11,
            })
            repeated = subprocess.run(
                readiness_command, cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(repeated.returncode, 3)

    def test_failed_stale_or_ambiguous_validation_evidence_is_rejected(self):
        commit = "d" * 40
        for mutation in ("failed", "stale", "zero"):
            evidence = validation_evidence(commit)
            if mutation == "failed":
                evidence["test_result"] = "failed"
            elif mutation == "stale":
                evidence["source_commit"] = "e" * 40
            else:
                evidence["test_total"] = 0
            with self.subTest(mutation=mutation), self.assertRaises(V1ContractError):
                validate_release_validation_evidence(evidence, source_commit=commit)

    def test_validation_evidence_generator_rejects_failed_or_ambiguous_logs(self):
        current = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
            capture_output=True, check=True,
        ).stdout.strip()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository_log = base / "repository.log"
            repository_log.write_text("repository configuration is valid\n", encoding="utf-8")
            for label, content in (
                ("failed", "Ran 1 test in 0.001s\n\nFAILED (failures=1)\n"),
                (
                    "ambiguous",
                    "Ran 1 test in 0.001s\nOK\nRan 1 test in 0.001s\nOK\n",
                ),
            ):
                test_log = base / f"{label}.log"
                test_log.write_text(content, encoding="utf-8")
                output = base / f"{label}.json"
                completed = subprocess.run(
                    [
                        sys.executable,
                        "scripts/generate_release_validation_evidence.py",
                        "--output", str(output), "--source-commit", current,
                        "--test-log", str(test_log),
                        "--repository-validation-log", str(repository_log),
                    ],
                    cwd=ROOT, text=True, capture_output=True, check=False,
                )
                with self.subTest(label=label):
                    self.assertEqual(completed.returncode, 3)
                    self.assertFalse(output.exists())

    def test_release_workflow_has_no_publication_trigger_or_command(self):
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(encoding="utf-8")
        self.assertIn("release-readiness.json", workflow)
        self.assertIn("generate_release_validation_evidence.py", workflow)
        self.assertIn("python3 -m unittest discover -s tests -v", workflow)
        self.assertIn("python3 scripts/validate_repository.py", workflow)
        self.assertNotIn("--test-total-file", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        for forbidden in ("pull_request_target", "gh release", "git tag", "git push", "contents: write"):
            self.assertNotIn(forbidden, workflow)


if __name__ == "__main__":
    unittest.main()
