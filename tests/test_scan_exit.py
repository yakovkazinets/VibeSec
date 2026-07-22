from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.preserve_scan_exit import read_scan_exit


ROOT = Path(__file__).resolve().parents[1]


class ScanExitContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "scan-exit-code.txt"

    def test_exact_contract_values_are_preserved(self):
        for code in range(4):
            with self.subTest(code=code):
                self.path.write_bytes(f"{code}\n".encode())
                self.assertEqual(read_scan_exit(self.path), code)
                completed = subprocess.run(
                    ["python3", "scripts/preserve_scan_exit.py", str(self.path)], cwd=ROOT, check=False,
                )
                self.assertEqual(completed.returncode, code)

    def test_missing_file_fails_as_invalid_input(self):
        self.assertEqual(read_scan_exit(self.path), 3)

    def test_malformed_duplicated_and_out_of_range_files_fail_as_invalid_input(self):
        for payload in (b"", b"0", b"0\n0\n", b"4\n", b"-1\n", b" 0\n", b"x\n"):
            with self.subTest(payload=payload):
                self.path.write_bytes(payload)
                self.assertEqual(read_scan_exit(self.path), 3)


if __name__ == "__main__":
    unittest.main()
