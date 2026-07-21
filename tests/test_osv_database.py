from datetime import date, timedelta
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from scripts.vibesec.osv_database import validate_offline_database


class OsvDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def create_archive(self, content: bytes = b"{}") -> None:
        ecosystem = self.root / "PyPI"
        ecosystem.mkdir()
        with zipfile.ZipFile(ecosystem / "all.zip", "w") as bundle:
            bundle.writestr("OSV-TEST.json", content)

    def test_validates_structure_integrity_and_freshness(self):
        self.create_archive(json.dumps({"id": "OSV-TEST"}).encode())
        result = validate_offline_database(self.root, date.today().isoformat(), 7)
        self.assertEqual(result["ecosystems"], ["PyPI"])
        self.assertEqual(result["age_days"], 0)

    def test_rejects_missing_corrupt_future_and_stale_databases(self):
        with self.assertRaises(ValueError):
            validate_offline_database(self.root, date.today().isoformat(), 7)
        self.create_archive()
        with self.assertRaises(ValueError):
            validate_offline_database(self.root, (date.today() + timedelta(days=1)).isoformat(), 7)
        with self.assertRaises(ValueError):
            validate_offline_database(self.root, (date.today() - timedelta(days=8)).isoformat(), 7)
        (self.root / "PyPI/all.zip").write_text("broken", encoding="utf-8")
        with self.assertRaises(ValueError):
            validate_offline_database(self.root, date.today().isoformat(), 7)


if __name__ == "__main__":
    unittest.main()
