import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from scripts.extract_tool_archive import extract_executable


class ToolArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def archive(self, members: list[tuple[str, bytes, str]]) -> Path:
        path = self.root / "asset.tar.gz"
        with tarfile.open(path, "w:gz") as bundle:
            for name, content, kind in members:
                info = tarfile.TarInfo(name)
                if kind == "file":
                    info.size = len(content)
                    bundle.addfile(info, io.BytesIO(content))
                elif kind == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = "elsewhere"
                    bundle.addfile(info)
        return path

    def test_extracts_one_regular_executable_atomically(self):
        output = self.root / "bin/tool"
        extract_executable(self.archive([("README", b"text", "file"), ("tool", b"binary", "file")]), "tool", output)
        self.assertEqual(output.read_bytes(), b"binary")
        self.assertTrue(output.stat().st_mode & 0o111)

    def test_rejects_traversal_and_leaves_destination_untouched(self):
        output = self.root / "tool"
        output.write_bytes(b"existing")
        with self.assertRaises(ValueError):
            extract_executable(self.archive([("../escape", b"bad", "file"), ("tool", b"new", "file")]), "tool", output)
        self.assertEqual(output.read_bytes(), b"existing")

    def test_rejects_links_and_duplicate_executables(self):
        for members in (
            [("link", b"", "symlink"), ("tool", b"ok", "file")],
            [("tool", b"one", "file"), ("nested/tool", b"two", "file")],
        ):
            with self.subTest(members=members), self.assertRaises(ValueError):
                extract_executable(self.archive(members), "tool", self.root / "output")


if __name__ == "__main__":
    unittest.main()
