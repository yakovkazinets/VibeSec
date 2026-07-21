#!/usr/bin/env python3
"""Extract one expected executable from a release tarball without trusting paths."""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import tempfile

MAX_MEMBERS = 1_000
MAX_EXECUTABLE_BYTES = 500 * 1024 * 1024


def extract_executable(archive: Path, expected_name: str, destination: Path) -> None:
    if not expected_name or PurePosixPath(expected_name).name != expected_name:
        raise ValueError("expected executable name must be a single path component")
    try:
        with tarfile.open(archive, mode="r:gz") as bundle:
            members = bundle.getmembers()
            if len(members) > MAX_MEMBERS:
                raise ValueError("archive contains too many members")
            candidates: list[tarfile.TarInfo] = []
            for member in members:
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or "" in path.parts:
                    raise ValueError(f"archive contains unsafe path: {member.name!r}")
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise ValueError(f"archive contains unsafe member type: {member.name!r}")
                if path.name == expected_name:
                    if not member.isfile():
                        raise ValueError("expected executable is not a regular file")
                    candidates.append(member)
            if len(candidates) != 1:
                raise ValueError(f"archive must contain exactly one {expected_name!r} executable")
            member = candidates[0]
            if member.size < 1 or member.size > MAX_EXECUTABLE_BYTES:
                raise ValueError("expected executable has an invalid size")
            source = bundle.extractfile(member)
            if source is None:
                raise ValueError("expected executable could not be read")
            destination.parent.mkdir(parents=True, exist_ok=True)
            handle, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
            try:
                with os.fdopen(handle, "wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
                os.replace(temporary, destination)
            except BaseException:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
                raise
    except (OSError, tarfile.TarError) as exc:
        raise ValueError(f"invalid release archive: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("expected_name")
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        extract_executable(args.archive, args.expected_name, args.destination)
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
