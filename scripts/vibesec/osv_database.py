"""Validate caller-provisioned OSV offline database metadata without extraction."""

from __future__ import annotations

from datetime import date
from pathlib import Path
import zipfile

MAX_ARCHIVES = 100
MAX_MEMBERS_PER_ARCHIVE = 1_000_000


def validate_offline_database(path: Path, declared_date: str, maximum_age_days: int) -> dict[str, object]:
    try:
        root = path.resolve(strict=True)
        if not root.is_dir() or path.is_symlink():
            raise ValueError("offline OSV database path must be a real directory")
        database_date = date.fromisoformat(declared_date)
    except (OSError, ValueError) as exc:
        raise ValueError(f"invalid offline OSV database configuration: {exc}") from exc
    age_days = (date.today() - database_date).days
    if age_days < 0:
        raise ValueError("offline OSV database date cannot be in the future")
    if maximum_age_days < 0 or maximum_age_days > 3650:
        raise ValueError("offline OSV maximum age must be between 0 and 3650 days")
    if age_days > maximum_age_days:
        raise ValueError(f"offline OSV database is stale ({age_days} days; maximum {maximum_age_days})")
    archives = sorted(root.glob("*/all.zip"))
    if not archives or len(archives) > MAX_ARCHIVES:
        raise ValueError("offline OSV database requires a bounded set of <ecosystem>/all.zip archives")
    ecosystems: list[str] = []
    for archive in archives:
        if archive.is_symlink() or archive.parent.parent != root:
            raise ValueError("offline OSV database archives must not be symlinks")
        try:
            with zipfile.ZipFile(archive) as bundle:
                members = bundle.infolist()
                if not members or len(members) > MAX_MEMBERS_PER_ARCHIVE:
                    raise ValueError(f"offline OSV archive {archive.parent.name} has an invalid member count")
                if not any(not member.is_dir() and member.filename.endswith(".json") and member.file_size > 0 for member in members):
                    raise ValueError(f"offline OSV archive {archive.parent.name} contains no advisory JSON")
                if bundle.testzip() is not None:
                    raise ValueError(f"offline OSV archive {archive.parent.name} failed integrity checking")
        except (OSError, zipfile.BadZipFile) as exc:
            raise ValueError(f"invalid offline OSV archive {archive}: {exc}") from exc
        ecosystems.append(archive.parent.name)
    return {"path": str(root), "date": declared_date, "age_days": age_days, "maximum_age_days": maximum_age_days, "ecosystems": ecosystems}
