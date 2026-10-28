"""Shared fixture: a fake AppData tree with known ages and sizes."""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

FILE_SIZE = 100
OLD = 100.0  # hours old: passes every age filter in the rule table
MID = 30.0  # passes >=24h filters, fails the 48h Temp filter
NEW = 1.0  # fails every age filter (smallest filter is 24h)

# root -> {relative/path: age_hours}
SPEC: dict[str, dict[str, float]] = {
    "roaming": {
        "Temp/old.log": OLD,
        "app/logs/app.log": OLD,
        "app/logs/recent.log": NEW,
        "Discord/Cache/blob": OLD,
        "Discord/Cache/notes.log": OLD,  # dir rule (moderate) must beat *.log (low)
        "Microsoft/Windows/Recent/doc.lnk": NEW,
        "Microsoft/Windows/Caches/win.dat": NEW,
        "keep/data.txt": OLD,
        "~owner.doc": OLD,
        "notes.md": NEW,
        ".dart_tool/pkg": NEW,
    },
    "local": {
        "Temp/old.tmp": OLD,
        "Temp/new.tmp": NEW,
        "Temp/aged.dmp": MID,  # too young for Temp (48h), old enough for *.dmp (24h)
        "Microsoft/Windows/Explorer/thumbcache_96.db": NEW,
        "Microsoft/Windows/Explorer/iconcache_32.db": NEW,
        "Microsoft/Windows/Explorer/keepme.txt": NEW,
        "Microsoft/Windows/WebCache/V01.db": NEW,
        "NVIDIA/DXCache/shader.bin": OLD,
        "Google/Chrome/User Data/Default/Cache/cached": OLD,
        "Google/Chrome/User Data/Default/Code Cache/cc": OLD,
        "Google/Chrome/User Data/Default/prefs.js": NEW,
        "npm-cache/_cacache/x": OLD,
        "uv/cache/archive/y": OLD,
        "pip/cache/wheels/z": OLD,
        "CrashDumps/app.dmp": OLD,
        "keep/important.db": OLD,
        ".cache/tool.bin": NEW,
    },
    "locallow": {
        "websites/data.txt": OLD,
    },
}

EMPTY_DIRS = ["emptydir", "empty/nested"]  # pre-created empty dirs in `local`

LOW_DELETED = [
    ("roaming", "Temp/old.log"),
    ("roaming", "app/logs/app.log"),
    ("roaming", "~owner.doc"),
    ("local", "Temp/old.tmp"),
    ("local", "Temp/aged.dmp"),
    ("local", "CrashDumps/app.dmp"),
]

LOW_SURVIVORS = [
    ("roaming", "app/logs/recent.log"),
    ("roaming", "keep/data.txt"),
    ("roaming", "Discord/Cache/notes.log"),
    ("roaming", "notes.md"),
    ("local", "Temp/new.tmp"),
    ("local", "Google/Chrome/User Data/Default/Cache/cached"),
    ("local", "Microsoft/Windows/Explorer/thumbcache_96.db"),
    ("local", "keep/important.db"),
    ("locallow", "websites/data.txt"),
]

MODERATE_DELETED = [
    ("roaming", "Discord/Cache/blob"),
    ("roaming", "Discord/Cache/notes.log"),
    ("roaming", ".dart_tool/pkg"),
    ("local", "Google/Chrome/User Data/Default/Cache/cached"),
    ("local", "Google/Chrome/User Data/Default/Code Cache/cc"),
    ("local", "npm-cache/_cacache/x"),
    ("local", "uv/cache/archive/y"),
    ("local", "pip/cache/wheels/z"),
    ("local", ".cache/tool.bin"),
    ("local", "NVIDIA/DXCache/shader.bin"),
]

HIGH_DELETED = [
    ("roaming", "Microsoft/Windows/Recent/doc.lnk"),
    ("roaming", "Microsoft/Windows/Caches/win.dat"),
    ("local", "Microsoft/Windows/Explorer/thumbcache_96.db"),
    ("local", "Microsoft/Windows/Explorer/iconcache_32.db"),
    ("local", "Microsoft/Windows/WebCache/V01.db"),
]


def put(base: Path, rel: str, age_hours: float, size: int = FILE_SIZE) -> Path:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"x" * size)
    t = time.time() - age_hours * 3600
    os.utime(p, (t, t))
    return p


def put_in(roots: dict[str, Path], root: str, rel: str, age_hours: float) -> Path:
    return put(roots[root], rel, age_hours)


def exists(roots: dict[str, Path], pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Return the subset of (root, rel) pairs that still exist."""
    return [(r, rel) for r, rel in pairs if (roots[r] / rel).exists()]


def missing(roots: dict[str, Path], pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Return the subset of (root, rel) pairs that no longer exist."""
    return [(r, rel) for r, rel in pairs if not (roots[r] / rel).exists()]


@pytest.fixture
def appdata(tmp_path):
    roots = {
        "roaming": tmp_path / "Roaming",
        "local": tmp_path / "Local",
        "locallow": tmp_path / "LocalLow",
    }
    for p in roots.values():
        p.mkdir()
    for root_name, files in SPEC.items():
        for rel, age in files.items():
            put(roots[root_name], rel, age)
    for rel in EMPTY_DIRS:
        (roots["local"] / rel).mkdir(parents=True)
    return roots
