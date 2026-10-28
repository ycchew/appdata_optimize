"""Threaded AppData walker: size totals and rule matching in a single pass."""
from __future__ import annotations

import concurrent.futures
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from classify import MatchResult, RuleMatcher

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_ATTRIBUTE_DIRECTORY = 0x10
MAX_WORKERS = 8


class Progress:
    """Shared counters, printed by a ticker while scan/cleanup runs."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.files = 0
        self.bytes = 0
        self.deleted = 0
        self.deleted_bytes = 0
        self.skipped = 0
        self.errors = 0

    def add_scan(self, files: int, nbytes: int) -> None:
        with self._lock:
            self.files += files
            self.bytes += nbytes

    def add_deleted(self, nbytes: int) -> None:
        with self._lock:
            self.deleted += 1
            self.deleted_bytes += nbytes

    def add_skipped(self) -> None:
        with self._lock:
            self.skipped += 1

    def add_error(self) -> None:
        with self._lock:
            self.errors += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "files": self.files,
                "bytes": self.bytes,
                "deleted": self.deleted,
                "deleted_bytes": self.deleted_bytes,
                "skipped": self.skipped,
                "errors": self.errors,
            }


# (root_name, dir_rel, file_name, st, match)
FileHook = Callable[[str, str, str, object, MatchResult], None]
DirHook = Callable[[str, str], None]


@dataclass
class ScanResult:
    roots: dict[str, tuple[int, int]]  # root -> (files, bytes)
    depth2: dict[str, dict[str, tuple[int, int]]]  # root -> key -> (files, bytes)
    rule_stats: dict[str, dict]  # rule id -> consumed/reclaim counters
    elapsed: float = 0.0

    def to_json(self) -> dict:
        return {
            "roots": self.roots,
            "depth2": self.depth2,
            "rule_stats": self.rule_stats,
            "elapsed": round(self.elapsed, 2),
        }


class ScanCollector:
    """Builds a ScanResult from walk callbacks (called from worker threads)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._roots: dict[str, list[int]] = {}
        self._depth2: dict[str, dict[str, list[int]]] = {}
        self._rule_stats: dict[str, dict] = {}

    def on_file(self, root: str, dir_rel: str, name: str, st, match: MatchResult) -> None:
        if dir_rel:
            parts = dir_rel.split("/")
            key = "/".join(parts[:2]) if len(parts) > 1 else parts[0]
        else:
            key = name
        with self._lock:
            rt = self._roots.setdefault(root, [0, 0])
            rt[0] += 1
            rt[1] += st.st_size
            d2 = self._depth2.setdefault(root, {})
            e = d2.setdefault(key, [0, 0])
            e[0] += 1
            e[1] += st.st_size
            if match.consumed is not None:
                rs = self._rule_stats.setdefault(
                    match.consumed.id, _new_rule_stat()
                )
                rs["consumed_files"] += 1
                rs["consumed_bytes"] += st.st_size
            if match.reclaim is not None:
                rs = self._rule_stats.setdefault(match.reclaim.id, _new_rule_stat())
                rs["reclaim_files"] += 1
                rs["reclaim_bytes"] += st.st_size

    def result(self, elapsed: float) -> ScanResult:
        return ScanResult(
            roots={k: (v[0], v[1]) for k, v in self._roots.items()},
            depth2={k: {dk: (dv[0], dv[1]) for dk, dv in v.items()} for k, v in self._depth2.items()},
            rule_stats=self._rule_stats,
            elapsed=elapsed,
        )


def _new_rule_stat() -> dict:
    return {
        "consumed_files": 0,
        "consumed_bytes": 0,
        "reclaim_files": 0,
        "reclaim_bytes": 0,
    }


def walk_roots(
    roots: dict[str, Path],
    matcher: RuleMatcher,
    progress: Progress,
    on_file: FileHook,
    on_dir: DirHook | None = None,
) -> None:
    """Walk every root concurrently, calling `on_file` for each regular file.

    Reparse points (junctions/symlinks) are never followed and never reach
    the hooks. Exceptions from worker threads are re-raised here.
    """
    now = time.time()
    jobs: list[tuple[str, Path, str, str, tuple]] = []
    for root_name, root in roots.items():
        initial = matcher.initial_active(root_name)
        try:
            entries = list(os.scandir(root))
        except OSError:
            progress.add_error()
            continue
        for entry in entries:
            jobs.append((root_name, entry.path, "", entry.name, initial))

    def run_job(job):
        root_name, path, parent_rel, name, active = job
        _visit(root_name, path, parent_rel, name, active, matcher, on_file, progress, on_dir, now)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(run_job, job) for job in jobs]
        for fut in concurrent.futures.as_completed(futures):
            exc = fut.exception()
            if exc is not None:
                raise exc


def _visit(
    root_name: str,
    path: str,
    parent_rel: str,
    name: str,
    active: tuple,
    matcher: RuleMatcher,
    on_file: FileHook,
    progress: Progress,
    on_dir: DirHook | None,
    now: float,
) -> None:
    """Process one top-level entry (file or directory), depth-first via a stack.

    Stack items are (entry_path, parent_dir_rel, entry_name, active_rules).
    """
    stack: list[tuple[str, str, str, tuple]] = [(path, parent_rel, name, active)]
    while stack:
        cur, parent_rel, name, active = stack.pop()
        try:
            st = os.lstat(cur)
        except OSError:
            progress.add_error()
            continue
        if st.st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            continue
        if st.st_file_attributes & FILE_ATTRIBUTE_DIRECTORY:
            self_rel = f"{parent_rel}/{name}" if parent_rel else name
            if on_dir is not None:
                on_dir(root_name, self_rel)
            child_active = matcher.active_for(root_name, self_rel, active)
            try:
                children = list(os.scandir(cur))
            except OSError:
                progress.add_error()
                continue
            files = 0
            nbytes = 0
            for child in children:
                try:
                    cst = os.lstat(child.path)
                except OSError:
                    progress.add_error()
                    continue
                if cst.st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                    continue
                if cst.st_file_attributes & FILE_ATTRIBUTE_DIRECTORY:
                    stack.append((child.path, self_rel, child.name, child_active))
                else:
                    files += 1
                    nbytes += cst.st_size
                    match = matcher.match(child.name, cst, child_active, now)
                    on_file(root_name, self_rel, child.name, cst, match)
            progress.add_scan(files, nbytes)
            continue
        # Regular file at a top level (files inside dirs are handled above).
        match = matcher.match(name, st, active, now)
        progress.add_scan(1, st.st_size)
        on_file(root_name, parent_rel, name, st, match)


def scan(
    roots: dict[str, Path],
    matcher: RuleMatcher,
    progress: Progress | None = None,
) -> ScanResult:
    """Run a full scan and return aggregated totals."""
    if progress is None:
        progress = Progress()
    collector = ScanCollector()
    start = time.monotonic()
    walk_roots(roots, matcher, progress, collector.on_file)
    return collector.result(time.monotonic() - start)
