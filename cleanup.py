"""Executes a cleanup tier: guarded deletion plus a JSONL audit log."""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from classify import MatchResult, RuleMatcher
from rules import LOW, Rule
from scanner import (
    FILE_ATTRIBUTE_REPARSE_POINT,
    Progress,
    walk_roots,
)


@dataclass
class CleanupResult:
    tier: str
    deleted_files: int = 0
    deleted_bytes: int = 0
    skipped_locked: int = 0
    skipped_process: int = 0
    refused: int = 0
    errors: int = 0
    empty_dirs_removed: int = 0
    elapsed: float = 0.0
    log_path: str = ""


def is_within(path: str | Path, root: Path) -> bool:
    """True if `path` resolves to a location inside `root` (junction-safe)."""
    p = os.path.normcase(os.path.realpath(str(path)))
    r = os.path.normcase(os.path.realpath(str(root)))
    return p == r or p.startswith(r + os.sep)


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("w", encoding="utf-8")
        self._lock = threading.Lock()

    def write(self, **record) -> None:
        record.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%S"))
        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            self._fh.write(line + "\n")

    def close(self) -> None:
        with self._lock:
            self._fh.close()


def guarded_delete(path: str, root: Path, log: AuditLog, rule: Rule, tier: str) -> str:
    """Delete one file if it resolves inside `root`. Returns an action label."""
    size = 0
    try:
        size = os.lstat(path).st_size
    except OSError:
        pass
    if not is_within(path, root):
        log.write(action="refused", reason="outside_root", path=path, rule=rule.id, tier=tier, size=size)
        return "refused"
    try:
        os.unlink(path)
    except FileNotFoundError:
        log.write(action="deleted", path=path, rule=rule.id, tier=tier, size=size, note="already_absent")
        return "deleted"
    except PermissionError:
        log.write(action="skipped_locked", path=path, rule=rule.id, tier=tier, size=size)
        return "locked"
    except OSError as exc:
        log.write(action="error", path=path, rule=rule.id, tier=tier, size=size, reason=str(exc))
        return "error"
    log.write(action="deleted", path=path, rule=rule.id, tier=tier, size=size)
    return "deleted"


def remove_empty_dirs(
    collected: list[tuple[str, str]],
    roots: dict[str, Path],
    log: AuditLog,
    tier: str,
) -> int:
    """Bottom-up removal of empty (non-reparse) dirs visited during the walk."""
    removed = 0
    ordered = sorted(collected, key=lambda item: item[1].count("/"), reverse=True)
    for root_name, rel in ordered:
        if rel == "Temp":
            # the top-level Temp folder must keep existing: GetTempFileName
            # fails when %TEMP% is missing; cleanup empties it, never removes it
            continue
        root = roots[root_name]
        d = os.path.join(str(root), rel.replace("/", os.sep))
        if not is_within(d, root):
            log.write(action="refused", reason="outside_root", path=d, tier=tier, size=0)
            continue
        try:
            with os.scandir(d) as it:
                if any(it):
                    continue
            os.rmdir(d)
        except OSError:
            continue
        removed += 1
        log.write(action="deleted_empty_dir", path=d, tier=tier, size=0)
    return removed


def run_cleanup(
    roots: dict[str, Path],
    matcher: RuleMatcher,
    tier: str,
    progress: Progress,
    log_path: Path,
    running_processes: frozenset[str] = frozenset(),
    rule_ids: frozenset[str] | None = None,
) -> CleanupResult:
    """Delete every file whose reclaim rule belongs to `tier`.

    `rule_ids` narrows the run to those rules; None cleans the whole tier.
    """
    result = CleanupResult(tier=tier, log_path=str(log_path))
    log = AuditLog(log_path)
    collected_dirs: list[tuple[str, str]] = []
    on_dir = (
        (lambda root_name, rel: collected_dirs.append((root_name, rel)))
        if tier == LOW
        else None
    )
    start = time.monotonic()
    def on_file(root_name: str, dir_rel: str, name: str, st, match: MatchResult) -> None:
        rule = match.reclaim
        if rule is None or rule.tier != tier:
            return
        if rule_ids is not None and rule.id not in rule_ids:
            return
        root = roots[root_name]
        path = os.path.join(str(root), dir_rel, name) if dir_rel else os.path.join(str(root), name)
        if rule.processes and set(rule.processes) & running_processes:
            result.skipped_process += 1
            log.write(
                action="skipped_process",
                path=path,
                rule=rule.id,
                tier=tier,
                size=st.st_size,
                process=sorted(set(rule.processes) & running_processes),
            )
            progress.add_skipped()
            return
        action = guarded_delete(path, root, log, rule, tier)
        if action == "deleted":
            result.deleted_files += 1
            result.deleted_bytes += st.st_size
            progress.add_deleted(st.st_size)
        elif action == "locked":
            result.skipped_locked += 1
            progress.add_skipped()
        elif action == "refused":
            result.refused += 1
            progress.add_error()
        else:
            result.errors += 1
            progress.add_error()

    try:
        walk_roots(roots, matcher, progress, on_file, on_dir=on_dir)
        if tier == LOW:
            result.empty_dirs_removed = remove_empty_dirs(collected_dirs, roots, log, tier)
    finally:
        log.close()
    result.elapsed = time.monotonic() - start
    return result
