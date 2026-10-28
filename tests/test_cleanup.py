"""Cleanup execution: exact deletion scope, guards, skips, audit log."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from cleanup import AuditLog, guarded_delete, is_within, run_cleanup
from classify import RuleMatcher
from conftest import (
    FILE_SIZE,
    HIGH_DELETED,
    LOW_DELETED,
    LOW_SURVIVORS,
    MODERATE_DELETED,
    exists,
    missing,
    put,
)
from rules import RULES_BY_ID
from scanner import Progress


def _run(roots, tier, tmp_path, running=frozenset(), rule_ids=None):
    log = tmp_path / "logs" / f"{tier}.jsonl"
    matcher = RuleMatcher()
    result = run_cleanup(
        roots, matcher, tier, Progress(), log, running_processes=running, rule_ids=rule_ids
    )
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    return result, records


def test_low_deletes_exactly_the_low_set(appdata, tmp_path):
    result, records = _run(appdata, "low", tmp_path)
    assert missing(appdata, LOW_DELETED) == LOW_DELETED
    assert exists(appdata, LOW_SURVIVORS) == LOW_SURVIVORS
    assert result.deleted_files == len(LOW_DELETED)
    assert result.deleted_bytes == len(LOW_DELETED) * FILE_SIZE
    assert result.refused == 0 and result.errors == 0
    deleted = [r for r in records if r["action"] == "deleted"]
    assert len(deleted) == len(LOW_DELETED)
    assert all(r["tier"] == "low" for r in deleted)


def test_low_removes_empty_dirs_only(appdata, tmp_path):
    result, _ = _run(appdata, "low", tmp_path)
    # emptied by the cleanup
    assert not (appdata["local"] / "CrashDumps").exists()
    # pre-existing empty dirs
    assert not (appdata["local"] / "emptydir").exists()
    assert not (appdata["local"] / "empty" / "nested").exists()
    assert not (appdata["local"] / "empty").exists()
    # the top-level Temp folder is emptied but NEVER removed: GetTempFileName
    # fails when %TEMP% itself is missing
    assert (appdata["roaming"] / "Temp").exists()
    assert not any((appdata["roaming"] / "Temp").iterdir())
    # non-empty dirs survive: app/logs still holds recent.log, local/Temp new.tmp
    assert (appdata["roaming"] / "app" / "logs").exists()
    assert (appdata["roaming"] / "app").exists()
    assert (appdata["local"] / "Temp").exists()
    assert (appdata["local"] / "keep").exists()
    assert result.empty_dirs_removed == 4


def test_subset_selection_deletes_only_that_category(appdata, tmp_path):
    result, records = _run(appdata, "low", tmp_path, rule_ids=frozenset({"temp_dir"}))
    # the picked category is cleaned
    assert missing(appdata, [("local", "Temp/old.tmp")]) == [("local", "Temp/old.tmp")]
    # every other low category is left alone
    assert exists(
        appdata,
        [
            ("local", "Temp/aged.dmp"),  # *.dmp, a different category
            ("local", "Temp/new.tmp"),
            ("roaming", "app/logs/app.log"),
            ("roaming", "Temp/old.log"),
            ("local", "CrashDumps/app.dmp"),
            ("roaming", "~owner.doc"),
        ],
    ) == [
        ("local", "Temp/aged.dmp"),
        ("local", "Temp/new.tmp"),
        ("roaming", "app/logs/app.log"),
        ("roaming", "Temp/old.log"),
        ("local", "CrashDumps/app.dmp"),
        ("roaming", "~owner.doc"),
    ]
    deleted = [r for r in records if r["action"] == "deleted"]
    assert len(deleted) == 1
    assert deleted[0]["rule"] == "temp_dir"
    assert result.deleted_files == 1
    assert result.deleted_bytes == FILE_SIZE


def test_empty_category_selection_deletes_nothing(appdata, tmp_path):
    result, records = _run(appdata, "low", tmp_path, rule_ids=frozenset())
    assert result.deleted_files == 0
    assert result.deleted_bytes == 0
    assert not [r for r in records if r["action"] == "deleted"]
    assert missing(appdata, LOW_DELETED) == []


def test_moderate_deletes_caches_only(appdata, tmp_path):
    result, records = _run(appdata, "moderate", tmp_path)
    assert missing(appdata, MODERATE_DELETED) == MODERATE_DELETED
    assert (appdata["local"] / "Google/Chrome/User Data/Default/prefs.js").exists()
    assert (appdata["roaming"] / "keep/data.txt").exists()
    assert (appdata["local"] / "Microsoft/Windows/Explorer/thumbcache_96.db").exists()
    assert result.deleted_files == len(MODERATE_DELETED)
    assert all(r["tier"] == "moderate" for r in records if r["action"] == "deleted")


def test_moderate_skips_files_of_running_process(appdata, tmp_path):
    result, records = _run(appdata, "moderate", tmp_path, running=frozenset({"chrome"}))
    # chrome files skipped, everything else deleted
    assert exists(
        appdata,
        [
            ("local", "Google/Chrome/User Data/Default/Cache/cached"),
            ("local", "Google/Chrome/User Data/Default/Code Cache/cc"),
        ],
    ) == [
        ("local", "Google/Chrome/User Data/Default/Cache/cached"),
        ("local", "Google/Chrome/User Data/Default/Code Cache/cc"),
    ]
    assert result.skipped_process == 2
    assert result.deleted_files == len(MODERATE_DELETED) - 2
    skipped = [r for r in records if r["action"] == "skipped_process"]
    assert len(skipped) == 2
    assert all("chrome" in r["process"] for r in skipped)


def test_high_deletes_windows_caches_only(appdata, tmp_path):
    result, _ = _run(appdata, "high", tmp_path)
    assert missing(appdata, HIGH_DELETED) == HIGH_DELETED
    assert (appdata["local"] / "Microsoft/Windows/Explorer/keepme.txt").exists()
    assert (appdata["roaming"] / "keep/data.txt").exists()
    assert (appdata["local"] / "Temp/old.tmp").exists()  # low-tier file untouched
    assert result.deleted_files == len(HIGH_DELETED)
    assert result.deleted_bytes == len(HIGH_DELETED) * FILE_SIZE


def test_guard_refuses_path_outside_root(appdata, tmp_path):
    outsider = tmp_path / "outside" / "victim.log"
    outsider.parent.mkdir()
    outsider.write_bytes(b"x" * 10)
    log = tmp_path / "guard.jsonl"
    action = guarded_delete(
        str(outsider), appdata["local"], AuditLog(log), RULES_BY_ID["log_files"], "low"
    )
    assert action == "refused"
    assert outsider.exists()
    record = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert record["action"] == "refused"
    assert record["reason"] == "outside_root"


def test_is_within(tmp_path):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    assert is_within(root / "sub" / "f.txt", root)
    assert not is_within(tmp_path / "other" / "f.txt", root)
    assert not is_within(tmp_path, root)


def test_locked_file_is_skipped_not_failed(appdata, tmp_path):
    target = appdata["local"] / "Temp" / "old.tmp"
    handle = target.open("r+b")
    try:
        result, records = _run(appdata, "low", tmp_path)
    finally:
        handle.close()
    assert target.exists()
    assert result.skipped_locked == 1
    assert result.deleted_files == len(LOW_DELETED) - 1
    assert any(r["action"] == "skipped_locked" for r in records)
    # the log is still written and closed properly
    assert all(r["action"] in {"deleted", "skipped_locked", "deleted_empty_dir"} for r in records)


def test_junctioned_dir_is_not_followed(appdata, tmp_path):
    external = tmp_path / "external"
    external.mkdir()
    victim = put(external, "victim.log", 100)
    link = appdata["local"] / "linkdir"
    # junctions are the reparse points AppData actually contains, and unlike
    # symlinks they can be created without extra privileges
    proc = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(external)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"junction creation unavailable: {proc.stderr.strip()}")
    result, _ = _run(appdata, "low", tmp_path)
    assert victim.exists()
    assert link.exists()
    # a followed junction would surface as a guard refusal (outside root)
    assert result.refused == 0
