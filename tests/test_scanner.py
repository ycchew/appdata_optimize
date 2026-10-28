"""Scan totals and per-rule statistics on the fixture tree."""
from __future__ import annotations

from classify import RuleMatcher
from conftest import FILE_SIZE, SPEC
from scanner import Progress, scan


def test_root_totals(appdata):
    result = scan(appdata, RuleMatcher(), Progress())
    expected_files = sum(len(files) for files in SPEC.values())
    assert sum(f for f, _ in result.roots.values()) == expected_files
    assert sum(b for _, b in result.roots.values()) == expected_files * FILE_SIZE
    assert set(result.roots) == set(SPEC)


def test_rule_stats_claim_precedence(appdata):
    result = scan(appdata, RuleMatcher(), Progress())
    stats = result.rule_stats

    def stat(rule_id):
        return stats.get(rule_id, {})

    # local Temp: 3 files consumed by Temp (48h), only old.tmp reclaims there
    assert stat("temp_dir")["consumed_files"] == 3
    assert stat("temp_dir")["reclaim_files"] == 1
    # aged.dmp falls through to the global *.dmp rule (24h)
    assert stat("dmp_files")["reclaim_files"] == 1
    assert stat("dmp_files").get("consumed_files", 0) == 0  # consumed by Temp first
    # new.tmp: consumed by Temp but never reclaims (too young for every filter)
    assert "tmp_files" not in stats  # no *.tmp outside Temp exists
    # logs dir: app.log reclaimed, recent.log only consumed
    assert stat("log_dirs")["consumed_files"] == 2
    assert stat("log_dirs")["reclaim_files"] == 1
    # Discord/Cache/notes.log is claimed by the moderate cache rule, not *.log
    assert stat("cache_dir")["consumed_files"] == 2
    assert stat("cache_dir")["reclaim_files"] == 2
    assert stat("log_files")["reclaim_files"] == 1  # roaming Temp/old.log only
    # browser / dev caches / windows caches
    assert stat("chrome_cache")["reclaim_files"] == 1
    assert stat("chrome_code_cache")["reclaim_files"] == 1
    assert stat("npm_cache")["reclaim_files"] == 1
    assert stat("uv_cache")["reclaim_files"] == 1
    assert stat("pip_cache")["reclaim_files"] == 1
    assert stat("dart_tool")["reclaim_files"] == 1
    assert stat("dot_cache")["reclaim_files"] == 1
    assert stat("gpu_cache").get("reclaim_files", 0) == 0  # no GPUCache fixture
    assert stat("dx_cache")["reclaim_files"] == 1
    assert stat("crashdump_dir")["reclaim_files"] == 1
    assert stat("thumbcache")["reclaim_files"] == 1
    assert stat("iconcache")["reclaim_files"] == 1
    assert stat("webcache")["reclaim_files"] == 1
    assert stat("recent_items")["reclaim_files"] == 1
    assert stat("win_caches")["reclaim_files"] == 1
    assert stat("tilde_files")["reclaim_files"] == 1


def test_unclaimed_files_absent_from_stats(appdata):
    result = scan(appdata, RuleMatcher(), Progress())
    # 29 fixture files exist; 6 match no rule at all (keep/data.txt, notes.md,
    # keep/important.db, keepme.txt, prefs.js, websites/data.txt).
    total_consumed = sum(s["consumed_bytes"] for s in result.rule_stats.values())
    total_bytes = sum(b for _, b in result.roots.values())
    assert total_bytes - total_consumed == 6 * FILE_SIZE


def test_depth2_grouping(appdata):
    result = scan(appdata, RuleMatcher(), Progress())
    local = result.depth2["local"]
    assert "Temp" in local
    assert local["Temp"][0] == 3  # old.tmp, new.tmp, aged.dmp
    assert "Microsoft/Windows" in local
    assert "Google/Chrome" in local
    # top-level files group under their own name
    assert "notes.md" in result.depth2["roaming"]
