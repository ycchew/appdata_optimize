"""Rule table sanity and pattern/classification unit tests."""
from __future__ import annotations

import os

import pytest

from classify import RuleMatcher, literal_prefix, pattern_to_regex
from rules import RULES, RULES_BY_ID


def test_rule_ids_unique():
    assert len(RULES_BY_ID) == len(RULES)


@pytest.mark.parametrize(
    "pattern,path,expected",
    [
        ("**/Cache", "Cache", True),
        ("**/Cache", "Discord/Cache", True),
        ("**/Cache", "a/b/Cache", True),
        ("**/Cache", "a/Cachex", False),
        ("**/Cache", "a/b", False),
        ("Temp", "Temp", True),
        ("Temp", "x/Temp", False),
        ("Temp", "temp", True),  # case-insensitive
        ("Microsoft/Windows/Recent", "Microsoft/Windows/Recent", True),
        ("Microsoft/Windows/Recent", "Microsoft/Windows/Recent-Auto", False),
        ("Google/Chrome/User Data/*/Cache", "Google/Chrome/User Data/Default/Cache", True),
        ("Google/Chrome/User Data/*/Cache", "Google/Chrome/User Data/Default/Sub/Cache", False),
        ("**", "", True),
        ("**", "anything/at/all", True),
        ("**/.dart*tool", ".dart_tool", True),
        ("**/.dart*tool", "x/.dart-tool", True),
        ("a/**", "a/b/c", True),
        ("a/**", "ab", False),
        ("a/**", "a", False),
    ],
)
def test_pattern_matching(pattern, path, expected):
    matched = pattern_to_regex(pattern).fullmatch(path) is not None
    assert matched == expected


@pytest.mark.parametrize(
    "pattern,expected",
    [
        ("Microsoft/Windows/Explorer", "Microsoft/Windows/Explorer"),
        ("**/Cache", ""),
        ("Google/Chrome/User Data/*/Cache", "Google/Chrome/User Data/"),
        ("Temp*", ""),
    ],
)
def test_literal_prefix(pattern, expected):
    assert literal_prefix(pattern) == expected


def _stat(path):
    return os.lstat(path)


def test_dir_rule_beats_global_file_rule(tmp_path):
    cache = tmp_path / "Discord" / "Cache"
    cache.mkdir(parents=True)
    f = cache / "notes.log"
    f.write_text("x")
    matcher = RuleMatcher()
    active = matcher.initial_active("local")
    active = matcher.active_for("local", "Discord", active)
    active = matcher.active_for("local", "Discord/Cache", active)
    result = matcher.match("notes.log", _stat(f), active)
    assert result.consumed is not None and result.consumed.id == "cache_dir"
    assert result.reclaim is not None and result.reclaim.id == "cache_dir"
    assert result.reclaim.tier == "moderate"


def test_age_filter_falls_through_to_next_rule(tmp_path):
    import os
    import time

    temp = tmp_path / "Temp"
    temp.mkdir()
    f = temp / "aged.dmp"
    f.write_text("x")
    t = time.time() - 30 * 3600
    os.utime(f, (t, t))
    matcher = RuleMatcher()
    active = matcher.initial_active("local")
    active = matcher.active_for("local", "Temp", active)
    result = matcher.match("aged.dmp", _stat(f), active)
    # 30h is too young for Temp (48h) but old enough for the global *.dmp rule
    assert result.consumed is not None and result.consumed.id == "temp_dir"
    assert result.reclaim is not None and result.reclaim.id == "dmp_files"


def test_too_young_file_is_not_reclaimed(tmp_path):
    temp = tmp_path / "Temp"
    temp.mkdir()
    f = temp / "new.tmp"
    f.write_text("x")
    matcher = RuleMatcher()
    active = matcher.active_for("local", "Temp", matcher.initial_active("local"))
    result = matcher.match("new.tmp", _stat(f), active)
    assert result.consumed is not None and result.consumed.id == "temp_dir"
    assert result.reclaim is None
