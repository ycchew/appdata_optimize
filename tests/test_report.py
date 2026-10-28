"""Category selection screen: input parsing, prompt wiring, row ordering."""
from __future__ import annotations

import pytest

from classify import RuleMatcher
from report import parse_selection, print_tier_detail, select_categories
from scanner import ScanResult

# reclaim bytes used to pin the largest-first ordering
BIG = 12_000_000  # -> "11.4 MB", sorts last when compared as text
SMALL = 3_000_000  # -> "2.9 MB", sorts first when compared as text


def _scan(stats: dict[str, tuple[int, int, int]]) -> ScanResult:
    """Minimal ScanResult: rule id -> (reclaim files, consumed bytes, reclaim bytes)."""
    rule_stats = {
        rid: {"reclaim_files": files, "consumed_bytes": consumed, "reclaim_bytes": reclaim}
        for rid, (files, consumed, reclaim) in stats.items()
    }
    return ScanResult(roots={}, depth2={}, rule_stats=rule_stats)


def _low_scan() -> ScanResult:
    return _scan({"temp_dir": (10, BIG, BIG), "log_dirs": (2, SMALL, SMALL)})


@pytest.mark.parametrize("text", ["", "   ", "all", "ALL", " all "])
def test_parse_selection_default_selects_everything(text):
    assert parse_selection(text, 4) == [0, 1, 2, 3]


@pytest.mark.parametrize(
    "text,expected",
    [
        ("1", [0]),
        ("1,3", [0, 2]),
        ("1 3", [0, 2]),
        ("3, 1", [2, 0]),
        ("2,2,1", [1, 0]),
        ("2, 4", [1, 3]),
    ],
)
def test_parse_selection_reads_number_lists(text, expected):
    assert parse_selection(text, 5) == expected


@pytest.mark.parametrize("bad", ["0", "6", "x", "1.5", "-1", ",", "1,x"])
def test_parse_selection_rejects_unusable_input(bad):
    with pytest.raises(ValueError):
        parse_selection(bad, 5)


def test_select_categories_returns_rule_ids_in_display_order(monkeypatch, capsys):
    # first invalid answer, then a valid one: the screen must re-prompt
    prompts: list[str] = []
    answers = iter(["nope", "1"])

    def fake_input(prompt=""):
        prompts.append(prompt)
        return next(answers)

    monkeypatch.setattr("builtins.input", fake_input)
    picked = select_categories(RuleMatcher(), _low_scan(), "low")
    assert picked == ["temp_dir"]  # largest reclaim is listed as #1
    assert len(prompts) == 2  # re-prompted after the bad answer
    assert prompts[0].startswith("Select categories [1,3 | all | Enter=all | b=back]")
    out = capsys.readouterr().out
    assert "'nope' is not a number" in out
    assert "choose categories to clean" in out


def test_select_categories_enter_selects_everything(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    assert select_categories(RuleMatcher(), _low_scan(), "low") == ["temp_dir", "log_dirs"]
    out = capsys.readouterr().out
    assert "1  User Temp folder" in out
    assert "2  Log directories" in out


def test_select_categories_back_returns_none(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda prompt="": "back")
    assert select_categories(RuleMatcher(), _low_scan(), "low") is None


def test_select_categories_with_nothing_matched_never_prompts(monkeypatch, capsys):
    def explode(prompt=""):
        raise AssertionError("input() must not be called when the tier is empty")

    monkeypatch.setattr("builtins.input", explode)
    assert select_categories(RuleMatcher(), _scan({}), "low") == []
    out = capsys.readouterr().out
    assert "no files matched this tier" in out


def test_print_tier_detail_sorts_by_reclaim_size_not_text(capsys):
    print_tier_detail(RuleMatcher(), _low_scan(), "low")
    out = capsys.readouterr().out
    assert out.index("11.4 MB") < out.index("2.9 MB")
