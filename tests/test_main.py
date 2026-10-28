"""Interactive menu: tier -> category picker -> scoped cleanup."""
from __future__ import annotations

import pytest
from conftest import LOW_DELETED, missing

import main
from classify import RuleMatcher


def _number_for(label: str, out: str) -> int:
    """The printed '#' of the category row whose name contains `label`."""
    for line in out.splitlines():
        parts = line.split()
        if len(parts) > 1 and parts[0].isdigit() and label in line:
            return int(parts[0])
    raise AssertionError(f"no numbered row for {label!r} in output:\n{out}")


class Scripted:
    """Answers for input(), plus what the screen looked like at each prompt."""

    def __init__(self) -> None:
        self.answers: list[str] = []
        self.prompts: list[str] = []
        self.category_screen: str = ""


@pytest.fixture
def scripted_input(monkeypatch, capsys, tmp_path):
    """Feed `interactive` a fixed answer per input() call, never more."""
    monkeypatch.setattr(main, "new_log_path", lambda: tmp_path / "logs" / "interactive.jsonl")
    scripted = Scripted()

    def fake_input(prompt=""):
        scripted.prompts.append(prompt)
        if not scripted.answers:
            raise AssertionError(f"unexpected extra input() call: {prompt!r}")
        answer = scripted.answers.pop(0)
        if answer == "__pick__":
            # the category screen has been printed by now: keep a copy of it
            scripted.category_screen = capsys.readouterr().out
            return str(_number_for("User Temp folder", scripted.category_screen))
        return answer

    monkeypatch.setattr("builtins.input", fake_input)
    return scripted


def test_interactive_cleans_only_the_selected_category(appdata, scripted_input):
    scripted_input.answers.extend(["1", "__pick__", "y", "q"])
    main.interactive(appdata, RuleMatcher(roots=tuple(appdata)))
    # picked category cleaned
    assert missing(appdata, [("local", "Temp/old.tmp")]) == [("local", "Temp/old.tmp")]
    # every other category untouched
    assert missing(
        appdata,
        [
            ("local", "Temp/aged.dmp"),
            ("roaming", "Temp/old.log"),
            ("roaming", "app/logs/app.log"),
            ("local", "CrashDumps/app.dmp"),
            ("roaming", "~owner.doc"),
        ],
    ) == []
    assert "choose categories to clean" in scripted_input.category_screen
    assert "User Temp folder" in scripted_input.category_screen
    assert any(p.startswith("Select categories [1,3") for p in scripted_input.prompts)
    assert any(p.startswith("Proceed with 1 category?") for p in scripted_input.prompts)


def test_interactive_enter_selects_the_whole_tier(appdata, scripted_input):
    scripted_input.answers.extend(["1", "", "y", "q"])
    main.interactive(appdata, RuleMatcher(roots=tuple(appdata)))
    assert missing(appdata, LOW_DELETED) == LOW_DELETED


def test_interactive_back_returns_to_the_tier_menu(appdata, scripted_input):
    scripted_input.answers.extend(["1", "b", "q"])
    main.interactive(appdata, RuleMatcher(roots=tuple(appdata)))
    assert missing(appdata, LOW_DELETED) == []


def test_interactive_declined_confirm_deletes_nothing(appdata, scripted_input):
    scripted_input.answers.extend(["1", "all", "n", "q"])
    main.interactive(appdata, RuleMatcher(roots=tuple(appdata)))
    assert missing(appdata, LOW_DELETED) == []
