"""Matches files against the rule table (used by both scan and cleanup)."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass

from rules import Rule, RULES, ALL_ROOTS

_WILDCARD_CHARS = "*?["


def pattern_to_regex(pattern: str) -> re.Pattern:
    """Compile a '/'-separated path pattern to a fullmatch regex.

    '*' matches within a path segment, '?' matches one character, and
    '**' matches zero or more whole segments (or the rest of the path as
    the final segment). Matching is case-insensitive.
    """
    parts = pattern.split("/")
    out: list[str] = []
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        if part == "**":
            if last:
                out.append("/.*" if (out and parts[i - 1] != "**") else ".*")
            else:
                out.append("(?:[^/]+/)*")  # includes its own separator
            continue
        if out and parts[i - 1] != "**":
            out.append("/")
        seg = []
        for ch in part:
            if ch == "*":
                seg.append("[^/]*")
            elif ch == "?":
                seg.append("[^/]")
            else:
                seg.append(re.escape(ch))
        out.append("".join(seg))
    return re.compile("".join(out), re.IGNORECASE)


def literal_prefix(pattern: str) -> str:
    """Longest segment-aligned literal prefix of a pattern (cheap filter)."""
    for i, ch in enumerate(pattern):
        if ch in _WILDCARD_CHARS:
            prefix = pattern[:i]
            cut = prefix.rfind("/")
            return prefix if cut >= 0 else ""
    return pattern


def _compile_file_test(file_pattern: str):
    """Return ('suffix', s) for simple '*<literal>' patterns, else ('rx', rx)."""
    rest = file_pattern[1:] if file_pattern.startswith("*") else None
    if rest is not None and not any(c in rest for c in "*?["):
        return ("suffix", rest.lower())
    return ("rx", pattern_to_regex(file_pattern))


@dataclass(frozen=True)
class MatchResult:
    consumed: Rule | None  # first rule whose patterns match (age ignored)
    reclaim: Rule | None  # first matching rule whose age filter passes


class RuleMatcher:
    def __init__(self, rules: tuple[Rule, ...] = RULES, roots: tuple[str, ...] = ALL_ROOTS):
        self.roots = tuple(r for r in ALL_ROOTS if r in roots)
        self.rules = [r for r in rules if set(r.roots) & set(self.roots)]
        self.index = {r.id: i for i, r in enumerate(self.rules)}
        self.file_tests = {
            r.id: _compile_file_test(r.file_pattern) for r in self.rules
        }
        self.global_rules: dict[str, tuple[Rule, ...]] = {}
        self.dir_rules: dict[str, tuple[tuple[Rule, re.Pattern, str], ...]] = {}
        for root in self.roots:
            glob_rules = tuple(
                r for r in self.rules if r.dir_pattern == "**" and root in r.roots
            )
            scoped = [
                (r, pattern_to_regex(r.dir_pattern), literal_prefix(r.dir_pattern))
                for r in self.rules
                if r.dir_pattern != "**" and root in r.roots
            ]
            scoped.sort(key=lambda t: self.index[t[0].id])
            self.global_rules[root] = glob_rules
            self.dir_rules[root] = tuple(scoped)

    def initial_active(self, root: str) -> tuple[Rule, ...]:
        """Rules active at the root directory itself (global file rules)."""
        return self.global_rules[root]

    def active_for(self, root: str, rel: str, parent_active: tuple[Rule, ...]) -> tuple[Rule, ...]:
        """Parent's active rules plus rules whose directory pattern matches `rel`."""
        added: list[Rule] = []
        lowered = rel.lower()
        for rule, rx, prefix in self.dir_rules[root]:
            if prefix and not lowered.startswith(prefix.lower()):
                continue
            if rx.fullmatch(rel):
                added.append(rule)
        if not added:
            return parent_active
        merged = set(parent_active)
        merged.update(added)
        return tuple(sorted(merged, key=lambda r: self.index[r.id]))

    def _file_matches(self, rule: Rule, name: str) -> bool:
        kind, value = self.file_tests[rule.id]
        if kind == "suffix":
            return name.lower().endswith(value)
        return value.fullmatch(name) is not None

    def match(self, name: str, st, active: tuple[Rule, ...], now: float | None = None) -> MatchResult:
        consumed: Rule | None = None
        reclaim: Rule | None = None
        if now is None:
            now = time.time()
        for rule in active:
            if not self._file_matches(rule, name):
                continue
            if consumed is None:
                consumed = rule
            # clamp: file mtimes can round ahead of time.time(), and a
            # min_age_hours=0 rule must always pass
            age = max(0.0, now - st.st_mtime)
            if age >= rule.min_age_hours * 3600:
                reclaim = rule
                break
        return MatchResult(consumed=consumed, reclaim=reclaim)
