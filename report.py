"""Terminal text report: status dashboard, tier summary, per-tier detail."""
from __future__ import annotations

import re
import shutil
import sys
import time
from pathlib import Path

from classify import RuleMatcher
from rules import LOW_REMOVES_EMPTY_DIRS, TIER_LABELS, TIER_ORDER, Rule
from scanner import ScanResult

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
CYAN = "\x1b[36m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
RED = "\x1b[31m"

TIER_COLORS = {t: c for t, c in zip(TIER_ORDER, (GREEN, YELLOW, RED))}
ROOT_LABELS = {"roaming": "Roaming (%APPDATA%)", "local": "Local (%LOCALAPPDATA%)", "locallow": "LocalLow"}

_colors = False


def enable_colors(on: bool) -> None:
    global _colors
    _colors = on and sys.stdout.isatty()


def c(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if _colors else text


def format_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def render_table(headers, rows, aligns=None, row_colors=None) -> str:
    aligns = aligns or ["left"] * len(headers)
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def fmt_row(row) -> str:
        cells = []
        for i, cell in enumerate(row):
            text = str(cell)
            cells.append(text.ljust(widths[i]) if aligns[i] == "left" else text.rjust(widths[i]))
        line = "  ".join(cells).rstrip()
        if row_colors:
            color = row_colors.get(id(row))
            if color:
                return c(line, color)
        return line

    lines = [c("  ".join(str(h).ljust(widths[i]) if aligns[i] == "left" else str(h).rjust(widths[i]) for i, h in enumerate(headers)).rstrip(), BOLD)]
    lines.append(c("  ".join("-" * w for w in widths), DIM))
    lines.extend(fmt_row(row) for row in rows)
    return "\n".join(lines)


def print_status(scan: ScanResult, roots: dict[str, Path]) -> None:
    total_files = sum(f for f, _ in scan.roots.values())
    total_bytes = sum(b for _, b in scan.roots.values())
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print()
    print(c("=== AppData Status ===", BOLD + CYAN))
    print(
        f"  Scanned {stamp} in {scan.elapsed:.1f}s   "
        f"Total: {c(format_bytes(total_bytes), BOLD)} in {total_files:,} files"
    )
    rows = []
    for name in roots:
        files, nbytes = scan.roots.get(name, (0, 0))
        rows.append([ROOT_LABELS.get(name, name), format_bytes(nbytes), f"{files:,}"])
    print(render_table(["Root", "Size", "Files"], rows, aligns=["left", "right", "right"]))
    for drive in sorted({r.drive for r in roots.values() if r.drive}):
        free = shutil.disk_usage(str(Path(drive + "\\"))).free
        print(f"  Free space on {drive} {format_bytes(free)}")

    top: list[tuple[str, int]] = []
    for root_name, entries in scan.depth2.items():
        for key, (_, nbytes) in entries.items():
            top.append((f"{root_name.capitalize()}\\{key.replace('/', chr(92))}", nbytes))
    top.sort(key=lambda t: t[1], reverse=True)
    if top:
        rows = [[key, format_bytes(nbytes)] for key, nbytes in top[:12]]
        print()
        print(c("Largest folders", BOLD))
        print(render_table(["Folder", "Size"], rows, aligns=["left", "right"]))


def _tier_totals(matcher: RuleMatcher, scan: ScanResult) -> dict[str, dict]:
    totals = {
        tier: {"rules": 0, "files": 0, "consumed": 0, "reclaim": 0} for tier in TIER_ORDER
    }
    for rule in matcher.rules:
        stat = scan.rule_stats.get(rule.id)
        bucket = totals[rule.tier]
        if stat:
            bucket["files"] += stat["reclaim_files"]
            bucket["consumed"] += stat["consumed_bytes"]
            bucket["reclaim"] += stat["reclaim_bytes"]
    for tier in TIER_ORDER:
        totals[tier]["rules"] = sum(1 for r in matcher.rules if r.tier == tier)
    return totals


def print_tier_summary(matcher: RuleMatcher, scan: ScanResult) -> None:
    print()
    print(c("=== Cleanup Options ===", BOLD + CYAN))
    totals = _tier_totals(matcher, scan)
    rows = []
    row_colors: dict = {}
    for tier in TIER_ORDER:
        t = totals[tier]
        row = [
            TIER_LABELS[tier],
            str(t["rules"]),
            f"{t['files']:,}",
            format_bytes(t["consumed"]),
            format_bytes(t["reclaim"]),
        ]
        row_colors[id(row)] = TIER_COLORS[tier]
        rows.append(row)
    print(
        render_table(
            ["Tier", "Categories", "Files", "Consumed", "Est. reclaim"],
            rows,
            aligns=["left", "right", "right", "right", "right"],
            row_colors=row_colors,
        )
    )
    print(c("  Consumed = size of matched files; Est. reclaim = after age filters (locked files drop at run time).", DIM))


def _tier_rows(matcher: RuleMatcher, scan: ScanResult, tier: str) -> list[tuple[Rule, int, int, int]]:
    """(rule, reclaim files, consumed bytes, reclaim bytes) for categories with content.

    Ordered by reclaim size, largest first.
    """
    rows: list[tuple[Rule, int, int, int]] = []
    for rule in matcher.rules:
        if rule.tier != tier:
            continue
        stat = scan.rule_stats.get(rule.id, {})
        consumed = stat.get("consumed_bytes", 0)
        reclaim = stat.get("reclaim_bytes", 0)
        files = stat.get("reclaim_files", 0)
        if consumed == 0 and reclaim == 0:
            continue
        rows.append((rule, files, consumed, reclaim))
    rows.sort(key=lambda t: t[3], reverse=True)
    return rows


def _print_tier_notes(tier: str, rows: list[tuple[Rule, int, int, int]]) -> None:
    if tier == "low" and LOW_REMOVES_EMPTY_DIRS:
        print("  + empty directories (0 bytes)")
    print()
    print(c("Risks:", BOLD))
    for rule, _, _, _ in rows:
        print(f"  * {rule.category}: {rule.risk}")
    if tier == "low" and LOW_REMOVES_EMPTY_DIRS:
        print("  * Empty directories: removed so apps re-create them on next start.")
    if not rows:
        print("  (nothing in this tier matches right now)")


def print_tier_detail(matcher: RuleMatcher, scan: ScanResult, tier: str) -> None:
    print()
    print(c(f"--- {TIER_LABELS[tier]}: what gets deleted ---", BOLD + TIER_COLORS[tier]))
    rows = _tier_rows(matcher, scan, tier)
    if rows:
        print(
            render_table(
                ["Category", "Files", "Consumed", "Est. reclaim"],
                [
                    [rule.category, f"{files:,}", format_bytes(consumed), format_bytes(reclaim)]
                    for rule, files, consumed, reclaim in rows
                ],
                aligns=["left", "right", "right", "right"],
            )
        )
    else:
        print("  (no files matched this tier at current age filters)")
    _print_tier_notes(tier, rows)


def parse_selection(text: str, count: int) -> list[int]:
    """Parse a category selection into 0-based indices of a list of `count` items.

    Accepts '1,3', '1 3' and 'all'; an empty line selects everything.
    Raises ValueError for anything unusable.
    """
    s = text.strip()
    if not s or s.lower() == "all":
        return list(range(count))
    picked: list[int] = []
    for token in re.split(r"[,\s]+", s):
        if not token:
            continue
        if not token.isdigit():
            raise ValueError(f"'{token}' is not a number")
        n = int(token)
        if not 1 <= n <= count:
            raise ValueError(f"{n} is out of range 1-{count}")
        if n - 1 not in picked:
            picked.append(n - 1)
    if not picked:
        raise ValueError("nothing selected")
    return picked


def select_categories(matcher: RuleMatcher, scan: ScanResult, tier: str) -> list[str] | None:
    """Numbered category picker for one tier.

    Returns the selected rule ids (empty when the tier matched nothing), or
    None when the user asks to go back to the tier menu.
    """
    rows = _tier_rows(matcher, scan, tier)
    print()
    print(c(f"--- {TIER_LABELS[tier]}: choose categories to clean ---", BOLD + TIER_COLORS[tier]))
    if not rows:
        print("  (no files matched this tier at current age filters)")
        return []
    print(
        render_table(
            ["#", "Category", "Files", "Consumed", "Est. reclaim"],
            [
                [str(i), rule.category, f"{files:,}", format_bytes(consumed), format_bytes(reclaim)]
                for i, (rule, files, consumed, reclaim) in enumerate(rows, start=1)
            ],
            aligns=["right", "left", "right", "right", "right"],
        )
    )
    _print_tier_notes(tier, rows)
    while True:
        answer = input("Select categories [1,3 | all | Enter=all | b=back] > ").strip()
        if answer.lower() in ("b", "back"):
            return None
        try:
            picked = parse_selection(answer, len(rows))
        except ValueError as exc:
            print(f"  ? {exc}")
            continue
        return [rows[i][0].id for i in picked]


def print_cleanup_result(result) -> None:
    print()
    print(c(f"Cleanup complete ({TIER_LABELS[result.tier]})", BOLD + TIER_COLORS[result.tier]))
    print(f"  Deleted:            {result.deleted_files:,} files ({format_bytes(result.deleted_bytes)})")
    print(f"  Skipped (locked):   {result.skipped_locked:,}")
    print(f"  Skipped (running):  {result.skipped_process:,}")
    print(f"  Refused (guard):    {result.refused:,}")
    print(f"  Errors:             {result.errors:,}")
    print(f"  Empty dirs removed: {result.empty_dirs_removed:,}")
    print(f"  Elapsed:            {result.elapsed:.1f}s")
    print(f"  Log:                {result.log_path}")
