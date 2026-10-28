"""AppData Optimize: analyze %AppData% and clean it up from the terminal.

Usage:
  python main.py                         menu: pick a tier, then its categories
  python main.py scan [--json P]         scan and print the status report
  python main.py clean TIER [--yes]      1-click cleanup of one risk tier

Tiers: low | moderate | high
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import cleanup as cleanup_mod
import report
from classify import RuleMatcher
from rules import ALL_ROOTS, MODERATE, TIER_ORDER
from scanner import Progress, ScanResult, scan

PROJECT_DIR = Path(__file__).resolve().parent
TIER_CHOICES = {1: "low", 2: "moderate", 3: "high"}


def resolve_roots(scope: str) -> dict[str, Path]:
    local = Path(os.environ["LOCALAPPDATA"])
    all_roots = {
        "roaming": Path(os.environ["APPDATA"]),
        "local": local,
        "locallow": local.parent / "LocalLow",
    }
    if scope == "all":
        return all_roots
    return {scope: all_roots[scope]}


def detect_processes() -> frozenset[str]:
    try:
        out = subprocess.run(
            ["tasklist", "/nh", "/fo", "csv"],
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        return frozenset()
    names = set()
    for row in csv.reader(io.StringIO(out.stdout)):
        if row:
            names.add(os.path.basename(row[0]).lower())
    return frozenset(names)


def with_ticker(progress: Progress, label: str, work):
    """Run `work()` in this thread while a progress line updates every 0.4s."""
    stop = threading.Event()

    def tick():
        while not stop.wait(0.4):
            s = progress.snapshot()
            line = (
                f"\r\x1b[K {label}: {s['files']:,} files · {report.format_bytes(s['bytes'])}"
                f" · deleted {s['deleted']:,} · skipped {s['skipped']:,}"
            )
            sys.stdout.write(line)
            sys.stdout.flush()

    thread = threading.Thread(target=tick, daemon=True)
    thread.start()
    try:
        return work()
    finally:
        stop.set()
        thread.join()
        sys.stdout.write("\r\x1b[K")
        sys.stdout.flush()


def do_scan(roots: dict[str, Path], matcher: RuleMatcher, json_out: str | None) -> ScanResult:
    progress = Progress()
    result = with_ticker(progress, "scanning", lambda: scan(roots, matcher, progress))
    report.print_status(result, roots)
    report.print_tier_summary(matcher, result)
    if json_out:
        Path(json_out).write_text(json.dumps(result.to_json(), indent=2), encoding="utf-8")
        print(f"  JSON report written to {json_out}")
    return result


def new_log_path() -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return PROJECT_DIR / "logs" / f"cleanup-{stamp}.jsonl"


def run_cleanup(
    roots: dict[str, Path],
    matcher: RuleMatcher,
    tier: str,
    rule_ids: frozenset[str] | None = None,
) -> cleanup_mod.CleanupResult:
    running = detect_processes() if tier == MODERATE else frozenset()
    progress = Progress()
    result = with_ticker(
        progress,
        "cleaning",
        lambda: cleanup_mod.run_cleanup(
            roots,
            matcher,
            tier,
            progress,
            new_log_path(),
            running_processes=running,
            rule_ids=rule_ids,
        ),
    )
    report.print_cleanup_result(result)
    return result


def confirm(question: str) -> bool:
    answer = input(f"{question} [y/N] ").strip().lower()
    return answer in ("y", "yes")


def interactive(roots: dict[str, Path], matcher: RuleMatcher) -> None:
    scan_result = do_scan(roots, matcher, None)
    while True:
        print()
        print(c("Select: [1] Low  [2] Moderate  [3] High  [s] rescan  [q] quit", report.BOLD))
        choice = input("> ").strip().lower()
        if choice == "q":
            return
        if choice == "s":
            scan_result = do_scan(roots, matcher, None)
            continue
        if choice not in ("1", "2", "3"):
            continue
        tier = TIER_CHOICES[int(choice)]
        selection = report.select_categories(matcher, scan_result, tier)
        if selection is None:
            continue
        if selection:
            n = len(selection)
            question = f"Proceed with {n} categor{'y' if n == 1 else 'ies'}?"
        else:
            question = "Proceed with cleanup?"
        if confirm(question):
            run_cleanup(roots, matcher, tier, frozenset(selection))
            print("Run [s] to rescan with updated numbers.")
        else:
            print("Cancelled.")


def c(text: str, code: str) -> str:
    return report.c(text, code)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="appdata-optimize",
        description="Analyze AppData and clean it by risk tier (terminal only).",
    )
    parser.add_argument("--root", choices=("all",) + ALL_ROOTS, default="all", help="limit to one AppData root")
    sub = parser.add_subparsers(dest="command")
    p_scan = sub.add_parser("scan", help="scan and print the status report")
    p_scan.add_argument("--json", metavar="PATH", help="also write the raw report as JSON")
    p_clean = sub.add_parser("clean", help="run one cleanup tier")
    p_clean.add_argument("tier", choices=TIER_ORDER, help="risk tier to clean")
    p_clean.add_argument("--yes", action="store_true", help="skip the preview/confirm (1-click mode)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report.enable_colors(sys.stdout.isatty() and os.environ.get("NO_COLOR") is None)
    roots = resolve_roots(args.root)
    matcher = RuleMatcher(roots=tuple(roots))
    try:
        if args.command == "scan":
            do_scan(roots, matcher, args.json)
        elif args.command == "clean":
            if args.yes:
                run_cleanup(roots, matcher, args.tier)
            else:
                scan_result = do_scan(roots, matcher, None)
                report.print_tier_detail(matcher, scan_result, args.tier)
                if confirm("Proceed with cleanup?"):
                    run_cleanup(roots, matcher, args.tier)
                else:
                    print("Cancelled.")
        else:
            interactive(roots, matcher)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
