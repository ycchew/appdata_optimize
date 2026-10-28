# AppData Optimize

Terminal tool for Windows that measures what is using space under `%APPDATA%`,
`%LOCALAPPDATA%` and `AppData\LocalLow`, then deletes files by risk tier.
Python standard library only.

## Tiers

| Tier | Meaning | Typical targets |
| --- | --- | --- |
| `low` | Probably safe | User `Temp` files older than 48h, logs older than 3 days, `*.tmp`/`*.temp`/`*.dmp`/`*.mdmp` older than 24h, `Thumbs.db`, Office `~` files older than 3 days, empty folders |
| `moderate` | Affects applications | Chrome/Edge/Firefox caches, npm/pip/uv/NuGet caches, and any `Cache`, `Code Cache`, `GPUCache`, `DXCache`, `CachedData` folder |
| `high` | Affects Windows | Explorer icon/thumbnail/WebCache databases, INetCache, DirectX shader cache, Windows Error Reporting, font cache, Recent items |

Browser and dev-tool caches are skipped while their process (`chrome.exe`,
`msedge.exe`, `firefox.exe`) is running. The rule table lives in `rules.py`.

## Usage

```
python main.py                              # interactive: scan, then pick a tier
python main.py scan [--json PATH]           # report only, optionally dump JSON
python main.py clean low|moderate|high [--yes]
python main.py --root all|roaming|local|locallow ...
```

`--root` defaults to `all` and goes before the subcommand. Without `--yes`,
`clean` prints the tier detail and waits for a `y` confirmation.

## Safety

- A file is deleted only if its resolved path is inside its AppData root;
  junctions and symlinks are never followed.
- Locked files are skipped, not forced.
- Every action is appended to `logs/cleanup-YYYYmmdd-HHMMSS.jsonl`.
- The top-level `Temp` folder is emptied but never removed.

## Layout

- `main.py` — CLI, scan/clean orchestration
- `rules.py` — tier definitions and risk notes
- `classify.py` — path/pattern matching against the rule table
- `scanner.py` — threaded walker, size totals
- `cleanup.py` — guarded deletion, audit log
- `report.py` — terminal dashboard and menus
- `tests/` — suite over a fake AppData tree

## Tests

```
python -m pytest
```

Windows only, as the code relies on `tasklist` and NT file attributes. The
suite builds its own temporary AppData tree and never touches real data.
