"""Rule table defining which files belong to each cleanup tier.

Rules are evaluated in list order (claim priority): a file is claimed by the
first rule whose directory pattern opens a scope containing the file, whose
file pattern matches the file name, and whose age filter passes. Directory
scopes are recursive: once a directory matches, every file below it is in scope.
"""
from __future__ import annotations

from dataclasses import dataclass

LOW = "low"
MODERATE = "moderate"
HIGH = "high"

ALL_ROOTS = ("roaming", "local", "locallow")

TIER_ORDER = (LOW, MODERATE, HIGH)
TIER_LABELS = {
    LOW: "Low Risk (probably safe)",
    MODERATE: "Moderate Risk (affects applications)",
    HIGH: "High Risk (affects Windows)",
}

# Low tier also removes empty directories (0 bytes); this is noted in reports
# and performed by cleanup, so it needs no size rule.
LOW_REMOVES_EMPTY_DIRS = True


@dataclass(frozen=True)
class Rule:
    id: str
    tier: str
    category: str
    roots: tuple[str, ...]
    dir_pattern: str
    file_pattern: str = "*"
    min_age_hours: float = 0.0
    processes: tuple[str, ...] = ()
    risk: str = ""


LOCAL = ("local",)
WINDOWS_ROOTS = ALL_ROOTS

RULES: tuple[Rule, ...] = (
    # --- Low: user Temp (first claim wins so Temp is handled as one unit) ---
    Rule(
        id="temp_dir",
        tier=LOW,
        category="User Temp folder",
        roots=LOCAL,
        dir_pattern="Temp",
        file_pattern="*",
        min_age_hours=48,
        risk="Files older than 48h in Local\\Temp; in-use files are skipped automatically.",
    ),
    # --- High: Windows OS/shell caches ---
    Rule(
        id="thumbcache",
        tier=HIGH,
        category="Explorer thumbnail cache",
        roots=LOCAL,
        dir_pattern="Microsoft/Windows/Explorer",
        file_pattern="thumbcache_*.db",
        risk="Explorer re-generates thumbnails; folders show blank icons until rebuilt.",
    ),
    Rule(
        id="iconcache",
        tier=HIGH,
        category="Explorer icon cache",
        roots=LOCAL,
        dir_pattern="Microsoft/Windows/Explorer",
        file_pattern="iconcache_*.db",
        risk="Desktop/taskbar icons redraw on next Explorer restart.",
    ),
    Rule(
        id="webcache",
        tier=HIGH,
        category="Explorer WebCache database",
        roots=LOCAL,
        dir_pattern="Microsoft/Windows/WebCache",
        file_pattern="*",
        risk="Clears Explorer browsing/search history; usually locked until Explorer restart.",
    ),
    Rule(
        id="inetcache",
        tier=HIGH,
        category="Internet cache (INetCache)",
        roots=LOCAL,
        dir_pattern="Microsoft/Windows/INetCache",
        file_pattern="*",
        risk="Web content cache used by Explorer/IE components; re-fetched on demand.",
    ),
    Rule(
        id="d3dscache",
        tier=HIGH,
        category="DirectX shader cache",
        roots=LOCAL,
        dir_pattern="Microsoft/Windows/D3DSCache",
        file_pattern="*",
        risk="Games re-compile shaders: one-time stutter after cleanup.",
    ),
    Rule(
        id="wer",
        tier=HIGH,
        category="Windows Error Reporting",
        roots=LOCAL,
        dir_pattern="Microsoft/Windows/WER",
        file_pattern="*",
        risk="Old crash reports deleted; loses diagnostic history only.",
    ),
    Rule(
        id="fontcache",
        tier=HIGH,
        category="Windows font cache",
        roots=LOCAL,
        dir_pattern="Microsoft/Windows/FontCache",
        file_pattern="*",
        risk="Font cache rebuilds after reboot; usually locked while Windows runs.",
    ),
    Rule(
        id="recent_items",
        tier=HIGH,
        category="Recent items list",
        roots=("roaming",),
        dir_pattern="Microsoft/Windows/Recent",
        file_pattern="*",
        risk="Start menu 'Recent items' history is cleared (shortcuts only, no documents).",
    ),
    Rule(
        id="win_caches",
        tier=HIGH,
        category="Explorer accelerator caches",
        roots=("roaming",),
        dir_pattern="Microsoft/Windows/Caches",
        file_pattern="*",
        risk="Explorer cache rebuilds; no user data affected.",
    ),
    Rule(
        id="theme_cache",
        tier=HIGH,
        category="Theme/wallpaper cache",
        roots=("roaming",),
        dir_pattern="Microsoft/Windows/Themes/CachedFiles",
        file_pattern="*",
        risk="Cached wallpaper variants regenerate from the original image.",
    ),
    # --- Moderate: browser caches (process-aware) ---
    Rule(
        id="chrome_cache",
        tier=MODERATE,
        category="Chrome cache",
        roots=LOCAL,
        dir_pattern="Google/Chrome/User Data/*/Cache",
        file_pattern="*",
        processes=("chrome",),
        risk="Chrome re-downloads page assets; skipped while chrome.exe runs.",
    ),
    Rule(
        id="chrome_code_cache",
        tier=MODERATE,
        category="Chrome code cache",
        roots=LOCAL,
        dir_pattern="Google/Chrome/User Data/*/Code Cache",
        file_pattern="*",
        processes=("chrome",),
        risk="Scripts re-compile/download on next visit; skipped while chrome.exe runs.",
    ),
    Rule(
        id="chrome_gpu_cache",
        tier=MODERATE,
        category="Chrome GPU cache",
        roots=LOCAL,
        dir_pattern="Google/Chrome/User Data/*/GPUCache",
        file_pattern="*",
        processes=("chrome",),
        risk="GPU resources rebuild; skipped while chrome.exe runs.",
    ),
    Rule(
        id="edge_cache",
        tier=MODERATE,
        category="Edge cache",
        roots=LOCAL,
        dir_pattern="Microsoft/Edge/User Data/*/Cache",
        file_pattern="*",
        processes=("msedge",),
        risk="Edge re-downloads page assets; skipped while msedge.exe runs.",
    ),
    Rule(
        id="edge_code_cache",
        tier=MODERATE,
        category="Edge code cache",
        roots=LOCAL,
        dir_pattern="Microsoft/Edge/User Data/*/Code Cache",
        file_pattern="*",
        processes=("msedge",),
        risk="Scripts re-compile/download on next visit; skipped while msedge.exe runs.",
    ),
    Rule(
        id="edge_gpu_cache",
        tier=MODERATE,
        category="Edge GPU cache",
        roots=LOCAL,
        dir_pattern="Microsoft/Edge/User Data/*/GPUCache",
        file_pattern="*",
        processes=("msedge",),
        risk="GPU resources rebuild; skipped while msedge.exe runs.",
    ),
    Rule(
        id="firefox_cache2",
        tier=MODERATE,
        category="Firefox cache",
        roots=("roaming",),
        dir_pattern="Mozilla/Firefox/Profiles/*/cache2",
        file_pattern="*",
        processes=("firefox",),
        risk="Firefox re-downloads page assets; skipped while firefox.exe runs.",
    ),
    # --- Moderate: developer tool caches (before the generic **/Cache rule
    #     so uv/cache, pip/cache and NuGet/cache are attributed correctly) ---
    Rule(
        id="npm_cache",
        tier=MODERATE,
        category="npm cache",
        roots=LOCAL,
        dir_pattern="npm-cache",
        file_pattern="*",
        risk="Packages re-download on next install (slower first npm install).",
    ),
    Rule(
        id="uv_cache",
        tier=MODERATE,
        category="uv cache",
        roots=LOCAL,
        dir_pattern="uv/cache",
        file_pattern="*",
        risk="Python packages re-download on next uv sync.",
    ),
    Rule(
        id="pip_cache",
        tier=MODERATE,
        category="pip cache",
        roots=LOCAL,
        dir_pattern="pip/cache",
        file_pattern="*",
        risk="Python packages re-download on next pip install.",
    ),
    Rule(
        id="nuget_v3_cache",
        tier=MODERATE,
        category="NuGet v3 cache",
        roots=LOCAL,
        dir_pattern="NuGet/v3-cache",
        file_pattern="*",
        risk="NuGet re-resolves packages on next restore.",
    ),
    Rule(
        id="nuget_cache",
        tier=MODERATE,
        category="NuGet HTTP cache",
        roots=LOCAL,
        dir_pattern="NuGet/cache",
        file_pattern="*",
        risk="NuGet re-resolves packages on next restore.",
    ),
    Rule(
        id="dart_tool",
        tier=MODERATE,
        category="Dart/Flutter build cache",
        roots=WINDOWS_ROOTS,
        dir_pattern="**/.dart*tool",
        file_pattern="*",
        risk="Next build re-creates tool state (one-time slower build).",
    ),
    # --- Moderate: generic application cache directories ---
    Rule(
        id="cache_dir",
        tier=MODERATE,
        category="Application caches (Cache)",
        roots=WINDOWS_ROOTS,
        dir_pattern="**/Cache",
        file_pattern="*",
        risk="App re-creates cache on next launch: slower first start, possible re-download.",
    ),
    Rule(
        id="code_cache",
        tier=MODERATE,
        category="Compiled code caches",
        roots=WINDOWS_ROOTS,
        dir_pattern="**/Code Cache",
        file_pattern="*",
        risk="JS/compiled artifacts rebuild on next app start.",
    ),
    Rule(
        id="gpu_cache",
        tier=MODERATE,
        category="GPU caches (GPUCache)",
        roots=WINDOWS_ROOTS,
        dir_pattern="**/GPUCache",
        file_pattern="*",
        risk="GPU resources rebuild on next app start.",
    ),
    Rule(
        id="dx_cache",
        tier=MODERATE,
        category="NVIDIA DirectX shader cache",
        roots=WINDOWS_ROOTS,
        dir_pattern="**/DXCache",
        file_pattern="*",
        risk="Shaders re-compile on next launch: one-time stutter.",
    ),
    Rule(
        id="cached_data",
        tier=MODERATE,
        category="Cached workspace data",
        roots=WINDOWS_ROOTS,
        dir_pattern="**/CachedData",
        file_pattern="*",
        risk="App rebuilds cached workspace/index data (initial rescan may be slower).",
    ),
    Rule(
        id="cache_data",
        tier=MODERATE,
        category="HTTP cache data",
        roots=WINDOWS_ROOTS,
        dir_pattern="**/Cache_Data",
        file_pattern="*",
        risk="Content re-downloaded on next use.",
    ),
    Rule(
        id="cache_storage",
        tier=MODERATE,
        category="Service worker caches",
        roots=WINDOWS_ROOTS,
        dir_pattern="**/CacheStorage",
        file_pattern="*",
        risk="Offline web-app data re-fetched; sites may load once from network only.",
    ),
    Rule(
        id="dot_cache",
        tier=MODERATE,
        category="Dot-cache folders",
        roots=WINDOWS_ROOTS,
        dir_pattern="**/.cache",
        file_pattern="*",
        risk="App re-populates cache; possible one-time re-download.",
    ),
    # --- Low: log directories ---
    Rule(
        id="log_dirs",
        tier=LOW,
        category="Log directories (>3 days)",
        roots=WINDOWS_ROOTS,
        dir_pattern="**/logs",
        file_pattern="*",
        min_age_hours=72,
        risk="Old log files only; recent logs kept, active files stay locked.",
    ),
    Rule(
        id="crashdump_dir",
        tier=LOW,
        category="Crash dump folders",
        roots=LOCAL,
        dir_pattern="CrashDumps",
        file_pattern="*",
        min_age_hours=24,
        risk="Old crash dumps only; used only for troubleshooting crashed apps.",
    ),
    # --- Low: global file patterns (claimed last) ---
    Rule(
        id="log_files",
        tier=LOW,
        category="Standalone log files",
        roots=WINDOWS_ROOTS,
        dir_pattern="**",
        file_pattern="*.log",
        min_age_hours=72,
        risk="Logs older than 3 days; recent/active logs are kept.",
    ),
    Rule(
        id="tmp_files",
        tier=LOW,
        category="*.tmp files",
        roots=WINDOWS_ROOTS,
        dir_pattern="**",
        file_pattern="*.tmp",
        min_age_hours=24,
        risk="Temporary scratch files older than 24h.",
    ),
    Rule(
        id="temp_ext_files",
        tier=LOW,
        category="*.temp files",
        roots=WINDOWS_ROOTS,
        dir_pattern="**",
        file_pattern="*.temp",
        min_age_hours=24,
        risk="Temporary scratch files older than 24h.",
    ),
    Rule(
        id="dmp_files",
        tier=LOW,
        category="Crash dump files (*.dmp)",
        roots=WINDOWS_ROOTS,
        dir_pattern="**",
        file_pattern="*.dmp",
        min_age_hours=24,
        risk="Crash dumps older than 24h; needed only to debug crashes.",
    ),
    Rule(
        id="mdmp_files",
        tier=LOW,
        category="Minidump files (*.mdmp)",
        roots=WINDOWS_ROOTS,
        dir_pattern="**",
        file_pattern="*.mdmp",
        min_age_hours=24,
        risk="Minidumps older than 24h; needed only to debug crashes.",
    ),
    Rule(
        id="thumbs_db",
        tier=LOW,
        category="Thumbs.db",
        roots=WINDOWS_ROOTS,
        dir_pattern="**",
        file_pattern="Thumbs.db",
        risk="Thumbnail index; Explorer rebuilds it automatically.",
    ),
    Rule(
        id="tilde_files",
        tier=LOW,
        category="Office lock/owner files (~ files)",
        roots=WINDOWS_ROOTS,
        dir_pattern="**",
        file_pattern="~*",
        min_age_hours=72,
        risk="Leftover lock/owner files older than 3 days.",
    ),
)

RULES_BY_ID = {r.id: r for r in RULES}
