# Changelog

## 0.4.2 (CI fix)
* Fixed: `downloads_dir()` compared the unresolved home directory against a *resolved* candidate path. On macOS, `$TMPDIR` (and therefore the test home, and on real machines anything under a symlinked mount) sits under `/var/...`, which resolves to `/private/var/...`; the mismatched prefixes made Meridian silently ignore a configured `XDG_DOWNLOAD_DIR` and fall back to `~/Downloads`. Both sides are now resolved before the containment check.
* Added `.gitattributes` (`install.sh`/`*.py` forced to LF, `*.bat` to CRLF) to stop line-ending drift when the repo is edited on Windows.
* Re-applied the executable bit on `install.sh`. If your checkout still fails `test_wrappers`, git itself is tracking the file as non-executable (common after a Windows commit or an editor that rewrites the file) — run once: `chmod +x install.sh && git add install.sh && git commit -m "fix: restore +x on install.sh"`.

## 0.4.1 (security release)
Local access control
* The page and every API call now need a session cookie that is obtained with a single-use launch key (`http://127.0.0.1:PORT/?k=...`, opened and printed by Meridian). Other programs or users on the same machine can no longer fetch the page, read results or start scans. See `SECURITY.md`.
* CSP: scripts only with a fresh per-page nonce (no `unsafe-inline` for scripts), `connect-src 'self'`, `object-src 'none'`, plus COOP/CORP/Permissions-Policy and `Content-Length`.

Fixes
* The custom profile could switch on the `vulners` NSE script (third-party lookup, default web-path sweep) without the confirmation and its safe arguments. It now only runs through the confirmed lookup.
* A non-ASCII `X-Token` header, a negative `Content-Length`, non-object JSON, wrong JSON types or `Infinity` no longer crash or hang a request thread; unknown POST paths answer 404 instead of starting a scan; `Content-Type` must be JSON; connections time out after 20 s.
* CSV export neutralises spreadsheet formulas, Markdown export is escaped, the HTML report has its own CSP; ports, protocols and ids are escaped in the UI; presets cannot use prototype names.
* `history.json` is validated and rebuilt on load; nmap XML with entity declarations or over 128 MB is refused; NaN/Infinity are dropped.
* `--uninstall` refuses to delete the home folder (or a parent) when `MERIDIAN_DATA_DIR` points there.
* Terminal messages no longer use `str.format` on language files; the page embeds languages with `<` escaped.
* `.desktop` `Exec` escapes `%`; CI has read-only permissions; the Docker image sets `PYTHONDONTWRITEBYTECODE`/`PYTHONUNBUFFERED`.

Tests: 176 -> 212 (`tests/test_security.py`).

Changed: open the link Meridian prints (it carries the launch key and works once); a bookmark of `http://127.0.0.1:8765` alone is no longer enough.

## 0.4.0
Languages
* English, Türkçe, Deutsch, Español and Français, for the app, the terminal messages (`--help`, `--doctor`, installer), reports and errors. All texts live in `locales/*.json`; a new language is one new file. The server sends error *codes*, the UI translates them. Meridian always starts in English; another language is used only when chosen in the header (remembered) or with `--lang` / `MERIDIAN_LANG`.
* `README.tr.md` (Turkish README).

Linux, macOS and Windows
* `install.py` installs on all three systems (`install.sh` and the new `install.bat` are thin wrappers): launcher that remembers the Python it was installed with, `.desktop` entry with icon (Linux), `Meridian.app` (macOS), Start Menu shortcut and user PATH (Windows). `install.py --uninstall` = `meridian --uninstall`, now platform-aware.
* Data folder per system (Linux unchanged; macOS `~/Library/Application Support/Meridian`; Windows `%LOCALAPPDATA%\Meridian`); honours `XDG_DATA_HOME` and `MERIDIAN_DATA_DIR`. A 0.3.0 history in `~/.local/share/meridian` is kept.
* Finds nmap in the Windows installer folder and Homebrew paths, and Edge / Chrome / Brave at their usual Windows and macOS places.
* Windows: UTF-8 console and files (no more `cp1254` crashes on Turkish text), exclusive port binding (a second program can no longer share Meridian's port), process-tree kill, no console window for nmap, no POSIX permission checks on NTFS, works under `pythonw`.
* macOS / Windows: stale-run cleanup no longer deletes the scratch files of a Meridian that is still running (it relied on `/proc`).
* Local-network detection falls back to the host name when there is no default route.
* `meridian --doctor`.

Features
* Trusted devices (`devices.json`): unknown devices are flagged on the map, in the table, in Findings and as watch alerts.
* Offline hints (no data sent): nine famous vulnerable releases, merged with the online lookup.
* Risk trend chart in History; desktop notifications for watch alerts; watch alerts are structured and new ones are detected by a counter (the old length check stopped working after 30 alerts).
* Favicon and app icon.

Tests: 77 -> 176 (languages, platform layouts, installers, devices, offline hints); CI runs on Ubuntu, macOS and Windows.

Changed: `./install.sh --uninstall` now behaves like `meridian --uninstall` (it asks about your data; add `--keep-data`).

## 0.3.0
Security and robustness
* Private per-run scratch directory (random name, `0700`, exclusive `0600` files) instead of a fixed `/tmp/meridian-<id>.xml` (CWE-377).
* `ScanManager` singleton: one place that starts, stops and cleans up scans; the one-scan-at-a-time rule can no longer be raced by two requests or by watch mode.
* nmap runs in its own process group; stop, time limit, exit and signals terminate and reap it; leftovers of a crashed run are cleaned up at start.
* nmap's stderr goes to a file (a full pipe could freeze a scan).
* The growing XML file is parsed only when it changed and at most every 2 s (adaptive), instead of every second.
* Old XML files and finished scans are pruned; audit log rotates; history is written atomically and validated when loaded; audit log and history never follow symlinks.
* Files created while running with sudo are handed to the real user.

UI
* The known-vulnerabilities box asks for confirmation every time it is ticked; the confirmation covers the next scan and nothing is remembered.
* Phones and tablets: normal page scroll, compact header, scrollable scan-type strip, readable map labels, visible radar sweep, no horizontal overflow.
* Colours no longer depend on a `data-theme` attribute being applied (the demo showed black and white in some hosts).
* `docs/index.html` is generated by `tools/build_demo.py`.
