# Changelog

## 0.5.2
* **Windows installer installs nmap for you:** at the end of setup it offers "Install nmap now". It uses winget, which downloads nmap from its own verified source and shows nmap's normal setup (it asks for permission and installs Npcap). Without winget the nmap download page is offered instead, as before. nmap is handled before Meridian starts, so Meridian finds it.
* Fixed: opening Meridian a second time while it was already open did nothing. The second window was handed to the browser of the first one and the second Meridian stopped at once. It now opens its own window with a temporary browser profile (its settings are not kept, the first window keeps them). Saved scan history is shared by both; if both save scans, the one that saves last wins.
* Fixed: dialogs (for example Report branding) were too big on a phone and could hide their buttons. They now stay inside the screen, scroll inside when needed and use smaller type, spacing and a two-column colour/logo row on narrow screens.

## 0.5.1
* **One-click installers:** `Meridian-Setup-<version>.exe` for Windows (no Python needed, per-user install, Start Menu and optional desktop icon, uninstall in Settings) and `meridian_<version>_all.deb` for Debian, Ubuntu, Kali and Mint (installs nmap with it). The terminal installers (`install.py`, `install.sh`, `install.bat`) stay. macOS stays a manual install.
* New `tools/build_deb.py` (standard library only), `installer/meridian.iss` and `.github/workflows/release.yml` (builds both files on a version tag). The Windows exe is not code-signed yet, so SmartScreen shows a warning on first run.
* **Report branding:** a new button next to Export opens "Report branding": company or team, client, author, confidentiality note, accent colour and a logo (PNG, JPG, WebP or SVG, up to 300 KB). It is stored only in the browser and used in the HTML report, the PDF and the Markdown report. Reports now start with a header, a date, a summary (hosts, ports, findings, posture, counts per severity) and carry a footer.
* **Print / PDF** now prints the branded report instead of the app window.
* Fixed: after a successful export the file was saved to the downloads folder AND the browser started a second download, and the "Saved to ..." message never appeared (a variable inside the save helper hid the translate function).
* **App icon on Windows and macOS:** the Start Menu shortcut now shows the Meridian emblem instead of the Python icon, and `Meridian.app` has a real icon (Launchpad, Dock, Finder). New files `assets/meridian.ico`, `meridian.icns`, `meridian.png`, made by `tools/make_icons.py` (Pillow, developer only).
* Windows: the process gets its own taskbar identity (`Meridian.Scanner`) and the icon cache is refreshed after install. If an old icon lingers, sign out and in once.
* New look, part 2: the small mascots are replaced by a security backdrop in the top-right corner of every theme (hooded hacker, globe, shield and lock, firewall, radar), drawn behind the UI. Smaller KPI numbers in the top strip. The Blue theme is now a dark navy, and the White theme uses cherry red for its accent colours.
* Cleanup: removed the unused Waves and Ocean theme code (CSS, canvas animation and their language strings) and a few unused imports. No change in behaviour.

## 0.5.0
* **AI analysis** (new tab, off by default): plain-language summary, what to fix first and how. Providers: Ollama and LM Studio (local) and Claude and OpenAI (cloud). No pip dependencies (`ai.py`).
* Privacy by design: no IPs, MACs or host names are ever sent; cloud requests show the exact data and need a single-use confirmation; model output is validated and shown as text only.
* New look: a redesigned editorial layout (left rail, italic serif headings and numbers, pill controls, rounded cards) five themes (Black, White, Blue, Violet, Ember) and a security backdrop for each theme. The theme follows the system until you choose one. Local fonts only, nothing is loaded from the internet.
* AI text is added to the HTML and Markdown reports, marked as generated. The live demo shows a ready-made answer and calls no API.

## 0.4.4 (CI that can turn green)
* Tests no longer depend on the executable bit of `install.sh` (uploading through the GitHub web page or committing from Windows drops it, which kept CI red for no real reason). The script is still syntax-checked.
* CI: Linux (Python 3.10 - 3.13) is the gate. macOS and Windows run the same tests as a separate job that reports but does not fail the workflow (`continue-on-error`) until both have been seen green; delete that line to make them required again.
* `tools/preflight.py`: one command that checks the file layout, line endings, the generated demo and the version, then runs the tests.
* No change to the program itself.

## 0.4.3 (Windows CI fix)
* Fixed: the Linux `.desktop` Exec= line and the macOS/Linux shell launcher script always used the host's native path separator when built. This was invisible on Linux/macOS (where native already means forward slashes) but on a real Windows machine it wrote backslash paths into files meant to be read on Linux/macOS — `install.py` now builds both with `.as_posix()` regardless of host.
* Fixed: the Windows-folder test (`test_platform.Folders.test_windows`) copied the *real* `LOCALAPPDATA`/`APPDATA`/`USERPROFILE`/`ProgramFiles*` of whatever machine ran the tests into its "clean" environment, so on an actual Windows runner the test silently checked against the runner's own real profile instead of the fake one it set up. Those variables are now excluded so the fake home is always used.
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
