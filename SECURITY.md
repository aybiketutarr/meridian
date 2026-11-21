# Security policy
 
Meridian is a local tool: it binds to `127.0.0.1` only and must never be exposed to a network.
 
## Intended use
Scan only networks and systems you own or have **explicit written permission** to test. The authorization checkbox, public-target confirmation and local audit log exist to support that, not to replace it.
 
## Reporting a vulnerability
Please open a private security advisory on GitHub (Security tab -> "Report a vulnerability") instead of a public issue. Include steps to reproduce and the version/commit.
 
## Design notes
Fixed scan profiles (no raw nmap flags), strict target validation (IPv4, CIDR up to /22, last-octet ranges, hostnames), local access control (below), per-run token, Host/Origin/Content-Type checks, a CSP without `unsafe-inline` for scripts (per-page nonce), one scan at a time, 1-hour limit, audit log in the data folder (`~/.local/share/meridian` on Linux, `~/Library/Application Support/Meridian` on macOS, `%LOCALAPPDATA%\Meridian` on Windows).
 
## Local access control (0.4.1)
`127.0.0.1` is reachable by every program and every user of the machine, so binding to it is not enough. Meridian creates a random **launch key** at start-up and opens (and prints) `http://127.0.0.1:PORT/?k=<key>`. The first request with the key is answered with a redirect and a session cookie (`HttpOnly`, `SameSite=Strict`) and the key is then **used up**; it also expires after one hour. The page (which carries the per-run token), every `GET /api/...` and every `POST` need that cookie; `POST` also needs the token, a matching `Host` and `Origin` and `Content-Type: application/json`. Anything else gets `403`.
* On a shared machine, another user can no longer fetch the page, read scan results, or start a scan with your (possibly root) nmap.
* Limit: while the window is starting, the key is visible to other local users in the process list (`ps`) for a moment. Because it works once, the window that Meridian opens normally uses it within a second. If you start Meridian with `--serve`, open the printed link yourself soon after start-up; if it was already used, start Meridian again.
* Limit: a program running as **you** can read your files and your browser; Meridian cannot protect against that.

## Hardening of requests and data (0.4.1)
* Request bodies are bounded and parsed strictly (bad `Content-Length`, non-object JSON, wrong JSON types, unknown paths and non-JSON content types are refused); stalled connections time out.
* The custom scan profile can no longer switch on the `vulners` script by itself: it only runs through the confirmed vulnerability lookup, always with the safe script arguments.
* nmap XML with entity declarations or above 128 MB is refused; `history.json` is rebuilt field by field when loaded (types, lengths, https-only links), so a tampered file cannot inject markup or break the page. NaN/Infinity are never passed on.
* Exports: CSV cells that start with `=`, `+`, `-`, `@` are neutralised (spreadsheet formula injection); Markdown is escaped; the saved HTML report carries its own CSP (no script) and `noopener` links.
* `--uninstall` never deletes your home folder, a folder above it or a drive root, even if `MERIDIAN_DATA_DIR` points there; a data folder with a foreign name only loses the files Meridian created.

## Network access
Meridian itself makes no outgoing connections unless you turn on the optional **AI analysis** (off by default, see below). Scans only touch the targets you enter. The optional **vulnerability lookup** (a warning window asks for confirmation every time the box is ticked, and the confirmation covers the next scan only) makes the nmap `vulners` script contact vulners.com with software names and versions only, and download fingerprint data from GitHub. It never sends IP addresses or hostnames, runs the script with the web-path sweep disabled (`vulners.paths=none`) so the target is not probed beyond normal version detection, and sets `vulners.max_items=0` so no API credits can be spent. Host discovery never uses it.
 
**Offline hints** (a local checkbox) make no connection at all: detected versions are matched in memory against a built-in list. **Trusted devices** are stored locally in `devices.json` (names, MAC or IP addresses; private file, atomic writes, at most 500 entries, labels cleaned of control characters). **Language files** in `locales/` are data loaded from the app folder; they are escaped when placed into the page and shown as text (never as HTML), but treat the app folder like code: anyone who can write there can change the program anyway.

## Windows and macOS notes
* The port is bound with `SO_EXCLUSIVEADDRUSE` on Windows, because `SO_REUSEADDR` there would let another program share it.
* Data lives under the user profile, which is private to the user through the file system permissions; POSIX mode bits are not meaningful on NTFS and are not checked there. On Linux and macOS the `0700` / `0600` rules below apply.
* nmap is stopped with `taskkill /T /F` on Windows (whole process tree) and with its own process group on Linux and macOS. Stale-run cleanup never removes the files of a Meridian that is still alive, also where `/proc` does not exist.
* The installers write only inside the user's own folders (no administrator, no root) and refuse to run as root.

## Temporary files and processes
* Scratch files (raw nmap XML, stderr) live in a per-run directory created with a random name and mode `0700`: under `/run` for root, under `$XDG_RUNTIME_DIR` (a private tmpfs) for normal users, else the system temp directory. Files inside are created exclusively (`O_EXCL`, no symlinks) with `0600`. A directory that is a symlink, belongs to someone else or is open to other users is refused (CWE-377, CWE-59).
* Disk use is bounded: only the XML of the 20 newest scans is kept, the audit log rotates at 1 MB, the history file keeps 50 scans and is replaced atomically. The scratch directory is deleted at exit.
* One `ScanManager` (a process-wide singleton) owns the job table, the single scan slot and every nmap child, so the web UI and watch mode cannot start two scans at once.
* Every nmap runs in its own process group with stderr redirected to a file. Stop, the 1-hour limit, `SIGTERM`/`SIGHUP`/Ctrl+C and normal exit send `SIGTERM`, then `SIGKILL`, then wait for the process, so no zombie or orphan stays behind. After a hard crash (`kill -9`, power loss) the next start finds the leftover directory, stops the orphaned nmap if its command line still names that directory, and deletes it.

## Saving exports
Exports are written by the local server into your download folder (`~/Downloads` or the XDG setting, never outside your home directory). Only the extensions `.json .csv .md .html .xml .txt` are accepted, names are sanitised and never overwrite an existing file, files are created with `0600` permissions, and the request needs the per-run token. If Meridian was started with `sudo`, the file is handed to the real user.

## Optional AI analysis (0.5.0)

Off until you choose a provider in the **AI** tab. **Local** providers (Ollama, LM Studio) are reached on `127.0.0.1` only and nothing leaves the computer. **Cloud** providers (Claude, OpenAI) are reached at fixed `https` addresses; you cannot enter another URL, and redirects are never followed, so the API key cannot be sent elsewhere.

* The browser never talks to an AI (the page's `connect-src 'self'` is unchanged). The server builds the data itself from its own scan result and removes every IP address, MAC address, host name, vendor, banner and script output. Only OS name, port, service, product, version and CVE ids remain; hosts are labelled H1, H2 and mapped back to addresses locally.
* A cloud request first shows the exact data and needs your confirmation. The confirmation is single use, expires after 5 minutes and is bound to that data and provider.
* Scanned devices control banner text, so it is treated as untrusted: it is cut to length, sent as JSON data under a system prompt that forbids following it, and the model has no tools. The answer is parsed, checked against a fixed schema, length-limited, shown as text (never HTML) and never executed.
* The API key comes from `MERIDIAN_AI_KEY` or a private file `ai.key` (mode 0600) in the data folder and is never sent back to the page. One AI request runs at a time; each one is written to the audit log. Reports mark AI text as generated and to be verified.
