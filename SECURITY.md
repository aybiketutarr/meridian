# Security policy
 
Meridian is a local tool: it binds to `127.0.0.1` only and must never be exposed to a network.
 
## Intended use
Scan only networks and systems you own or have **explicit written permission** to test. The authorization checkbox, public-target confirmation and local audit log exist to support that, not to replace it.
 
## Reporting a vulnerability
Please open a private security advisory on GitHub (Security tab -> "Report a vulnerability") instead of a public issue. Include steps to reproduce and the version/commit.
 
## Design notes
Fixed scan profiles (no raw nmap flags), strict target validation (IPv4, CIDR up to /22, last-octet ranges, hostnames), per-run token, Host/Origin checks, strict CSP, one scan at a time, 1-hour limit, audit log at `~/.local/share/meridian/audit.log`.
 
## Network access
Meridian itself makes no outgoing connections. Scans only touch the targets you enter. The optional **vulnerability lookup** (a warning window asks for confirmation every time the box is ticked, and the confirmation covers the next scan only) makes the nmap `vulners` script contact vulners.com with software names and versions only, and download fingerprint data from GitHub. It never sends IP addresses or hostnames, runs the script with the web-path sweep disabled (`vulners.paths=none`) so the target is not probed beyond normal version detection, and sets `vulners.max_items=0` so no API credits can be spent. Host discovery never uses it.
 
## Temporary files and processes
* Scratch files (raw nmap XML, stderr) live in a per-run directory created with a random name and mode `0700`: under `/run` for root, under `$XDG_RUNTIME_DIR` (a private tmpfs) for normal users, else the system temp directory. Files inside are created exclusively (`O_EXCL`, no symlinks) with `0600`. A directory that is a symlink, belongs to someone else or is open to other users is refused (CWE-377, CWE-59).
* Disk use is bounded: only the XML of the 20 newest scans is kept, the audit log rotates at 1 MB, the history file keeps 50 scans and is replaced atomically. The scratch directory is deleted at exit.
* One `ScanManager` (a process-wide singleton) owns the job table, the single scan slot and every nmap child, so the web UI and watch mode cannot start two scans at once.
* Every nmap runs in its own process group with stderr redirected to a file. Stop, the 1-hour limit, `SIGTERM`/`SIGHUP`/Ctrl+C and normal exit send `SIGTERM`, then `SIGKILL`, then wait for the process, so no zombie or orphan stays behind. After a hard crash (`kill -9`, power loss) the next start finds the leftover directory, stops the orphaned nmap if its command line still names that directory, and deletes it.

## Saving exports
Exports are written by the local server into your download folder (`~/Downloads` or the XDG setting, never outside your home directory). Only the extensions `.json .csv .md .html .xml .txt` are accepted, names are sanitised and never overwrite an existing file, files are created with `0600` permissions, and the request needs the per-run token. If Meridian was started with `sudo`, the file is handed to the real user.
