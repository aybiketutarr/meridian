# Security policy
 
Meridian is a local tool: it binds to `127.0.0.1` only and must never be exposed to a network.
 
## Intended use
Scan only networks and systems you own or have **explicit written permission** to test. The authorization checkbox, public-target confirmation and local audit log exist to support that, not to replace it.
 
## Reporting a vulnerability
Please open a private security advisory on GitHub (Security tab -> "Report a vulnerability") instead of a public issue. Include steps to reproduce and the version/commit.
 
## Design notes
Fixed scan profiles (no raw nmap flags), strict target validation (IPv4, CIDR up to /22, last-octet ranges, hostnames), per-run token, Host/Origin checks, strict CSP, one scan at a time, 1-hour limit, audit log at `~/.local/share/meridian/audit.log`.
 
## Network access
Meridian itself makes no outgoing connections. Scans only touch the targets you enter. The optional **vulnerability lookup** (asked once, can be switched off in the left panel) makes the nmap `vulners` script contact vulners.com with software names and versions only, and download fingerprint data from GitHub. It never sends IP addresses or hostnames, runs the script with the web-path sweep disabled (`vulners.paths=none`) so the target is not probed beyond normal version detection, and sets `vulners.max_items=0` so no API credits can be spent. Host discovery never uses it.
