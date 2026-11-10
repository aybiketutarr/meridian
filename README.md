Meridian
A live web UI on top of the nmap engine: scan profiles, radial topology map, host table, risk scoring, scan history with diff, watch mode and JSON / CSV / Markdown / HTML / Nmap-XML export. Pure Python standard library, no pip dependencies.
Live demo - runs entirely in your browser with sample data (no scanning).
> **Use responsibly.** Scan only networks you own or have explicit permission to test.
Quick start
```sh
sudo apt install nmap chromium      # chromium/chrome gives the standalone app window
./install.sh                        # installs the `meridian` command + menu entry
meridian                            # the app window opens
```
Window mode: `pywebview` if installed, else a Chromium/Chrome `--app` window, else your default browser. `meridian --serve` runs headless (open the printed URL yourself).
OS detection, SYN scans and traceroute need root: `sudo -E "$(command -v meridian)"`.
No nmap? Click Try with sample data to preview the whole UI.
Remove: `./install.sh --uninstall`.
Without installing
```sh
python3 server.py            # or: python3 server.py --serve
```
Set `MERIDIAN_PORT=8765` to use a fixed port (default: a random free port).
Docker
```sh
docker build -t meridian .
docker run --rm --net=host meridian     # then open http://127.0.0.1:8765
```
`--net=host` (Linux) is required because Meridian only listens on `127.0.0.1`. The container runs as a non-root user, so OS detection and raw-socket scans are limited.
Features
Quick / Services / Full / OS / Vuln / Traceroute / Custom scans (validated options, no raw nmap arguments), stop button
Risk scoring (Critical / High / Medium / Low) and findings, device-type guess, MAC vendor, CVE extraction (enable the `vulners` script in Custom)
Radial topology map, sortable and filterable host table, per-host notes, saved Custom presets
Scan history (stored locally) with a diff between two scans
Watch mode: re-scan a target every 5 min to 6 h and get alerts for new hosts, new ports and vanished hosts (works while Meridian is open)
Export: JSON, CSV, Markdown, HTML, PDF (print), raw Nmap XML, copy IP list
4 themes, including Waves (animated background, static if reduced motion is on)
Accepted targets
IPv4 address, CIDR (up to `/22`), last-octet range (`192.168.1.10-50`) or hostname. Separate several with spaces or commas (max 32 targets, 1024 addresses in total). IPv6 is not supported yet.
Security model
Localhost-only binding, per-run token (constant-time compare), Host and Origin checks, strict CSP, whitelisted scan options, strict target validation, one scan at a time, 1-hour scan limit, public-target confirmation, authorization checkbox before every scan, and a local audit log at `~/.local/share/meridian/audit.log` (history is stored with `0600` permissions). See SECURITY.md.
Risk scores are heuristics from exposed services and NSE output, not a substitute for a professional assessment.
Development
```sh
python3 -m unittest discover -s tests -v
```
CI runs the same command on Python 3.10 - 3.13 (`.github/workflows/tests.yml`).
Layout: `server.py` (HTTP server, nmap runner, XML parser, validation), `index.html` (single-file UI), `tests/`, `install.sh`, `Dockerfile`.
Roadmap
CVE lookup from service versions, NSE script picker, IPv6 targets.
License
MIT - see LICENSE.
