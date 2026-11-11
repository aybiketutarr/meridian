# Meridian
 
A live web UI on top of the **nmap** engine: scan profiles, radial topology map, host table, risk scoring, known vulnerabilities and exploits for the software it finds, scan history with diff, watch mode and JSON / CSV / Markdown / HTML / Nmap-XML export. Pure Python standard library, **no pip dependencies**.
 
**[Live demo](https://aybiketutarr.github.io/meridian/)** - runs entirely in your browser with sample data (no scanning).
 
> **Use responsibly.** Scan only networks you own or have explicit permission to test.
 
## Installation (Linux, step by step)
 
Tested on Kali Linux. Works on Debian/Ubuntu-based systems too. Run every command in a terminal as your **normal user** (not root, do not log in as root).
 
### Step 1 - Install the required packages
```sh
sudo apt update
sudo apt install -y git python3 nmap chromium
```
`chromium` is only needed for the standalone app window. Without it, Meridian opens your default browser. On Ubuntu the package may be called `chromium-browser` (or use Google Chrome).
 
### Step 2 - Check the versions
```sh
whoami
python3 --version
nmap --version
```
`whoami` must **not** print `root`. Python must be **3.10 or newer**.
 
### Step 3 - Download Meridian
```sh
cd ~
git clone https://github.com/aybiketutarr/meridian.git
cd meridian
ls
```
You should see `server.py`, `index.html`, `install.sh`, `tests` and more.
 
### Step 4 - Run the self-tests (optional but recommended)
```sh
python3 -m unittest discover -s tests
```
The last line must say `OK`.
 
### Step 5 - Install the `meridian` command
```sh
sh install.sh
```
This copies the app to `~/.local/share/meridian-app`, creates the `meridian` command in `~/.local/bin` and adds a menu entry. No root needed.
 
If the next step says `command not found: meridian`, add the folder to your PATH once:
```sh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc    # Kali (zsh)
# bash users: use ~/.bashrc instead of ~/.zshrc
source ~/.zshrc
```
 
### Step 6 - Start Meridian
```sh
meridian
```
The app window opens. Keep the terminal open while you use it; closing the window ends the program.
 
### Step 7 - Run your first scan
1. Click the **auto** button next to the target box (it fills in your local network, for example `192.168.1.0/24`).
2. Tick the authorization checkbox (you confirm you may scan this network).
3. Choose **Quick** and press **Scan**.
4. Hosts appear in the table and on the topology map.
No nmap yet? Click **Try with sample data** to see the full UI.
 
### Step 8 - Full results with root (recommended on a LAN)
Without root, nmap cannot use ARP and misses phones, TVs and firewalled devices. Close Meridian (Ctrl+C in the terminal) and start it like this:
```sh
sudo -E "$(command -v meridian)"
```
Type your password when asked. Meridian is still opened as **your** user, only the scanning gets root rights. Run the same scan again: you should now see more devices, with MAC vendors and OS guesses.
 
### Using a VirtualBox VM?
Set **Settings -> Network -> Adapter 1 -> Attached to: Bridged Adapter** and pick the network card your PC is really using (Wi-Fi or Ethernet). On Wi-Fi also set **Advanced -> Promiscuous Mode: Allow All**. With NAT, the VM only sees its own virtual network.
 
### Update
```sh
cd ~/meridian
git pull
sh install.sh
```
 
### Remove
```sh
meridian --uninstall
```
Lists what it will delete, asks for confirmation, then removes the command, the app copy, the menu entry **and your saved data** (scan history, audit log, browser profile with theme, presets and notes in `~/.local/share/meridian`). To remove only the application and keep your data:
```sh
meridian --uninstall --keep-data
```
Run it as your normal user, without sudo. Add `--yes` to skip the confirmation question.
 
### Without installing
```sh
python3 server.py            # or: python3 server.py --serve
```
`--serve` runs without a window and prints a URL such as `http://127.0.0.1:44959` to open in your browser. Meridian uses port 8765 (so your theme, presets and notes are remembered between runs) and falls back to a free port if that one is busy. Set `MERIDIAN_PORT` to choose another one.
 
### Docker (optional)
```sh
docker build -t meridian .
docker run --rm --net=host meridian     # then open http://127.0.0.1:8765
```
`--net=host` (Linux) is required because Meridian only listens on `127.0.0.1`. The container runs as a non-root user, so OS detection and raw-socket scans are limited.
 
## Features
 
* Quick / Services / Full / OS / Vuln / Traceroute / Custom scans (validated options, no raw nmap arguments), stop button
* Risk scoring (Critical / High / Medium / Low) and findings, device-type guess, MAC vendor
* **Known vulnerabilities (optional, online):** every port that is scanned gets its software version checked for CVEs and public exploits, with a recommended action ([details](#vulnerability-lookup))
* Radial topology map, sortable and filterable host table, per-host notes, saved Custom presets
* Scan history (stored locally) with a diff between two scans
* Watch mode: re-scan a target every 5 min to 6 h and get alerts for new hosts, new ports and vanished hosts (works while Meridian is open)
* Export: JSON, CSV, Markdown, HTML, PDF (print), raw Nmap XML, copy IP list
* 4 themes, including *Waves* (animated background, static if reduced motion is on)
### Accepted targets
IPv4 address, CIDR (up to `/22`), last-octet range (`192.168.1.10-50`) or hostname. Separate several with spaces or commas (max 32 targets, 1024 addresses in total). IPv6 is not supported yet.
 
## Vulnerability lookup
 
When it is turned on, every scan that checks ports (Quick, Services, Full TCP, OS, Traceroute, Vulnerability and Custom with version detection) does two extra things:
 
1. nmap detects the **software and version** behind each open port (`-sV`; Quick and Traceroute use the fast `--version-light`).
2. The `vulners` NSE script that ships with nmap looks that software up at vulners.com and returns **CVEs, CVSS scores and whether public exploit code exists**.
Meridian shows the result under each port in the host panel (worst first), adds a finding with a **recommended action**, raises the host's risk score, and includes the CVEs in the JSON, CSV, Markdown and HTML exports. **Host discovery never runs it**, because it does not check ports.
 
**Turning it on and off.** The first time you start a port scan, Meridian asks once. After that, use the **Check known vulnerabilities (online)** switch in the left panel.
 
**What leaves your machine.** Only software names and versions (for example `vsftpd 2.3.4`) go to vulners.com, never IP addresses or hostnames. The nmap script also downloads its fingerprint data from GitHub. No API key is needed or used.
 
**What it does not tell you**
* Matches come from the **version text**, so they are "possible", not confirmed. Distributions such as Debian and Ubuntu patch software without changing the version number, so an old-looking version can already be fixed.
* The lookup does not report **which version fixes** an issue. Use the advisory link or your package manager (for example `apt changelog <package>`).
* Nothing is found when nmap cannot read a version number (a banner such as `nginx` without a number). The panel says so for that port.
* Without an API key the data has no CISA "actively exploited" flag; public-exploit flags and CVSS are included. A free vulners.com key adds that flag, and Meridian never spends API credits.
* Meridian only **reports** that exploits exist. It does not run or download exploit code.
## Security model
Localhost-only binding, per-run token (constant-time compare), Host and Origin checks, strict CSP, whitelisted scan options, strict target validation, one scan at a time, 1-hour scan limit, public-target confirmation, authorization checkbox before every scan, and a local audit log at `~/.local/share/meridian/audit.log` (history is stored with `0600` permissions). See [SECURITY.md](SECURITY.md).
 
Risk scores are heuristics from exposed services and NSE output, not a substitute for a professional assessment.
 
## Troubleshooting
 
* **Only a few hosts are found on my LAN.** Run with root (Step 8). Also check that the target is *your* network (the **auto** button fills it in) and, inside a VM, that the adapter is **Bridged**. Some routers hide devices from each other (AP / client isolation).
* **`vaInitialize failed` or other Chromium messages in the terminal** are harmless GPU warnings from the browser.
* **`Running as root without --no-sandbox`**: fixed in current versions (the window is opened as the user who ran `sudo`). If you log in as a real root user, open the printed URL in a normal browser instead.
* **No vulnerabilities are listed for a port.** The panel says why: "No version number detected" means nmap could not read a version (nothing to look up); "No known vulnerabilities returned" means the lookup ran and found nothing for that version. If a scan shows "No vulnerability data returned", check that the machine can reach vulners.com. Windows services often have no usable version-to-CVE mapping.
* **`command not found: meridian`**: add `~/.local/bin` to your PATH (see Step 5).
* **`nmap: NOT FOUND`** in the start-up line: run `sudo apt install nmap`.
## Development
 
```sh
python3 -m unittest discover -s tests -v
```
CI runs the same command on Python 3.10 - 3.13 (`.github/workflows/tests.yml`).
 
Layout: `server.py` (HTTP server, nmap runner, XML parser, validation), `index.html` (single-file UI), `docs/` (browser-only demo), `tests/`, `install.sh`, `Dockerfile`.
 
## Roadmap
Optional vulners API key setting (adds the "actively exploited" flag), offline lookup, NSE script picker, IPv6 targets.
 
## License
MIT - see [LICENSE](LICENSE).
