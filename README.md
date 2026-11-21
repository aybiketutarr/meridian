# Meridian
[![tests](https://github.com/aybiketutarr/meridian/actions/workflows/tests.yml/badge.svg)](https://github.com/aybiketutarr/meridian/actions/workflows/tests.yml)
A live web UI on top of the **nmap** engine: scan profiles, radial topology map, host table, risk scoring, known vulnerabilities and exploits for the software it finds, a trusted-device list that flags unknown devices, scan history with diff and risk trend, watch mode with desktop notifications, optional AI analysis, branded reports, and JSON / CSV / Markdown / HTML / PDF / Nmap-XML export. Pure Python standard library, **no pip dependencies**. Runs on **Linux, macOS and Windows**, in **English, Türkçe, Deutsch, Español and Français**.

**[Live demo](https://aybiketutarr.github.io/meridian/)** - runs entirely in your browser with sample data (no scanning).  ·  **[Türkçe README](README.tr.md)**

> **Use responsibly.** Scan only networks you own or have explicit permission to test.

## What is new in 0.5

* **One-click installers:** `Meridian-Setup-<version>.exe` for Windows (no Python needed) and `meridian_<version>_all.deb` for Debian, Ubuntu, Kali and Mint (nmap is installed with it). The terminal installers stay ([Installation](#installation)).
* **AI analysis (optional, off by default):** a plain-language summary and a "fix this first" list. Works with Ollama and LM Studio (local) or Claude and OpenAI (cloud). No IP, MAC or host name is ever sent ([details](#ai-analysis-optional)).
* **Report branding:** add your company or team, client, author, confidentiality note, accent colour and logo; they appear in the HTML, PDF and Markdown reports, which now start with a summary and end with a footer.
* **New look:** an editorial layout with a left rail, five themes (Black, White, Blue, Violet, Ember) and a security-themed backdrop for each. Fonts are local; nothing is loaded from the internet.
* **App icon** on Windows and macOS, and a Windows taskbar identity of its own.

Earlier versions (languages, trusted devices, offline hints, `meridian --doctor`, security hardening): see the [CHANGELOG](CHANGELOG.md).

## Installation

### One-click install (Windows and Linux)

Download the file for your system from the [Releases page](https://github.com/aybiketutarr/meridian/releases). No Python needed on Windows.

| | File | How |
|---|---|---|
| Windows 10/11 | `Meridian-Setup-<version>.exe` | Double-click. Installs for your user (no administrator), adds a Start Menu entry and an optional desktop icon. Windows may show a blue **SmartScreen** page because the file is not signed yet: choose **More info**, then **Run anyway**. Uninstall in *Settings > Apps*. |
| Debian, Ubuntu, Kali, Mint | `meridian_<version>_all.deb` | Double-click (the software centre opens) or `sudo apt install ./meridian_<version>_all.deb`. Remove with `sudo apt remove meridian`. nmap is installed with it. |
| macOS | | Manual install only for now, see below. |

Real scans need **nmap**. The Linux package installs it; on Windows the installer offers to open the download page. Your scans, devices and settings live in your own folder and survive updates. The terminal installers below stay available for everyone who prefers them.

Maintainers: `python3 tools/build_deb.py` builds the package; pushing a tag such as `v0.5.1` makes GitHub build both files (`.github/workflows/release.yml`).

### Manual install (terminal)

Needs **Python 3.10 or newer** and, for real scans, **nmap**. No Python packages. Everything installs for your own user: no root, no administrator. Without nmap you can still try everything with **Sample data**.

| | Linux | macOS | Windows |
|---|---|---|---|
| nmap | `sudo apt install nmap` | `brew install nmap` | installer from [nmap.org](https://nmap.org/download.html) (includes Npcap) |
| Install | `python3 install.py` (or `sh install.sh`) | `python3 install.py` | double-click `install.bat` (or `py install.py`) |
| Start | `meridian` | `meridian` or open **Meridian** from Launchpad | `meridian` or **Meridian** in the Start Menu |
| Full LAN results | `sudo -E "$(command -v meridian)"` | `sudo -E meridian` | terminal as **Administrator**, then `meridian` |
| Data folder | `~/.local/share/meridian` | `~/Library/Application Support/Meridian` | `%LOCALAPPDATA%\Meridian` |
| App window | Chromium / Chrome / Brave / Edge | Chrome / Edge / Brave / Chromium | Edge (always there) / Chrome / Brave |

Without a Chromium-family browser Meridian opens your default browser instead.

### Linux (step by step)

Tested on Kali Linux; works on Debian and Ubuntu too. Use your **normal user** (not root).

```sh
sudo apt update
sudo apt install -y git python3 nmap chromium      # chromium is optional (app window); on Ubuntu: chromium-browser
git clone https://github.com/aybiketutarr/meridian.git
cd meridian
python3 -m unittest discover -s tests              # optional; the last line must say OK
python3 install.py                                  # installs the 'meridian' command and a menu entry
meridian
```

If `meridian` is "command not found", add `~/.local/bin` to your PATH once:
```sh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc    # bash users: ~/.bashrc
source ~/.zshrc
```

### macOS

```sh
brew install nmap                  # Homebrew: https://brew.sh
git clone https://github.com/aybiketutarr/meridian.git && cd meridian
python3 install.py
meridian                           # or open Meridian from Launchpad / Spotlight
```
`python3` comes with the Xcode command line tools, or install it from python.org. The installer creates `~/Applications/Meridian.app` and the `meridian` command in `~/.local/bin` (add that folder to your PATH if the shell does not find it). For ARP discovery, OS detection and traceroute start with `sudo -E meridian`.

### Windows

1. Install **Python 3.10+** from [python.org](https://www.python.org/downloads/) (tick *Add python.exe to PATH*) and **nmap** from [nmap.org](https://nmap.org/download.html).
2. Download or clone Meridian, then double-click **`install.bat`** (or run `py install.py` in a terminal).
3. Open a **new** terminal and run `meridian`, or use **Meridian** in the Start Menu.

The installer adds its folder to your *user* PATH (no administrator needed; use `--no-path` to skip). For ARP discovery, OS detection and traceroute, open the terminal with **Run as administrator**. Windows Defender Firewall may ask once whether nmap may use the network.

### Check your setup

```sh
meridian --doctor           # add --lang tr (or de, es, fr) for another language
```
It lists Python, nmap, scan privileges, browser, data folder and port, and says how to fix each problem.

### Version, options, update, remove

```sh
meridian --version
meridian --help
```
Update: `git pull`, then `python3 install.py` again (it replaces the app copy and keeps your data). Remove:
```sh
meridian --uninstall              # removes the command, the app copy, the menu entry AND your saved data
meridian --uninstall --keep-data  # keeps the data; add --yes to skip the question
```
Run it as your normal user, without sudo.

### Without installing

```sh
python3 server.py            # or: python3 server.py --serve   (no window; prints the URL)
```
Meridian uses port 8765 (so theme, presets and notes are remembered) and falls back to a free port if it is busy. Environment: `MERIDIAN_PORT`, `MERIDIAN_LANG`, `MERIDIAN_NMAP` (path to nmap), `MERIDIAN_DATA_DIR` (where saved data lives), `MERIDIAN_AI_KEY` (API key for a cloud AI provider).

### Docker (optional, Linux)

```sh
docker build -t meridian .
docker run --rm --net=host -e MERIDIAN_LANG=tr meridian     # then open the link printed in the log (http://127.0.0.1:8765/?k=..., it works once)
```
`--net=host` is required because Meridian only listens on `127.0.0.1`. Docker Desktop on Windows and macOS runs containers inside a virtual machine and cannot see your real network: install Meridian natively there.

### First scan

1. Click **Auto** next to the target box (it fills in your local network, for example `192.168.1.0/24`).
2. Tick the authorization checkbox.
3. Choose **Quick** and press **Scan**.

On a VirtualBox VM set the adapter to **Bridged**; with NAT the VM only sees its own virtual network.

## Languages

Meridian starts in English. A different language is used only if you choose it in the header (remembered) or start with `--lang` / `MERIDIAN_LANG`; the browser or system language is not used. Reports you export (HTML, Markdown) use the language you see. Machine-readable output (JSON, CSV headers, the audit log) stays in English on purpose.

### Adding a language

Copy `locales/en.json` to `locales/<code>.json` (for example `pt.json`), translate the values, set `_name` to the language's own name. Keep the `{placeholders}` and the `_one` / `_other` pairs. Nothing else to change: the file is picked up by the app, the terminal messages, the installer and the demo build. `python3 -m unittest tests.test_i18n` checks that no key or placeholder is missing. Right-to-left languages are not supported yet.

## Features

* Quick / Services / Full / OS / Vuln / Traceroute / Custom scans (validated options, no raw nmap arguments), stop button
* Risk scoring (Critical / High / Medium / Low) and findings, device-type guess, MAC vendor
* **Known vulnerabilities (optional, online):** software versions checked for CVEs and public exploits, with a recommended action ([details](#vulnerability-lookup))
* **Offline hints (optional):** matched locally against a small built-in list, nothing is sent ([details](#offline-hints))
* **Trusted devices:** a list that survives restarts; unknown devices are flagged everywhere ([details](#trusted-devices))
* Radial topology map, sortable and filterable host table, per-host notes, saved Custom presets
* Scan history (stored locally) with a diff between two scans and a **risk trend** for repeated scans of the same target
* Watch mode: re-scan a target every 5 min to 6 h and get alerts for new hosts, unknown devices, new ports and vanished hosts, optionally as **desktop notifications** (works while Meridian is open)
* **AI analysis (optional):** summary and prioritised fixes from a local or cloud model, with no IPs or host names sent ([details](#ai-analysis-optional))
* Export: JSON, CSV, Markdown, HTML, PDF (print), raw Nmap XML, copy IP list. Files are saved straight into your Downloads folder (a message shows the exact path)
* **Report branding:** company, client, author, confidentiality note, accent colour and logo in the HTML, PDF and Markdown reports (stored only in your browser)
* 5 themes (Black, White, Blue, Violet, Ember); the theme follows your system until you pick one

### Accepted targets
IPv4 address, CIDR (up to `/22`), last-octet range (`192.168.1.10-50`) or hostname. Separate several with spaces or commas (max 32 targets, 1024 addresses in total). IPv6 is not supported yet.

## Trusted devices

Open a device on the map and tick **Trusted device** (optionally give it a name), or press **Trust all found devices** on the Hosts tab to take today's network as your baseline. From then on:

* every device that is *not* trusted gets an **UNKNOWN** badge, a dashed ring on the map, a "Device not in your trusted list" finding (Medium) and is counted in a fifth counter;
* in watch mode a new device outside the list raises an **UNKNOWN DEVICE** alert instead of a plain "new host".

Devices are recognised by **MAC address** when nmap sees one (run as root / Administrator on your LAN), otherwise by IP address, which can change. The list is stored in `devices.json` in the data folder (private file, atomic writes). Without any trusted device nothing is flagged, so there is no noise until you decide to use it.

## Offline hints

Tick **Offline hints** and the scan also detects service versions (like the Services profile) and compares them with a small list inside Meridian: vsftpd 2.3.4 backdoor, Apache 2.4.49 / 2.4.50 path traversal, OpenSSH 7.7 and older user enumeration, Samba "SambaCry", Exim 4.87-4.91, OpenSSL "Heartbleed" 1.0.1-1.0.1f, UnrealIRCd 3.2.8.1 backdoor and ProFTPD 1.3.5 mod_copy. **Nothing is sent anywhere** and no confirmation is needed. Hints are marked OFFLINE and can be combined with the online lookup (each CVE is listed once). This is a short list of famous cases, not a vulnerability database: no hint does not mean safe. As with the online lookup, a distribution may have patched the software without changing its version number.

## Vulnerability lookup

When it is turned on, every scan that checks ports (Quick, Services, Full TCP, OS, Traceroute, Vulnerability and Custom with version detection) does two extra things:

1. nmap detects the **software and version** behind each open port (`-sV`; Quick and Traceroute use the fast `--version-light`).
2. The `vulners` NSE script that ships with nmap looks that software up at vulners.com and returns **CVEs, CVSS scores and whether public exploit code exists**.

Meridian shows the result under each port in the host panel (worst first), adds a finding with a **recommended action**, raises the host's risk score, and includes the CVEs in the exports. **Host discovery never runs it**, because it does not check ports.

**Turning it on.** Every time you tick **Check known vulnerabilities (online)**, a warning window explains what is sent and asks you to confirm. The confirmation counts for the next scan only: the box clears itself when that scan starts, and nothing is remembered between runs.

**What leaves your machine.** Only software names and versions (for example `vsftpd 2.3.4`) go to vulners.com, never IP addresses or hostnames. The nmap script also downloads its fingerprint data from GitHub. No API key is needed or used.

**What it does not tell you**
* Matches come from the **version text**, so they are "possible", not confirmed. Distributions such as Debian and Ubuntu patch software without changing the version number.
* The lookup does not report **which version fixes** an issue. Use the advisory link or your package manager (for example `apt changelog <package>`).
* Nothing is found when nmap cannot read a version number. The panel says so for that port.
* Without an API key the data has no CISA "actively exploited" flag; public-exploit flags and CVSS are included. Meridian never spends API credits.
* Meridian only **reports** that exploits exist. It does not run or download exploit code.

## AI analysis (optional)

Open the **AI** tab and choose a provider; until then nothing is used and nothing is sent.

| Provider | Where it runs | Needs |
|---|---|---|
| Ollama | your computer (`127.0.0.1:11434`) | Ollama running with a model pulled |
| LM Studio | your computer (`127.0.0.1:1234`) | LM Studio's local server on |
| Claude, OpenAI | their cloud | an API key (paste it in the tab, or set `MERIDIAN_AI_KEY`) |

Meridian builds the data itself from the scan result and removes every IP address, MAC address, host name, vendor and banner; only OS, ports, services, versions and CVE ids remain, under labels like H1, H2. A cloud request first shows you the exact data and needs a single-use confirmation. The answer is checked, shown as plain text and marked as generated in the HTML and Markdown reports: verify it before acting. More in [SECURITY.md](SECURITY.md).

## Security model
Localhost-only binding, per-run token (constant-time compare), Host and Origin checks, strict CSP, whitelisted scan options, strict target validation, one scan at a time (a single `ScanManager`), 1-hour scan limit, public-target confirmation, authorization checkbox before every scan, and a local audit log in the data folder (rotated at 1 MB; history, devices and the audit log are private files). Scratch files live in a private directory with a random name, and every nmap runs in its own process group (Windows: process tree) that is stopped and reaped on stop, time limit, exit and crash recovery. On Windows the port is bound exclusively, so no other program can share it. See [SECURITY.md](SECURITY.md).

Risk scores are heuristics from exposed services and NSE output, not a substitute for a professional assessment.

## Troubleshooting

Start with `meridian --doctor`.

* **Only a few hosts are found on my LAN.** Run with root / Administrator (table above). Also check that the target is *your* network (**Auto**) and, inside a VM, that the adapter is **Bridged**. Some routers hide devices from each other (AP / client isolation).
* **`nmap: NOT FOUND`** in the start-up line: install nmap (table above). On Windows open a *new* terminal after installing it; Meridian also looks in `C:\Program Files (x86)\Nmap`. You can point to any nmap with `MERIDIAN_NMAP`.
* **`command not found: meridian`** (Linux, macOS): add `~/.local/bin` to your PATH. **Windows:** open a new terminal after installing.
* **No app window, a normal browser tab opens:** no Chromium-family browser was found. Install Chrome, Edge or Brave, or just use the tab.
* **macOS: "Meridian.app" does not open from Finder.** Start `meridian` once in a terminal and read the message; `meridian --doctor` shows what is missing.
* **`vaInitialize failed` or other Chromium messages in the terminal** are harmless GPU warnings from the browser.
* **Window opened as root:** Meridian opens the window as the user who ran `sudo`. If you log in as a real root user, open the printed URL in a normal browser.
* **No vulnerabilities are listed for a port.** The panel says why: "No version number detected" means nothing to look up; "No known vulnerabilities returned" means the lookup ran and found nothing. If a scan shows "No vulnerability data returned", check that the machine can reach vulners.com.
* **Garbled letters in a Windows console:** Meridian switches its output to UTF-8; if your console font lacks a letter, use Windows Terminal.

## Development

```sh
python3 -m unittest discover -s tests -v
```
Before every push run `python3 tools/preflight.py`: it checks the files, line endings, the generated demo and the version, then runs the tests, so the CI cross is never a surprise.

CI runs the same command on **Ubuntu, macOS and Windows** with Python 3.10 - 3.13 (`.github/workflows/tests.yml`). Most platform logic is tested by faking the platform, so the tests also run everywhere; Windows- and macOS-only system calls (registry, PowerShell shortcut, `ps`) are covered with fakes and need a real machine for a final check.

Releases: the version number lives in `VERSION` at the top of `server.py`. Bump it for every release and tag the same number on GitHub (for example `v0.5.1`).

Layout: `server.py` (HTTP server, `ScanManager`, nmap runner, parser, validation, platform helpers, languages for the terminal), `ai.py` (optional AI analysis), `index.html` (single-file UI), `locales/*.json` (all texts), `install.py` (+ `install.sh`, `install.bat`), `installer/meridian.iss` (Windows setup), `assets/` (icons), `docs/` (browser-only demo), `tools/` (`build_demo.py`, `build_deb.py`, `make_icons.py`, `preflight.py`), `.github/workflows/` (tests and release), `tests/`, `Dockerfile`.

The demo `docs/index.html` is **generated** from `index.html`, `locales/` and `docs/demo-shim.js`. After changing any of them run `python3 tools/build_demo.py`; a test fails if they are out of sync.

## Roadmap
Right-to-left languages, optional vulners API key setting (adds the "actively exploited" flag), NSE script picker, IPv6 targets, `pipx` package.

## License
MIT - see [LICENSE](LICENSE).
