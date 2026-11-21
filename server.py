#!/usr/bin/env python3
"""Meridian - nmap engine + live web UI. Binds to localhost only. Scan only what you are authorized to scan."""
import atexit, ipaddress, json, os, platform, signal, socket, re, secrets, shutil, stat, subprocess, sys, threading, time, tempfile, uuid
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from http import cookies as http_cookies
import math
import ai
 
PORT = 0  # chosen at start-up (free port)
VERSION = "0.5.1"   # bump for every release and tag the same number on GitHub (v0.5.1)
TOKEN = secrets.token_urlsafe(16)
# Local access control. The page and every API call need a session cookie, and the only way to get one is the single-use launch key in the URL that
# Meridian opens itself (and prints). Another program or another user on the same machine can reach 127.0.0.1, but without the key it can neither
# fetch the page (which carries TOKEN) nor read scan results nor start a scan with this user's (possibly root) nmap.
LAUNCH_KEY, LAUNCH_TTL, LAUNCH_T0, LAUNCH_STATE = secrets.token_urlsafe(16), 3600, time.monotonic(), {"used": False}
SESSIONS, SESSION_LOCK, MAX_SESSIONS, COOKIE = [], threading.Lock(), 8, "mr_sid"

def _eq(a, b):
    """Constant-time comparison that never raises (secrets.compare_digest refuses non-ASCII str, and HTTP headers can carry such bytes)."""
    return secrets.compare_digest(str(a).encode("utf-8", "replace"), str(b).encode("utf-8", "replace"))

def new_session():
    sid = secrets.token_urlsafe(24)
    with SESSION_LOCK: SESSIONS.append(sid); del SESSIONS[:-MAX_SESSIONS]
    return sid

def redeem_launch_key(k):
    """The launch key works once, and only for LAUNCH_TTL seconds after start-up. Returns a new session id or None."""
    with SESSION_LOCK:
        ok = not LAUNCH_STATE["used"] and time.monotonic() - LAUNCH_T0 <= LAUNCH_TTL and _eq(k, LAUNCH_KEY)
        if ok: LAUNCH_STATE["used"] = True
    return new_session() if ok else None

def launch_url(): return f"http://127.0.0.1:{PORT}/?k={LAUNCH_KEY}"
JOBS = {}
IS_WIN = os.name == "nt"
IS_MAC = sys.platform == "darwin"
ROOT = Path(__file__).resolve().parent         # server.py, index.html, locales/ and assets/ live here (also in the installed copy)
APP_FILES, APP_DIRS = ("server.py", "ai.py", "index.html"), ("locales", "assets")      # what install.py copies and the Dockerfile ships
UI_LANG = ""                                   # language forced with --lang / MERIDIAN_LANG; empty = the browser decides
LANG = "en"                                    # language of messages printed in the terminal
def current_os(): return "windows" if IS_WIN else "macos" if IS_MAC else "linux"

def fix_stdio():
    """Windows consoles use legacy code pages (cp437, cp1254, ...) and pythonw has no console at all: make print() safe for every language."""
    for name in ("stdout", "stderr"):
        st = getattr(sys, name)
        if st is None: setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))
        else:
            try: st.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError, OSError): pass

def app_data_dir():
    """Where history, audit log, trusted devices and the browser profile live. Linux keeps ~/.local/share/meridian (unchanged since 0.1)."""
    o = os.environ.get("MERIDIAN_DATA_DIR")
    if o: return Path(o).expanduser()
    home = Path.home()
    if IS_WIN: return Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local") / "Meridian"
    if IS_MAC: return home / "Library" / "Application Support" / "Meridian"
    xdg, legacy = Path(os.environ.get("XDG_DATA_HOME") or home / ".local" / "share") / "meridian", home / ".local" / "share" / "meridian"
    return xdg if xdg.exists() or not legacy.exists() else legacy

def install_paths():
    """Where install.py puts things and where --uninstall looks, per OS. Everything is inside the user's own folders: no root, no administrator."""
    home = Path.home()
    if IS_WIN:
        base = Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local"); app = base / "Meridian-app"
        menu = Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming") / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Meridian.lnk"
        return {"os": "windows", "app": app, "bin": app / "bin", "launcher": app / "bin" / "meridian.cmd", "menu": [menu]}
    if IS_MAC:
        return {"os": "macos", "app": home / "Library" / "Application Support" / "Meridian-app", "bin": home / ".local" / "bin",
                "launcher": home / ".local" / "bin" / "meridian", "menu": [home / "Applications" / "Meridian.app"]}
    share = Path(os.environ.get("XDG_DATA_HOME") or home / ".local" / "share")
    return {"os": "linux", "app": share / "meridian-app", "bin": home / ".local" / "bin", "launcher": home / ".local" / "bin" / "meridian",
            "menu": [share / "applications" / "meridian.desktop", share / "icons" / "hicolor" / "scalable" / "apps" / "meridian.svg"]}

def win_user_path(add=None, remove=None):
    """Add or remove a folder in the per-user PATH (HKCU\\Environment). Windows only; needs no administrator."""
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
        try: cur, typ = winreg.QueryValueEx(k, "Path")
        except FileNotFoundError: cur, typ = "", winreg.REG_EXPAND_SZ
        norm = lambda p: os.path.normcase(os.path.normpath(os.path.expandvars(p)))
        parts = [p for p in cur.split(os.pathsep) if p]
        if remove: parts = [p for p in parts if norm(p) != norm(str(remove))]
        if add and not any(norm(p) == norm(str(add)) for p in parts): parts.append(str(add))
        new = os.pathsep.join(parts)
        if new != cur: winreg.SetValueEx(k, "Path", 0, typ, new)
    try:
        import ctypes; ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x1A, 0, "Environment", 2, 5000, None)    # tell running programs about the change
    except (AttributeError, OSError, ImportError): pass

def is_admin():
    """True when raw-socket scans are possible: root on Linux/macOS, an elevated prompt on Windows. None when unknown."""
    if hasattr(os, "geteuid"): return os.geteuid() == 0
    if IS_WIN:
        try:
            import ctypes; return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError, ImportError): return None
    return None

def wait_forever():
    ev = threading.Event()
    while not ev.wait(1.0): pass         # a timeout keeps Ctrl+C working on Windows

# ---------- languages: locales/<code>.json, shared by the web UI and the terminal ----------
_LOC = {}

def load_locales(force=False):
    """{code: {key: text}} from locales/*.json. A missing or broken file is skipped, so one bad translation can never stop Meridian."""
    global _LOC
    if _LOC and not force: return _LOC
    out = {}
    for f in sorted((ROOT / "locales").glob("*.json")):
        if not re.fullmatch(r"[a-z]{2,3}(?:-[A-Za-z]{2,4})?", f.stem): continue
        try: d = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError): continue
        if isinstance(d, dict) and all(isinstance(v, str) for v in d.values()): out[f.stem] = d
    _LOC = out
    return out

def pick_lang(*cands):
    """First candidate ('tr_TR.UTF-8', 'de-AT', 'fr') whose language we have a file for, else English."""
    have = load_locales()
    for c in cands:
        c = str(c or "").replace("_", "-").split(".")[0].split("@")[0].strip().lower()
        for k in (c, c.split("-")[0]):
            for h in have:
                if k and h.lower() == k: return h
    return "en"

def system_langs():
    """Language hints for the terminal. Meridian starts in English on every machine; only an explicit MERIDIAN_LANG (or --lang) changes that."""
    return [os.environ.get("MERIDIAN_LANG", "")]

def T(key, **kw):
    """Message for the terminal in LANG; falls back to English, then to the key itself."""
    loc = load_locales(); s = loc.get(LANG, {}).get(key) or loc.get("en", {}).get(key) or key
    return re.sub(r"\{(\w+)\}", lambda m: str(kw[m.group(1)]) if m.group(1) in kw else m.group(0), s)       # plain {name} substitution only

def locales_js():
    """All languages as one JSON literal for the page (the UI works offline and in the browser-only demo). '</' is escaped so it can never close the script tag."""
    return json.dumps(load_locales(), ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")

# Whitelisted profiles: the user never supplies raw nmap flags (no argument injection).
PROFILES = {
    "ping":    ["-sn"],
    "quick":   ["-T4", "-F"],
    "service": ["-T4", "-sV", "--top-ports", "200"],
    "full":    ["-T4", "-p-", "-sV"],
    "os":      ["-T4", "-sV", "-O", "--top-ports", "200"],
    "trace":   ["-T4", "--top-ports", "20", "--traceroute"],
    "vuln":    ["-T4", "-sV", "--script", "vuln", "--top-ports", "100"],
}
SCRIPTS = {"default", "safe", "vuln", "discovery", "auth", "version", "vulners"}
HIST = app_data_dir() / "history.json"      # HIST.parent is the data folder: history, audit log, trusted devices, browser profile
MAX_JOBS = 100          # finished scans kept in memory
KEEP_XML = 20           # raw nmap XML files kept on disk (the newest scans); older ones are deleted
SCAN_LIMIT = 3600       # seconds; a scan running longer is stopped
MIN_PARSE_GAP = 2.0     # seconds between two parses of the growing XML file (and never when it did not change)
AUDIT_MAX = 1_000_000   # bytes; audit.log is rotated to audit.log.1 above this size, so it cannot grow forever
 
# The UI shows these in the chosen language (by code); the English text stays in the response for scripts and logs.
ERR_CODES = {"Timing must be 0-5": "timing", "Invalid port list": "ports", "Invalid target": "target", "IPv6 targets are not supported yet": "ipv6",
             "Invalid CIDR range": "cidr", "Range too large (max /22)": "range_big", "Invalid IP range": "ip_range", "Enter 1 to 32 targets": "target_count",
             "Too many addresses in total (max 1024)": "addr_total", "Profile/authorization missing": "auth", "Invalid interval": "interval",
             "At most 5 watches": "watch_max", "A scan is already running. Stop it first.": "busy", "Export is empty or too large": "export_size",
             "Unsupported file type": "export_type", "nmap not found. Install it or use demo mode.": "nmap_missing", "nmap not found": "nmap_missing",
             "Could not create the private scratch directory": "scratch", "Stopped: 1 hour limit reached": "time_limit",
             "Invalid device": "device", "Too many devices": "devices_max", "Invalid request": "request", "Invalid AI settings": "ai_settings"}

def err(msg): return {"error": msg, "code": ERR_CODES.get(msg, "")}

def custom_args(o):
    if not isinstance(o, dict): raise ValueError("Invalid request")
    try: t = int(o.get("timing", 4))
    except (TypeError, ValueError, OverflowError): raise ValueError("Timing must be 0-5")
    if not 0 <= t <= 5: raise ValueError("Timing must be 0-5")
    a = [f"-T{t}"]
    ports = str(o.get("ports", "")).strip()
    if ports:
        if not re.fullmatch(r"[0-9,\-]{1,120}", ports): raise ValueError("Invalid port list")
        a += ["-p", ports]
    for k, f in (("sv", "-sV"), ("os", "-O"), ("pn", "-Pn"), ("sn", "-sn")):
        if o.get(k) is True: a.append(f)
    # "vulners" is NOT accepted here: it contacts a third party, so it only runs through the confirmed lookup (scan_args), always with its safe arguments
    sc = [x for x in (o.get("scripts") if isinstance(o.get("scripts"), list) else []) if isinstance(x, str) and x in SCRIPTS and x != "vulners"]
    if sc: a += ["--script", ",".join(sc)]
    return a
 
def add_script(a, name):
    """Add an NSE script to a nmap argument list (merging into an existing --script)."""
    a = list(a)
    if "--script" in a:
        i = a.index("--script") + 1
        if name not in a[i].split(","): a[i] += "," + name
    else: a += ["--script", name]
    return a
 
def scan_args(profile, options=None, lookup=False, offline=False):
    """Final nmap arguments. With lookup=True every port-scanning profile also detects versions and runs the vulners NSE
    script, which turns a software name + version into CVEs and known exploits. offline=True only needs the versions (the hints are
    matched locally, nothing is sent anywhere). Host discovery (-sn) is left alone."""
    a = custom_args(options or {}) if profile == "custom" else list(PROFILES[profile])
    if not (lookup or offline) or "-sn" in a: return a
    if "-sV" not in a:
        if profile == "custom": return a        # the user switched version detection off: nothing to look up
        a += ["-sV", "--version-light"]
    if not lookup: return a
    # paths=none: do not probe ~900 web paths on the target. max_items=0: never spend API credits (smart audit).
    return add_script(a, "vulners") + ["--script-args", "vulners.paths=none,vulners.max_items=0"]
 
def _num(x):
    try: v = float(x)
    except (TypeError, ValueError): return None
    return v if math.isfinite(v) else None
 
def safe_url(u):
    u = (u or "").strip()
    return u[:300] if u.startswith("https://") else ""
 
def cvss_sev(c):
    return "" if c is None else "critical" if c >= 9 else "high" if c >= 7 else "medium" if c >= 4 else "low"
 
def parse_vulners(sc, limit=15):
    """<script id="vulners"> (nmap-vulners 1.x and 2.x) -> summary dict with the top findings, or None when it holds none."""
    mode = next(((e.text or "").strip() for e in sc.findall("elem") if e.get("key") == "mode"), "")
    items = []
    for cpe_t in sc.findall("table"):
        for ft in cpe_t.findall("table"):
            f = {e.get("key"): (e.text or "").strip() for e in ft.findall("elem") if e.get("key")}
            if not f.get("id"): continue
            flag = lambda k: f.get(k, "").lower() == "true"
            cvss = _num(f.get("cvss"))
            items.append({"id": f["id"][:80], "type": f.get("type", "")[:24], "cvss": cvss,
                          "sev": (f.get("severity") or cvss_sev(cvss)).lower()[:10],
                          "kev": flag("kev"), "active": f.get("exploitation", "").lower() == "active",
                          "exploit": flag("is_exploit") or flag("exploit_known"),
                          "epss": _num(f.get("epss")), "ai": _num(f.get("ai_score")),
                          "title": f.get("title", "")[:160], "href": safe_url(f.get("href")), "src": safe_url(f.get("source_href")),
                          "cpe": (cpe_t.get("key") or "")[:120]})
    return _vsum(items, mode, limit) if items else None

def _vsum(items, mode, limit=15, extra=0):
    """Sorted summary of findings for one port. extra = findings that were counted before but are not in `items` any more."""
    # facts outrank predictions: actively exploited, then public exploit, then likelihood; CVSS breaks ties
    items = sorted(items, key=lambda i: (i["kev"], i["active"], i["exploit"], i["epss"] if i["epss"] is not None else (i["ai"] or 0) / 10, i["cvss"] or 0), reverse=True)
    return {"mode": mode, "total": len(items) + extra, "cves": sum(i["id"].upper().startswith("CVE-") for i in items) + extra,
            "exploits": sum(i["exploit"] for i in items), "kev": sum(i["kev"] for i in items), "items": items[:limit]}

def _vt(s):
    """'2.4.49' -> (2, 4, 49); '9.2p1 Debian' -> (9, 2); () when the text starts with no number."""
    m = re.match(r"\s*(\d+(?:\.\d+)*)", s or "")
    return tuple(int(x) for x in m.group(1).split(".")) if m else ()

# Offline hints: a SMALL list of very well known vulnerable releases, matched on the detected product + version text. Nothing leaves the machine.
# (product regex, version test(v tuple, version text), id, cvss, severity, public exploit, English title). Not a database; the vulners lookup is the broad one.
OFFLINE_RULES = [
    (r"vsftpd", lambda v, s: v == (2, 3, 4), "CVE-2011-2523", 9.8, "critical", True, "vsftpd 2.3.4 has a backdoor: a smiley in the user name opens a root shell"),
    (r"apache httpd", lambda v, s: v == (2, 4, 49), "CVE-2021-41773", 7.5, "high", True, "Apache 2.4.49 path traversal, can lead to remote code execution"),
    (r"apache httpd", lambda v, s: v == (2, 4, 50), "CVE-2021-42013", 9.8, "critical", True, "Apache 2.4.50 incomplete fix: path traversal and remote code execution"),
    (r"openssh", lambda v, s: bool(v) and v <= (7, 7), "CVE-2018-15473", 5.3, "medium", True, "OpenSSH 7.7 and older reveals which user names exist"),
    (r"samba", lambda v, s: (3, 5, 0) <= v < (4, 4, 14) or (4, 5, 0) <= v < (4, 5, 10) or (4, 6, 0) <= v < (4, 6, 4), "CVE-2017-7494", 9.8, "critical", True, "Samba 'SambaCry': remote code execution through a writable share"),
    (r"exim", lambda v, s: (4, 87) <= v <= (4, 91), "CVE-2019-10149", 9.8, "critical", True, "Exim 4.87 to 4.91: remote command execution"),
    (r"openssl", lambda v, s: re.fullmatch(r"1\.0\.1[a-f]?", s) is not None, "CVE-2014-0160", 7.5, "high", True, "OpenSSL 1.0.1 to 1.0.1f 'Heartbleed': memory contents can be read remotely"),
    (r"unrealircd", lambda v, s: s == "3.2.8.1", "CVE-2010-2075", None, "critical", True, "UnrealIRCd 3.2.8.1 contains a backdoor"),
    (r"proftpd", lambda v, s: s == "1.3.5", "CVE-2015-3306", None, "high", True, "ProFTPD 1.3.5 mod_copy lets anyone copy files without logging in"),
]

def offline_items(product, version):
    """Findings of the offline list for one detected product + version (empty list when nothing matches)."""
    prod, ver = (product or "").lower(), (version or "").strip()
    if not ver: return []
    v = _vt(ver)
    return [{"id": id_, "type": "cve", "cvss": cvss, "sev": sev, "kev": False, "active": False, "exploit": ex, "epss": None, "ai": None, "title": title,
             "href": f"https://vulners.com/cve/{id_}", "src": f"https://nvd.nist.gov/vuln/detail/{id_}", "cpe": "", "offline": True}
            for rx, test, id_, cvss, sev, ex, title in OFFLINE_RULES if re.search(rx, prod) and test(v, ver)]

def attach_offline(hosts):
    """Add offline hints to every open port; merges with what the online lookup already found (the same id is kept once)."""
    for h in hosts:
        for p in h["ports"]:
            items, old = offline_items(p.get("product", ""), p.get("vnum", "")), p.get("vulns")
            if old:
                ids = {i["id"] for i in old["items"]}; items = [i for i in items if i["id"] not in ids]
                if items: p["vulns"] = _vsum(old["items"] + items, old["mode"] + "+offline", extra=old["total"] - len(old["items"]))
            elif items: p["vulns"] = _vsum(items, "offline")
    return hosts
 
def _owners():
    """Users allowed to own our directories: ourselves, plus the real user when started with sudo."""
    me = os.geteuid() if hasattr(os, "geteuid") else None
    sudo = os.environ.get("SUDO_UID", "")
    return {me} | ({int(sudo)} if me == 0 and sudo.isdigit() else set())

def _chown_sudo(path):
    """Started with sudo: hand a file we created to the real user, so a later normal run can still use it."""
    if hasattr(os, "geteuid") and os.geteuid() == 0 and os.environ.get("SUDO_UID", "").isdigit():
        try: os.chown(path, int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID") or os.environ["SUDO_UID"]))
        except OSError: pass

def private_dir(p, fix=False):
    """Create (if needed) and verify a directory that only we can use. A symlink or a directory owned by somebody else is refused (CWE-59/377).
    fix=True tightens the mode of our own directory to 0700 instead of refusing it."""
    p = Path(p)
    try: os.mkdir(p, 0o700)
    except FileExistsError: pass
    st = os.lstat(p)    # lstat: a symlink is not a directory here
    if not stat.S_ISDIR(st.st_mode) or (hasattr(os, "geteuid") and st.st_uid not in _owners()): raise OSError(f"Unsafe directory: {p}")
    if st.st_mode & 0o077 and not IS_WIN:       # Windows reports fake mode bits; a folder in the user profile is private by its ACL
        if not fix: raise OSError(f"Directory is open to other users: {p}")
        os.chmod(p, 0o700)
    return p

def data_dir():
    HIST.parent.parent.mkdir(parents=True, exist_ok=True)
    d = private_dir(HIST.parent, fix=True); _chown_sudo(d)
    return d

def runtime_base():
    """Where the per-run scratch directory lives: /run for root, $XDG_RUNTIME_DIR (a private tmpfs, nothing reaches the disk) for users, else the system temp dir."""
    if hasattr(os, "geteuid") and os.geteuid() == 0 and Path("/run").is_dir(): return Path("/run")
    x = os.environ.get("XDG_RUNTIME_DIR")
    if x:
        try: private_dir(x); return Path(x)
        except OSError: pass
    return Path(tempfile.gettempdir())

class Workspace:
    """Private scratch directory of ONE Meridian process. mkdtemp gives a random name and mode 0700 atomically, which removes the predictable-name
    and symlink race of a fixed /tmp/meridian-<id>.xml (CWE-377). Files inside are created exclusively (O_EXCL, no symlinks) with mode 0600."""
    def __init__(self, base=None):
        self.path = Path(tempfile.mkdtemp(prefix=f"meridian-run-{os.getpid()}-", dir=base or runtime_base()))
        private_dir(self.path)
    def new_file(self, name):
        p = self.path / name
        return os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600), p
    def contains(self, p):
        try: return Path(p).resolve().parent == self.path.resolve()
        except OSError: return False
    def tail(self, p, n=300):
        try: return Path(p).read_text(encoding="utf-8", errors="ignore")[-n:]
        except OSError: return ""
    def destroy(self): shutil.rmtree(self.path, ignore_errors=True)

def _cmdline(pid):
    """Command line of a process, or '' when it cannot be read. Linux: /proc. macOS/BSD: ps. Windows: not available."""
    try: return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="ignore")
    except OSError: pass
    if not IS_WIN:
        try: return subprocess.run(["ps", "-p", str(int(pid)), "-o", "command="], capture_output=True, text=True, timeout=3).stdout.strip()
        except (OSError, ValueError, subprocess.SubprocessError): pass
    return ""

def pid_alive(pid):
    """Is there a process with this id? (A live Meridian's scratch directory must never be swept.)"""
    try: pid = int(pid)
    except (TypeError, ValueError): return False
    if pid <= 0: return False
    if IS_WIN:
        try:
            import ctypes
            k = ctypes.windll.kernel32; h = k.OpenProcess(0x1000, False, pid)         # PROCESS_QUERY_LIMITED_INFORMATION
            if not h: return False
            code = ctypes.c_ulong(); ok = k.GetExitCodeProcess(h, ctypes.byref(code)); k.CloseHandle(h)
            return bool(ok) and code.value == 259                                      # STILL_ACTIVE
        except (AttributeError, OSError, ImportError): return True                     # unknown: assume alive, never delete a live run's files
    try: os.kill(pid, 0)
    except ProcessLookupError: return False
    except PermissionError: return True
    except OSError: return False
    return True

def find_nmap():
    """The nmap executable: MERIDIAN_NMAP, then PATH, then where installers put it when PATH is not set up (Windows installer, Homebrew)."""
    o = os.environ.get("MERIDIAN_NMAP")
    if o and Path(o).is_file(): return o
    p = shutil.which("nmap")
    if p or not (IS_WIN or IS_MAC): return p
    if IS_WIN: cands = [Path(os.environ[v]) / "Nmap" / "nmap.exe" for v in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA") if os.environ.get(v)]
    else: cands = [Path(x) / "nmap" for x in ("/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin")]
    return next((str(c) for c in cands if c.is_file()), None)

def popen_flags():
    """Own process group for every nmap, so one signal reaches nmap and anything it started (POSIX: new session; Windows: new group, no console window)."""
    if IS_WIN: return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    return {"start_new_session": True}

def sweep_stale(base=None):
    """After a crash (kill -9, power loss) an old run may have left an nmap process and its scratch directory behind. Stop that nmap (only if
    its command line still names the directory) and delete the directory. Directories of Meridian processes that are still alive are left alone."""
    base = Path(base) if base else runtime_base()
    for d in base.glob("meridian-run-*"):
        m = re.fullmatch(r"meridian-run-(\d+)-\w+", d.name)
        try:
            st = os.lstat(d)
            if not m or not stat.S_ISDIR(st.st_mode) or (hasattr(os, "geteuid") and st.st_uid not in _owners()) or int(m.group(1)) == os.getpid(): continue
            if pid_alive(m.group(1)):
                cmd = _cmdline(m.group(1))
                if not cmd or "server.py" in cmd or "meridian" in cmd.lower(): continue    # that Meridian is still running (or we cannot tell: keep its files)
            try:
                pid = int((d / "nmap.pid").read_text(encoding="utf-8").strip())
                if hasattr(os, "killpg") and str(d) in _cmdline(pid):
                    os.killpg(pid, signal.SIGTERM); time.sleep(0.3)
                    if str(d) in _cmdline(pid): os.killpg(pid, signal.SIGKILL)
            except (OSError, ValueError, ProcessLookupError): pass
            shutil.rmtree(d, ignore_errors=True)
        except OSError: continue

class Busy(Exception): pass

class ScanManager:
    """Singleton (one per process) that owns everything a scan needs: the job table, the single scan slot, the private workspace and every nmap child.
    All starts go through submit(), so the one-scan-at-a-time rule holds for the web UI and the watcher alike, with no check-then-start race."""
    _instance, _guard = None, threading.Lock()
    def __new__(cls):
        with cls._guard:
            if cls._instance is None:
                o = super().__new__(cls); o.lock = threading.RLock(); o.ws = None; cls._instance = o
            return cls._instance
    def jobs(self):
        with self.lock: return list(JOBS.values())
    def workspace(self):
        with self.lock:
            if self.ws is None: self.ws = Workspace()
            return self.ws
    def submit(self, target, profile, args, demo=False, lookup=False, audit_line=None, offline=False):
        with self.lock:
            if any(j["status"] == "running" for j in JOBS.values()): raise Busy("A scan is already running. Stop it first.")
            jid = uuid.uuid4().hex[:8]; xml = ""
            if not demo:
                fd, p = self.workspace().new_file(f"{jid}.xml"); os.close(fd); xml = str(p)
            JOBS[jid] = {"status": "running", "hosts": [], "error": "", "target": target, "profile": profile, "id": jid, "ts": time.time(),
                         "t0": time.time(), "demo": demo, "lookup": lookup, "offline": offline, "xml": xml}
            job = JOBS[jid]
        if audit_line: audit(audit_line(jid))
        threading.Thread(target=run, args=(job, args), daemon=True).start()
        return jid
    def stop(self, jid):
        j = JOBS.get(jid)
        if not j: return False
        with self.lock:
            if j["status"] == "running": j["status"] = "stopped"
            p = j.get("proc")
        if p: self._signal(p, signal.SIGTERM)     # the scan thread escalates to SIGKILL and reaps the process
        return True
    @staticmethod
    def _signal(p, sig):
        if p.poll() is not None: return
        try:
            if IS_WIN: subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
                                      creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))        # the whole process tree
            elif hasattr(os, "killpg"): os.killpg(p.pid, sig)        # the whole process group: nmap and anything it started
            else: p.send_signal(sig)
        except (ProcessLookupError, PermissionError, OSError, subprocess.SubprocessError):
            if IS_WIN:
                try: p.kill()
                except OSError: pass
    def _terminate(self, p, grace=5):
        """TERM, then KILL, then wait(): the child is always reaped, so no zombie stays behind."""
        for sig in (signal.SIGTERM, getattr(signal, "SIGKILL", signal.SIGTERM)):
            if p.poll() is not None: break
            self._signal(p, sig)
            try: p.wait(timeout=grace)
            except subprocess.TimeoutExpired: pass
        try: p.wait(timeout=2)
        except subprocess.TimeoutExpired: pass
    def execute(self, job, args):
        try:
            if job["demo"]: self._demo(job)
            else: self._nmap(job, args)
        except Exception as e:
            with self.lock: job["status"], job["error"], job["error_code"] = "error", str(e)[:300], ERR_CODES.get(str(e), "")
        finally:
            with self.lock:
                if job["status"] == "running": job["status"] = "done"
                job["dur"] = int(time.time() - job["t0"]); job.pop("proc", None)
            save_history(); self._prune()
    def _demo(self, job):
        for k in range(1, 7):
            time.sleep(1.2)
            if job["status"] != "running": break
            job["hosts"] = demo(job.get("lookup"), job.get("offline"))[:k]
    def _nmap(self, job, args):
        nmap = find_nmap()
        if not nmap: raise RuntimeError("nmap not found")
        ws = self.workspace(); efd, errp = ws.new_file(f"{job['id']}.err")      # stderr goes to a file: a full pipe can never block nmap
        try:
            p = subprocess.Popen([nmap, *args, "-oX", job["xml"], *job["target"].split()], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=efd, close_fds=True, **popen_flags())   # own process group: one signal reaches nmap and its children
        finally: os.close(efd)
        job["proc"] = p
        try: (ws.path / "nmap.pid").write_text(str(p.pid), encoding="utf-8")      # lets the next start find an orphan after a crash (sweep_stale)
        except OSError: pass
        deadline, seen, last, gap = time.monotonic() + SCAN_LIMIT, None, 0.0, MIN_PARSE_GAP
        try:
            while True:
                try: p.wait(timeout=1.0); break      # wakes up the moment nmap exits, no busy polling
                except subprocess.TimeoutExpired: pass
                if job["status"] != "running": break     # stopped by the user
                if time.monotonic() > deadline:
                    job["status"], job["error"], job["error_code"] = "stopped", "Stopped: 1 hour limit reached", "time_limit"; break
                try: st = os.stat(job["xml"]); sig = (st.st_size, st.st_mtime_ns)
                except OSError: sig = None
                if sig != seen and time.monotonic() - last >= gap:       # parse only when nmap wrote something new, and not too often
                    t = time.monotonic(); hosts = self._read(job)
                    if hosts: job["hosts"] = hosts
                    seen, last = sig, time.monotonic(); gap = max(MIN_PARSE_GAP, 4 * (last - t))    # a slow parse backs the polling off
        finally:
            self._terminate(p)       # nothing to do when nmap already exited; otherwise TERM -> KILL -> wait()
            try: (ws.path / "nmap.pid").unlink()
            except OSError: pass
        hosts = self._read(job)
        if hosts: job["hosts"] = hosts
        with self.lock:
            if job["status"] == "running":
                job["status"] = "done" if p.returncode == 0 else "error"
                if p.returncode: job["error"] = ws.tail(errp)
        try: os.unlink(errp)
        except OSError: pass
    @staticmethod
    def _read(job):
        """Parse the nmap XML of a job; with offline hints on, the hints are matched locally on the parsed ports."""
        hosts = parse(job["xml"])
        if hosts and job.get("offline"): attach_offline(hosts)
        return hosts
    def _prune(self):
        """Bounded memory and disk: keep the newest MAX_JOBS finished scans and the XML of the newest KEEP_XML ones."""
        with self.lock:
            done = sorted((j for j in JOBS.values() if j["status"] != "running"), key=lambda j: j["ts"])
            for j in done[:-MAX_JOBS] if len(done) > MAX_JOBS else []:
                JOBS.pop(j["id"], None)
            with_xml = [j for j in done if j.get("xml")]
            for j in with_xml[:-KEEP_XML] if len(with_xml) > KEEP_XML else []:
                try: os.unlink(j["xml"])
                except OSError: pass
                j["xml"] = ""
    def shutdown(self):
        """Stop every nmap we started and delete the scratch directory (runs at exit and on SIGTERM/SIGHUP)."""
        with self.lock:
            for j in list(JOBS.values()):
                p = j.get("proc")
                if p and p.poll() is None:
                    j["status"] = "stopped"; self._terminate(p, grace=2)
            if self.ws: self.ws.destroy(); self.ws = None

MANAGER = ScanManager()

def _atomic_json(path, obj):
    """Atomic: write a private temp file next to the target, fsync, then rename over it. A crash can never leave half a file."""
    fd, tmp = tempfile.mkstemp(dir=Path(path).parent, prefix=".tmp-", suffix=".json")     # mode 0600, random name
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f: json.dump(obj, f); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try: os.unlink(tmp)
        except OSError: pass
        raise
    _chown_sudo(path)

def save_history():
    """Atomic: see _atomic_json. A crash can never leave half a history file."""
    try:
        d = data_dir()
        keep = [{k: j[k] for k in ("id", "target", "profile", "hosts", "ts", "dur")} for j in MANAGER.jobs() if j["status"] in ("done", "stopped") and "dur" in j]
        _atomic_json(HIST, keep[-50:])
    except (OSError, TypeError, ValueError): pass

def _s(x, n): return str(x if x is not None else "")[:n]
def _i(x, lo, hi, d=0):
    v = _num(x)
    return d if v is None else int(min(max(v, lo), hi))

def clean_item(i):
    o = {"id": _s(i.get("id"), 80), "type": _s(i.get("type"), 24), "cvss": _num(i.get("cvss")), "sev": _s(i.get("sev"), 10).lower(), "kev": i.get("kev") is True,
         "active": i.get("active") is True, "exploit": i.get("exploit") is True, "epss": _num(i.get("epss")), "ai": _num(i.get("ai")), "title": _s(i.get("title"), 160),
         "href": safe_url(i.get("href")), "src": safe_url(i.get("src")), "cpe": _s(i.get("cpe"), 120)}
    if i.get("offline") is True: o["offline"] = True
    return o

def clean_vulns(v):
    if not isinstance(v, dict) or not isinstance(v.get("items"), list): return None
    return {"mode": _s(v.get("mode"), 20), "total": _i(v.get("total"), 0, 100000), "cves": _i(v.get("cves"), 0, 100000), "exploits": _i(v.get("exploits"), 0, 100000),
            "kev": _i(v.get("kev"), 0, 100000), "items": [clean_item(i) for i in v["items"][:50] if isinstance(i, dict)]}

def clean_hosts(hosts):
    """Rebuild host records from untrusted JSON (history.json) with exactly the fields, types and sizes the UI expects, so a tampered file cannot inject markup or break the page."""
    out = []
    for h in hosts[:2048]:
        if not isinstance(h, dict): continue
        ports = []
        for p in (h.get("ports") if isinstance(h.get("ports"), list) else [])[:2000]:
            if not isinstance(p, dict): continue
            q = {"port": _i(p.get("port"), 0, 65535), "proto": _s(p.get("proto"), 8), "product": _s(p.get("product"), 120), "vnum": _s(p.get("vnum"), 120), "service": _s(p.get("service"), 60),
                 "version": _s(p.get("version"), 240), "ver": p.get("ver") is True,
                 "cpes": [_s(c, 120) for c in (p.get("cpes") if isinstance(p.get("cpes"), list) else [])[:4]],
                 "scripts": [{"id": _s(x.get("id"), 80), "out": _s(x.get("out"), 1500)} for x in (p.get("scripts") if isinstance(p.get("scripts"), list) else [])[:50] if isinstance(x, dict)]}
            vz = clean_vulns(p.get("vulns"))
            if vz: q["vulns"] = vz
            ports.append(q)
        out.append({"ip": _s(h.get("ip"), 64), "mac": _s(h.get("mac"), 17), "vendor": _s(h.get("vendor"), 80), "name": _s(h.get("name"), 253), "os": _s(h.get("os"), 120),
                    "ports": ports, "vuln": h.get("vuln") is True, "hops": [_s(x, 64) for x in (h.get("hops") if isinstance(h.get("hops"), list) else [])[:64]]})
    return out

def clean_job(j):
    return {"id": j["id"], "target": _s(j.get("target"), 100), "profile": _s(j.get("profile"), 20), "hosts": clean_hosts(j["hosts"]), "ts": _num(j.get("ts")) or 0.0, "dur": _i(j.get("dur"), 0, 10**7)}

def load_history():
    try:
        if HIST.stat().st_size > 20_000_000: return
        for j in json.loads(HIST.read_text(encoding="utf-8")):
            if isinstance(j, dict) and re.fullmatch(r"[0-9a-f]{8}", str(j.get("id", ""))) and isinstance(j.get("hosts"), list):
                JOBS[j["id"]] = clean_job(j) | {"status": "done", "error": "", "t0": 0, "demo": False, "xml": ""}
    except (OSError, ValueError, KeyError, TypeError): pass
 
DEVICE_KEY = re.compile(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}|ip:\d{1,3}(?:\.\d{1,3}){3}")
MAX_DEVICES = 500
DEV_LOCK = threading.Lock()

def device_key(h):
    """Stable id of a device: its MAC address when nmap saw one (needs root/admin on a LAN), else its IP address."""
    mac = (h.get("mac") or "").upper()
    return mac if re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", mac) else "ip:" + str(h.get("ip"))

def clean_label(x): return re.sub(r"[\x00-\x1f\x7f]", "", str(x or ""))[:40].strip()

def load_devices():
    """The trusted-device list {key: {"trusted": bool, "label": str}}. Anything unreadable or malformed is ignored."""
    p = HIST.parent / "devices.json"
    try:
        if p.stat().st_size > 1_000_000: return {}
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError): return {}
    if not isinstance(raw, dict): return {}
    return {k: {"trusted": v.get("trusted") is True, "label": clean_label(v.get("label"))}
            for k, v in raw.items() if isinstance(v, dict) and DEVICE_KEY.fullmatch(str(k))}

def update_devices(d):
    """POST /api/devices. {"key", "trusted"?, "label"?} changes one device; {"trust": [keys]} trusts all of them (baseline); {"clear": true} forgets all."""
    if not isinstance(d, dict): raise ValueError("Invalid device")
    with DEV_LOCK:
        devs = load_devices()
        def entry(k):
            if not isinstance(k, str) or not DEVICE_KEY.fullmatch(k): raise ValueError("Invalid device")
            return devs.setdefault(k, {"trusted": False, "label": ""})
        if d.get("clear") is True: devs = {}
        elif isinstance(d.get("trust"), list):
            if len(d["trust"]) > MAX_DEVICES: raise ValueError("Too many devices")
            for k in d["trust"]: entry(k)["trusted"] = True
        else:
            e = entry(d.get("key"))
            if "trusted" in d: e["trusted"] = d["trusted"] is True
            if "label" in d: e["label"] = clean_label(d["label"])
            if not e["trusted"] and not e["label"]: devs.pop(d["key"], None)       # nothing worth remembering
        if len(devs) > MAX_DEVICES: raise ValueError("Too many devices")
        data_dir(); _atomic_json(HIST.parent / "devices.json", devs)
    audit(f"devices updated: {sum(v['trusted'] for v in devs.values())} trusted of {len(devs)}")
    return devs

HOST_RE = re.compile(r"^(?=.*[A-Za-z])[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")
RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$")  # 192.168.1.10-50
MAX_ADDRS = 1024  # a /22
 
def target_size(t):
    """Validate ONE target (IPv4, CIDR, last-octet range or hostname) and return how many addresses it covers."""
    t = (t or "").strip()
    if not t or len(t) > 253 or t.startswith("-"): raise ValueError("Invalid target")
    if ":" in t: raise ValueError("IPv6 targets are not supported yet")
    if "/" in t:
        try: n = ipaddress.ip_network(t, strict=False)
        except ValueError: raise ValueError("Invalid CIDR range")
        if n.num_addresses > MAX_ADDRS: raise ValueError("Range too large (max /22)")
        return n.num_addresses
    m = RANGE_RE.match(t)
    if m:
        try: ipaddress.ip_address(f"{m.group(1)}.{m.group(2)}")
        except ValueError: raise ValueError("Invalid IP range")
        lo, hi = int(m.group(2)), int(m.group(3))
        if hi > 255 or hi < lo: raise ValueError("Invalid IP range")
        return hi - lo + 1
    try: ipaddress.ip_address(t); return 1
    except ValueError: pass
    if HOST_RE.match(t): return 1
    raise ValueError("Invalid target")
 
def valid_target(t):
    target_size(t); return t.strip()
 
def is_public(t):
    """True for anything that is not a private/loopback/link-local IPv4 target (hostnames count as public)."""
    try:
        m = RANGE_RE.match(t)
        nets = [ipaddress.ip_network(f"{m.group(1)}.{m.group(i)}") for i in (2, 3)] if m else [ipaddress.ip_network(t, strict=False)]
        return not all(n.is_private or n.is_loopback or n.is_link_local for n in nets)
    except ValueError:
        return True
 
def valid_targets(t):
    """Space/comma separated list: 1 to 32 targets, at most 1024 addresses in total."""
    parts = re.split(r"[\s,]+", (t or "").strip())
    if not parts or len(parts) > 32 or "" in parts: raise ValueError("Enter 1 to 32 targets")
    if sum(target_size(p) for p in parts) > MAX_ADDRS: raise ValueError("Too many addresses in total (max 1024)")
    return " ".join(p.strip() for p in parts)
 
def any_public(t): return any(is_public(x) for x in t.split())
 
SAVE_EXT = {".json", ".csv", ".md", ".html", ".xml", ".txt"}
MAX_SAVE = 8 * 1024 * 1024
 
def downloads_dir():
    """The user's download folder (XDG setting, else ~/Downloads), created if missing. Always inside the home directory."""
    home, d = Path.home(), None
    try:
        for line in (home / ".config" / "user-dirs.dirs").read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("XDG_DOWNLOAD_DIR="): d = Path(os.path.expandvars(line.split("=", 1)[1].strip().strip('"')))
    except OSError: pass
    if d is None or home.resolve() not in d.resolve().parents: d = home / "Downloads"
    d.mkdir(parents=True, exist_ok=True)
    return d
 
def save_export(d):
    """Write an export straight into the download folder, so no browser download window is needed. Returns {"path": ...}."""
    name = str(d.get("name", "")); ext = Path(name).suffix.lower(); data = d.get("data")
    if ext not in SAVE_EXT: raise ValueError("Unsupported file type")
    if not isinstance(data, str) or len(data) > MAX_SAVE: raise ValueError("Export is empty or too large")
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).stem)[:40].strip("._") or "meridian"
    base, k = f"{stem}-{time.strftime('%Y%m%d-%H%M%S')}", 0
    folder = downloads_dir()
    while True:
        dest = folder / f"{base}{'-' + str(k) if k else ''}{ext}"
        try: fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600); break
        except FileExistsError: k += 1
    with os.fdopen(fd, "w", encoding="utf-8") as f: f.write(data)
    _chown_sudo(dest)       # started with sudo: give the file to the real user
    audit(f"export saved {dest.name} ({len(data)} chars)")
    return {"path": str(dest)}
 
def local_cidr():
    """Best-effort guess of the local /24. A UDP connect sends no packet: it only asks the OS which interface it would use."""
    ip = None
    for dest in (("10.255.255.255", 1), ("192.0.2.1", 9)):
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: sk.connect(dest); ip = sk.getsockname()[0]
        except OSError: ip = None
        finally: sk.close()
        if ip and not ip.startswith("127.") and ip != "0.0.0.0": break
        ip = None
    if not ip:      # no default route (Wi-Fi just reconnecting, some VPNs): ask the host name instead
        try: ip = next(x for x in socket.gethostbyname_ex(socket.gethostname())[2] if not x.startswith("127."))
        except (OSError, StopIteration): ip = None
    try: return str(ipaddress.ip_network(ip + "/24", strict=False)) if ip else "192.168.1.0/24"
    except ValueError: return "192.168.1.0/24"

def audit(msg):
    """Append-only local audit trail of every scan that was started. Never follows a symlink, rotates at AUDIT_MAX."""
    try:
        d = data_dir(); p = d / "audit.log"
        try:
            if p.stat().st_size > AUDIT_MAX: os.replace(p, d / "audit.log.1")
        except FileNotFoundError: pass
        fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f: f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + re.sub(r"[\r\n]+", " ", msg) + "\n")
        _chown_sudo(p)
    except OSError: pass
 

# ---- optional AI analysis (off by default; see ai.py). The page never talks to an AI: this server does, with data it builds itself. ----
AI_RESULTS, CONSENTS, CONSENT_TTL = {}, {}, 300
AI_ERR_STATUS = {"ai_busy": 409, "ai_http": 502, "ai_unreachable": 502, "ai_badjson": 502}

def ai_config():
    try: d = json.loads((data_dir() / "ai.json").read_text(encoding="utf-8"))
    except (OSError, ValueError): d = {}
    if not isinstance(d, dict): d = {}
    pv = d.get("provider") if d.get("provider") in ai.PROVIDERS else ""
    model = d.get("model") if isinstance(d.get("model"), str) and ai.MODEL_RE.match(d["model"]) else ""
    port = d.get("port") if isinstance(d.get("port"), int) and 1024 <= d["port"] <= 65535 else None
    return {"provider": pv, "model": model, "port": port or ai.LOCAL.get(pv, 11434)}

def ai_key():
    k = os.environ.get("MERIDIAN_AI_KEY", "").strip()
    if k: return k, "env"
    try: return (data_dir() / "ai.key").read_text(encoding="utf-8").strip(), "file"
    except OSError: return "", ""

def ai_write_key(k):
    p = data_dir() / "ai.key"
    if not k:
        try: p.unlink()
        except OSError: pass
        return
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".tmp-", suffix=".key")      # private (0600) from the start
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f: f.write(k)
        os.replace(tmp, p)
    except BaseException:
        try: os.unlink(tmp)
        except OSError: pass
        raise
    _chown_sudo(p)

def ai_status():
    c = ai_config(); k, src = ai_key()
    return {"provider": c["provider"], "model": c["model"], "port": c["port"], "default_model": ai.DEFAULT_MODEL.get(c["provider"], ""), "cloud": ai.is_cloud(c["provider"]),
            "key": bool(k), "key_src": src, "providers": list(ai.PROVIDERS), "models": ai.list_local_models(c["provider"], c["port"]) if c["provider"] in ai.LOCAL else []}

def ai_set_config(d):
    """POST /api/ai/config. {"provider": ""|one of ai.PROVIDERS, "model"?, "port"?, "key"? (stored in a private file, never sent back), "clear_key"?: true}"""
    c = ai_config()
    if "provider" in d:
        if d["provider"] not in ("",) + ai.PROVIDERS: raise ValueError("Invalid AI settings")
        c["provider"] = d["provider"]; c["port"] = ai.LOCAL.get(c["provider"], 11434)
    if "model" in d:
        m = str(d["model"] or "").strip()
        if m and not ai.MODEL_RE.match(m): raise ValueError("Invalid AI settings")
        c["model"] = m
    if "port" in d and c["provider"] in ai.LOCAL:
        if not isinstance(d["port"], int) or isinstance(d["port"], bool) or not 1024 <= d["port"] <= 65535: raise ValueError("Invalid AI settings")
        c["port"] = d["port"]
    if d.get("clear_key") is True: ai_write_key("")
    elif "key" in d:
        k = str(d["key"] or "").strip()
        if not k or len(k) > 300 or re.search(r"\s|[\x00-\x1f]", k): raise ValueError("Invalid AI settings")
        ai_write_key(k)
    _atomic_json(data_dir() / "ai.json", {"provider": c["provider"], "model": c["model"], "port": c["port"]})
    audit(f"ai settings provider={c['provider'] or 'off'} model={c['model'] or 'default'} key={'set' if ai_key()[0] else 'none'}")
    return ai_status()

def ai_prepare(d):
    """Everything the AI call needs, from the server's own scan result (never from the browser). Returns (cfg, model, key, payload, labels)."""
    c = ai_config()
    if not c["provider"]: raise ai.AIError("ai_off")
    j = JOBS.get(str(d.get("id", "")))
    if not j or not re.fullmatch(r"[0-9a-f]{8}", str(d.get("id", ""))): raise ai.AIError("ai_nodata")
    if j.get("status") == "running": raise ai.AIError("ai_running")
    lang = d.get("lang") if d.get("lang") in ai.LANG_NAMES else "en"
    payload, labels = ai.build_payload(j.get("hosts") or [], lang)
    if not any(h["ports"] for h in payload["hosts"]): raise ai.AIError("ai_nodata")
    key = ai_key()[0]
    if ai.is_cloud(c["provider"]) and not key: raise ai.AIError("ai_nokey")
    model = c["model"] or ai.DEFAULT_MODEL.get(c["provider"], "")
    if not model: raise ai.AIError("ai_nomodel")
    return c, model, key, payload, labels

def ai_preview(d):
    c, model, key, payload, labels = ai_prepare(d)
    out = {"provider": c["provider"], "model": model, "cloud": ai.is_cloud(c["provider"]), "payload": payload}
    if out["cloud"]:      # the confirmation covers exactly this data, this provider and this one request
        now = time.time()
        for t in [t for t, v in CONSENTS.items() if v[1] < now]: CONSENTS.pop(t, None)
        if len(CONSENTS) > 20: CONSENTS.clear()
        tok = secrets.token_urlsafe(16); CONSENTS[tok] = (ai.digest(c["provider"], model, payload), now + CONSENT_TTL); out["consent"] = tok
    return out

def ai_analyze(d):
    c, model, key, payload, labels = ai_prepare(d)
    cloud = ai.is_cloud(c["provider"])
    if cloud:
        want = CONSENTS.pop(str(d.get("consent", "")), None)
        if not want or want[1] < time.time() or not _eq(want[0], ai.digest(c["provider"], model, payload)): raise ai.AIError("ai_consent")
    if not ai.LOCK.acquire(blocking=False): raise ai.AIError("ai_busy")
    try:
        audit(f"ai analysis job={d['id']} provider={c['provider']} model={model} hosts={len(payload['hosts'])} cloud={cloud}")
        res = ai.parse_answer(ai.call(c["provider"], model, key, c["port"], payload), labels)
    finally: ai.LOCK.release()
    res |= {"provider": c["provider"], "model": model, "cloud": cloud, "ts": time.time()}
    AI_RESULTS[d["id"]] = res
    if len(AI_RESULTS) > MAX_JOBS:
        for k in list(AI_RESULTS)[:len(AI_RESULTS) - MAX_JOBS]: AI_RESULTS.pop(k, None)
    return res

MAX_XML = 128 * 1024 * 1024     # bytes of nmap XML we are willing to parse

def parse(path):
    try:
        if Path(path).stat().st_size > MAX_XML: return None
        txt = Path(path).read_text(encoding="utf-8", errors="ignore")
        if "<!ENTITY" in txt: return None       # nmap never writes entity declarations; refuse anything that does (entity-expansion attacks)
        root = ET.fromstring(txt if "</nmaprun>" in txt else txt + "</nmaprun>")
    except (OSError, ET.ParseError):
        return None
    hosts = []
    for h in root.iter("host"):
        if (h.find("status") is None) or h.find("status").get("state") != "up":
            continue
        addrs = {a.get("addrtype"): a.get("addr") for a in h.findall("address")}
        hn = h.find("hostnames/hostname")
        om = h.find("os/osmatch")
        ports = []
        for p in h.iter("port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            try: portno = int(p.get("portid"))
            except (TypeError, ValueError): continue
            s = p.find("service")
            scripts, vulns = [], None
            for x in p.findall("script"):
                if x.get("id") == "vulners":
                    vulns = parse_vulners(x)
                    if vulns: continue          # structured: shown as a list instead of raw text
                scripts.append({"id": x.get("id"), "out": (x.get("output") or "")[:1500]})
            port = {"port": portno, "proto": p.get("protocol") or "",
                    "product": s.get("product", "") if s is not None else "", "vnum": s.get("version", "") if s is not None else "",
                    "service": s.get("name", "") if s is not None else "",
                    "version": " ".join(filter(None, [s.get("product"), s.get("version")])) if s is not None else "",
                    "ver": bool(s is not None and s.get("version")),
                    "cpes": [c.text for c in s.findall("cpe") if c.text][:4] if s is not None else [],
                    "scripts": scripts}
            if vulns: port["vulns"] = vulns
            ports.append(port)
        vuln = any("VULNERABLE" in x["out"].upper() for p in ports for x in p["scripts"])
        hosts.append({"ip": addrs.get("ipv4") or addrs.get("ipv6"), "mac": addrs.get("mac", ""), "vendor": (h.find("address[@addrtype='mac']").get("vendor", "") if h.find("address[@addrtype='mac']") is not None else ""),
                      "name": hn.get("name") if hn is not None else "",
                      "os": om.get("name") if om is not None else "", "ports": ports, "vuln": vuln,
                      "hops": [x.get("ipaddr") for x in h.findall("trace/hop") if x.get("ipaddr")]})
    return hosts
 
def split_version(text):
    """'Apache httpd 2.4.49' -> ('Apache httpd', '2.4.49'); text without a trailing version number -> (text, '')."""
    m = re.match(r"^(.*?)\s+(\d[\w.\-+~]*)$", text or "")
    return (m.group(1), m.group(2)) if m else (text or "", "")

def _dv(id_, cvss, exploit=False):
    return {"id": id_, "type": "cve", "cvss": cvss, "sev": cvss_sev(cvss), "kev": False, "active": False, "exploit": exploit, "epss": None, "ai": None,
            "title": "", "href": f"https://vulners.com/cve/{id_}", "src": f"https://nvd.nist.gov/vuln/detail/{id_}", "cpe": ""}
 
DEMO_VULNS = {("192.168.1.10", 21): [_dv("CVE-2011-2523", 9.8, True)],
              ("192.168.1.10", 8080): [_dv("CVE-2021-42013", 9.8, True), _dv("CVE-2021-41773", 7.5, True)],
              ("192.168.1.57", 80): [_dv("CVE-2017-17562", 8.1, True)]}
 
def demo(lookup=False, offline=False):
    d = [("192.168.1.1", "gateway.lan", "Linux 5.15", [(22, "ssh", "OpenSSH 9.2"), (80, "http", "lighttpd 1.4"), (443, "https", "")], False),
         ("192.168.1.10", "nas.lan", "Linux 4.x", [(21, "ftp", "vsftpd 2.3.4"), (445, "smb", "Samba 4.13"), (5000, "http", "Synology DSM"), (8080, "http", "Apache httpd 2.4.49")], True),
         ("192.168.1.23", "printer.lan", "", [(631, "ipp", "CUPS 2.4"), (9100, "jetdirect", ""), (23, "telnet", "")], False),
         ("192.168.1.42", "dev-laptop", "Windows 11", [(135, "msrpc", ""), (3389, "rdp", "")], False),
         ("192.168.1.57", "cam-garage", "Linux 3.x", [(554, "rtsp", ""), (80, "http", "GoAhead 2.5")], True),
         ("192.168.1.88", "", "", [], False)]
    def port(i, p, sv, ver):
        o = {"port": p, "proto": "tcp", "service": sv, "version": ver, "product": split_version(ver)[0], "vnum": split_version(ver)[1], "ver": bool(re.search(r"\d", ver)), "cpes": ["cpe:/a:demo:" + sv] if re.search(r"\d", ver) else [],
             "scripts": [{"id": "smb-vuln-ms17-010", "out": "VULNERABLE: Remote Code Execution (CVE-2017-0143)"}] if p == 445 else []}
        v = DEMO_VULNS.get((i, p)) if lookup else None
        if v: o["vulns"] = {"mode": "free", "total": len(v), "cves": len(v), "exploits": sum(x["exploit"] for x in v), "kev": 0, "items": v}
        return o
    hosts = [{"ip": i, "mac": "", "name": n, "os": o, "vuln": v,
             "hops": ([] if i.endswith(".1") else ["192.168.1.1"] + (["192.168.1.254"] if i.endswith(("42", "57")) else [])),
             "ports": [port(i, p, sv, ver) for p, sv, ver in ps]}
            for i, n, o, ps, v in d]
    return attach_offline(hosts) if offline else hosts
 
def run(job, args): MANAGER.execute(job, args)

WATCH, ALERTS, ALERT_N = [], [], [0]       # ALERT_N: how many alerts ever happened, so the UI can tell which ones are new
STOP = threading.Event()

def start_job(target, profile, args):
    return MANAGER.submit(target, profile, args, audit_line=lambda jid: f"watch-scan {jid} target={target} profile={profile}")
 
def diff_alert(prev, cur, label):
    """Compare two finished scans of one watch. Alerts are structured ({kind, ip, ...}) so the UI can show them in its language."""
    now = time.strftime("%H:%M:%S"); old = {h["ip"]: {p["port"] for p in h["ports"]} for h in prev["hosts"]}
    devs = load_devices(); baseline = any(v["trusted"] for v in devs.values())
    def add(kind, ip, **kw): ALERT_N[0] += 1; ALERTS.append({"t": now, "kind": kind, "ip": ip, "target": label, **kw})
    for h in cur["hosts"]:
        if h["ip"] not in old: add("unknown" if baseline and not devs.get(device_key(h), {}).get("trusted") else "new_host", h["ip"])
        else:
            for p in sorted({p["port"] for p in h["ports"]} - old[h["ip"]]): add("new_port", h["ip"], port=p)
    for ip in old:
        if ip not in {h["ip"] for h in cur["hosts"]}: add("host_gone", ip)
    del ALERTS[:-200]
 
def watch_tick():
    with MANAGER.lock: items = list(WATCH)
    for w in items:
        j = JOBS.get(w.get("jid"))
        if j and j["status"] == "running": continue
        if j and j["status"] == "done" and w.get("seen") != w["jid"]:
            if w.get("prev"): diff_alert(w["prev"], j, w["target"])
            w["prev"], w["seen"] = j, w["jid"]
        if time.time() >= w["next"]:
            try: w["jid"] = start_job(w["target"], w["profile"], PROFILES[w["profile"]]); w["next"] = time.time() + w["every"] * 60
            except Busy: pass                       # the UI or an earlier scan holds the slot: try again on the next tick
            except OSError: w["next"] = time.time() + 60

def watcher():
    while not STOP.wait(20):
        try: watch_tick()
        except Exception: pass                      # one bad tick must never end the watcher

def handle_watch(d):
    if d.get("ack") is not True or d.get("profile") not in PROFILES: raise ValueError("Profile/authorization missing")
    t = valid_targets(d.get("target"))
    try: m = int(d.get("minutes", 0))
    except (TypeError, ValueError, OverflowError): raise ValueError("Invalid interval")
    with MANAGER.lock:
        WATCH[:] = [w for w in WATCH if w["target"] != t]
        if m == 0: return 200, {"ok": True}
        if m not in (5, 15, 60, 360): raise ValueError("Invalid interval")
        if len(WATCH) >= 5: raise ValueError("At most 5 watches")
        if any_public(t) and d.get("public_ok") is not True: return 409, {"error": "public"}
        WATCH.append({"target": t, "profile": d["profile"], "every": m, "next": 0})
    audit(f"watch target={t} profile={d['profile']} every={m}min")
    return 200, {"ok": True}
 
class H(BaseHTTPRequestHandler):
    timeout = 20            # a client that stops sending (slow-loris) cannot hold a thread forever
    def log_message(self, *a): pass
    def send(self, code, body, ctype="application/json", nonce=None, extra=()):
        b = body if isinstance(body, bytes) else json.dumps(body).encode()
        script = f"'nonce-{nonce}'" if nonce else "'none'"      # only the page's own script (marked with a fresh nonce) may run; no 'unsafe-inline' for scripts
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store"); self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", f"default-src 'self'; script-src {script}; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.send_header("X-Frame-Options", "DENY"); self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin"); self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        for k, v in extra: self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)
    def host_ok(self):  # blocks DNS-rebinding
        return self.headers.get("Host", "") in (f"127.0.0.1:{PORT}", f"localhost:{PORT}")
    def origin_ok(self):
        o = self.headers.get("Origin")
        return o is None or o in (f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}")
    def session_ok(self):
        try: m = http_cookies.SimpleCookie(self.headers.get("Cookie", "")).get(COOKIE)
        except http_cookies.CookieError: return False
        if m is None: return False
        with SESSION_LOCK: ids = list(SESSIONS)
        return any(_eq(m.value, i) for i in ids)
    def body_json(self, limit, msg="Invalid request"):
        """The request body as a JSON object. A missing, negative, non-numeric or oversized Content-Length, bad JSON or a non-object are refused; never reads past `limit`."""
        try: n = int(self.headers.get("Content-Length", ""))
        except ValueError: raise ValueError(msg)
        if not 0 < n <= limit: raise ValueError(msg)
        try: d = json.loads(self.rfile.read(n))
        except ValueError: raise ValueError(msg)      # JSONDecodeError and UnicodeDecodeError are both ValueErrors
        if not isinstance(d, dict): raise ValueError(msg)
        return d
    def do_GET(self):
        if not self.host_ok(): return self.send(403, {"error": "bad host"})
        u = urlsplit(self.path); path = u.path
        if path == "/" and u.query:       # the launch link: exchange the single-use key for a session cookie, then drop it from the address bar
            sid = redeem_launch_key((parse_qs(u.query).get("k") or [""])[0])
            if sid: return self.send(302, b"", "text/plain", extra=(("Location", "/"), ("Set-Cookie", f"{COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/")))
        if not self.session_ok():
            if path == "/": return self.send(403, b"Meridian: open the link that Meridian printed or opened for you (it works once). Start Meridian again for a new one.\n", "text/plain; charset=utf-8")
            return self.send(403, {"error": "forbidden"})
        if path == "/":
            nonce = secrets.token_urlsafe(12)
            html = (ROOT / "index.html").read_text(encoding="utf-8").replace("__TOKEN__", TOKEN).replace("__NONCE__", nonce).replace("__VERSION__", VERSION).replace("__LANG__", UI_LANG)
            return self.send(200, html.replace("/*__LOCALES__*/{}", locales_js()).encode("utf-8"), "text/html; charset=utf-8", nonce=nonce)
        xm = re.fullmatch(r"/api/xml/([0-9a-f]{8})", path)
        if xm:
            x = (JOBS.get(xm.group(1)) or {}).get("xml")
            if x and MANAGER.ws and MANAGER.ws.contains(x) and Path(x).is_file():      # only files inside our private scratch directory
                return self.send(200, Path(x).read_bytes(), "application/xml")
        if path == "/api/alerts": return self.send(200, {"alerts": ALERTS[-30:], "seq": ALERT_N[0], "watch": [{"target": w["target"], "profile": w["profile"], "every": w["every"]} for w in WATCH]})
        if path == "/api/net": return self.send(200, {"cidr": local_cidr(), "root": is_admin(), "os": current_os()})
        if path == "/api/devices": return self.send(200, {"devices": load_devices()})
        if path == "/api/ai": return self.send(200, ai_status())
        am = re.fullmatch(r"/api/ai/result/([0-9a-f]{8})", path)
        if am: return self.send(*((200, AI_RESULTS[am.group(1)]) if am.group(1) in AI_RESULTS else (404, {"error": "not found"})))
        if path == "/api/history":
            return self.send(200, [{"id": j["id"], "target": j["target"], "profile": j["profile"], "status": j["status"], "ts": j["ts"], "hosts": len(j["hosts"])} for j in sorted(MANAGER.jobs(), key=lambda x: -x["ts"])])
        m = re.fullmatch(r"/api/scan/([0-9a-f]{8})", path)
        j = JOBS.get(m.group(1)) if m else None
        if not j: return self.send(404, {"error": "not found"})
        self.send(200, {k: j.get(k) for k in ("status", "hosts", "error", "error_code", "target", "profile", "lookup", "offline")} | {"elapsed": j.get("dur") if j["status"] != "running" else int(time.time() - j["t0"])})
    def do_POST(self):
        # every one of these is needed: right Host (no DNS rebinding), right Origin (no other site), the session cookie (launch key) and the per-run token
        if not (self.host_ok() and self.origin_ok() and self.session_ok() and _eq(self.headers.get("X-Token", ""), TOKEN)): return self.send(403, {"error": "forbidden"})
        if not self.headers.get("Content-Type", "").lower().startswith("application/json"): return self.send(415, {"error": "JSON only"})
        path = self.path.split("?", 1)[0]
        if path == "/api/save":
            try: return self.send(200, save_export(self.body_json(12_000_000, "Export is empty or too large")))
            except (ValueError, TypeError, OSError) as e: return self.send(400, err(str(e)))
        if path == "/api/devices":
            try: return self.send(200, {"devices": update_devices(self.body_json(65536, "Invalid device"))})
            except (TypeError, KeyError): return self.send(400, err("Invalid device"))
            except ValueError as e: return self.send(400, err(str(e)))
            except OSError: return self.send(500, {"error": "Could not save the device list", "code": ""})
        if path in ("/api/ai/config", "/api/ai/preview", "/api/ai/analyze"):
            try:
                d = self.body_json(8192, "Invalid AI settings")
                return self.send(200, {"/api/ai/config": ai_set_config, "/api/ai/preview": ai_preview, "/api/ai/analyze": ai_analyze}[path](d))
            except ai.AIError as e: return self.send(AI_ERR_STATUS.get(e.code, 400), {"error": str(e), "code": e.code})
            except (ValueError, TypeError, KeyError): return self.send(400, err("Invalid AI settings"))
            except OSError: return self.send(500, {"error": "Could not save the AI settings", "code": ""})
        sm = re.fullmatch(r"/api/stop/([0-9a-f]{8})", path)
        if sm: return self.send(*((200, {"ok": True}) if MANAGER.stop(sm.group(1)) else (404, {"error": "not found"})))
        if path not in ("/api/scan", "/api/watch"): return self.send(404, {"error": "not found"})
        try:
            d = self.body_json(4096)
            if path == "/api/watch": return self.send(*handle_watch(d))
            if (d.get("profile") not in PROFILES and d.get("profile") != "custom") or d.get("ack") is not True: raise ValueError("Profile/authorization missing")
            lookup = d.get("lookup") is True
            offline = d.get("offline") is True
            args = scan_args(d["profile"], d.get("options"), lookup, offline)
            demo_mode = bool(d.get("demo"))
            target = re.sub(r"[^\w.\-/ ,]", "", str(d.get("target") or "demo"))[:100] or "demo" if demo_mode else valid_targets(d.get("target"))
            if not demo_mode and not find_nmap(): raise ValueError("nmap not found. Install it or use demo mode.")
        except ValueError as e:
            return self.send(400, err(str(e)))
        except (TypeError, KeyError, AttributeError, OverflowError):      # wrong JSON types: a plain refusal, never an internal error text
            return self.send(400, err("Invalid request"))
        if not demo_mode and any_public(target) and d.get("public_ok") is not True:
            return self.send(409, {"error": "public"})
        lk = lookup and "-sn" not in args
        ol = offline and "-sn" not in args and (demo_mode or "-sV" in args)      # hints need a detected version
        try:
            jid = MANAGER.submit(target, d["profile"], args, demo=demo_mode, lookup=lk, offline=ol,
                                 audit_line=lambda j: f"scan {j} target={target} profile={d['profile']} public={any_public(target)} demo={demo_mode} lookup={lk} offline={ol}")
        except Busy as e: return self.send(409, err(str(e)))
        except OSError: return self.send(500, err("Could not create the private scratch directory"))
        self.send(200, {"id": jid})
 
def browser_candidates():
    """Chromium-family browsers at their usual install places (they are rarely on PATH on Windows and macOS). Edge comes first on Windows: it is always there."""
    if IS_WIN:
        roots = [os.environ.get(v) for v in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA")]
        rel = (r"Microsoft\Edge\Application\msedge.exe", r"Google\Chrome\Application\chrome.exe", r"BraveSoftware\Brave-Browser\Application\brave.exe", r"Chromium\Application\chrome.exe")
        return [str(Path(r) / x) for x in rel for r in roots if r]
    if IS_MAC:
        return [f"{b}/{a}.app/Contents/MacOS/{a}" for a in ("Google Chrome", "Microsoft Edge", "Brave Browser", "Chromium") for b in ("/Applications", str(Path.home() / "Applications"))]
    return []

def find_browser():
    for b in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "brave-browser", "microsoft-edge", "microsoft-edge-stable"):
        if shutil.which(b): return shutil.which(b)
    for c in browser_candidates():
        if Path(c).is_file(): return c
 
QUIET = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}  # hide harmless Chromium GPU/D-Bus warnings
 
def open_window(url, srv):
    """Native-feeling window: pywebview if installed, else a Chromium-family --app window, else the default browser."""
    if IS_WIN:
        try: import ctypes; ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Meridian.Scanner")   # own taskbar identity, not "Python"
        except (AttributeError, OSError, ImportError): pass
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        # Chromium refuses to run as root, so start the window as the user who ran sudo.
        user, b = os.environ.get("SUDO_USER"), find_browser()
        if user and user != "root" and b:
            prof = tempfile.mkdtemp(prefix="meridian-ui-")      # random name, mode 0700; then handed to the user the browser runs as
            try:
                import pwd; pw = pwd.getpwnam(user); os.chown(prof, pw.pw_uid, pw.pw_gid)
            except (ImportError, KeyError, OSError): pass
            keep = "DISPLAY,XAUTHORITY,WAYLAND_DISPLAY,XDG_RUNTIME_DIR,DBUS_SESSION_BUS_ADDRESS"
            r = subprocess.run(["sudo", "-u", user, f"--preserve-env={keep}", b, f"--app={url}", f"--user-data-dir={prof}",
                                "--window-size=1360,860", "--no-first-run", "--disable-extensions", "--log-level=3"], **QUIET)
            shutil.rmtree(prof, ignore_errors=True)
            if r.returncode == 0: return
        print(T("win.root", url=url))
        wait_forever(); return
    try:
        import webview
        webview.create_window("Meridian", url, width=1360, height=860, min_size=(980, 640), background_color="#08171f")
        webview.start(); return
    except ImportError:
        pass
    b = find_browser()
    if b:
        prof = HIST.parent / "browser-profile"   # persistent, so theme, presets and notes survive restarts
        prof.mkdir(parents=True, exist_ok=True, mode=0o700)
        subprocess.run([b, f"--app={url}", f"--user-data-dir={prof}", "--window-size=1360,860", "--no-first-run", "--disable-extensions", "--log-level=3"], **QUIET)
        return
    import webbrowser; webbrowser.open(url)
    print(T("win.default"))
    wait_forever()
 
KNOWN_DATA = ("history.json", "audit.log", "audit.log.1", "devices.json", "ai.json", "ai.key", "browser-profile")

def unsafe_data_dir(p):
    """True for a folder that must never be deleted as 'Meridian data': a filesystem root, the home folder or any folder above it."""
    try: r, home = Path(p).resolve(), Path.home().resolve()
    except (OSError, RuntimeError): return True
    return r == home or r in home.parents or r == Path(r.anchor) or len(r.parts) < 3

def remove_data(p):
    """A folder named like Meridian's own is removed as a whole; any other folder (MERIDIAN_DATA_DIR) only loses the files Meridian creates, and is removed only if that leaves it empty."""
    p = Path(p)
    if "meridian" in p.name.lower(): shutil.rmtree(p, ignore_errors=True); return
    for n in KNOWN_DATA:
        q = p / n
        if q.is_dir() and not q.is_symlink(): shutil.rmtree(q, ignore_errors=True)
        else: q.unlink(missing_ok=True)
    try: p.rmdir()
    except OSError: pass

def uninstall():
    """`meridian --uninstall`: remove the command, the app copy, the menu entry AND saved data. `--keep-data` keeps the data."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print(T("un.root")); return 1
    P = install_paths(); app = [P["app"], P["launcher"], *P["menu"]]
    keep = "--keep-data" in sys.argv
    saved = [] if keep else [HIST.parent]
    if saved and unsafe_data_dir(saved[0]): print(T("un.unsafe", path=saved[0])); return 1
    found = [(t, T("un.kind_app")) for t in app if t.exists() or t.is_symlink()] + [(t, T("un.kind_data")) for t in saved if t.exists()]
    if not found: print(T("un.nothing")); return 0
    print(T("un.will_remove")); [print(f"  {t}   ({kind})") for t, kind in found]
    if keep: print("  " + T("un.keeping", path=HIST.parent))
    yes = {"y", "yes"} | {x.strip() for x in T("un.yes").lower().split(",")}
    if "--yes" not in sys.argv and input(T("un.ask")).strip().lower() not in yes:
        print(T("un.cancelled")); return 1
    for t, _ in found:
        if t in saved: remove_data(t)
        else: shutil.rmtree(t, ignore_errors=True) if t.is_dir() and not t.is_symlink() else t.unlink(missing_ok=True)
    if IS_WIN:
        try: win_user_path(remove=P["bin"])
        except (OSError, ImportError): pass
    print(T("un.done_keep", path=HIST.parent) if keep else T("un.done"))
    return 0

def doctor_report():
    """What a user (or a bug report) needs to see when something does not work. List of (status 'ok'|'warn'|'fail', label, detail)."""
    o, out = current_os(), []
    def add(status, label, detail=""): out.append((status, T(label), detail))
    add("ok", "dr.version", VERSION)
    add("ok", "dr.os", f"{platform.system()} {platform.release()} ({platform.machine()})")
    py_ok = sys.version_info >= (3, 10)
    add("ok" if py_ok else "fail", "dr.python", platform.python_version() + ("" if py_ok else " - " + T("dr.python_old")))
    n = find_nmap()
    if n:
        try: ver = subprocess.run([n, "--version"], capture_output=True, text=True, timeout=10).stdout.strip().splitlines()[0]
        except (OSError, IndexError, subprocess.SubprocessError): ver = "?"
        add("ok", "dr.nmap", f"{ver} - {n}")
    else: add("warn", "dr.nmap", T("dr.nmap_" + o))
    adm = is_admin()
    add("ok" if adm else "warn", "dr.priv", T("dr.priv_yes") if adm else T("dr.priv_no_" + o))
    b = find_browser(); add("ok" if b else "warn", "dr.browser", b or T("dr.browser_none"))
    try:
        d = data_dir(); probe = d / f".probe-{os.getpid()}"; probe.write_text("x", encoding="utf-8"); probe.unlink()
        add("ok", "dr.data", str(d))
    except OSError as e: add("fail", "dr.data", f"{HIST.parent}: {e}")
    try: port = int(os.environ.get("MERIDIAN_PORT", 8765))
    except ValueError: port = 8765
    sk = socket.socket()
    try: sk.bind(("127.0.0.1", port)); add("ok", "dr.port", T("dr.port_free", port=port))
    except OSError: add("warn", "dr.port", T("dr.port_busy", port=port))
    finally: sk.close()
    add("ok", "dr.lang", f"{LANG} ({', '.join(load_locales())})")
    return out

def doctor():
    marks = {"ok": "[ OK ]", "warn": "[ !! ]", "fail": "[FAIL]"}
    print(f"Meridian {VERSION} - {T('dr.title')}\n")
    rep = doctor_report()
    for st, label, detail in rep: print(f"{marks[st]} {label}: {detail}")
    return 1 if any(st == "fail" for st, _, _ in rep) else 0

def help_text(): return T("cli.help", version=VERSION, langs=", ".join(load_locales()))

def argval(flag):
    """Value of `--flag value` or `--flag=value` on the command line ('' when absent)."""
    for i, a in enumerate(sys.argv):
        if a == flag and i + 1 < len(sys.argv): return sys.argv[i + 1]
        if a.startswith(flag + "="): return a.split("=", 1)[1]
    return ""

class Server(ThreadingHTTPServer):
    allow_reuse_address = not IS_WIN     # on Windows SO_REUSEADDR lets a second process share a busy port; SO_EXCLUSIVEADDRUSE below prevents that
    def server_bind(self):
        if IS_WIN and hasattr(socket, "SO_EXCLUSIVEADDRUSE"): self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

if __name__ == "__main__":
    fix_stdio()
    forced = argval("--lang") or os.environ.get("MERIDIAN_LANG", "")
    LANG = pick_lang(forced, *system_langs()); UI_LANG = pick_lang(forced) if forced else ""
    if "--version" in sys.argv or "-V" in sys.argv: print(f"Meridian {VERSION}"); sys.exit(0)
    if "--help" in sys.argv or "-h" in sys.argv: print(help_text()); sys.exit(0)
    if "--doctor" in sys.argv: sys.exit(doctor())
    if "--uninstall" in sys.argv: sys.exit(uninstall())
    try: sweep_stale()          # an nmap or scratch directory left behind by a crashed run
    except OSError: pass
    atexit.register(MANAGER.shutdown)
    for _s in (signal.SIGTERM, getattr(signal, "SIGHUP", None), getattr(signal, "SIGBREAK", None)):      # Ctrl+C already raises KeyboardInterrupt
        if _s:
            try: signal.signal(_s, lambda *a: sys.exit(0))
            except (ValueError, OSError): pass
    load_history(); threading.Thread(target=watcher, daemon=True).start()
    try: srv = Server(("127.0.0.1", int(os.environ.get("MERIDIAN_PORT", 8765))), H)   # fixed port keeps browser storage (theme, notes) stable
    except (OSError, ValueError): srv = Server(("127.0.0.1", 0), H)                    # busy: any free port
    PORT = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = launch_url()
    print(f"Meridian {VERSION} {url}  (nmap: {find_nmap() or T('start.nonmap')})")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print(T("start.root"))
    try:
        if "--serve" in sys.argv: wait_forever()   # headless: no window
        else: open_window(url, srv)
    except KeyboardInterrupt:
        pass
    finally:
        STOP.set(); MANAGER.shutdown()
    print(T("start.bye"))
