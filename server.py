#!/usr/bin/env python3
"""Meridian - nmap engine + live web UI. Binds to localhost only. Scan only what you are authorized to scan."""
import atexit, ipaddress, json, os, signal, socket, re, secrets, shutil, stat, subprocess, sys, threading, time, tempfile, uuid
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
 
PORT = 0  # chosen at start-up (free port)
VERSION = "0.3.0"   # bump for every release and tag the same number on GitHub (v0.3.0)
TOKEN = secrets.token_urlsafe(16)
JOBS = {}
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
HIST = Path.home() / ".local/share/meridian/history.json"
MAX_JOBS = 100          # finished scans kept in memory
KEEP_XML = 20           # raw nmap XML files kept on disk (the newest scans); older ones are deleted
SCAN_LIMIT = 3600       # seconds; a scan running longer is stopped
MIN_PARSE_GAP = 2.0     # seconds between two parses of the growing XML file (and never when it did not change)
AUDIT_MAX = 1_000_000   # bytes; audit.log is rotated to audit.log.1 above this size, so it cannot grow forever
 
def custom_args(o):
    t = int(o.get("timing", 4))
    if not 0 <= t <= 5: raise ValueError("Timing must be 0-5")
    a = [f"-T{t}"]
    ports = str(o.get("ports", "")).strip()
    if ports:
        if not re.fullmatch(r"[0-9,\-]{1,120}", ports): raise ValueError("Invalid port list")
        a += ["-p", ports]
    for k, f in (("sv", "-sV"), ("os", "-O"), ("pn", "-Pn"), ("sn", "-sn")):
        if o.get(k) is True: a.append(f)
    sc = [x for x in o.get("scripts", []) if x in SCRIPTS]
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
 
def scan_args(profile, options=None, lookup=False):
    """Final nmap arguments. With lookup=True every port-scanning profile also detects versions and runs the vulners NSE
    script, which turns a software name + version into CVEs and known exploits. Host discovery (-sn) is left alone."""
    a = custom_args(options or {}) if profile == "custom" else list(PROFILES[profile])
    if not lookup or "-sn" in a: return a
    if "-sV" not in a:
        if profile == "custom": return a        # the user switched version detection off: nothing to look up
        a += ["-sV", "--version-light"]
    # paths=none: do not probe ~900 web paths on the target. max_items=0: never spend API credits (smart audit).
    return add_script(a, "vulners") + ["--script-args", "vulners.paths=none,vulners.max_items=0"]
 
def _num(x):
    try: return float(x)
    except (TypeError, ValueError): return None
 
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
    if not items: return None
    # facts outrank predictions: actively exploited, then public exploit, then likelihood; CVSS breaks ties
    items.sort(key=lambda i: (i["kev"], i["active"], i["exploit"], i["epss"] if i["epss"] is not None else (i["ai"] or 0) / 10, i["cvss"] or 0), reverse=True)
    return {"mode": mode, "total": len(items), "cves": sum(i["id"].upper().startswith("CVE-") for i in items),
            "exploits": sum(i["exploit"] for i in items), "kev": sum(i["kev"] for i in items), "items": items[:limit]}
 
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
    if st.st_mode & 0o077:
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
        return os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600), p
    def contains(self, p):
        try: return Path(p).resolve().parent == self.path.resolve()
        except OSError: return False
    def tail(self, p, n=300):
        try: return Path(p).read_text(errors="ignore")[-n:]
        except OSError: return ""
    def destroy(self): shutil.rmtree(self.path, ignore_errors=True)

def _cmdline(pid):
    try: return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="ignore")
    except OSError: return ""

def sweep_stale(base=None):
    """After a crash (kill -9, power loss) an old run may have left an nmap process and its scratch directory behind. Stop that nmap (only if
    its command line still names the directory) and delete the directory. Directories of Meridian processes that are still alive are left alone."""
    base = Path(base) if base else runtime_base()
    for d in base.glob("meridian-run-*"):
        m = re.fullmatch(r"meridian-run-(\d+)-\w+", d.name)
        try:
            st = os.lstat(d)
            if not m or not stat.S_ISDIR(st.st_mode) or st.st_uid not in _owners() or int(m.group(1)) == os.getpid(): continue
            if "server.py" in _cmdline(m.group(1)) or "meridian" in _cmdline(m.group(1)).lower(): continue    # that Meridian is still running
            try:
                pid = int((d / "nmap.pid").read_text().strip())
                if str(d) in _cmdline(pid):
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
    def submit(self, target, profile, args, demo=False, lookup=False, audit_line=None):
        with self.lock:
            if any(j["status"] == "running" for j in JOBS.values()): raise Busy("A scan is already running. Stop it first.")
            jid = uuid.uuid4().hex[:8]; xml = ""
            if not demo:
                fd, p = self.workspace().new_file(f"{jid}.xml"); os.close(fd); xml = str(p)
            JOBS[jid] = {"status": "running", "hosts": [], "error": "", "target": target, "profile": profile, "id": jid, "ts": time.time(),
                         "t0": time.time(), "demo": demo, "lookup": lookup, "xml": xml}
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
        try: os.killpg(p.pid, sig) if hasattr(os, "killpg") else p.send_signal(sig)    # the whole process group: nmap and anything it started
        except (ProcessLookupError, PermissionError, OSError): pass
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
            with self.lock: job["status"], job["error"] = "error", str(e)[:300]
        finally:
            with self.lock:
                if job["status"] == "running": job["status"] = "done"
                job["dur"] = int(time.time() - job["t0"]); job.pop("proc", None)
            save_history(); self._prune()
    def _demo(self, job):
        for k in range(1, 7):
            time.sleep(1.2)
            if job["status"] != "running": break
            job["hosts"] = demo(job.get("lookup"))[:k]
    def _nmap(self, job, args):
        nmap = shutil.which("nmap")
        if not nmap: raise RuntimeError("nmap not found")
        ws = self.workspace(); efd, errp = ws.new_file(f"{job['id']}.err")      # stderr goes to a file: a full pipe can never block nmap
        try:
            p = subprocess.Popen([nmap, *args, "-oX", job["xml"], *job["target"].split()], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=efd, start_new_session=True, close_fds=True)   # own process group: one signal reaches nmap and its children
        finally: os.close(efd)
        job["proc"] = p
        try: (ws.path / "nmap.pid").write_text(str(p.pid))      # lets the next start find an orphan after a crash (sweep_stale)
        except OSError: pass
        deadline, seen, last, gap = time.monotonic() + SCAN_LIMIT, None, 0.0, MIN_PARSE_GAP
        try:
            while True:
                try: p.wait(timeout=1.0); break      # wakes up the moment nmap exits, no busy polling
                except subprocess.TimeoutExpired: pass
                if job["status"] != "running": break     # stopped by the user
                if time.monotonic() > deadline:
                    job["status"], job["error"] = "stopped", "Stopped: 1 hour limit reached"; break
                try: st = os.stat(job["xml"]); sig = (st.st_size, st.st_mtime_ns)
                except OSError: sig = None
                if sig != seen and time.monotonic() - last >= gap:       # parse only when nmap wrote something new, and not too often
                    t = time.monotonic(); hosts = parse(job["xml"])
                    if hosts: job["hosts"] = hosts
                    seen, last = sig, time.monotonic(); gap = max(MIN_PARSE_GAP, 4 * (last - t))    # a slow parse backs the polling off
        finally:
            self._terminate(p)       # nothing to do when nmap already exited; otherwise TERM -> KILL -> wait()
            try: (ws.path / "nmap.pid").unlink()
            except OSError: pass
        hosts = parse(job["xml"])
        if hosts: job["hosts"] = hosts
        with self.lock:
            if job["status"] == "running":
                job["status"] = "done" if p.returncode == 0 else "error"
                if p.returncode: job["error"] = ws.tail(errp)
        try: os.unlink(errp)
        except OSError: pass
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

def save_history():
    """Atomic: write a private temp file next to the history, fsync, then rename over it. A crash can never leave half a file."""
    try:
        d = data_dir()
        keep = [{k: j[k] for k in ("id", "target", "profile", "hosts", "ts", "dur")} for j in MANAGER.jobs() if j["status"] in ("done", "stopped") and "dur" in j]
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".history-", suffix=".tmp")     # mode 0600, random name
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f: json.dump(keep[-50:], f); f.flush(); os.fsync(f.fileno())
            os.replace(tmp, HIST)
        except BaseException:
            try: os.unlink(tmp)
            except OSError: pass
            raise
        _chown_sudo(HIST)
    except (OSError, TypeError, ValueError): pass

def load_history():
    try:
        if HIST.stat().st_size > 20_000_000: return
        for j in json.loads(HIST.read_text()):
            if isinstance(j, dict) and re.fullmatch(r"[0-9a-f]{8}", str(j.get("id", ""))) and isinstance(j.get("hosts"), list):
                JOBS[j["id"]] = j | {"status": "done", "error": "", "t0": 0, "demo": False, "xml": ""}
    except (OSError, ValueError, KeyError, TypeError): pass
 
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
        for line in (home / ".config" / "user-dirs.dirs").read_text().splitlines():
            if line.startswith("XDG_DOWNLOAD_DIR="): d = Path(os.path.expandvars(line.split("=", 1)[1].strip().strip('"')))
    except OSError: pass
    if d is None or home not in d.resolve().parents: d = home / "Downloads"
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
        try: fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); break
        except FileExistsError: k += 1
    with os.fdopen(fd, "w", encoding="utf-8") as f: f.write(data)
    _chown_sudo(dest)       # started with sudo: give the file to the real user
    audit(f"export saved {dest.name} ({len(data)} chars)")
    return {"path": str(dest)}
 
def local_cidr():
    """Best-effort guess of the local /24 (no packets are sent by this UDP connect)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]; s.close()
        return str(ipaddress.ip_network(ip + "/24", strict=False))
    except OSError:
        return "192.168.1.0/24"
 
def audit(msg):
    """Append-only local audit trail of every scan that was started. Never follows a symlink, rotates at AUDIT_MAX."""
    try:
        d = data_dir(); p = d / "audit.log"
        try:
            if p.stat().st_size > AUDIT_MAX: os.replace(p, d / "audit.log.1")
        except FileNotFoundError: pass
        fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f: f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + re.sub(r"[\r\n]+", " ", msg) + "\n")
        _chown_sudo(p)
    except OSError: pass
 
def parse(path):
    try:
        txt = Path(path).read_text(errors="ignore")
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
            if p.find("state").get("state") != "open":
                continue
            s = p.find("service")
            scripts, vulns = [], None
            for x in p.findall("script"):
                if x.get("id") == "vulners":
                    vulns = parse_vulners(x)
                    if vulns: continue          # structured: shown as a list instead of raw text
                scripts.append({"id": x.get("id"), "out": (x.get("output") or "")[:1500]})
            port = {"port": int(p.get("portid")), "proto": p.get("protocol"),
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
 
def _dv(id_, cvss, exploit=False):
    return {"id": id_, "type": "cve", "cvss": cvss, "sev": cvss_sev(cvss), "kev": False, "active": False, "exploit": exploit, "epss": None, "ai": None,
            "title": "", "href": f"https://vulners.com/cve/{id_}", "src": f"https://nvd.nist.gov/vuln/detail/{id_}", "cpe": ""}
 
DEMO_VULNS = {("192.168.1.10", 21): [_dv("CVE-2011-2523", 9.8, True)],
              ("192.168.1.10", 8080): [_dv("CVE-2021-42013", 9.8, True), _dv("CVE-2021-41773", 7.5, True)],
              ("192.168.1.57", 80): [_dv("CVE-2017-17562", 8.1, True)]}
 
def demo(lookup=False):
    d = [("192.168.1.1", "gateway.lan", "Linux 5.15", [(22, "ssh", "OpenSSH 9.2"), (80, "http", "lighttpd 1.4"), (443, "https", "")], False),
         ("192.168.1.10", "nas.lan", "Linux 4.x", [(21, "ftp", "vsftpd 2.3.4"), (445, "smb", "Samba 4.13"), (5000, "http", "Synology DSM"), (8080, "http", "Apache httpd 2.4.49")], True),
         ("192.168.1.23", "printer.lan", "", [(631, "ipp", "CUPS 2.4"), (9100, "jetdirect", ""), (23, "telnet", "")], False),
         ("192.168.1.42", "dev-laptop", "Windows 11", [(135, "msrpc", ""), (3389, "rdp", "")], False),
         ("192.168.1.57", "cam-garage", "Linux 3.x", [(554, "rtsp", ""), (80, "http", "GoAhead 2.5")], True),
         ("192.168.1.88", "", "", [], False)]
    def port(i, p, sv, ver):
        o = {"port": p, "proto": "tcp", "service": sv, "version": ver, "ver": bool(re.search(r"\d", ver)), "cpes": ["cpe:/a:demo:" + sv] if re.search(r"\d", ver) else [],
             "scripts": [{"id": "smb-vuln-ms17-010", "out": "VULNERABLE: Remote Code Execution (CVE-2017-0143)"}] if p == 445 else []}
        v = DEMO_VULNS.get((i, p)) if lookup else None
        if v: o["vulns"] = {"mode": "free", "total": len(v), "cves": len(v), "exploits": sum(x["exploit"] for x in v), "kev": 0, "items": v}
        return o
    return [{"ip": i, "mac": "", "name": n, "os": o, "vuln": v,
             "hops": ([] if i.endswith(".1") else ["192.168.1.1"] + (["192.168.1.254"] if i.endswith(("42", "57")) else [])),
             "ports": [port(i, p, sv, ver) for p, sv, ver in ps]}
            for i, n, o, ps, v in d]
 
def run(job, args): MANAGER.execute(job, args)

WATCH, ALERTS = [], []
STOP = threading.Event()

def start_job(target, profile, args):
    return MANAGER.submit(target, profile, args, audit_line=lambda jid: f"watch-scan {jid} target={target} profile={profile}")
 
def diff_alert(prev, cur, label):
    now = time.strftime("%H:%M:%S"); old = {h["ip"]: {p["port"] for p in h["ports"]} for h in prev["hosts"]}
    for h in cur["hosts"]:
        if h["ip"] not in old: ALERTS.append(f"{now} NEW HOST {h['ip']} on {label}")
        else:
            for p in {p["port"] for p in h["ports"]} - old[h["ip"]]: ALERTS.append(f"{now} NEW PORT {h['ip']}:{p}")
    for ip in old:
        if ip not in {h["ip"] for h in cur["hosts"]}: ALERTS.append(f"{now} HOST GONE {ip}")
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
    t = valid_targets(d.get("target")); m = int(d.get("minutes", 0))
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
    def log_message(self, *a): pass
    def send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store"); self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.send_header("X-Frame-Options", "DENY"); self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers(); self.wfile.write(b)
    def host_ok(self):  # blocks DNS-rebinding
        return self.headers.get("Host", "") in (f"127.0.0.1:{PORT}", f"localhost:{PORT}")
    def origin_ok(self):
        o = self.headers.get("Origin")
        return o is None or o in (f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}")
    def do_GET(self):
        if not self.host_ok(): return self.send(403, {"error": "bad host"})
        if self.path == "/":
            html = (Path(__file__).parent / "index.html").read_text().replace("__TOKEN__", TOKEN).replace("__VERSION__", VERSION)
            return self.send(200, html.encode(), "text/html; charset=utf-8")
        xm = re.fullmatch(r"/api/xml/([0-9a-f]{8})", self.path)
        if xm:
            x = (JOBS.get(xm.group(1)) or {}).get("xml")
            if x and MANAGER.ws and MANAGER.ws.contains(x) and Path(x).is_file():      # only files inside our private scratch directory
                return self.send(200, Path(x).read_bytes(), "application/xml")
        if self.path == "/api/alerts": return self.send(200, {"alerts": ALERTS[-30:], "watch": [{"target": w["target"], "profile": w["profile"], "every": w["every"]} for w in WATCH]})
        if self.path == "/api/net": return self.send(200, {"cidr": local_cidr(), "root": (os.geteuid() == 0) if hasattr(os, "geteuid") else None})
        if self.path == "/api/history":
            return self.send(200, [{"id": j["id"], "target": j["target"], "profile": j["profile"], "status": j["status"], "ts": j["ts"], "hosts": len(j["hosts"])} for j in sorted(MANAGER.jobs(), key=lambda x: -x["ts"])])
        m = re.fullmatch(r"/api/scan/([0-9a-f]{8})", self.path)
        j = JOBS.get(m.group(1)) if m else None
        if not j: return self.send(404, {"error": "not found"})
        self.send(200, {k: j.get(k) for k in ("status", "hosts", "error", "target", "profile", "lookup")} | {"elapsed": j.get("dur") if j["status"] != "running" else int(time.time() - j["t0"])})
    def do_POST(self):
        if not self.host_ok() or not self.origin_ok() or not secrets.compare_digest(self.headers.get("X-Token", ""), TOKEN): return self.send(403, {"error": "forbidden"})
        if self.path == "/api/save":
            try:
                n = int(self.headers.get("Content-Length", 0))
                if not 0 < n <= 12_000_000: raise ValueError("Export is empty or too large")
                return self.send(200, save_export(json.loads(self.rfile.read(n))))
            except (ValueError, TypeError, OSError, json.JSONDecodeError) as e:
                return self.send(400, {"error": str(e)})
        sm = re.fullmatch(r"/api/stop/([0-9a-f]{8})", self.path)
        if sm and MANAGER.stop(sm.group(1)): return self.send(200, {"ok": True})
        try:
            d = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 4096)))
            if self.path == "/api/watch": return self.send(*handle_watch(d))
            if (d.get("profile") not in PROFILES and d.get("profile") != "custom") or d.get("ack") is not True: raise ValueError("Profile/authorization missing")
            lookup = d.get("lookup") is True
            args = scan_args(d["profile"], d.get("options"), lookup)
            demo_mode = bool(d.get("demo"))
            target = re.sub(r"[^\w.\-/ ,]", "", str(d.get("target") or "demo"))[:100] or "demo" if demo_mode else valid_targets(d.get("target"))
            if not demo_mode and not shutil.which("nmap"): raise ValueError("nmap not found. Install it or use demo mode.")
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as e:
            return self.send(400, {"error": str(e)})
        if not demo_mode and any_public(target) and d.get("public_ok") is not True:
            return self.send(409, {"error": "public"})
        lk = lookup and "-sn" not in args
        try:
            jid = MANAGER.submit(target, d["profile"], args, demo=demo_mode, lookup=lk,
                                 audit_line=lambda j: f"scan {j} target={target} profile={d['profile']} public={any_public(target)} demo={demo_mode} lookup={lk}")
        except Busy as e: return self.send(409, {"error": str(e)})
        except OSError: return self.send(500, {"error": "Could not create the private scratch directory"})
        self.send(200, {"id": jid})
 
def find_browser():
    for b in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "brave-browser", "microsoft-edge"):
        if shutil.which(b): return shutil.which(b)
 
QUIET = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}  # hide harmless Chromium GPU/D-Bus warnings
 
def open_window(url, srv):
    """Native-feeling window: pywebview if installed, else a Chromium-family --app window, else the default browser."""
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
        print(f"Could not open a window as root. Open {url} in your normal browser. Ctrl+C to quit.")
        threading.Event().wait(); return
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
    print("No app-mode browser found; opened default browser. Ctrl+C to quit.")
    threading.Event().wait()
 
def uninstall():
    """`meridian --uninstall`: remove the command, the app copy, the menu entry AND saved data. `--keep-data` keeps the data."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("Run this as your normal user, without sudo."); return 1
    share = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    app = [share / "meridian-app", Path.home() / ".local" / "bin" / "meridian", share / "applications" / "meridian.desktop"]
    keep = "--keep-data" in sys.argv
    saved = [] if keep else [HIST.parent]
    found = [(t, "application") for t in app if t.exists() or t.is_symlink()] + [(t, "saved data: scan history, audit log, browser profile") for t in saved if t.exists()]
    if not found: print("Meridian is not installed (nothing to remove)."); return 0
    print("This will remove:"); [print(f"  {t}   ({kind})") for t, kind in found]
    if keep: print(f"  (keeping saved data in {HIST.parent})")
    if "--yes" not in sys.argv and input("Remove Meridian? [y/N] ").strip().lower() not in ("y", "yes"):
        print("Cancelled."); return 1
    for t, _ in found: shutil.rmtree(t, ignore_errors=True) if t.is_dir() and not t.is_symlink() else t.unlink(missing_ok=True)
    print("Meridian removed." + (f" Saved data kept in {HIST.parent}." if keep else " Saved data deleted."))
    return 0
 
HELP = f"""Meridian {VERSION} - network scanner UI on top of nmap
 
Usage: meridian [option]
  (no option)      open the app window
  --serve          run without a window and print the URL to open yourself
  --version, -V    print the version and exit
  --uninstall      remove the app AND your saved data
                   (--keep-data keeps the data, --yes skips the question)
  --help, -h       show this help
 
Environment: MERIDIAN_PORT=8765 (preferred port; any free port is used if it is busy)
Scan only networks you own or have permission to test."""
 
if __name__ == "__main__":
    if "--version" in sys.argv or "-V" in sys.argv: print(f"Meridian {VERSION}"); sys.exit(0)
    if "--help" in sys.argv or "-h" in sys.argv: print(HELP); sys.exit(0)
    if "--uninstall" in sys.argv: sys.exit(uninstall())
    try: sweep_stale()          # an nmap or scratch directory left behind by a crashed run
    except OSError: pass
    atexit.register(MANAGER.shutdown)
    for _s in (signal.SIGTERM, getattr(signal, "SIGHUP", None)):      # Ctrl+C already raises KeyboardInterrupt
        if _s:
            try: signal.signal(_s, lambda *a: sys.exit(0))
            except (ValueError, OSError): pass
    load_history(); threading.Thread(target=watcher, daemon=True).start()
    try: srv = ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("MERIDIAN_PORT", 8765))), H)   # fixed port keeps browser storage (theme, notes) stable
    except OSError: srv = ThreadingHTTPServer(("127.0.0.1", 0), H)                                      # busy: any free port
    PORT = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{PORT}"
    print(f"Meridian {VERSION} {url}  (nmap: {shutil.which('nmap') or 'NOT FOUND, sample-data mode only'})")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("Warning: running as root. Keep Meridian on localhost and scan only authorized targets.")
    try:
        if "--serve" in sys.argv: threading.Event().wait()   # headless: no window
        else: open_window(url, srv)
    except KeyboardInterrupt:
        pass
    finally:
        STOP.set(); MANAGER.shutdown()
    print("Bye.")
