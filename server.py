#!/usr/bin/env python3
"""Meridian - nmap engine + live web UI. Binds to localhost only. Scan only what you are authorized to scan."""
import ipaddress, json, os, signal, socket, re, secrets, shutil, subprocess, sys, threading, time, tempfile, uuid
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = 0  # chosen at start-up (free port)
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

def save_history():
    try:
        HIST.parent.mkdir(parents=True, exist_ok=True)
        keep = [{k: j[k] for k in ("id", "target", "profile", "hosts", "ts", "dur")} for j in JOBS.values() if j["status"] in ("done", "stopped")]
        HIST.write_text(json.dumps(keep[-50:])); os.chmod(HIST, 0o600)
    except OSError: pass

def load_history():
    try:
        for j in json.loads(HIST.read_text()):
            JOBS[j["id"]] = j | {"status": "done", "error": "", "t0": 0, "demo": False, "xml": ""}
    except (OSError, ValueError, KeyError): pass

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

def local_cidr():
    """Best-effort guess of the local /24 (no packets are sent by this UDP connect)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]; s.close()
        return str(ipaddress.ip_network(ip + "/24", strict=False))
    except OSError:
        return "192.168.1.0/24"

def audit(msg):
    """Append-only local audit trail of every scan that was started."""
    try:
        p = HIST.parent / "audit.log"; p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(p, "a") as f: f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + re.sub(r"[\r\n]+", " ", msg) + "\n")
        os.chmod(p, 0o600)
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
            scripts = [{"id": x.get("id"), "out": (x.get("output") or "")[:1500]} for x in p.findall("script")]
            ports.append({"port": int(p.get("portid")), "proto": p.get("protocol"),
                          "service": s.get("name", "") if s is not None else "",
                          "version": " ".join(filter(None, [s.get("product"), s.get("version")])) if s is not None else "",
                          "scripts": scripts})
        vuln = any("VULNERABLE" in x["out"].upper() for p in ports for x in p["scripts"])
        hosts.append({"ip": addrs.get("ipv4") or addrs.get("ipv6"), "mac": addrs.get("mac", ""), "vendor": (h.find("address[@addrtype='mac']").get("vendor", "") if h.find("address[@addrtype='mac']") is not None else ""),
                      "name": hn.get("name") if hn is not None else "",
                      "os": om.get("name") if om is not None else "", "ports": ports, "vuln": vuln,
                      "hops": [x.get("ipaddr") for x in h.findall("trace/hop") if x.get("ipaddr")]})
    return hosts

def demo():
    d = [("192.168.1.1", "gateway.lan", "Linux 5.15", [(22, "ssh", "OpenSSH 9.2"), (80, "http", "lighttpd 1.4"), (443, "https", "")], False),
         ("192.168.1.10", "nas.lan", "Linux 4.x", [(445, "smb", "Samba 4.13"), (5000, "http", "Synology DSM")], True),
         ("192.168.1.23", "printer.lan", "", [(631, "ipp", "CUPS 2.4"), (9100, "jetdirect", ""), (23, "telnet", "")], False),
         ("192.168.1.42", "dev-laptop", "Windows 11", [(135, "msrpc", ""), (3389, "rdp", "")], False),
         ("192.168.1.57", "cam-garage", "Linux 3.x", [(554, "rtsp", ""), (80, "http", "GoAhead 2.5")], True),
         ("192.168.1.88", "", "", [], False)]
    return [{"ip": i, "mac": "", "name": n, "os": o, "vuln": v,
             "hops": ([] if i.endswith(".1") else ["192.168.1.1"] + (["192.168.1.254"] if i.endswith(("42", "57")) else [])),
             "ports": [{"port": p, "proto": "tcp", "service": s, "version": ver, "scripts": ([{"id": "smb-vuln-ms17-010", "out": "VULNERABLE: Remote Code Execution (CVE-2017-0143)"}] if p == 445 else [{"id": "vulners", "out": "CVE-2021-33044 9.8 CVE-2020-25078 7.5"}] if (p == 80 and i.endswith("57")) else [])} for p, s, ver in ps]}
            for i, n, o, ps, v in d]

def run(job, args):
    xml = job["xml"]
    try:
        if job["demo"]:
            for k in range(1, 7):
                time.sleep(1.2); job["hosts"] = demo()[:k]
                if job["status"] == "stopped": break
        else:
            p = job["proc"] = subprocess.Popen(["nmap", *args, "-oX", xml, *job["target"].split()], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            while p.poll() is None:
                time.sleep(1); job["hosts"] = parse(xml) or job["hosts"]
                if time.time() - job["t0"] > 3600:
                    p.terminate(); job["status"], job["error"] = "stopped", "Stopped: 1 hour limit reached"
            job["hosts"] = parse(xml) or job["hosts"]
            if job["status"] != "stopped":
                job["status"] = "done" if p.returncode == 0 else "error"
                if p.returncode: job["error"] = p.stderr.read()[-300:]
        if job["status"] == "running": job["status"] = "done"
    except Exception as e:
        job["status"], job["error"] = "error", str(e)
    job["dur"] = int(time.time() - job["t0"]); save_history()

WATCH, ALERTS = [], []

def start_job(target, profile, args):
    jid = uuid.uuid4().hex[:8]
    JOBS[jid] = {"status": "running", "hosts": [], "error": "", "target": target, "profile": profile, "id": jid, "ts": time.time(),
                 "t0": time.time(), "demo": False, "xml": str(Path(tempfile.gettempdir()) / f"meridian-{jid}.xml")}
    audit(f"watch-scan {jid} target={target} profile={profile}")
    threading.Thread(target=run, args=(JOBS[jid], args), daemon=True).start()
    return jid

def diff_alert(prev, cur, label):
    now = time.strftime("%H:%M:%S"); old = {h["ip"]: {p["port"] for p in h["ports"]} for h in prev["hosts"]}
    for h in cur["hosts"]:
        if h["ip"] not in old: ALERTS.append(f"{now} NEW HOST {h['ip']} on {label}")
        else:
            for p in {p["port"] for p in h["ports"]} - old[h["ip"]]: ALERTS.append(f"{now} NEW PORT {h['ip']}:{p}")
    for ip in old:
        if ip not in {h["ip"] for h in cur["hosts"]}: ALERTS.append(f"{now} HOST GONE {ip}")

def watcher():
    while True:
        time.sleep(20)
        for w in list(WATCH):
            j = JOBS.get(w.get("jid"))
            if j and j["status"] == "running": continue
            if j and j["status"] == "done" and w.get("seen") != w["jid"]:
                if w.get("prev"): diff_alert(w["prev"], j, w["target"])
                w["prev"], w["seen"] = j, w["jid"]
            if time.time() >= w["next"] and not any(x["status"] == "running" for x in JOBS.values()):
                w["jid"] = start_job(w["target"], w["profile"], PROFILES[w["profile"]]); w["next"] = time.time() + w["every"] * 60

def handle_watch(d):
    if d.get("ack") is not True or d.get("profile") not in PROFILES: raise ValueError("Profile/authorization missing")
    t = valid_targets(d.get("target")); m = int(d.get("minutes", 0))
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
            html = (Path(__file__).parent / "index.html").read_text().replace("__TOKEN__", TOKEN)
            return self.send(200, html.encode(), "text/html; charset=utf-8")
        xm = re.fullmatch(r"/api/xml/([0-9a-f]{8})", self.path)
        if xm and xm.group(1) in JOBS and JOBS[xm.group(1)]["xml"] and Path(JOBS[xm.group(1)]["xml"]).exists():
            return self.send(200, Path(JOBS[xm.group(1)]["xml"]).read_bytes(), "application/xml")
        if self.path == "/api/alerts": return self.send(200, {"alerts": ALERTS[-30:], "watch": [{"target": w["target"], "profile": w["profile"], "every": w["every"]} for w in WATCH]})
        if self.path == "/api/net": return self.send(200, {"cidr": local_cidr(), "root": (os.geteuid() == 0) if hasattr(os, "geteuid") else None})
        if self.path == "/api/history":
            return self.send(200, [{"id": j["id"], "target": j["target"], "profile": j["profile"], "status": j["status"], "ts": j["ts"], "hosts": len(j["hosts"])} for j in sorted(JOBS.values(), key=lambda x: -x["ts"])])
        m = re.fullmatch(r"/api/scan/([0-9a-f]{8})", self.path)
        j = JOBS.get(m.group(1)) if m else None
        if not j: return self.send(404, {"error": "not found"})
        self.send(200, {k: j[k] for k in ("status", "hosts", "error", "target", "profile")} | {"elapsed": j.get("dur") if j["status"] != "running" else int(time.time() - j["t0"])})
    def do_POST(self):
        if not self.host_ok() or not self.origin_ok() or not secrets.compare_digest(self.headers.get("X-Token", ""), TOKEN): return self.send(403, {"error": "forbidden"})
        sm = re.fullmatch(r"/api/stop/([0-9a-f]{8})", self.path)
        if sm and sm.group(1) in JOBS:
            j = JOBS[sm.group(1)]; j["status"] = "stopped"
            if j.get("proc"): j["proc"].terminate()
            return self.send(200, {"ok": True})
        try:
            d = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 4096)))
            if self.path == "/api/watch": return self.send(*handle_watch(d))
            if (d.get("profile") not in PROFILES and d.get("profile") != "custom") or d.get("ack") is not True: raise ValueError("Profile/authorization missing")
            args = custom_args(d.get("options") or {}) if d["profile"] == "custom" else PROFILES[d["profile"]]
            demo_mode = bool(d.get("demo"))
            target = re.sub(r"[^\w.\-/ ,]", "", str(d.get("target") or "demo"))[:100] or "demo" if demo_mode else valid_targets(d.get("target"))
            if not demo_mode and not shutil.which("nmap"): raise ValueError("nmap not found. Install it or use demo mode.")
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as e:
            return self.send(400, {"error": str(e)})
        if not demo_mode and any_public(target) and d.get("public_ok") is not True:
            return self.send(409, {"error": "public"})
        if any(j["status"] == "running" for j in JOBS.values()):
            return self.send(409, {"error": "A scan is already running. Stop it first."})
        jid = uuid.uuid4().hex[:8]
        JOBS[jid] = {"status": "running", "hosts": [], "error": "", "target": target, "profile": d["profile"],
                     "id": jid, "ts": time.time(), "t0": time.time(), "demo": demo_mode, "xml": str(Path(tempfile.gettempdir()) / f"meridian-{jid}.xml")}
        audit(f"scan {jid} target={target} profile={d['profile']} public={any_public(target)} demo={demo_mode}")
        threading.Thread(target=run, args=(JOBS[jid], args), daemon=True).start()
        self.send(200, {"id": jid})

def find_browser():
    for b in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "brave-browser", "microsoft-edge"):
        if shutil.which(b): return shutil.which(b)

def open_window(url, srv):
    """Native-feeling window: pywebview if installed, else a Chromium-family --app window, else the default browser."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        # Chromium refuses to run as root, so start the window as the user who ran sudo.
        user, b = os.environ.get("SUDO_USER"), find_browser()
        if user and user != "root" and b:
            prof = str(Path(tempfile.gettempdir()) / f"meridian-ui-{uuid.uuid4().hex[:8]}")
            keep = "DISPLAY,XAUTHORITY,WAYLAND_DISPLAY,XDG_RUNTIME_DIR,DBUS_SESSION_BUS_ADDRESS"
            r = subprocess.run(["sudo", "-u", user, f"--preserve-env={keep}", b, f"--app={url}", f"--user-data-dir={prof}",
                                "--window-size=1360,860", "--no-first-run", "--disable-extensions"])
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
        prof = tempfile.mkdtemp(prefix="meridian-ui-")
        subprocess.run([b, f"--app={url}", f"--user-data-dir={prof}", "--window-size=1360,860", "--no-first-run", "--disable-extensions"])
        shutil.rmtree(prof, ignore_errors=True); return
    import webbrowser; webbrowser.open(url)
    print("No app-mode browser found; opened default browser. Ctrl+C to quit.")
    threading.Event().wait()

if __name__ == "__main__":
    load_history(); threading.Thread(target=watcher, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("MERIDIAN_PORT", 0))), H)
    PORT = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{PORT}"
    print(f"Meridian {url}  (nmap: {shutil.which('nmap') or 'NOT FOUND, sample-data mode only'})")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("Warning: running as root. Keep Meridian on localhost and scan only authorized targets.")
    try:
        if "--serve" in sys.argv: threading.Event().wait()   # headless: no window
        else: open_window(url, srv)
    except KeyboardInterrupt:
        pass
    print("Bye.")
