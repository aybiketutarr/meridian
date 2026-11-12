import json, sys, tempfile, threading, time, unittest, urllib.error, urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock
 
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402
 
 
class Validation(unittest.TestCase):
    def ok(self, t): return server.valid_targets(t)
    def bad(self, t):
        with self.assertRaises(ValueError): server.valid_targets(t)
 
    def test_accepts(self):
        for t in ("192.168.1.0/24", "10.0.0.0/22", "1.1.1.1", "scanme.nmap.org", "192.168.1.1-50", "192.168.1.5 192.168.1.9"):
            self.ok(t)
 
    def test_rejects_injection_and_junk(self):
        for t in ("-oX /tmp/x", "192.168.1.1;ls", "$(id)", "a_b.com", "1.2.3", "300.1.1.1", ""):
            self.bad(t)
 
    def test_size_limits(self):
        self.bad("10.0.0.0/8")
        self.bad("10.0.0.0/21")
        self.ok("10.0.0.0/23 10.0.4.0/23")          # exactly 1024 in total
        self.bad("10.0.0.0/23 10.0.4.0/23 10.0.8.1")  # 1025
        self.bad(" ".join(f"10.0.0.{i}" for i in range(33)))  # > 32 targets
 
    def test_bad_ranges(self):
        self.bad("192.168.1.50-10")
        self.bad("192.168.1.1-300")
        self.bad("10.0.0.1-8.8.8.8")
 
    def test_ipv6_message(self):
        with self.assertRaisesRegex(ValueError, "IPv6"): server.valid_targets("::1")
 
    def test_is_public(self):
        self.assertFalse(server.any_public("192.168.1.0/24 10.1.2.3 127.0.0.1"))
        self.assertTrue(server.any_public("8.8.8.8"))
        self.assertTrue(server.any_public("example.com"))
        self.assertTrue(server.any_public("192.168.1.1 8.8.8.8"))
 
 
class CustomArgs(unittest.TestCase):
    def test_whitelist(self):
        a = server.custom_args({"timing": 3, "ports": "22,80-90", "sv": True, "scripts": ["vulners", "evil"]})
        self.assertEqual(a, ["-T3", "-p", "22,80-90", "-sV", "--script", "vulners"])
 
    def test_rejects(self):
        for o in ({"ports": "22;ls"}, {"timing": 9}, {"timing": "x"}):
            with self.assertRaises(ValueError): server.custom_args(o)
 
 
XML = """<nmaprun><host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme"/><hostnames><hostname name="nas.lan"/></hostnames>
<ports><port protocol="tcp" portid="445"><state state="open"/><service name="smb" product="Samba" version="4.13"/>
<script id="smb-vuln-ms17-010" output="VULNERABLE: RCE"/></port>
<port protocol="tcp" portid="22"><state state="closed"/></port></ports></host>
<host><status state="down"/><address addr="192.168.1.99" addrtype="ipv4"/></host></nmaprun>"""
 
 
class Parse(unittest.TestCase):
    def test_parse(self):
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f: f.write(XML)
        hosts = server.parse(f.name)
        self.assertEqual(len(hosts), 1)                      # down host skipped
        h = hosts[0]
        self.assertEqual((h["ip"], h["name"], h["vendor"]), ("192.168.1.10", "nas.lan", "Acme"))
        self.assertEqual([p["port"] for p in h["ports"]], [445])  # closed port skipped
        self.assertTrue(h["vuln"])
 
    def test_parse_missing_file(self):
        self.assertIsNone(server.parse("/nonexistent.xml"))
 
 
class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        server.HIST = Path(cls.tmp.name) / "history.json"   # never touch the real ~/.local/share
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), server.H)
        server.PORT = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{server.PORT}"
 
    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.tmp.cleanup()
 
    def setUp(self): server.JOBS.clear()
 
    def req(self, path, body=None, token=True, host=None):
        h = {"Content-Type": "application/json", "Origin": self.base}
        if token: h["X-Token"] = server.TOKEN
        if host: h["Host"] = host
        r = urllib.request.Request(self.base + path, json.dumps(body).encode() if body is not None else None, h)
        try:
            with urllib.request.urlopen(r) as x: return x.status, json.loads(x.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")
 
    def test_index_has_token_and_security_headers(self):
        with urllib.request.urlopen(self.base + "/") as r:
            html = r.read().decode()
            self.assertIn(server.TOKEN, html); self.assertNotIn("__TOKEN__", html)
            self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
            self.assertEqual(r.headers["X-Frame-Options"], "DENY")
 
    def test_bad_host_blocked(self):
        self.assertEqual(self.req("/api/history", host="evil.com")[0], 403)
 
    def test_post_needs_token(self):
        self.assertEqual(self.req("/api/scan", {"demo": True, "profile": "quick", "ack": True}, token=False)[0], 403)
 
    def test_ack_required(self):
        self.assertEqual(self.req("/api/scan", {"demo": True, "profile": "quick"})[0], 400)
 
    def test_invalid_target_rejected_before_nmap_check(self):
        with mock.patch.object(server.shutil, "which", return_value=None):
            c, d = self.req("/api/scan", {"target": "-oX /tmp/x", "profile": "quick", "ack": True})
        self.assertEqual(c, 400); self.assertIn("Invalid target", d["error"])
 
    def test_public_target_needs_confirmation(self):
        with mock.patch.object(server.shutil, "which", return_value="/usr/bin/nmap"), mock.patch.object(server, "run"):
            c, d = self.req("/api/scan", {"target": "8.8.8.8", "profile": "quick", "ack": True})
            self.assertEqual((c, d["error"]), (409, "public"))
            c, d = self.req("/api/scan", {"target": "8.8.8.8", "profile": "quick", "ack": True, "public_ok": True})
            self.assertEqual(c, 200)
 
    def test_one_scan_at_a_time(self):
        with mock.patch.object(server, "run"):
            self.assertEqual(self.req("/api/scan", {"demo": True, "profile": "quick", "ack": True})[0], 200)
            self.assertEqual(self.req("/api/scan", {"demo": True, "profile": "quick", "ack": True})[0], 409)
 
    def test_demo_scan_and_stop(self):
        c, d = self.req("/api/scan", {"demo": True, "profile": "service", "ack": True}); self.assertEqual(c, 200)
        c, j = self.req("/api/scan/" + d["id"]); self.assertEqual(c, 200); self.assertEqual(j["profile"], "service")
        self.assertEqual(self.req("/api/stop/" + d["id"], {})[0], 200)
 
    def test_demo_label_is_sanitized(self):
        c, d = self.req("/api/scan", {"demo": True, "target": "x\nFAKE LOG LINE<script>", "profile": "quick", "ack": True})
        self.assertEqual(c, 200)
        self.assertNotIn("\n", server.JOBS[d["id"]]["target"]); self.assertNotIn("<", server.JOBS[d["id"]]["target"])
 
    def test_net_reports_root_flag(self):
        c, d = self.req("/api/net")
        self.assertEqual(c, 200); self.assertIn("cidr", d); self.assertIn("root", d)
 
    def post_scan(self, body):
        with mock.patch.object(server.shutil, "which", return_value="/usr/bin/nmap"), mock.patch.object(server, "run") as run:
            c, d = self.req("/api/scan", {"profile": "quick", "ack": True, **body})
            time.sleep(0.3)
            return c, d, (run.call_args[0][1] if run.call_args else None)
 
    def test_lookup_adds_vulners_and_is_reported(self):
        c, d, args = self.post_scan({"target": "192.168.1.5", "lookup": True})
        self.assertEqual(c, 200); self.assertIn("vulners", " ".join(args))
        self.assertTrue(self.req("/api/scan/" + d["id"])[1]["lookup"])
 
    def test_no_lookup_by_default(self):
        c, d, args = self.post_scan({"target": "192.168.1.5"})
        self.assertEqual(c, 200); self.assertNotIn("vulners", " ".join(args))
        self.assertFalse(self.req("/api/scan/" + d["id"])[1]["lookup"])
 
    def test_host_discovery_never_looks_up(self):
        c, d, args = self.post_scan({"target": "192.168.1.0/24", "profile": "ping", "lookup": True})
        self.assertEqual(args, ["-sn"]); self.assertFalse(self.req("/api/scan/" + d["id"])[1]["lookup"])
 
    def test_lookup_must_be_exactly_true(self):
        c, d, args = self.post_scan({"target": "192.168.1.5", "lookup": "yes"})
        self.assertNotIn("vulners", " ".join(args))
 
    def test_api_save_over_http(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(server.os.environ, {"HOME": d}):
            c, r = self.req("/api/save", {"name": "meridian.html", "data": "<p>hi</p>"})
            self.assertEqual(c, 200); self.assertEqual(Path(r["path"]).read_text(), "<p>hi</p>")
            self.assertEqual(self.req("/api/save", {"name": "x.py", "data": "print(1)"})[0], 400)
            self.assertEqual(self.req("/api/save", {"name": "a.json", "data": "x"}, token=False)[0], 403)
 
    def test_api_save_rejects_oversized_body(self):
        try: code = self.req("/api/save", {"name": "a.json", "data": "x" * 13_000_000})[0]
        except urllib.error.URLError: code = 400      # the server refuses without reading the body and closes the connection
        self.assertEqual(code, 400)
 
    def test_unknown_profile(self):
        self.assertEqual(self.req("/api/scan", {"demo": True, "profile": "rm -rf", "ack": True})[0], 400)
 
 
class RootWindow(unittest.TestCase):
    def test_root_launches_browser_as_sudo_user(self):
        with mock.patch.object(server.os, "geteuid", return_value=0), \
             mock.patch.dict(server.os.environ, {"SUDO_USER": "alice"}), \
             mock.patch.object(server, "find_browser", return_value="/usr/bin/chromium"), \
             mock.patch.object(server.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
            server.open_window("http://127.0.0.1:1234", None)
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[:3], ["sudo", "-u", "alice"])
        self.assertIn("/usr/bin/chromium", cmd)
        self.assertNotIn("--no-sandbox", cmd)
 
    def test_real_root_without_sudo_user_does_not_launch_browser(self):
        env = {k: v for k, v in server.os.environ.items() if k != "SUDO_USER"}
        with mock.patch.object(server.os, "geteuid", return_value=0), \
             mock.patch.dict(server.os.environ, env, clear=True), \
             mock.patch.object(server, "find_browser", return_value="/usr/bin/chromium"), \
             mock.patch.object(server.subprocess, "run") as run, \
             mock.patch.object(server.threading, "Event") as ev:
            server.open_window("http://127.0.0.1:1234", None)
        run.assert_not_called(); ev.return_value.wait.assert_called()
 
 
class Uninstall(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.home = Path(self.tmp.name)
        for p in (".local/share/meridian-app/server.py", ".local/bin/meridian", ".local/share/applications/meridian.desktop",
                  ".local/share/meridian/history.json", ".local/share/meridian/audit.log", ".local/share/meridian/browser-profile/Default/x"):
            f = self.home / p; f.parent.mkdir(parents=True, exist_ok=True); f.write_text("x")
        self.patches = [mock.patch.dict(server.os.environ, {"HOME": str(self.home)}),
                        mock.patch.object(server, "HIST", self.home / ".local/share/meridian/history.json"),
                        mock.patch.object(server.os, "geteuid", return_value=1000),
                        mock.patch.object(server.sys, "argv", ["meridian", "--uninstall"]),
                        mock.patch("builtins.print")]
        for p in self.patches: p.start()
        server.os.environ.pop("XDG_DATA_HOME", None)
 
    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.tmp.cleanup()
 
    def gone(self, rel): return not (self.home / rel).exists()
 
    def test_removes_app_and_saved_data(self):
        with mock.patch("builtins.input", return_value="y"): self.assertEqual(server.uninstall(), 0)
        for rel in (".local/share/meridian-app", ".local/bin/meridian", ".local/share/applications/meridian.desktop", ".local/share/meridian"):
            self.assertTrue(self.gone(rel), rel)
 
    def test_keep_data_flag(self):
        server.sys.argv.append("--keep-data")
        with mock.patch("builtins.input", return_value="y"): self.assertEqual(server.uninstall(), 0)
        self.assertTrue(self.gone(".local/bin/meridian")); self.assertTrue(self.gone(".local/share/meridian-app"))
        self.assertFalse(self.gone(".local/share/meridian/history.json")); self.assertFalse(self.gone(".local/share/meridian/audit.log"))
 
    def test_yes_flag_skips_prompt(self):
        server.sys.argv.append("--yes")
        with mock.patch("builtins.input", side_effect=AssertionError("must not prompt")): self.assertEqual(server.uninstall(), 0)
        self.assertTrue(self.gone(".local/share/meridian"))
 
    def test_cancel_keeps_everything(self):
        with mock.patch("builtins.input", return_value="n"): self.assertEqual(server.uninstall(), 1)
        self.assertFalse(self.gone(".local/bin/meridian")); self.assertFalse(self.gone(".local/share/meridian/history.json"))
 
    def test_refuses_under_root(self):
        with mock.patch.object(server.os, "geteuid", return_value=0): self.assertEqual(server.uninstall(), 1)
        self.assertFalse(self.gone(".local/bin/meridian"))
 
    def test_nothing_installed(self):
        import shutil
        for rel in (".local/share/meridian-app", ".local/bin/meridian", ".local/share/applications/meridian.desktop", ".local/share/meridian"):
            f = self.home / rel; shutil.rmtree(f) if f.is_dir() else f.unlink()
        self.assertEqual(server.uninstall(), 0)
 
 
class PersistentProfile(unittest.TestCase):
    def test_window_uses_persistent_profile_dir(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(server, "HIST", Path(d) / "meridian" / "history.json"), \
             mock.patch.object(server.os, "geteuid", return_value=1000), \
             mock.patch.dict(sys.modules, {"webview": None}), \
             mock.patch.object(server, "find_browser", return_value="/usr/bin/chromium"), \
             mock.patch.object(server.subprocess, "run") as run:
            server.open_window("http://127.0.0.1:8765", None)
            prof = Path(d) / "meridian" / "browser-profile"
            self.assertIn(f"--user-data-dir={prof}", run.call_args[0][0])
            self.assertTrue(prof.is_dir())   # not deleted after the window closes
 
 
VULNERS_20 = """<nmaprun><host><status state="up"/><address addr="192.168.1.44" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"><cpe>cpe:/a:vsftpd:vsftpd:2.3.4</cpe></service>
<script id="vulners" output="x"><elem key="schema">2.0</elem><elem key="mode">free</elem>
<table key="cpe:/a:vsftpd:vsftpd:2.3.4">
<table><elem key="id">CVE-2011-2523</elem><elem key="type">cve</elem><elem key="severity">CRITICAL</elem><elem key="cvss">9.8</elem><elem key="is_exploit">false</elem><elem key="exploit_known">true</elem><elem key="ai_score">9.5</elem><elem key="href">https://vulners.com/cve/CVE-2011-2523</elem><elem key="source_href">https://nvd.nist.gov/vuln/detail/CVE-2011-2523</elem></table>
<table><elem key="id">EDB-ID:17491</elem><elem key="type">exploitdb</elem><elem key="cvss">10.0</elem><elem key="is_exploit">true</elem><elem key="href">javascript:alert(1)</elem></table>
<table><elem key="id">CVE-2007-0001</elem><elem key="type">cve</elem><elem key="cvss">4.3</elem><elem key="is_exploit">false</elem></table>
</table></script></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/><script id="http-title" output="Welcome"/></port>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="Foo" version="1.0"/><script id="vulners" output="raw text only"/></port>
</ports></host></nmaprun>"""
 
VULNERS_1X = """<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="7.2p2"/>
<script id="vulners" output="x"><table key="cpe:/a:openbsd:openssh:7.2p2"><table><elem key="is_exploit">true</elem><elem key="cvss">7.8</elem><elem key="id">EDB-ID:40888</elem><elem key="type">exploitdb</elem></table>
<table><elem key="is_exploit">false</elem><elem key="cvss">5.3</elem><elem key="id">CVE-2016-6210</elem><elem key="type">cve</elem></table></table></script></port></ports></host></nmaprun>"""
 
 
def parse_xml(txt):
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f: f.write(txt)
    return server.parse(f.name)
 
 
class VulnLookup(unittest.TestCase):
    def test_parse_vulners_2x(self):
        hosts = parse_xml(VULNERS_20); p21, p80, p8080 = hosts[0]["ports"]
        v = p21["vulns"]
        self.assertEqual((v["mode"], v["total"], v["cves"], v["exploits"], v["kev"]), ("free", 3, 2, 2, 0))
        self.assertEqual(v["items"][0]["id"], "CVE-2011-2523")           # exploit + likelihood outranks a bare 10.0
        self.assertEqual(v["items"][-1]["id"], "CVE-2007-0001")          # low, unexploited last
        self.assertEqual(v["items"][0]["src"], "https://nvd.nist.gov/vuln/detail/CVE-2011-2523")
        self.assertTrue(p21["ver"]); self.assertEqual(p21["cpes"], ["cpe:/a:vsftpd:vsftpd:2.3.4"])
        self.assertNotIn("vulners", [s["id"] for s in p21["scripts"]])     # structured, not shown as raw text
        self.assertFalse(p80["ver"]); self.assertEqual(p80["cpes"], []); self.assertNotIn("vulns", p80)
        self.assertIn("http-title", [s["id"] for s in p80["scripts"]])
 
    def test_unsafe_links_are_dropped(self):
        edb = [i for i in parse_xml(VULNERS_20)[0]["ports"][0]["vulns"]["items"] if i["id"].startswith("EDB")][0]
        self.assertEqual(edb["href"], "")                                  # javascript: is never kept
        self.assertEqual(server.safe_url("https://vulners.com/x"), "https://vulners.com/x")
        for bad in ("javascript:alert(1)", "http://x", "data:text/html,x", "", None): self.assertEqual(server.safe_url(bad), "")
 
    def test_parse_vulners_1x(self):
        v = parse_xml(VULNERS_1X)[0]["ports"][0]["vulns"]
        self.assertEqual((v["mode"], v["total"], v["cves"], v["exploits"]), ("", 2, 1, 1))
        self.assertEqual(v["items"][0]["id"], "EDB-ID:40888")             # exploit first
        self.assertEqual(v["items"][1]["sev"], "medium")                  # derived from CVSS when no severity is given
 
    def test_unstructured_vulners_output_is_kept_as_text(self):
        p8080 = parse_xml(VULNERS_20)[0]["ports"][2]
        self.assertNotIn("vulns", p8080); self.assertEqual([s["id"] for s in p8080["scripts"]], ["vulners"])
 
    def test_kev_and_active_outrank_everything(self):
        x = ET_vulners([("A", "9.9", "true", "false", "0.99"), ("B", "5.0", "false", "true", None)])
        self.assertEqual([i["id"] for i in x["items"]], ["B", "A"])
 
    def test_scan_args_every_port_profile(self):
        for prof in ("quick", "service", "full", "os", "trace", "vuln"):
            a = server.scan_args(prof, None, True)
            self.assertIn("-sV", a, prof); self.assertIn("vulners", " ".join(a), prof)
            self.assertIn("vulners.paths=none,vulners.max_items=0", a, prof)   # no web sweep, never spend credits
            self.assertEqual(server.scan_args(prof, None, False), server.PROFILES[prof], prof)
        self.assertIn("--version-light", server.scan_args("quick", None, True))
        self.assertNotIn("--version-light", server.scan_args("full", None, True))   # already runs -sV
        self.assertIn("vuln,vulners", server.scan_args("vuln", None, True))
 
    def test_host_discovery_is_left_alone(self):
        self.assertEqual(server.scan_args("ping", None, True), ["-sn"])
        self.assertEqual(server.scan_args("custom", {"sv": True, "sn": True}, True), ["-T4", "-sV", "-sn"])
 
    def test_custom_respects_version_detection_switch(self):
        self.assertEqual(server.scan_args("custom", {"sv": False}, True), ["-T4"])
        self.assertIn("vulners", " ".join(server.scan_args("custom", {"sv": True, "ports": "21"}, True)))
 
    def test_demo_data_only_with_lookup(self):
        on = {(h["ip"], p["port"]): p for h in server.demo(True) for p in h["ports"]}
        off = [p for h in server.demo(False) for p in h["ports"]]
        self.assertEqual(on[("192.168.1.10", 21)]["vulns"]["items"][0]["id"], "CVE-2011-2523")
        self.assertFalse(any("vulns" in p for p in off))
 
 
def ET_vulners(rows):
    import xml.etree.ElementTree as ET
    xml = "<script id='vulners'><table key='cpe:/a:x:y:1'>" + "".join(
        f"<table><elem key='id'>{i}</elem><elem key='cvss'>{c}</elem><elem key='is_exploit'>{e}</elem><elem key='kev'>{k}</elem>"
        + (f"<elem key='epss'>{p}</elem>" if p else "") + "</table>" for i, c, e, k, p in rows) + "</table></script>"
    return server.parse_vulners(ET.fromstring(xml))
 
 
class SaveExport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.home = Path(self.tmp.name)
        self.p = [mock.patch.dict(server.os.environ, {"HOME": str(self.home)}), mock.patch.object(server, "HIST", self.home / "m" / "history.json")]
        for x in self.p: x.start()
 
    def tearDown(self):
        for x in reversed(self.p): x.stop()
        self.tmp.cleanup()
 
    def test_saves_into_downloads_with_private_permissions(self):
        r = server.save_export({"name": "meridian.json", "data": '{"a": 1}'}); f = Path(r["path"])
        self.assertEqual(f.parent, self.home / "Downloads"); self.assertEqual(f.read_text(), '{"a": 1}')
        self.assertEqual(f.stat().st_mode & 0o777, 0o600); self.assertRegex(f.name, r"^meridian-\d{8}-\d{6}\.json$")
 
    def test_never_overwrites(self):
        a = server.save_export({"name": "meridian.csv", "data": "1"})["path"]; b = server.save_export({"name": "meridian.csv", "data": "2"})["path"]
        self.assertNotEqual(a, b); self.assertEqual(Path(a).read_text(), "1")
 
    def test_rejects_bad_names_and_data(self):
        for bad in ({"name": "evil.sh", "data": "x"}, {"name": "x.exe", "data": "x"}, {"name": "noext", "data": "x"},
                    {"name": "a.json", "data": 5}, {"name": "a.json", "data": None}, {"name": "a.json", "data": "x" * (server.MAX_SAVE + 1)}):
            with self.assertRaises(ValueError): server.save_export(bad)
 
    def test_path_traversal_stays_in_downloads(self):
        f = Path(server.save_export({"name": "../../etc/passwd.json", "data": "x"})["path"])
        self.assertEqual(f.parent, self.home / "Downloads"); self.assertTrue(f.name.startswith("passwd-"))
 
    def test_respects_xdg_download_dir_inside_home(self):
        (self.home / ".config").mkdir(); (self.home / ".config" / "user-dirs.dirs").write_text('XDG_DOWNLOAD_DIR="$HOME/Indirilenler"\n')
        self.assertEqual(Path(server.save_export({"name": "a.md", "data": "x"})["path"]).parent, self.home / "Indirilenler")
 
    def test_xdg_dir_outside_home_is_ignored(self):
        (self.home / ".config").mkdir(); (self.home / ".config" / "user-dirs.dirs").write_text('XDG_DOWNLOAD_DIR="/tmp/evil"\n')
        self.assertEqual(Path(server.save_export({"name": "a.md", "data": "x"})["path"]).parent, self.home / "Downloads")
 
    def test_file_goes_to_the_sudo_user(self):
        with mock.patch.object(server.os, "geteuid", return_value=0), mock.patch.dict(server.os.environ, {"SUDO_UID": "1234", "SUDO_GID": "1235"}), \
             mock.patch.object(server.os, "chown") as chown:
            f = server.save_export({"name": "a.json", "data": "x"})["path"]
        chown.assert_called_once_with(Path(f), 1234, 1235)
 
 
if __name__ == "__main__":
    unittest.main()
