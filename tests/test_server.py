import json, sys, tempfile, threading, unittest, urllib.error, urllib.request
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
                        mock.patch.object(server.sys, "argv", ["meridian", "--uninstall"])]
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


if __name__ == "__main__":
    unittest.main()
