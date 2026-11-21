"""v0.4.0 features: offline vulnerability hints, trusted-device list, structured alerts, error codes."""
import json, os, sys, tempfile, threading, time, unittest, urllib.error, urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402

POSIX = os.name != "nt"


class OfflineRules(unittest.TestCase):
    HIT = [("vsftpd", "2.3.4", "CVE-2011-2523"), ("Apache httpd", "2.4.49", "CVE-2021-41773"), ("Apache httpd", "2.4.50", "CVE-2021-42013"),
           ("OpenSSH", "7.2p2 Ubuntu 4ubuntu2.8", "CVE-2018-15473"), ("OpenSSH", "7.7", "CVE-2018-15473"), ("Samba smbd", "4.5.9", "CVE-2017-7494"),
           ("Samba smbd", "3.6.25", "CVE-2017-7494"), ("Exim smtpd", "4.89", "CVE-2019-10149"), ("OpenSSL", "1.0.1f", "CVE-2014-0160"),
           ("UnrealIRCd", "3.2.8.1", "CVE-2010-2075"), ("ProFTPD", "1.3.5", "CVE-2015-3306")]
    MISS = [("vsftpd", "3.0.5"), ("Apache httpd", "2.4.51"), ("Apache httpd", "2.4.48"), ("OpenSSH", "7.8"), ("OpenSSH", "9.2p1 Debian 2+deb12u3"),
            ("Samba smbd", "4.4.14"), ("Samba smbd", "4.6.4"), ("Samba smbd", "3.X - 4.X"), ("Exim smtpd", "4.92"), ("Exim smtpd", "4.86"),
            ("OpenSSL", "1.0.2"), ("OpenSSL", "1.0.1g"), ("UnrealIRCd", "3.2.8"), ("ProFTPD", "1.3.5a"), ("nginx", "1.2.3"), ("vsftpd", ""), ("", ""),
            ("something", "2.3.4")]

    def test_known_releases_are_flagged(self):
        for prod, ver, cve in self.HIT:
            self.assertEqual([i["id"] for i in server.offline_items(prod, ver)], [cve], (prod, ver))

    def test_other_releases_are_not(self):
        for prod, ver in self.MISS: self.assertEqual(server.offline_items(prod, ver), [], (prod, ver))

    def test_items_have_the_shape_the_ui_expects(self):
        for prod, ver, cve in self.HIT:
            i = server.offline_items(prod, ver)[0]
            self.assertTrue(i["offline"]); self.assertTrue(i["exploit"]); self.assertFalse(i["kev"])
            self.assertTrue(i["href"].startswith("https://") and i["src"].startswith("https://") and cve in i["href"])
            self.assertIn(i["sev"], ("critical", "high", "medium"))

    def test_every_rule_has_a_translation_key_in_every_language(self):
        for code, d in server.load_locales().items():
            for rule in server.OFFLINE_RULES: self.assertIn("off." + rule[2], d, code)

    def test_version_numbers(self):
        self.assertEqual(server._vt("2.4.49"), (2, 4, 49)); self.assertEqual(server._vt("9.2p1 Debian"), (9, 2))
        self.assertEqual(server._vt("3.X - 4.X"), (3,)); self.assertEqual(server._vt(""), ())

    def test_scan_args(self):
        a = server.scan_args("quick", offline=True)
        self.assertIn("-sV", a); self.assertIn("--version-light", a); self.assertNotIn("--script", a)         # versions only: nothing is sent anywhere
        self.assertEqual(server.scan_args("ping", offline=True), server.PROFILES["ping"])
        self.assertEqual(server.scan_args("quick"), server.PROFILES["quick"])
        self.assertNotIn("-sV", server.scan_args("custom", {"sv": False, "timing": 3, "ports": "", "scripts": []}, offline=True))
        self.assertIn("vulners", " ".join(server.scan_args("quick", lookup=True, offline=True)))

    def test_merge_with_the_online_lookup_keeps_each_id_once(self):
        online = server._vsum([{"id": "CVE-2011-2523", "type": "cve", "cvss": 9.8, "sev": "critical", "kev": False, "active": False, "exploit": True, "epss": None, "ai": None, "title": "", "href": "", "src": "", "cpe": ""},
                               {"id": "CVE-2000-0001", "type": "cve", "cvss": 5.0, "sev": "medium", "kev": False, "active": False, "exploit": False, "epss": None, "ai": None, "title": "", "href": "", "src": "", "cpe": ""}],
                              "free", limit=1, extra=3)               # the lookup found 5 but only 1 item is kept
        hosts = [{"ip": "10.0.0.1", "ports": [{"port": 21, "product": "vsftpd", "vnum": "2.3.4", "vulns": online},
                                              {"port": 80, "product": "Apache httpd", "vnum": "2.4.49", "vulns": None}]}]
        server.attach_offline(hosts)
        self.assertEqual(hosts[0]["ports"][0]["vulns"], online)           # same id: nothing added, nothing changed
        v80 = hosts[0]["ports"][1]["vulns"]; self.assertEqual((v80["mode"], v80["total"], v80["items"][0]["id"]), ("offline", 1, "CVE-2021-41773"))
        h2 = [{"ip": "10.0.0.2", "ports": [{"port": 80, "product": "Apache httpd", "vnum": "2.4.50", "vulns": online}]}]
        server.attach_offline(h2); v = h2[0]["ports"][0]["vulns"]
        self.assertEqual(v["mode"], "free+offline"); self.assertEqual(v["total"], online["total"] + 1); self.assertIn("CVE-2021-42013", [i["id"] for i in v["items"]])

    def test_parse_keeps_product_and_version_separately(self):
        xml = """<nmaprun><host><status state="up"/><address addr="192.168.1.5" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/></port></ports></host></nmaprun>"""
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.xml"; f.write_text(xml, encoding="utf-8")
            p = server.parse(str(f))[0]["ports"][0]
        self.assertEqual((p["product"], p["vnum"]), ("vsftpd", "2.3.4"))

    def test_demo(self):
        plain = server.demo()
        self.assertTrue(all("vulns" not in p or p["vulns"] is None for h in plain for p in h["ports"]))
        off = {(h["ip"], p["port"]): p.get("vulns") for h in server.demo(offline=True) for p in h["ports"]}
        self.assertEqual(off[("192.168.1.10", 21)]["items"][0]["id"], "CVE-2011-2523"); self.assertEqual(off[("192.168.1.10", 21)]["mode"], "offline")
        self.assertEqual(off[("192.168.1.10", 8080)]["items"][0]["id"], "CVE-2021-41773")
        self.assertEqual([k for k, v in off.items() if v], [("192.168.1.10", 21), ("192.168.1.10", 8080)])
        self.assertEqual(server.split_version("Apache httpd 2.4.49"), ("Apache httpd", "2.4.49")); self.assertEqual(server.split_version("Synology DSM"), ("Synology DSM", ""))


class Devices(unittest.TestCase):
    MAC, MAC2 = "AA:BB:CC:00:11:22", "AA:BB:CC:00:11:33"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.p = mock.patch.object(server, "HIST", Path(self.tmp.name) / "meridian" / "history.json"); self.p.start()
    def tearDown(self): self.p.stop(); self.tmp.cleanup()

    def test_keys(self):
        self.assertEqual(server.device_key({"mac": "aa:bb:cc:00:11:22", "ip": "10.0.0.5"}), self.MAC)
        self.assertEqual(server.device_key({"mac": "", "ip": "10.0.0.5"}), "ip:10.0.0.5")
        self.assertEqual(server.device_key({"mac": "garbage", "ip": "10.0.0.5"}), "ip:10.0.0.5")

    def test_trust_label_and_forget(self):
        self.assertEqual(server.load_devices(), {})
        server.update_devices({"key": self.MAC, "trusted": True, "label": "  Mom's phone\x00\x07  "})
        self.assertEqual(server.load_devices(), {self.MAC: {"trusted": True, "label": "Mom's phone"}})
        server.update_devices({"key": self.MAC, "label": "x" * 100}); self.assertEqual(len(server.load_devices()[self.MAC]["label"]), 40)
        server.update_devices({"key": self.MAC, "trusted": False, "label": ""}); self.assertEqual(server.load_devices(), {})     # nothing worth remembering

    def test_baseline_and_clear(self):
        server.update_devices({"trust": [self.MAC, "ip:10.0.0.9"]})
        self.assertTrue(all(v["trusted"] for v in server.load_devices().values()) and len(server.load_devices()) == 2)
        server.update_devices({"clear": True}); self.assertEqual(server.load_devices(), {})

    def test_rejects_junk(self):
        for bad in ({"key": "aa:bb:cc:00:11:22"}, {"key": "ip:1.2.3"}, {"key": "../x"}, {"key": 5}, {}, {"trust": ["nope"]}, [], "x", None):
            with self.assertRaises(ValueError, msg=repr(bad)): server.update_devices(bad)
        self.assertEqual(server.load_devices(), {})
        with self.assertRaises(ValueError): server.update_devices({"trust": [f"ip:10.0.{i // 250}.{i % 250}" for i in range(server.MAX_DEVICES + 1)]})

    def test_trusted_is_only_ever_exactly_true(self):
        server.update_devices({"key": self.MAC, "trusted": "yes", "label": "a"}); self.assertFalse(server.load_devices()[self.MAC]["trusted"])

    def test_damaged_file_is_ignored(self):
        d = server.data_dir(); f = d / "devices.json"
        for junk in ("not json", "[1,2]", "5"):
            f.write_text(junk, encoding="utf-8"); self.assertEqual(server.load_devices(), {}, junk)
        f.write_text(json.dumps({"../x": {"trusted": True}, self.MAC: "x", self.MAC2: {"trusted": True, "label": 5}}), encoding="utf-8")
        self.assertEqual(server.load_devices(), {self.MAC2: {"trusted": True, "label": "5"}})          # only well-formed entries survive

    @unittest.skipIf(not POSIX, "POSIX file modes")
    def test_file_is_private_and_atomic(self):
        server.update_devices({"key": self.MAC, "trusted": True}); f = server.HIST.parent / "devices.json"
        self.assertEqual(f.stat().st_mode & 0o777, 0o600); self.assertEqual([x.name for x in server.HIST.parent.iterdir() if x.name.startswith(".tmp-")], [])


class Alerts(unittest.TestCase):
    MAC = "AA:BB:CC:00:11:22"
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.p = mock.patch.object(server, "HIST", Path(self.tmp.name) / "m" / "history.json"); self.p.start()
        server.ALERTS.clear()
    def tearDown(self): self.p.stop(); self.tmp.cleanup(); server.ALERTS.clear()
    @staticmethod
    def scan(*hosts): return {"hosts": [{"ip": ip, "mac": mac, "ports": [{"port": p} for p in ports]} for ip, mac, ports in hosts]}

    def test_alerts_are_structured(self):
        n = server.ALERT_N[0]
        server.diff_alert(self.scan(("10.0.0.1", "", [22]), ("10.0.0.2", "", [])), self.scan(("10.0.0.1", "", [22, 80]), ("10.0.0.3", "", [])), "10.0.0.0/24")
        got = {(a["kind"], a["ip"], a.get("port")) for a in server.ALERTS}
        self.assertEqual(got, {("new_port", "10.0.0.1", 80), ("new_host", "10.0.0.3", None), ("host_gone", "10.0.0.2", None)})
        self.assertTrue(all(isinstance(a, dict) and a["target"] == "10.0.0.0/24" and a["t"] for a in server.ALERTS)); self.assertEqual(server.ALERT_N[0], n + 3)

    def test_a_new_device_outside_the_trusted_list_is_flagged_unknown(self):
        server.update_devices({"key": self.MAC, "trusted": True})
        server.diff_alert(self.scan(("10.0.0.1", self.MAC, [])), self.scan(("10.0.0.1", self.MAC, []), ("10.0.0.7", "11:22:33:44:55:66", [])), "t")
        self.assertEqual([(a["kind"], a["ip"]) for a in server.ALERTS], [("unknown", "10.0.0.7")])
        server.ALERTS.clear(); server.update_devices({"key": "11:22:33:44:55:66", "trusted": True})
        server.diff_alert(self.scan(("10.0.0.1", self.MAC, [])), self.scan(("10.0.0.1", self.MAC, []), ("10.0.0.7", "11:22:33:44:55:66", [])), "t")
        self.assertEqual([a["kind"] for a in server.ALERTS], ["new_host"])         # trusted: just new

    def test_without_a_trusted_list_nothing_is_called_unknown(self):
        server.diff_alert(self.scan(), self.scan(("10.0.0.7", "", [])), "t"); self.assertEqual([a["kind"] for a in server.ALERTS], ["new_host"])


class Live(unittest.TestCase):
    """The HTTP surface of the new features."""
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(); cls.hp = mock.patch.object(server, "HIST", Path(cls.tmp.name) / "history.json"); cls.hp.start()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), server.H); server.PORT = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start(); cls.base = f"http://127.0.0.1:{server.PORT}"; cls.sid = server.new_session()
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown(); cls.hp.stop(); cls.tmp.cleanup()
    def setUp(self): server.JOBS.clear()

    def req(self, path, body=None, token=True, raw=None):
        h = {"Content-Type": "application/json", "Origin": self.base, "Cookie": f"{server.COOKIE}={self.sid}"}
        if token: h["X-Token"] = server.TOKEN
        r = urllib.request.Request(self.base + path, raw if raw is not None else (json.dumps(body).encode() if body is not None else None), h)
        try:
            with urllib.request.urlopen(r) as x: return x.status, json.loads(x.read() or b"{}")
        except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}")

    def test_devices_endpoint(self):
        self.assertEqual(self.req("/api/devices"), (200, {"devices": {}}))
        self.assertEqual(self.req("/api/devices", {"key": "AA:BB:CC:00:11:22", "trusted": True}, token=False)[0], 403)
        c, d = self.req("/api/devices", {"key": "AA:BB:CC:00:11:22", "trusted": True, "label": "NAS"})
        self.assertEqual((c, d["devices"]["AA:BB:CC:00:11:22"]), (200, {"trusted": True, "label": "NAS"}))
        self.assertEqual(self.req("/api/devices")[1], d)
        c, d = self.req("/api/devices", {"key": "nope"}); self.assertEqual((c, d["code"]), (400, "device"))
        self.assertEqual(self.req("/api/devices", raw=b"{not json")[1]["code"], "device")
        try: code = self.req("/api/devices", raw=b"x" * 70000)[0]
        except (urllib.error.URLError, ConnectionError): code = 400      # refused without reading the body; macOS and Windows report the closed connection as an error
        self.assertEqual(code, 400)
        c, d = self.req("/api/devices", {"trust": ["ip:10.0.0.1", "ip:10.0.0.2"]}); self.assertEqual((c, len(d["devices"])), (200, 3))
        self.assertEqual(self.req("/api/devices", {"clear": True})[1], {"devices": {}})

    def test_errors_carry_a_code_for_the_ui_to_translate(self):
        self.assertEqual(self.req("/api/scan", {"target": "not a host!", "profile": "quick", "ack": True})[1]["code"], "target")      # validated before nmap is even looked for
        c, d = self.req("/api/scan", {"target": "192.168.1.0/24", "profile": "quick", "demo": True}); self.assertEqual((c, d["code"]), (400, "auth"))
        self.assertTrue(set(server.ERR_CODES.values()) <= {k[4:] for k in server.load_locales()["en"] if k.startswith("err.")})

    def test_index_carries_every_language_and_the_forced_one(self):
        with mock.patch.object(server, "UI_LANG", "tr"):
            with urllib.request.urlopen(urllib.request.Request(self.base + "/", headers={"Cookie": f"{server.COOKIE}={self.sid}"})) as r: html = r.read().decode("utf-8")
        self.assertIn('DEFLANG="tr"', html); self.assertNotIn("__LANG__", html); self.assertNotIn("/*__LOCALES__*/{}", html)
        for code in server.load_locales(): self.assertIn(f'"_name":"{server.load_locales()[code]["_name"]}"', html)
        self.assertIn("Zafiyet", html)                                              # Turkish text really is in the page, as UTF-8

    def test_offline_hints_end_to_end(self):
        c, d = self.req("/api/scan", {"target": "192.168.1.0/24", "profile": "quick", "ack": True, "demo": True, "offline": True}); self.assertEqual(c, 200)
        jid = d["id"]; deadline = time.time() + 40
        while time.time() < deadline:
            c, j = self.req("/api/scan/" + jid)
            if j["status"] != "running": break
            time.sleep(0.5)
        self.assertEqual((j["status"], j["offline"], j["lookup"]), ("done", True, False))
        vs = [p["vulns"] for h in j["hosts"] for p in h["ports"] if p.get("vulns")]
        self.assertEqual(sorted(i["id"] for v in vs for i in v["items"]), ["CVE-2011-2523", "CVE-2021-41773"])
        # host discovery never asks for hints
        c, d = self.req("/api/scan", {"target": "192.168.1.0/24", "profile": "ping", "ack": True, "demo": True, "offline": True})
        self.assertEqual(c, 200); jid = d["id"]; deadline = time.time() + 40
        while time.time() < deadline:
            c, j = self.req("/api/scan/" + jid)
            if j["status"] != "running": break
            time.sleep(0.5)
        self.assertEqual(j["offline"], False)

    def test_alerts_report_a_running_counter(self):
        c, d = self.req("/api/alerts"); self.assertIn("seq", d); self.assertIsInstance(d["alerts"], list)


class Reports(unittest.TestCase):
    """Static checks on the export code in index.html (the real browser run is covered by hand: tools/preflight.py cannot click)."""
    HTML = (server.ROOT / "index.html").read_text(encoding="utf-8")

    def test_the_save_helper_does_not_shadow_the_translate_function(self):
        # dl(n, t, m) once took the file text as `t` and then called t("toast.saved"): the save worked, the toast threw and a second browser download started
        self.assertRegex(self.HTML, r"const dl=async\(n,d,m\)=>")
        self.assertNotRegex(self.HTML, r"const dl=async\([^)]*\bt\b[^)]*\)=>")

    def test_branding_is_validated_before_it_reaches_a_report(self):
        for needle in ("LOGO_RE", "^#[0-9a-f]{6}$", "300*1024", "img-src data:", "esc(b.company)"): self.assertIn(needle, self.HTML)
        self.assertNotIn("${b.company}", self.HTML); self.assertNotIn("${b.client}", self.HTML)

    def test_every_export_format_is_wired(self):
        for f in ("html", "md", "json", "csv", "xml", "ips"): self.assertIn(f'data-f="{f}"', self.HTML)
        self.assertIn("pdf:printReport", self.HTML); self.assertIn('id="brb"', self.HTML)


if __name__ == "__main__":
    unittest.main()
