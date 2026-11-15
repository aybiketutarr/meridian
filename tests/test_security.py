"""Security hardening (0.4.1): local access control, request parsing, CSP, untrusted data, uninstall safety, export escaping."""
import http.client, json, os, re, sys, tempfile, threading, unittest, urllib.error, urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import server  # noqa: E402


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None


class Access(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(); cls.hp = mock.patch.object(server, "HIST", Path(cls.tmp.name) / "history.json"); cls.hp.start()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), server.H); server.PORT = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start(); cls.base = f"http://127.0.0.1:{server.PORT}"
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown(); cls.hp.stop(); cls.tmp.cleanup()
    def setUp(self):
        server.JOBS.clear(); server.SESSIONS.clear(); server.LAUNCH_STATE["used"] = False

    def get(self, path, cookie=None, redirect=True):
        op = urllib.request.build_opener() if redirect else urllib.request.build_opener(NoRedirect)
        r = urllib.request.Request(self.base + path, headers={"Cookie": cookie} if cookie else {})
        try:
            with op.open(r) as x: return x.status, x.read(), x.headers
        except urllib.error.HTTPError as e: return e.code, e.read(), e.headers

    def test_page_and_api_need_a_session(self):
        for p in ("/", "/api/history", "/api/devices", "/api/net", "/api/alerts", "/api/scan/aaaaaaaa", "/api/xml/aaaaaaaa"): self.assertEqual(self.get(p)[0], 403, p)
        self.assertNotIn(server.TOKEN.encode(), self.get("/")[1])                       # the token is never handed out without the session

    def test_launch_key_works_once_and_sets_a_strict_http_only_cookie(self):
        c, _, h = self.get("/?k=" + server.LAUNCH_KEY, redirect=False)
        self.assertEqual((c, h["Location"]), (302, "/"))
        ck = h["Set-Cookie"]; self.assertTrue(all(x in ck for x in ("HttpOnly", "SameSite=Strict", "Path=/")))
        sid = re.match(rf"{server.COOKIE}=([^;]+)", ck).group(1)
        self.assertEqual(self.get("/", f"{server.COOKIE}={sid}")[0], 200)
        self.assertEqual(self.get("/?k=" + server.LAUNCH_KEY)[0], 403)                  # second use of the key is refused
        self.assertEqual(self.get("/", f"{server.COOKIE}={sid}")[0], 200)               # the session itself keeps working

    def test_wrong_or_expired_launch_key(self):
        self.assertEqual(self.get("/?k=nope")[0], 403); self.assertEqual(self.get("/?k=")[0], 403)
        with mock.patch.object(server, "LAUNCH_TTL", -1): self.assertEqual(self.get("/?k=" + server.LAUNCH_KEY)[0], 403)
        self.assertFalse(server.LAUNCH_STATE["used"])

    def test_forged_cookie_is_refused(self):
        self.assertEqual(self.get("/api/history", f"{server.COOKIE}=forged")[0], 403)
        self.assertEqual(self.get("/api/history", "garbage;;;=")[0], 403)

    def test_sessions_are_capped(self):
        ids = [server.new_session() for _ in range(server.MAX_SESSIONS + 5)]
        self.assertEqual(len(server.SESSIONS), server.MAX_SESSIONS); self.assertEqual(server.SESSIONS, ids[-server.MAX_SESSIONS:])

    def test_launch_url_carries_the_key(self): self.assertIn("/?k=" + server.LAUNCH_KEY, server.launch_url())


class Requests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(); cls.hp = mock.patch.object(server, "HIST", Path(cls.tmp.name) / "history.json"); cls.hp.start()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), server.H); server.PORT = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start(); cls.sid = server.new_session()
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown(); cls.hp.stop(); cls.tmp.cleanup()
    def setUp(self): server.JOBS.clear()

    def raw(self, method, path, body=b"", headers=None, token=True):
        h = {"Host": f"127.0.0.1:{server.PORT}", "Cookie": f"{server.COOKIE}={self.sid}", "Content-Type": "application/json", "Origin": f"http://127.0.0.1:{server.PORT}", **(headers or {})}
        if token: h.setdefault("X-Token", server.TOKEN)
        c = http.client.HTTPConnection("127.0.0.1", server.PORT, timeout=10)
        try:
            c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for k, v in h.items(): c.putheader(k, v)
            c.endheaders(body); r = c.getresponse(); data = r.read()
            return r.status, json.loads(data or b"{}") if data[:1] in (b"{", b"[") else data, r.headers
        finally: c.close()

    def test_non_ascii_token_is_a_refusal_not_a_crash(self):
        self.assertEqual(self.raw("POST", "/api/scan", b"{}", {"X-Token": "t\xf6ken"})[0], 403)

    def test_negative_or_bad_content_length_never_blocks(self):
        for cl in ("-5", "abc", "0", "999999999"):
            c, d, _ = self.raw("POST", "/api/scan", b"", {"Content-Length": cl}); self.assertEqual((c, d.get("code")), (400, "request"), cl)

    def test_body_must_be_a_json_object(self):
        for body in (b"[1]", b'"x"', b"null", b"{oops", b"\xff\xfe"):
            self.assertEqual(self.raw("POST", "/api/scan", body)[0], 400, body)
            self.assertEqual(self.raw("POST", "/api/watch", body)[0], 400, body)

    def test_wrong_json_types_are_plain_refusals(self):
        for b in ({"profile": "custom", "ack": True, "options": [1, 2]}, {"profile": "custom", "ack": True, "options": {"timing": "x"}},
                  {"profile": "custom", "ack": True, "options": {"timing": float("inf")}}, {"profile": ["quick"], "ack": True}, {"profile": "quick", "ack": True, "target": 5}):
            c, d, _ = self.raw("POST", "/api/scan", json.dumps(b).encode()); self.assertEqual(c, 400, b); self.assertNotIn("object", d.get("error", ""))
        c, d, _ = self.raw("POST", "/api/watch", b'{"ack": true, "profile": "quick", "target": "192.168.1.5", "minutes": Infinity}'); self.assertEqual(c, 400)

    def test_content_type_must_be_json(self):
        self.assertEqual(self.raw("POST", "/api/scan", b"{}", {"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.raw("POST", "/api/scan", b"{}", {"Content-Type": "application/x-www-form-urlencoded"})[0], 415)

    def test_unknown_post_paths_and_stop_ids_are_404(self):
        self.assertEqual(self.raw("POST", "/api/anything", b'{"profile":"quick","ack":true,"demo":true}')[0], 404)
        self.assertEqual(self.raw("POST", "/", b"{}")[0], 404)
        self.assertEqual(self.raw("POST", "/api/stop/deadbeef", b"{}")[0], 404)
        self.assertEqual(server.JOBS, {})

    def test_post_needs_session_and_token_and_origin(self):
        body = b'{"profile":"quick","ack":true,"demo":true}'
        self.assertEqual(self.raw("POST", "/api/scan", body, {"Cookie": ""})[0], 403)
        self.assertEqual(self.raw("POST", "/api/scan", body, token=False)[0], 403)
        self.assertEqual(self.raw("POST", "/api/scan", body, {"Origin": "http://evil.example"})[0], 403)
        self.assertEqual(self.raw("POST", "/api/scan", body, {"Host": "evil.example"})[0], 403)

    def test_csp_blocks_inline_script_and_uses_a_fresh_nonce_per_page(self):
        seen = []
        for _ in range(2):
            r = urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{server.PORT}/", headers={"Cookie": f"{server.COOKIE}={self.sid}"}))
            csp, html = r.headers["Content-Security-Policy"], r.read().decode()
            script = re.search(r"script-src ([^;]+)", csp).group(1); self.assertNotIn("unsafe-inline", script); self.assertNotIn("unsafe-eval", script)
            n = re.search(r"'nonce-([^']+)'", script).group(1); self.assertIn(f'<script nonce="{n}">', html); self.assertNotIn("__NONCE__", html); seen.append(n)
            for d in ("object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "connect-src 'self'"): self.assertIn(d, csp)
            self.assertEqual(r.headers["Cross-Origin-Opener-Policy"], "same-origin"); self.assertEqual(int(r.headers["Content-Length"]), len(html.encode()))
        self.assertNotEqual(*seen)
        c, d, h = self.raw("GET", "/api/history"); self.assertIn("script-src 'none'", h["Content-Security-Policy"])      # data answers can never run script

    def test_handler_has_a_socket_timeout(self): self.assertTrue(0 < server.H.timeout <= 60)


class Scans(unittest.TestCase):
    def test_custom_profile_cannot_smuggle_vulners_in(self):
        for sc in (["vulners"], ["default", "vulners"], ["VULNERS"], [["vulners"]], "vulners", {"vulners": 1}):
            a = server.scan_args("custom", {"sv": True, "scripts": sc}, lookup=False)
            self.assertNotIn("vulners", " ".join(a), sc)
        a = server.scan_args("custom", {"sv": True, "scripts": ["default", "vulners"]}, lookup=True)
        self.assertIn("default,vulners", " ".join(a)); self.assertIn("vulners.paths=none,vulners.max_items=0", " ".join(a))      # the confirmed lookup keeps its safe arguments
        a = server.scan_args("custom", {"sv": False, "scripts": ["vulners"]}, lookup=True); self.assertNotIn("vulners", " ".join(a))
        a = server.scan_args("custom", {"sn": True, "sv": True, "scripts": ["vulners"]}, lookup=True); self.assertNotIn("vulners", " ".join(a))

    def test_target_cannot_become_an_option(self):
        for t in ("-oN /tmp/x", "--script=x", "-iL /etc/passwd", "1.2.3.4 -oX x", "a" * 300): 
            with self.assertRaises(ValueError): server.valid_targets(t)


class Data(unittest.TestCase):
    def test_nmap_xml_with_entities_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.xml"
            p.write_text('<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><nmaprun><host><status state="up"/><address addr="1.1.1.1" addrtype="ipv4"/><hostnames><hostname name="&b;"/></hostnames></host></nmaprun>')
            self.assertIsNone(server.parse(str(p)))
            with mock.patch.object(server, "MAX_XML", 10): p.write_text("<nmaprun/>" * 5); self.assertIsNone(server.parse(str(p)))

    def test_port_without_state_or_number_is_skipped_not_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.xml"
            p.write_text('<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"/><port protocol="tcp" portid="x"><state state="open"/></port>'
                         '<port protocol="tcp" portid="80"><state state="open"/></port></ports></host></nmaprun>')
            h = server.parse(str(p)); self.assertEqual([x["port"] for x in h[0]["ports"]], [80])

    def test_numbers_are_finite(self):
        for v in ("nan", "inf", "-Infinity", float("nan"), "x", None): self.assertIsNone(server._num(v))
        self.assertEqual(server._num("9.8"), 9.8)

    def test_history_is_rebuilt_from_untrusted_json(self):
        evil = {"id": "aaaaaaaa", "target": "<img src=x onerror=alert(1)>" * 20, "profile": {"x": 1}, "ts": "nan", "dur": "inf",
                "hosts": [5, {"ip": "<b>1</b>", "mac": "M" * 99, "name": ["x"], "unknown": "drop", "ports": [{"port": "99999", "proto": "<script>", "scripts": [{"id": "<i>", "out": "o" * 5000}, 7],
                           "vulns": {"items": [{"id": "CVE-1", "cvss": "nan", "href": "javascript:alert(1)", "src": "https://ok.example/x", "sev": "CRITICAL", "extra": 1}, 3], "total": "9" * 30}}, "junk"]}]}
        j = server.clean_job(evil); h = j["hosts"][0]; p = h["ports"][0]
        self.assertEqual((len(j["target"]), j["profile"], j["ts"], j["dur"]), (100, str({"x": 1})[:20], 0.0, 0))
        self.assertEqual((len(j["hosts"]), len(h["mac"]), h["name"], "unknown" in h), (1, 17, str(["x"]), False))
        self.assertEqual((p["port"], len(p["scripts"][0]["out"]), len(p["scripts"])), (65535, 1500, 1))
        it = p["vulns"]["items"][0]; self.assertEqual((it["href"], it["src"], it["cvss"], it["sev"], "extra" in it, len(p["vulns"]["items"])), ("", "https://ok.example/x", None, "critical", False, 1))
        self.assertLessEqual(p["vulns"]["total"], 100000); json.dumps(j, allow_nan=False)        # strict JSON: the browser can always parse it

    def test_history_round_trip_keeps_a_real_scan(self):
        h = server.demo(True, True); j = {"id": "abcdef01", "target": "192.168.1.0/24", "profile": "quick", "hosts": h, "ts": 1.5, "dur": 3}
        self.assertEqual(server.clean_job(j)["hosts"], [{**x, "vendor": x.get("vendor", "")} for x in h])      # the only difference: a missing vendor becomes ""

    def test_locale_js_never_contains_script_or_comment_openers(self):
        evil = {"en": {"x": "</script><script>alert(1)</script><!-- <script>"}}
        with mock.patch.object(server, "_LOC", evil): js = server.locales_js()
        for bad in ("<", "</script>", "<!--"): self.assertNotIn(bad, js)
        self.assertEqual(json.loads(js.replace("\\u003c", "<")), evil)

    def test_terminal_messages_never_evaluate_format_expressions(self):
        with mock.patch.object(server, "_LOC", {"en": {"k": "{url.__class__} {0} {path!r} {path:>20} {nope}"}}), mock.patch.object(server, "LANG", "en"):
            self.assertEqual(server.T("k", url="u", path="p"), "{url.__class__} {0} {path!r} {path:>20} {nope}")
            self.assertEqual(server.T("k", url="u", path="p", nope="N").count("N"), 1)

    def test_audit_lines_cannot_be_split(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(server, "HIST", Path(d) / "h" / "history.json"):
            server.audit("scan x\n2099-01-01 00:00:00 scan forged\r\nmore"); lines = (Path(d) / "h" / "audit.log").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)


class Uninstall(unittest.TestCase):
    def test_home_and_its_parents_are_never_data_dirs(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(Path, "home", return_value=Path(d) / "u"):
            (Path(d) / "u").mkdir()
            for p in (Path(d) / "u", Path(d), Path(d).parent, Path(Path(d).anchor)): self.assertTrue(server.unsafe_data_dir(p), p)
            self.assertFalse(server.unsafe_data_dir(Path(d) / "u" / ".local" / "share" / "meridian"))

    def test_uninstall_refuses_home_and_deletes_nothing(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(Path, "home", return_value=Path(d)), mock.patch.dict(os.environ, {"MERIDIAN_DATA_DIR": d}), \
             mock.patch.object(server, "HIST", Path(d) / "history.json"), mock.patch.object(server.sys, "argv", ["meridian", "--uninstall", "--yes"]), \
             mock.patch.object(server.os, "geteuid", create=True, return_value=1000):
            (Path(d) / "precious.txt").write_text("keep"); self.assertEqual(server.uninstall(), 1); self.assertEqual((Path(d) / "precious.txt").read_text(), "keep")

    def test_foreign_named_data_dir_only_loses_meridian_files(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "mydata"; (p / "browser-profile").mkdir(parents=True)
            for n in ("history.json", "audit.log", "devices.json", "mine.txt"): (p / n).write_text("x")
            server.remove_data(p); self.assertEqual([x.name for x in p.iterdir()], ["mine.txt"])
            q = Path(d) / "Meridian"; q.mkdir(); (q / "anything").write_text("x"); server.remove_data(q); self.assertFalse(q.exists())


class Ui(unittest.TestCase):
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    def test_script_is_nonce_marked_and_has_no_inline_handlers(self):
        self.assertEqual(self.html.count("<script"), 1); self.assertIn('<script nonce="__NONCE__">', self.html)
        self.assertIsNone(re.search(r"\son[a-z]+\s*=\s*[\"']", re.sub(r"<script.*?</script>", "", self.html, flags=re.S)))      # no onclick= & co in the markup
        self.assertNotIn("javascript:", self.html)
    def test_exports_neutralise_network_data(self):
        self.assertIn("csvCell", self.html); self.assertIn("mdx(h.name)", self.html); self.assertIn("mdx(p.version)", self.html)
        self.assertIn("Content-Security-Policy", self.html); self.assertIn('rel="noopener noreferrer">${esc(i.id)}', self.html)
    def test_ports_and_ids_are_escaped(self):
        for bad in ("${p.proto}", 'data-c="${x.id}"', 'data-l="${x.id}"', "${x.hosts}"): self.assertNotIn(bad, self.html)
    def test_presets_have_no_prototype(self): self.assertIn("Object.create(null)", self.html); self.assertIn("__proto__", self.html)


class Project(unittest.TestCase):
    def test_ci_is_read_only(self): self.assertIn("contents: read", (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8"))
    def test_dockerfile_runs_unprivileged_and_ships_no_tests(self):
        d = (ROOT / "Dockerfile").read_text(encoding="utf-8"); self.assertRegex(d, r"(?m)^USER meridian$"); self.assertNotIn("COPY tests", d)
    def test_every_language_has_the_new_messages(self):
        for code, d in server.load_locales().items(): self.assertIn("err.request", d, code); self.assertIn("un.unsafe", d, code)
    def test_desktop_exec_escapes_percent(self):
        import install; self.assertEqual(install.desk_quote("/a b/%f"), '"/a b/%%f"')


if __name__ == "__main__":
    unittest.main()
