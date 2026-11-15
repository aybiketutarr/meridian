"""Languages: every locale file is complete, every key the UI or the terminal uses exists, and the selection logic picks the right language."""
import io, json, os, re, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import server  # noqa: E402

PLURAL = ("map.scanning", "cve.known", "vz.issue", "log.lookup.n", "dev.baseline.done")
ph = lambda s: sorted(re.findall(r"\{(\w+)\}", s))
LOC = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted((ROOT / "locales").glob("*.json"))}
EN = LOC["en"]
HTML = (ROOT / "index.html").read_text(encoding="utf-8")
PY = (ROOT / "server.py").read_text(encoding="utf-8") + (ROOT / "install.py").read_text(encoding="utf-8")


class Files(unittest.TestCase):
    def test_the_five_launch_languages_exist(self): self.assertEqual(sorted(LOC), ["de", "en", "es", "fr", "tr"])

    def test_same_keys_everywhere(self):
        for code, d in LOC.items():
            self.assertEqual(sorted(set(EN) - set(d)), [], f"{code} is missing keys"); self.assertEqual(sorted(set(d) - set(EN)), [], f"{code} has extra keys")

    def test_same_placeholders_everywhere(self):
        for code, d in LOC.items():
            for k, v in d.items():
                if not k.startswith("_"): self.assertEqual(ph(v), ph(EN[k]), f"{code}:{k}")

    def test_nothing_is_empty_and_every_language_has_a_name(self):
        for code, d in LOC.items():
            self.assertTrue(d["_name"].strip(), code)
            for k, v in d.items(): self.assertTrue(v.strip(), f"{code}:{k}")

    def test_plural_forms_come_in_pairs(self):
        for k in PLURAL:
            for code, d in LOC.items(): self.assertIn(k + "_one", d, code); self.assertIn(k + "_other", d, code); self.assertNotIn(k, d, code)

    def test_translations_do_not_inject_markup(self):
        for code, d in LOC.items():
            for k, v in d.items(): self.assertNotRegex(v, r"<[a-zA-Z/]", f"{code}:{k}")

    def test_other_languages_are_really_translated(self):
        for code in ("tr", "de", "es", "fr"):
            same = [k for k, v in LOC[code].items() if v == EN[k] and len(v) > 25]
            self.assertEqual(same, [], f"{code}: left in English")

    def test_turkish_keeps_its_special_letters(self):
        text = " ".join(LOC["tr"].values())
        for ch in "ığşçöüİ": self.assertIn(ch, text)


class KeysUsed(unittest.TestCase):
    def test_every_literal_key_in_the_ui_exists(self):
        spaces = {k.split(".")[0] for k in EN if not k.startswith("_")}
        used = set(re.findall(r'data-i18n(?:-ph|-title|-aria)?="([\w.\-]+)"', HTML))
        used |= {k for k in re.findall(r'"([a-z]+\.[\w.\-]+)"', HTML) if k.split(".")[0] in spaces}          # also catches keys inside ternaries
        used = {k for k in used if not k.endswith(".")}                                                    # "alert." + kind: prefixes, checked below
        missing = sorted(k for k in used if k not in EN and k + "_other" not in EN)
        self.assertEqual(missing, [])
        self.assertGreater(len(used), 150)

    def test_dynamic_key_families_are_complete(self):
        need = [f"pf.{p}.{x}" for p in ("quick", "ping", "service", "full", "os", "trace", "vuln", "custom") for x in "nd"]
        risky = re.search(r"const RISKY=\{(.*?)\};", HTML).group(1); ids = set(re.findall(r'"(?:high|med)","(\w+)"', risky))
        need += [f"rk.{i}.{x}" for i in ids for x in "tf"]
        need += [f"st.{x}" for x in ("ready", "running", "done", "error", "stopped")] + [f"sev.{x}" for x in ("crit", "high", "med", "low", "info")]
        need += [f"alert.{x}" for x in ("new_host", "new_port", "host_gone", "unknown")] + [f"root.hint.{x}" for x in ("linux", "macos", "windows")]
        need += [f"err.{c}" for c in set(server.ERR_CODES.values()) | {"demo_only"}] + [f"off.{r[2]}" for r in server.OFFLINE_RULES]
        need += [f"kind.{x}" for x in ("router", "printer", "camera", "nas", "win", "linux", "device", "unknown")] + [f"watch.{m}" for m in ("off", "5", "15", "60", "360")]
        self.assertGreater(len(ids), 10)
        for code, d in LOC.items(): self.assertEqual([k for k in need if k not in d], [], code)

    def test_every_terminal_key_exists(self):
        used = set(re.findall(r'\bT\("([\w.\-]+)"', PY)) | set(re.findall(r'\bsay\("([\w.\-]+)"', PY)) | set(re.findall(r'add\("(?:ok|warn|fail)(?:"\s*if [^"]*"|" if [^,]*else "warn")?,\s*"(dr\.[\w]+)"', PY))
        used |= {f"dr.nmap_{o}" for o in ("linux", "macos", "windows")} | {f"dr.priv_no_{o}" for o in ("linux", "macos", "windows")} | {f"in.root_tip_{o}" for o in ("linux", "macos", "windows")}
        used |= {"dr.title", "dr.version", "dr.os", "dr.python", "dr.nmap", "dr.priv", "dr.browser", "dr.data", "dr.port", "dr.lang"}
        self.assertEqual([k for k in sorted(used) if k not in EN and not k.endswith("_")], [])         # keys ending in _ are prefixes completed at run time (checked above)

    def test_help_mentions_every_option_in_every_language(self):
        for code, d in LOC.items():
            for opt in ("--serve", "--lang", "--doctor", "--version", "--uninstall", "--keep-data", "--yes", "--help", "MERIDIAN_PORT", "MERIDIAN_LANG", "MERIDIAN_NMAP", "MERIDIAN_DATA_DIR"):
                self.assertIn(opt, d["cli.help"], f"{code} {opt}")


class Selection(unittest.TestCase):
    def test_pick_lang(self):
        for given, want in (("tr_TR.UTF-8", "tr"), ("tr", "tr"), ("de-AT", "de"), ("DE_de", "de"), ("fr_CA.UTF-8@euro", "fr"), ("es-419", "es"), ("xx", "en"), ("", "en"), (None, "en"), ("C", "en"), ("POSIX", "en")):
            self.assertEqual(server.pick_lang(given), want, given)
        self.assertEqual(server.pick_lang("xx", "", "de_DE"), "de"); self.assertEqual(server.pick_lang("zz", "tr"), "tr")

    def test_english_is_the_default_whatever_the_system_language_is(self):
        keep = {k: v for k, v in os.environ.items() if k not in ("MERIDIAN_LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG")}
        with mock.patch.dict(os.environ, {**keep, "LANG": "tr_TR.UTF-8", "LC_ALL": "tr_TR.UTF-8", "LANGUAGE": "tr:de"}, clear=True): self.assertEqual(server.pick_lang(*server.system_langs()), "en")
        with mock.patch.dict(os.environ, {**keep, "MERIDIAN_LANG": "tr"}, clear=True): self.assertEqual(server.pick_lang(*server.system_langs()), "tr")      # only an explicit choice counts
        self.assertNotIn("navigator.language", HTML)                                                     # the page does not look at the browser language either

    def test_terminal_messages_use_the_language_and_fall_back(self):
        with mock.patch.object(server, "LANG", "tr"):
            self.assertEqual(server.T("un.cancelled"), "İptal edildi."); self.assertIn("/x", server.T("un.keeping", path="/x"))
            self.assertEqual(server.T("no.such.key"), "no.such.key"); self.assertEqual(server.T("un.keeping"), "(kayıtlı veriler {path} içinde korunuyor)")      # missing placeholder: no crash
        with mock.patch.object(server, "LANG", "klingon"): self.assertEqual(server.T("un.cancelled"), "Cancelled.")

    def test_page_data_is_valid_json_and_cannot_close_the_script_tag(self):
        js = server.locales_js(); self.assertNotIn("</", js)
        self.assertEqual(json.loads(js.replace("<\\/", "</")), server.load_locales())
        evil = {"en": {"_name": "e", "x": "</script><script>alert(1)</script>"}}
        with mock.patch.object(server, "_LOC", evil): self.assertNotIn("</script>", server.locales_js())

    def test_a_broken_locale_file_never_stops_meridian(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "locales").mkdir()
            (Path(d) / "locales" / "en.json").write_text('{"_name": "English", "a": "b"}', encoding="utf-8")
            (Path(d) / "locales" / "de.json").write_text("{broken", encoding="utf-8")
            (Path(d) / "locales" / "fr.json").write_text('{"a": 5}', encoding="utf-8")                  # not text
            (Path(d) / "locales" / "es.json").write_text("[1]", encoding="utf-8")
            (Path(d) / "locales" / "Not A Code.json").write_text('{"a": "b"}', encoding="utf-8")
            with mock.patch.object(server, "ROOT", Path(d)):
                self.assertEqual(server.load_locales(force=True), {"en": {"_name": "English", "a": "b"}})
        server.load_locales(force=True)                                                           # back to the real files

    def test_a_new_language_is_picked_up_without_code_changes(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "locales").mkdir()
            for code in ("en", "pt"): (Path(d) / "locales" / f"{code}.json").write_text(json.dumps({"_name": code, "un.cancelled": code}), encoding="utf-8")
            with mock.patch.object(server, "ROOT", Path(d)):
                server.load_locales(force=True); self.assertEqual(server.pick_lang("pt_BR.UTF-8"), "pt")
        server.load_locales(force=True)


class Terminal(unittest.TestCase):
    def cli(self, *args, **env):
        e = {**os.environ, **env}
        for k in ("LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE"): e.pop(k, None) if k not in env else None
        return subprocess.run([sys.executable, str(ROOT / "server.py"), *args], capture_output=True, text=True, encoding="utf-8", timeout=60, env=e)

    def test_help_in_each_language(self):
        for code, word in (("tr", "Kullanım"), ("de", "Aufruf"), ("es", "Uso"), ("fr", "Usage"), ("en", "Usage")):
            r = self.cli("--lang", code, "--help"); self.assertEqual(r.returncode, 0); self.assertIn(word, r.stdout, code); self.assertIn("tr, ", r.stdout.replace("de, en, es, fr, tr", "tr, "))

    def test_language_by_environment_and_flag_beats_environment(self):
        self.assertIn("Kullanım", self.cli("--help", MERIDIAN_LANG="tr").stdout)
        self.assertIn("Aufruf", self.cli("--lang=de", "--help", MERIDIAN_LANG="tr").stdout)
        self.assertIn("Usage", self.cli("--help", LANG="tr_TR.UTF-8", LC_ALL="tr_TR.UTF-8").stdout)        # a Turkish system still starts in English

    def test_doctor(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.cli("--doctor", "--lang", "tr", MERIDIAN_DATA_DIR=str(Path(d) / "data"), MERIDIAN_PORT="0")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr); self.assertIn("tanılama", r.stdout)
            for word in ("Meridian sürümü", "Python", "nmap", "Tarama yetkileri", "Veri klasörü", "Dil"): self.assertIn(word, r.stdout)
            self.assertTrue((Path(d) / "data").is_dir()); self.assertEqual([x.name for x in (Path(d) / "data").iterdir() if x.name.startswith(".probe")], [])

    def test_data_folder_can_be_moved(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"MERIDIAN_DATA_DIR": d}): self.assertEqual(server.app_data_dir(), Path(d))

    def test_stdio_survives_legacy_code_pages_and_pythonw(self):
        old = io.TextIOWrapper(io.BytesIO(), encoding="ascii"); err = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
        with mock.patch.object(sys, "stdout", old), mock.patch.object(sys, "stderr", err):
            server.fix_stdio(); print("ğüşİ ı"); sys.stdout.flush(); self.assertEqual(sys.stdout.encoding, "utf-8")
        with mock.patch.object(sys, "stdout", None), mock.patch.object(sys, "stderr", None):
            server.fix_stdio(); print("no console, no crash"); sys.stdout.flush(); a, b = sys.stdout, sys.stderr
        a.close(); b.close()


if __name__ == "__main__":
    unittest.main()
