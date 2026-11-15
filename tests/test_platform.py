"""Windows, macOS and Linux behaviour. Most checks fake the platform (IS_WIN / IS_MAC), so they run on every OS."""
import os, socket, subprocess, sys, tempfile, types, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402

POSIX = os.name != "nt"
_WIN_LEAKY = ("LOCALAPPDATA", "APPDATA", "USERPROFILE", "ProgramFiles", "ProgramFiles(x86)")  # the real CI runner's own values; tests must use the faked self.home instead
CLEAN = {k: v for k, v in os.environ.items() if k not in ("MERIDIAN_DATA_DIR", "XDG_DATA_HOME", "MERIDIAN_NMAP", *_WIN_LEAKY)}
def fake_home(d): return mock.patch.object(server.Path, "home", return_value=Path(d))
class platform:
    """with platform(win=True): pretend to be Windows (or macOS with mac=True); the default is Linux."""
    def __init__(self, win=False, mac=False): self.p = [mock.patch.object(server, "IS_WIN", win), mock.patch.object(server, "IS_MAC", mac)]
    def __enter__(self): [p.start() for p in self.p]
    def __exit__(self, *a): [p.stop() for p in reversed(self.p)]


class Folders(unittest.TestCase):
    def setUp(self): self.tmp = tempfile.TemporaryDirectory(); self.home = Path(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()
    def where(self, win=False, mac=False, **env):
        with mock.patch.dict(os.environ, {**CLEAN, **env}, clear=True), fake_home(self.home), platform(win, mac): return server.app_data_dir(), server.install_paths()

    def test_linux(self):
        data, P = self.where()
        self.assertEqual(data, self.home / ".local" / "share" / "meridian"); self.assertEqual(P["os"], "linux")
        self.assertEqual(P["app"], self.home / ".local" / "share" / "meridian-app"); self.assertEqual(P["launcher"], self.home / ".local" / "bin" / "meridian")
        self.assertEqual([m.name for m in P["menu"]], ["meridian.desktop", "meridian.svg"])

    def test_linux_honours_xdg_but_keeps_an_existing_history(self):
        other = self.home / "xdg"
        self.assertEqual(self.where(XDG_DATA_HOME=str(other))[0], other / "meridian")
        (self.home / ".local" / "share" / "meridian").mkdir(parents=True)                      # history from 0.3.0 must not be orphaned
        self.assertEqual(self.where(XDG_DATA_HOME=str(other))[0], self.home / ".local" / "share" / "meridian")
        (other / "meridian").mkdir(parents=True); self.assertEqual(self.where(XDG_DATA_HOME=str(other))[0], other / "meridian")

    def test_macos(self):
        data, P = self.where(mac=True)
        self.assertEqual(data, self.home / "Library" / "Application Support" / "Meridian"); self.assertEqual(P["os"], "macos")
        self.assertEqual(P["app"], self.home / "Library" / "Application Support" / "Meridian-app"); self.assertEqual(P["menu"], [self.home / "Applications" / "Meridian.app"])
        self.assertNotEqual(data, P["app"])                     # uninstall --keep-data must not touch the data

    def test_windows(self):
        local, roam = self.home / "L", self.home / "R"
        data, P = self.where(win=True, LOCALAPPDATA=str(local), APPDATA=str(roam))
        self.assertEqual(data, local / "Meridian"); self.assertEqual(P["os"], "windows"); self.assertEqual(P["app"], local / "Meridian-app")
        self.assertEqual(P["launcher"], local / "Meridian-app" / "bin" / "meridian.cmd"); self.assertEqual(P["bin"], local / "Meridian-app" / "bin")
        self.assertEqual(P["menu"], [roam / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Meridian.lnk"])
        self.assertEqual(self.where(win=True)[0], self.home / "AppData" / "Local" / "Meridian")       # variables missing: sane default

    def test_data_folder_override(self):
        self.assertEqual(self.where(MERIDIAN_DATA_DIR=str(self.home / "x"))[0], self.home / "x")
        self.assertEqual(server.HIST.name, "history.json")


class Executables(unittest.TestCase):
    def setUp(self): self.tmp = tempfile.TemporaryDirectory(); self.d = Path(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()

    def test_nmap_override_then_path(self):
        exe = self.d / "my-nmap"; exe.write_text("x", encoding="utf-8")
        with mock.patch.dict(os.environ, {**CLEAN, "MERIDIAN_NMAP": str(exe)}, clear=True), mock.patch.object(server.shutil, "which", return_value="/usr/bin/nmap"): self.assertEqual(server.find_nmap(), str(exe))
        with mock.patch.dict(os.environ, CLEAN, clear=True), mock.patch.object(server.shutil, "which", return_value="/usr/bin/nmap"): self.assertEqual(server.find_nmap(), "/usr/bin/nmap")
        with mock.patch.dict(os.environ, {**CLEAN, "MERIDIAN_NMAP": str(self.d / "gone")}, clear=True), mock.patch.object(server.shutil, "which", return_value="/usr/bin/nmap"): self.assertEqual(server.find_nmap(), "/usr/bin/nmap")

    def test_linux_looks_nowhere_else(self):
        with mock.patch.dict(os.environ, CLEAN, clear=True), mock.patch.object(server.shutil, "which", return_value=None), platform(), \
             mock.patch.object(server.Path, "is_file", return_value=True): self.assertIsNone(server.find_nmap())

    def test_windows_finds_the_installer_location_without_path(self):
        exe = self.d / "Nmap" / "nmap.exe"; exe.parent.mkdir(); exe.write_text("x", encoding="utf-8")
        with mock.patch.dict(os.environ, {**CLEAN, "ProgramFiles(x86)": str(self.d)}, clear=True), mock.patch.object(server.shutil, "which", return_value=None), platform(win=True):
            self.assertEqual(server.find_nmap(), str(exe))
        with mock.patch.dict(os.environ, {**CLEAN, "ProgramFiles(x86)": str(self.d / "nothing")}, clear=True), mock.patch.object(server.shutil, "which", return_value=None), platform(win=True):
            self.assertIsNone(server.find_nmap())

    def test_macos_finds_homebrew_when_a_gui_start_has_no_path(self):
        with mock.patch.dict(os.environ, CLEAN, clear=True), mock.patch.object(server.shutil, "which", return_value=None), platform(mac=True), \
             mock.patch.object(server.Path, "is_file", lambda self: self.parts[-3:] == ("homebrew", "bin", "nmap")):
            self.assertEqual(Path(server.find_nmap()).parts[-3:], ("homebrew", "bin", "nmap"))

    def test_browser_candidates(self):
        with mock.patch.dict(os.environ, {**CLEAN, "ProgramFiles": str(self.d / "PF"), "LOCALAPPDATA": str(self.d / "LA")}, clear=True), platform(win=True):
            c = server.browser_candidates()
        self.assertTrue(c[0].endswith("msedge.exe")); self.assertTrue(any(x.endswith("chrome.exe") for x in c)); self.assertTrue(any("brave.exe" in x for x in c))
        with fake_home(self.d), platform(mac=True): c = server.browser_candidates()
        self.assertIn("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", [x.replace("\\", "/") for x in c]); self.assertTrue(any("Microsoft Edge.app" in x for x in c))
        with platform(): self.assertEqual(server.browser_candidates(), [])

    def test_find_browser_uses_the_candidates(self):
        edge = self.d / "msedge.exe"; edge.write_text("x", encoding="utf-8")
        with mock.patch.object(server.shutil, "which", return_value=None), mock.patch.object(server, "browser_candidates", return_value=[str(self.d / "no"), str(edge)]): self.assertEqual(server.find_browser(), str(edge))
        with mock.patch.object(server.shutil, "which", return_value=None), mock.patch.object(server, "browser_candidates", return_value=[]): self.assertIsNone(server.find_browser())
        with mock.patch.object(server.shutil, "which", lambda n: "/x/chromium" if n == "chromium" else None): self.assertEqual(server.find_browser(), "/x/chromium")

    def test_process_flags(self):
        with platform(win=True): f = server.popen_flags()
        self.assertEqual(list(f), ["creationflags"])
        with platform(): self.assertEqual(server.popen_flags(), {"start_new_session": True})


class Processes(unittest.TestCase):
    def test_pid_alive(self):
        self.assertTrue(server.pid_alive(os.getpid())); self.assertTrue(server.pid_alive(str(os.getpid())))
        for bad in ("abc", None, 0, -5, ""): self.assertFalse(server.pid_alive(bad), repr(bad))
        p = subprocess.Popen([sys.executable, "-c", "pass"]); p.wait(); self.assertFalse(server.pid_alive(p.pid))

    @unittest.skipIf(not POSIX, "needs /proc or ps")
    def test_cmdline_of_this_process(self): self.assertIn("python", server._cmdline(os.getpid()).lower())

    def test_cmdline_falls_back_to_ps_off_linux(self):
        with mock.patch.object(server.Path, "read_bytes", side_effect=OSError), platform(mac=True), \
             mock.patch.object(server.subprocess, "run", return_value=types.SimpleNamespace(stdout="  python3 /x/server.py\n")) as run:
            self.assertEqual(server._cmdline(4242), "python3 /x/server.py")
        self.assertEqual(run.call_args[0][0], ["ps", "-p", "4242", "-o", "command="])
        with mock.patch.object(server.Path, "read_bytes", side_effect=OSError), platform(win=True): self.assertEqual(server._cmdline(4242), "")      # Windows: cannot tell

    def test_a_live_run_is_never_swept_when_its_command_line_cannot_be_read(self):
        """macOS/Windows without /proc: 'cannot tell' must mean 'keep', or a second Meridian would delete the first one's files."""
        with tempfile.TemporaryDirectory() as b:
            other = Path(b) / "meridian-run-999999-abcd1234"; other.mkdir(mode=0o700)
            with mock.patch.object(server, "pid_alive", return_value=True), mock.patch.object(server, "_cmdline", return_value=""): server.sweep_stale(b)
            self.assertTrue(other.is_dir())
            with mock.patch.object(server, "pid_alive", return_value=True), mock.patch.object(server, "_cmdline", return_value="vim notes.txt"): server.sweep_stale(b)    # pid reused by something else
            self.assertFalse(other.exists())

    def test_a_dead_run_is_swept_on_every_platform(self):
        with tempfile.TemporaryDirectory() as b, platform(win=True):
            d = Path(b) / "meridian-run-999999-abcd1234"; d.mkdir(); (d / "scan.xml").write_text("x", encoding="utf-8")
            with mock.patch.object(server, "pid_alive", return_value=False): server.sweep_stale(b)
            self.assertFalse(d.exists())


class Permissions(unittest.TestCase):
    @unittest.skipIf(not POSIX, "POSIX modes")
    def test_windows_does_not_apply_posix_modes(self):
        with tempfile.TemporaryDirectory() as b:
            loose = Path(b) / "loose"; loose.mkdir(); loose.chmod(0o755)
            with platform(win=True): server.private_dir(loose)                    # NTFS reports fake modes: must not refuse
            with platform(), self.assertRaises(OSError): server.private_dir(loose)

    def test_files_are_opened_in_binary_mode_on_windows(self):
        with tempfile.TemporaryDirectory() as b, mock.patch.object(server.os, "O_BINARY", 0x8000, create=True), mock.patch.object(server, "HIST", Path(b) / "h" / "history.json"):
            flags, real = [], os.open
            def spy(p, f, *a): flags.append(f); return real(p, f & ~0x8000, *a)
            with mock.patch.object(server.os, "open", spy): server.audit("x")
        self.assertTrue(flags and all(f & 0x8000 for f in flags))         # no CRLF surprises in the audit log


class Network(unittest.TestCase):
    class Dead:
        def __init__(self, *a): pass
        def connect(self, *a): raise OSError("unreachable")
        def getsockname(self): raise OSError
        def close(self): pass

    def test_falls_back_to_the_host_name_without_a_default_route(self):
        with mock.patch.object(server.socket, "socket", self.Dead), mock.patch.object(server.socket, "gethostbyname_ex", return_value=("h", [], ["127.0.1.1", "192.168.7.23"])): self.assertEqual(server.local_cidr(), "192.168.7.0/24")

    def test_last_resort(self):
        with mock.patch.object(server.socket, "socket", self.Dead), mock.patch.object(server.socket, "gethostbyname_ex", side_effect=OSError): self.assertEqual(server.local_cidr(), "192.168.1.0/24")
        with mock.patch.object(server.socket, "socket", self.Dead), mock.patch.object(server.socket, "gethostbyname_ex", return_value=("h", [], ["127.0.1.1"])): self.assertEqual(server.local_cidr(), "192.168.1.0/24")

    def test_normal_case(self):
        class Ok(self.Dead):
            def connect(self, *a): pass
            def getsockname(self): return ("10.20.30.40", 5)
        with mock.patch.object(server.socket, "socket", Ok): self.assertEqual(server.local_cidr(), "10.20.30.0/24")

    def test_admin_check(self):
        with mock.patch.object(server.os, "geteuid", create=True, return_value=0): self.assertTrue(server.is_admin())
        with mock.patch.object(server.os, "geteuid", create=True, return_value=1000): self.assertFalse(server.is_admin())
        self.assertIn(server.current_os(), ("linux", "macos", "windows"))
        with platform(mac=True): self.assertEqual(server.current_os(), "macos")
        with platform(win=True): self.assertEqual(server.current_os(), "windows")


class WindowsPath(unittest.TestCase):
    """HKCU\\Environment\\Path with a fake registry: add once, keep the rest, remove cleanly."""
    def fake(self, store):
        class Key:
            def __enter__(s): return s
            def __exit__(s, *a): return False
        def query(k, name):
            if name not in store: raise FileNotFoundError
            return store[name], 2
        return types.SimpleNamespace(HKEY_CURRENT_USER=1, KEY_READ=1, KEY_SET_VALUE=2, REG_EXPAND_SZ=2, OpenKey=lambda *a, **k: Key(), QueryValueEx=query,
                                     SetValueEx=lambda k, n, r, t, v: store.__setitem__(n, v))

    def test_add_is_idempotent_and_remove_keeps_other_entries(self):
        a, b, mine = os.path.normpath("/a"), os.path.normpath("/b"), os.path.normpath("/m/bin"); store = {"Path": os.pathsep.join([a, b])}
        with mock.patch.dict(sys.modules, {"winreg": self.fake(store)}):
            server.win_user_path(add=mine); server.win_user_path(add=mine)
            self.assertEqual(store["Path"].split(os.pathsep), [a, b, mine])
            server.win_user_path(remove=mine); self.assertEqual(store["Path"].split(os.pathsep), [a, b])
            server.win_user_path(remove=mine); self.assertEqual(store["Path"].split(os.pathsep), [a, b])

    def test_path_variable_missing(self):
        store = {}
        with mock.patch.dict(sys.modules, {"winreg": self.fake(store)}): server.win_user_path(add=os.path.normpath("/m/bin"))
        self.assertEqual(store["Path"], os.path.normpath("/m/bin"))


class Doctor(unittest.TestCase):
    def setUp(self): self.tmp = tempfile.TemporaryDirectory(); self.p = mock.patch.object(server, "HIST", Path(self.tmp.name) / "m" / "history.json"); self.p.start()
    def tearDown(self): self.p.stop(); self.tmp.cleanup()

    def test_report(self):
        with mock.patch.object(server, "find_nmap", return_value=None), mock.patch.object(server, "find_browser", return_value=None), mock.patch.object(server, "is_admin", return_value=False), platform(mac=True):
            r = server.doctor_report()
        by = {label: (st, detail) for st, label, detail in r}
        self.assertEqual(by["Python"][0], "ok"); self.assertEqual(by["nmap"][0], "warn"); self.assertIn("brew install nmap", by["nmap"][1])
        self.assertEqual(by["Scan privileges"][0], "warn"); self.assertIn("sudo -E meridian", by["Scan privileges"][1])
        self.assertEqual(by["App window browser"][0], "warn"); self.assertEqual(by["Data folder"][0], "ok")
        self.assertEqual(by["Meridian version"][1], server.VERSION)

    def test_windows_advice_and_exit_code(self):
        with mock.patch.object(server, "find_nmap", return_value=None), mock.patch.object(server, "is_admin", return_value=False), platform(win=True), mock.patch("builtins.print") as pr:
            self.assertEqual(server.doctor(), 0)
            out = " ".join(str(c.args[0]) for c in pr.call_args_list)
        self.assertIn("nmap.org", out); self.assertIn("Run as administrator", out)

    def test_unwritable_data_folder_is_a_failure(self):
        with mock.patch.object(server, "data_dir", side_effect=OSError("read-only")), mock.patch("builtins.print"): self.assertEqual(server.doctor(), 1)

    def test_everything_fine(self):
        with mock.patch.object(server, "find_nmap", return_value=__file__), mock.patch.object(server, "find_browser", return_value="/x/chrome"), mock.patch.object(server, "is_admin", return_value=True), \
             mock.patch.object(server.subprocess, "run", return_value=types.SimpleNamespace(stdout="Nmap version 7.95 ( https://nmap.org )\n")):
            st = {label: s for s, label, _ in server.doctor_report()}
        self.assertEqual(set(st.values()) - {"ok", "warn"}, set()); self.assertEqual(st["nmap"], "ok"); self.assertEqual(st["Scan privileges"], "ok")


if __name__ == "__main__":
    unittest.main()
