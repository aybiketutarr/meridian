"""install.py on every layout (Linux, macOS, Windows), the launcher it writes, upgrade, uninstall, and that every shipped file is where the installers expect it."""
import os, plistlib, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import install  # noqa: E402
import server  # noqa: E402

POSIX = os.name != "nt"
ENV = {k: v for k, v in os.environ.items() if k not in ("XDG_DATA_HOME", "MERIDIAN_DATA_DIR", "MERIDIAN_NMAP")}


class Base(unittest.TestCase):
    win = mac = False
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.home = Path(self.tmp.name)
        self.patches = [mock.patch.dict(os.environ, {**ENV, "HOME": str(self.home), "USERPROFILE": str(self.home), "LOCALAPPDATA": str(self.home / "L"), "APPDATA": str(self.home / "R")}, clear=True),
                        mock.patch.object(server.Path, "home", return_value=self.home), mock.patch.object(server, "IS_WIN", self.win), mock.patch.object(server, "IS_MAC", self.mac),
                        mock.patch.object(server, "HIST", self.home / "data" / "history.json"), mock.patch.object(server, "LANG", "en"),
                        mock.patch("builtins.print")]
        for p in self.patches: p.start()
        self.P = server.install_paths()
    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.tmp.cleanup()


class Linux(Base):
    def test_install_layout_and_menu_entry(self):
        install.install(ROOT, python="/usr/bin/python3")
        app = self.P["app"]
        for f in ("server.py", "index.html", "locales/tr.json", "locales/en.json", "assets/meridian.svg"): self.assertTrue((app / f).is_file(), f)
        self.assertFalse(any("__pycache__" in str(p) for p in app.rglob("*")))
        desk, icon = self.P["menu"]; text = desk.read_text(encoding="utf-8")
        self.assertIn("Name=Meridian", text); self.assertIn("Comment[tr]=nmap üzerinde ağ tarayıcı arayüzü", text); self.assertIn("Comment[de]=", text)
        self.assertIn(f'Exec="{self.P["launcher"].as_posix()}"', text); self.assertIn(f"Icon={icon}", text); self.assertTrue(icon.is_file())
        self.assertEqual(icon.read_bytes(), (ROOT / "assets" / "meridian.svg").read_bytes())

    @unittest.skipIf(not POSIX, "POSIX launcher")
    def test_the_installed_command_really_runs_and_finds_its_translations(self):
        install.install(ROOT, python=sys.executable)
        L = self.P["launcher"]; self.assertTrue(os.access(L, os.X_OK)); body = L.read_text(encoding="utf-8")
        self.assertTrue(body.startswith("#!/usr/bin/env sh")); self.assertIn("python3", body)
        r = subprocess.run([str(L), "--version"], capture_output=True, text=True, encoding="utf-8", timeout=30); self.assertEqual((r.returncode, r.stdout), (0, f"Meridian {server.VERSION}\n"))
        r = subprocess.run([str(L), "--lang", "tr", "--help"], capture_output=True, text=True, encoding="utf-8", timeout=30); self.assertIn("Kullanım", r.stdout)

    @unittest.skipIf(not POSIX, "POSIX launcher")
    def test_a_python_path_with_spaces_and_a_dead_python_both_work(self):
        spaced = self.home / "my python" / "bin"; spaced.mkdir(parents=True); exe = spaced / "python3"; exe.symlink_to(sys.executable)
        install.install(ROOT, python=str(exe)); L = self.P["launcher"]
        self.assertEqual(subprocess.run([str(L), "--version"], capture_output=True, text=True, timeout=30).stdout, f"Meridian {server.VERSION}\n")
        exe.unlink()                                             # Python upgraded or removed later: fall back to python3 on PATH
        self.assertEqual(subprocess.run([str(L), "--version"], capture_output=True, text=True, timeout=30).stdout, f"Meridian {server.VERSION}\n")

    def test_upgrade_replaces_the_copy_and_keeps_user_data(self):
        install.install(ROOT, python="/usr/bin/python3"); app = self.P["app"]
        (app / "stale-from-old-version.py").write_text("x", encoding="utf-8"); (app / "locales" / "old.json").write_text("{}", encoding="utf-8")
        data = self.home / "data"; data.mkdir(); (data / "history.json").write_text("[]", encoding="utf-8")
        install.install(ROOT, python="/usr/bin/python3")
        self.assertFalse((app / "stale-from-old-version.py").exists()); self.assertFalse((app / "locales" / "old.json").exists()); self.assertTrue((data / "history.json").exists())

    def test_uninstall(self):
        install.install(ROOT, python="/usr/bin/python3"); data = self.home / "data"; data.mkdir(); (data / "history.json").write_text("[]", encoding="utf-8")
        with mock.patch.object(server.sys, "argv", ["meridian", "--uninstall", "--yes", "--keep-data"]), mock.patch.object(server.os, "geteuid", create=True, return_value=1000):
            self.assertEqual(server.uninstall(), 0)
        for p in (self.P["app"], self.P["launcher"], *self.P["menu"]): self.assertFalse(p.exists(), str(p))
        self.assertTrue(data.exists())
        install.install(ROOT, python="/usr/bin/python3")
        with mock.patch.object(server.sys, "argv", ["meridian", "--uninstall", "--yes"]), mock.patch.object(server.os, "geteuid", create=True, return_value=1000):
            self.assertEqual(server.uninstall(), 0)
        self.assertFalse(data.exists())

    def test_missing_file_is_reported_not_crashed(self):
        with tempfile.TemporaryDirectory() as partial:
            (Path(partial) / "server.py").write_text("x", encoding="utf-8"); (Path(partial) / "ai.py").write_text("x", encoding="utf-8")
            with self.assertRaises(FileNotFoundError) as e: install.install(partial)
        self.assertEqual(e.exception.args[0], "index.html")
        self.assertFalse(self.P["app"].exists())                  # nothing half-installed
        with mock.patch.object(install, "install", side_effect=FileNotFoundError("index.html")), mock.patch.object(server.os, "geteuid", create=True, return_value=1000): self.assertEqual(install.main(["--lang", "en"]), 1)

    def test_refuses_to_run_as_root(self):
        with mock.patch.object(server.os, "geteuid", create=True, return_value=0), mock.patch.object(install, "install") as inst: self.assertEqual(install.main([]), 1)
        inst.assert_not_called()

    def test_main_installs_and_can_uninstall(self):
        with mock.patch.object(server.os, "geteuid", create=True, return_value=1000), mock.patch.object(install, "install") as inst:
            self.assertEqual(install.main(["--lang", "tr", "--no-path"]), 0); inst.assert_called_once_with(add_path=False); self.assertEqual(server.LANG, "tr")
        with mock.patch.object(server.os, "geteuid", create=True, return_value=1000), mock.patch.object(server, "uninstall", return_value=0) as un: self.assertEqual(install.main(["--uninstall"]), 0); un.assert_called_once()


class MacOS(Base):
    mac = True
    def test_layout_app_bundle_and_command(self):
        install.install(ROOT, python="/usr/bin/python3"); app = self.P["app"]
        self.assertEqual(app, self.home / "Library" / "Application Support" / "Meridian-app"); self.assertTrue((app / "server.py").is_file() and (app / "locales" / "tr.json").is_file())
        bundle = self.home / "Applications" / "Meridian.app"; plist = plistlib.loads((bundle / "Contents" / "Info.plist").read_bytes())
        self.assertEqual((plist["CFBundleExecutable"], plist["CFBundlePackageType"], plist["CFBundleShortVersionString"]), ("Meridian", "APPL", server.VERSION))
        exe = bundle / "Contents" / "MacOS" / "Meridian"; self.assertTrue(exe.is_file())
        if POSIX: self.assertTrue(os.access(exe, os.X_OK))
        body = exe.read_text(encoding="utf-8"); self.assertIn("/usr/bin/python3", body); self.assertIn("Application Support/Meridian-app/server.py", body.replace("'", ""))   # quoted: the folder name has a space
        self.assertTrue(self.P["launcher"].is_file())
        self.assertEqual(plist["CFBundleIconFile"], "Meridian"); self.assertTrue((bundle / "Contents" / "Resources" / "Meridian.icns").is_file())

    @unittest.skipIf(not POSIX, "POSIX launcher")
    def test_the_command_works_from_a_folder_with_a_space_in_its_name(self):
        install.install(ROOT, python=sys.executable)
        r = subprocess.run([str(self.P["launcher"]), "--version"], capture_output=True, text=True, timeout=30); self.assertEqual(r.stdout, f"Meridian {server.VERSION}\n")
        r = subprocess.run([str(self.home / "Applications" / "Meridian.app" / "Contents" / "MacOS" / "Meridian"), "--version"], capture_output=True, text=True, timeout=30); self.assertEqual(r.stdout, f"Meridian {server.VERSION}\n")

    def test_reinstall_replaces_the_bundle(self):
        install.install(ROOT, python="/usr/bin/python3"); stale = self.home / "Applications" / "Meridian.app" / "Contents" / "old"; stale.write_text("x", encoding="utf-8")
        install.install(ROOT, python="/usr/bin/python3"); self.assertFalse(stale.exists())

    def test_uninstall_removes_the_bundle(self):
        install.install(ROOT, python="/usr/bin/python3")
        with mock.patch.object(server.sys, "argv", ["meridian", "--uninstall", "--yes", "--keep-data"]), mock.patch.object(server.os, "geteuid", create=True, return_value=1000): self.assertEqual(server.uninstall(), 0)
        self.assertFalse((self.home / "Applications" / "Meridian.app").exists()); self.assertFalse(self.P["app"].exists())


class Windows(Base):
    win = True
    def test_layout_launcher_path_and_shortcut(self):
        with mock.patch.object(server, "win_user_path") as upath, mock.patch.object(install, "make_win_shortcut") as lnk:
            install.install(ROOT, python=r"C:\Python312\python.exe")
        app = self.P["app"]; self.assertEqual(app, self.home / "L" / "Meridian-app"); self.assertTrue((app / "server.py").is_file() and (app / "locales" / "de.json").is_file())
        raw = self.P["launcher"].read_bytes(); text = raw.decode("utf-8")
        self.assertEqual(self.P["launcher"].name, "meridian.cmd"); self.assertTrue(text.startswith("@echo off\r\nchcp 65001 >nul\r\n")); self.assertNotIn(b"\r\r", raw); self.assertTrue(text.endswith("%*\r\n"))
        self.assertIn(r'"C:\Python312\python.exe"', text); self.assertIn(str(app / "server.py"), text)
        upath.assert_called_once_with(add=self.P["bin"]); lnk.assert_called_once_with(self.P["menu"][0], Path(r"C:\Python312\python.exe"), app)

    def test_no_path_flag_leaves_the_path_alone(self):
        with mock.patch.object(server, "win_user_path") as upath, mock.patch.object(install, "make_win_shortcut"): install.install(ROOT, python="python.exe", add_path=False)
        upath.assert_not_called()

    def test_a_failing_shortcut_or_registry_never_breaks_the_install(self):
        with mock.patch.object(server, "win_user_path", side_effect=OSError), mock.patch.object(install, "make_win_shortcut", side_effect=subprocess.CalledProcessError(1, "powershell")):
            install.install(ROOT, python="python.exe")
        self.assertTrue(self.P["launcher"].is_file())

    def test_shortcut_command_quotes_apostrophes_in_paths(self):
        calls = []
        with mock.patch.object(install.subprocess, "run", side_effect=lambda cmd, **k: calls.append(cmd)):
            install.make_win_shortcut(self.home / "O'Brien" / "Meridian.lnk", Path(self.home / "py" / "python.exe"), self.home / "L" / "Meridian-app")
        ps = calls[0][-1]; self.assertEqual(calls[0][0], "powershell"); self.assertIn("O''Brien", ps); self.assertIn("server.py", ps); self.assertIn("CreateShortcut", ps); self.assertIn("IconLocation", ps); self.assertIn("meridian.ico", ps)

    def test_uninstall_cleans_the_path(self):
        with mock.patch.object(server, "win_user_path"), mock.patch.object(install, "make_win_shortcut"): install.install(ROOT, python="python.exe")
        with mock.patch.object(server.sys, "argv", ["meridian", "--uninstall", "--yes", "--keep-data"]), mock.patch.object(server, "win_user_path") as upath, mock.patch.object(server.os, "geteuid", create=True, return_value=1000): self.assertEqual(server.uninstall(), 0)
        upath.assert_called_once_with(remove=self.P["bin"]); self.assertFalse(self.P["app"].exists())


class Shipped(unittest.TestCase):
    def test_every_installed_file_exists_in_the_source_tree(self):
        for n in (*server.APP_FILES, *server.APP_DIRS, "install.py", "install.sh", "install.bat", "Dockerfile", "README.md", "README.tr.md", "CHANGELOG.md"): self.assertTrue((ROOT / n).exists(), n)

    def test_dockerfile_ships_what_the_installer_ships(self):
        d = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        for n in server.APP_DIRS: self.assertIn(f"COPY {n} ", d)
        for n in server.APP_FILES: self.assertIn(n, d.split("COPY server.py")[1].split("\n")[0] if n != "server.py" else "server.py")

    def test_wrappers(self):
        sh = (ROOT / "install.sh").read_text(encoding="utf-8"); self.assertTrue(sh.startswith("#!/usr/bin/env sh")); self.assertIn("install.py", sh); self.assertNotIn("\r", sh)
        bat = (ROOT / "install.bat").read_bytes(); self.assertIn(b"\r\n", bat); self.assertNotIn(b"\n", bat.replace(b"\r\n", b"")); self.assertIn(b"install.py", bat); self.assertIn(b"py -3", bat)
        if POSIX:       # syntax only: the +x bit is deliberately NOT checked (a web upload or a Windows commit drops it; the docs say `sh install.sh`)
            self.assertEqual(subprocess.run(["sh", "-n", str(ROOT / "install.sh")]).returncode, 0)

    def test_ci_runs_on_all_three_systems(self):
        y = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
        for os_ in ("ubuntu-latest", "macos-latest", "windows-latest"): self.assertIn(os_, y)
        for py in ('"3.10"', '"3.13"'): self.assertIn(py, y)

    def test_python_files_need_nothing_newer_than_3_10(self):
        import ast
        for f in ("server.py", "install.py", "tools/build_demo.py"):
            ast.parse((ROOT / f).read_text(encoding="utf-8"), feature_version=(3, 10))

    def test_icons_for_windows_and_macos_are_real(self):
        ico, icns = (ROOT / "assets" / "meridian.ico").read_bytes(), (ROOT / "assets" / "meridian.icns").read_bytes()
        self.assertEqual(ico[:4], b"\x00\x00\x01\x00"); self.assertGreaterEqual(int.from_bytes(ico[4:6], "little"), 6)      # ICO header, several sizes
        self.assertEqual(icns[:4], b"icns"); self.assertEqual(int.from_bytes(icns[4:8], "big"), len(icns))
        self.assertEqual((ROOT / "assets" / "meridian.png").read_bytes()[:8], b"\x89PNG\r\n\x1a\n")

    def test_the_icon_is_valid_svg(self):
        import xml.etree.ElementTree as ET
        self.assertTrue(ET.parse(ROOT / "assets" / "meridian.svg").getroot().tag.endswith("svg"))


if __name__ == "__main__":
    unittest.main()
