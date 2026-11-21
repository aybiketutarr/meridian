"""One-click installers: the .deb is really built and well formed, and the Windows installer files agree with the program (nothing was left out)."""
import gzip, io, re, shutil, subprocess, sys, tarfile, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "tools"))
import server  # noqa: E402
import build_deb  # noqa: E402

def read_ar(blob):
    assert blob[:8] == b"!<arch>\n"; i, out = 8, {}
    while i < len(blob):
        hdr = blob[i:i + 60]; assert hdr[58:60] == b"`\n"
        name, size = hdr[:16].decode().strip().rstrip("/"), int(hdr[48:58]); i += 60
        out[name] = blob[i:i + size]; i += size + (size % 2)
    return out


class Deb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(); cls.deb = build_deb.build(cls.tmp); cls.ar = read_ar(cls.deb.read_bytes())
        cls.data = tarfile.open(fileobj=io.BytesIO(gzip.decompress(cls.ar["data.tar.gz"])))
        cls.ctl = tarfile.open(fileobj=io.BytesIO(gzip.decompress(cls.ar["control.tar.gz"])))

    @classmethod
    def tearDownClass(cls): shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_file_name_and_members(self):
        self.assertEqual(self.deb.name, f"meridian_{server.VERSION}_all.deb")
        self.assertEqual(list(self.ar), ["debian-binary", "control.tar.gz", "data.tar.gz"]); self.assertEqual(self.ar["debian-binary"], b"2.0\n")

    def test_control_file(self):
        c = self.ctl.extractfile("./control").read().decode()
        for line in ("Package: meridian", f"Version: {server.VERSION}", "Architecture: all", "Depends: python3 (>= 3.10)"): self.assertIn(line, c)
        self.assertRegex(c, r"Recommends: nmap,")

    def test_everything_the_program_needs_is_inside(self):
        names = {m.name for m in self.data.getmembers()}
        for n in ("server.py", "ai.py", "index.html", "locales/tr.json", "assets/meridian.svg"): self.assertIn("./opt/meridian/" + n, names)
        for n in ("./usr/bin/meridian", "./usr/share/applications/meridian.desktop", "./usr/share/icons/hicolor/scalable/apps/meridian.svg"): self.assertIn(n, names)
        self.assertFalse([n for n in names if n.endswith((".ico", ".icns", ".pyc"))])        # Windows/macOS icons and bytecode stay out

    def test_command_is_executable_and_everything_belongs_to_root(self):
        m = self.data.getmember("./usr/bin/meridian"); self.assertEqual(m.mode, 0o755)
        self.assertIn(b"/opt/meridian/server.py", self.data.extractfile(m).read())
        for m in self.data.getmembers(): self.assertEqual((m.uid, m.gid, m.uname), (0, 0, "root"), m.name)

    def test_desktop_entry(self):
        d = self.data.extractfile("./usr/share/applications/meridian.desktop").read().decode()
        for line in ("Exec=meridian", "Icon=meridian", "Terminal=false"): self.assertIn(line, d)

    @unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb not installed")
    def test_dpkg_accepts_it(self):
        r = subprocess.run(["dpkg-deb", "--field", str(self.deb), "Package", "Version"], capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(server.VERSION, r.stdout)
        r = subprocess.run(["dpkg-deb", "--contents", str(self.deb)], capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_build_is_reproducible(self):
        a, b = build_deb.build(self.tmp).read_bytes(), build_deb.build(self.tmp).read_bytes()
        import os; os.environ["SOURCE_DATE_EPOCH"] = "1700000000"
        try: x, y = build_deb.build(self.tmp).read_bytes(), build_deb.build(self.tmp).read_bytes()
        finally: del os.environ["SOURCE_DATE_EPOCH"]
        self.assertEqual(x, y)


class Windows(unittest.TestCase):
    ISS = (ROOT / "installer" / "meridian.iss").read_text(encoding="utf-8")
    FLOW = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    def test_installer_script_points_at_real_files(self):
        for rel in re.findall(r'(?:SetupIconFile|LicenseFile)=\.\.\\([^\r\n]+)', self.ISS): self.assertTrue((ROOT / rel.replace("\\", "/")).is_file(), rel)
        self.assertIn("{#AppVersion}", self.ISS); self.assertRegex(self.ISS, r"AppId=\{\{[0-9A-F-]{36}\}")
        self.assertIn("PrivilegesRequired=lowest", self.ISS)            # no administrator needed

    def test_pyinstaller_ships_everything_the_installer_copies(self):
        for name in server.APP_DIRS: self.assertIn(f'--add-data "{name};{name}"', self.FLOW)
        self.assertIn('--add-data "index.html;."', self.FLOW); self.assertIn("--hidden-import ai", self.FLOW)
        self.assertIn("--windowed", self.FLOW); self.assertIn("assets/meridian.ico", self.FLOW)

    def test_release_workflow_builds_both_and_publishes_on_tags(self):
        for needle in ("tools/build_deb.py", "installer\\meridian.iss", "tags:", "softprops/action-gh-release", "contents: write"): self.assertIn(needle, self.FLOW)
        self.assertNotIn("@master", self.FLOW)

    def test_terminal_install_still_exists_for_every_system(self):
        for f in ("install.py", "install.sh", "install.bat"): self.assertTrue((ROOT / f).is_file(), f)


if __name__ == "__main__":
    unittest.main()
