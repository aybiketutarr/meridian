#!/usr/bin/env python3
"""Run this before every push:   python3 tools/preflight.py
It checks what most often turns the CI cross red (files in the wrong place, line endings, an out-of-date demo, an
inconsistent version) and then runs the whole test suite. Exit code 0 = safe to push."""
import importlib.util, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
problems = []

def check(ok, text):
    print(("ok    " if ok else "FAIL  ") + text)
    if not ok: problems.append(text)

for p in ("server.py", "index.html", "install.py", "locales/en.json", "tests", "docs/index.html", "tools/build_demo.py", "tools/build_deb.py", "installer/meridian.iss", ".github/workflows/release.yml", ".github/workflows/tests.yml", ".gitattributes", "CHANGELOG.md"):
    check((ROOT / p).exists(), f"{p} is in the repository root (not inside a sub-folder)")
for p in ("install.sh", "server.py", "install.py"):
    f = ROOT / p
    check(f.exists() and b"\r" not in f.read_bytes(), f"{p} uses LF line endings")
bat = ROOT / "install.bat"
check(bat.exists() and b"\r\n" in bat.read_bytes() and b"\n" not in bat.read_bytes().replace(b"\r\n", b""), "install.bat uses CRLF line endings")

import server
spec = importlib.util.spec_from_file_location("build_demo", ROOT / "tools" / "build_demo.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
check(m.build() == (ROOT / "docs" / "index.html").read_text(encoding="utf-8"), "docs/index.html is up to date   (if not: python3 tools/build_demo.py)")
check(f"## {server.VERSION}" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), f"CHANGELOG.md has an entry for {server.VERSION}")

r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"], cwd=ROOT)
check(r.returncode == 0, "all tests pass")
print("\n" + ("READY TO PUSH" if not problems else f"{len(problems)} problem(s) - fix them before pushing"))
sys.exit(1 if problems else 0)
