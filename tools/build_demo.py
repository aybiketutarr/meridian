#!/usr/bin/env python3
"""Builds docs/index.html (the browser-only demo) from index.html + docs/demo-shim.js, so the demo can never drift from the real UI.
Usage:  python3 tools/build_demo.py          (writes docs/index.html)"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def build():
    ui = (ROOT / "index.html").read_text()
    shim = (ROOT / "docs" / "demo-shim.js").read_text()
    version = re.search(r'^VERSION = "([^"]+)"', (ROOT / "server.py").read_text(), re.M).group(1)
    assert ui.count('const TOKEN="__TOKEN__"') == 1 and "<title>Meridian</title>" in ui and "v__VERSION__" in ui
    out = ui.replace("<title>Meridian</title>", "<title>Meridian - live demo (sample data)</title>")
    out = out.replace("v__VERSION__", "v" + version)
    # the shim answers /api/* in the browser; it runs in its own <script> before the real one
    return out.replace('const TOKEN="__TOKEN__"', "window.DEMO_MODE=true;\n" + shim + "</script>\n \n<script>\n" + 'const TOKEN="demo"')

if __name__ == "__main__":
    (ROOT / "docs" / "index.html").write_text(build())
    print("docs/index.html written")
