#!/usr/bin/env python3
"""Builds docs/index.html (the browser-only demo) from index.html + docs/demo-shim.js + locales/*.json, so the demo can never drift from the real UI.
Usage:  python3 tools/build_demo.py          (writes docs/index.html)"""
import re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

def build():
    import server
    ui = (ROOT / "index.html").read_text(encoding="utf-8")
    shim = (ROOT / "docs" / "demo-shim.js").read_text(encoding="utf-8")
    version = re.search(r'^VERSION = "([^"]+)"', (ROOT / "server.py").read_text(encoding="utf-8"), re.M).group(1)
    assert ui.count('const TOKEN="__TOKEN__"') == 1 and "<title>Meridian</title>" in ui and "v__VERSION__" in ui
    assert ui.count("/*__LOCALES__*/{}") == 1 and ui.count('DEFLANG="__LANG__"') == 1
    out = ui.replace("<title>Meridian</title>", "<title>Meridian - live demo (sample data)</title>")
    out = out.replace("v__VERSION__", "v" + version).replace('const VER="__VERSION__"', f'const VER="{version}"').replace(' nonce="__NONCE__"', "")       # a static page: no CSP nonce
    out = out.replace("/*__LOCALES__*/{}", server.locales_js()).replace('DEFLANG="__LANG__"', 'DEFLANG=""')    # no forced language: the browser decides
    # the shim answers /api/* in the browser; it runs in its own <script> before the real one
    return out.replace('const TOKEN="__TOKEN__"', "window.DEMO_MODE=true;\n" + shim + "</script>\n \n<script>\n" + 'const TOKEN="demo"')

if __name__ == "__main__":
    (ROOT / "docs" / "index.html").write_text(build(), encoding="utf-8")
    print("docs/index.html written")
