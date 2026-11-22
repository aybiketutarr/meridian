#!/usr/bin/env python3
"""Builds docs/index.html (the browser-only demo) from index.html + docs/demo-shim.js + locales/*.json, so the demo can never drift from the real UI.
Usage:  python3 tools/build_demo.py          (writes docs/index.html)"""
import re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# mobile header (demo only): row 1 = logo flush left + language at the right; row 2 = theme, report branding, export
DEMO_MOBILE_CSS = (
    "/* mobile header: row 1 = logo flush left + language at the right; row 2 = theme, report branding, export */\n"
    "@media(max-width:1000px){header{row-gap:8px}header::after{content:\"\";order:3;flex:0 0 100%;height:0;margin-top:-8px}"
    ".brand{order:1;flex:1;margin:0}#lang{order:2}#theme{order:4}#brb{order:5}.menu{order:6}.target{order:7}.go{order:8}#demo{order:9}}\n"
)

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
    out = out.replace("</style></head><body>", DEMO_MOBILE_CSS + "</style></head><body>", 1)    # demo-only mobile header layout
    # the shim answers /api/* in the browser; it runs in its own <script> before the real one
    return out.replace('const TOKEN="__TOKEN__"', "window.DEMO_MODE=true;\n" + shim + "</script>\n \n<script>\n" + 'const TOKEN="demo"')

if __name__ == "__main__":
    (ROOT / "docs" / "index.html").write_text(build(), encoding="utf-8")
    print("docs/index.html written")
