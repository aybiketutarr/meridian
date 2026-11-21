#!/usr/bin/env python3
"""Meridian installer for Linux, macOS and Windows. Installs for the current user only: no root, no administrator.

  python3 install.py                 install or update
  python3 install.py --lang tr       messages in another language (en, tr, de, es, fr)
  python3 install.py --no-path       Windows: do not change the PATH
  python3 install.py --uninstall     same as  meridian --uninstall  (--keep-data, --yes)
"""
import os, shlex, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import server  # noqa: E402  (importing it has no side effects)

def say(key, **kw): print(server.T(key, **kw))

def sh_launcher(py, app):
    """POSIX launcher: the Python that ran the installer (so GUI starts work without a PATH), else python3.
    Always forward slashes: this script runs on Linux/macOS even when the installer itself was built on Windows."""
    return ("#!/usr/bin/env sh\n" f"PY={shlex.quote(Path(py).as_posix())}\n" '[ -x "$PY" ] || PY=python3\n'
            f'exec "$PY" {shlex.quote((Path(app) / "server.py").as_posix())} "$@"\n')

def copy_app(src, app):
    for name in (*server.APP_FILES, *server.APP_DIRS):
        if not (Path(src) / name).exists(): raise FileNotFoundError(name)
    if app.name.lower() == "meridian-app": shutil.rmtree(app, ignore_errors=True)       # a clean copy, so files of older versions never linger
    app.mkdir(parents=True, exist_ok=True)
    for f in server.APP_FILES: shutil.copy2(Path(src) / f, app / f)
    for d in server.APP_DIRS: shutil.copytree(Path(src) / d, app / d, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

def write_launcher(P, py, app):
    P["bin"].mkdir(parents=True, exist_ok=True); L = P["launcher"]
    if P["os"] == "windows":
        # chcp 65001: user names with accents (e.g. Turkish letters) survive the batch file
        L.write_text(f'@echo off\r\nchcp 65001 >nul\r\n"{py}" "{app / "server.py"}" %*\r\n', encoding="utf-8", newline="")
    else:
        L.write_text(sh_launcher(py, app), encoding="utf-8"); L.chmod(0o755)

def desk_quote(p):
    """.desktop Exec= value. Always forward slashes: this file is read by a Linux desktop even when built on Windows."""
    return '"' + Path(p).as_posix().replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`").replace("%", "%%") + '"'

def make_linux_menu(P, launcher, src):
    desk, icon = P["menu"]
    desk.parent.mkdir(parents=True, exist_ok=True); icon.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(Path(src) / "assets" / "meridian.svg", icon)
    loc = server.load_locales()
    comments = "".join(f"Comment[{c}]={d['desktop.comment']}\n" for c, d in loc.items() if c != "en" and d.get("desktop.comment"))
    desk.write_text("[Desktop Entry]\nType=Application\nName=Meridian\n" f"Comment={loc.get('en', {}).get('desktop.comment', 'Meridian')}\n{comments}"
                    f"Exec={desk_quote(launcher)}\nIcon={icon}\nTerminal=false\nCategories=Network;Security;\nKeywords=nmap;scanner;network;security;\n", encoding="utf-8")

def make_mac_app(bundle, py, app):
    """A small Meridian.app in ~/Applications (Launchpad and Spotlight find it). It only starts server.py."""
    shutil.rmtree(bundle, ignore_errors=True)
    macos = bundle / "Contents" / "MacOS"; macos.mkdir(parents=True)
    (bundle / "Contents" / "Info.plist").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>\n<key>CFBundleName</key><string>Meridian</string>\n<key>CFBundleDisplayName</key><string>Meridian</string>\n'
        '<key>CFBundleIdentifier</key><string>app.meridian.scanner</string>\n<key>CFBundleExecutable</key><string>Meridian</string>\n'
        '<key>CFBundleIconFile</key><string>Meridian</string>\n<key>NSHighResolutionCapable</key><true/>\n'
        f'<key>CFBundlePackageType</key><string>APPL</string>\n<key>CFBundleShortVersionString</key><string>{server.VERSION}</string>\n</dict></plist>\n', encoding="utf-8")
    icns = Path(app) / "assets" / "meridian.icns"                       # the emblem: Launchpad, Dock and Finder show it instead of a generic icon
    if icns.is_file(): (bundle / "Contents" / "Resources").mkdir(); shutil.copy2(icns, bundle / "Contents" / "Resources" / "Meridian.icns")
    bundle.touch()                                                       # nudges Finder to refresh a cached icon on reinstall
    exe = macos / "Meridian"; exe.write_text(sh_launcher(py, app), encoding="utf-8"); exe.chmod(0o755)

def make_win_shortcut(lnk, py, app):
    """Start Menu shortcut through PowerShell (no extra packages). pythonw.exe: no console window; the Meridian emblem replaces the Python icon."""
    pyw = Path(py).with_name("pythonw.exe"); target = pyw if pyw.exists() else Path(py)
    q = lambda x: str(x).replace("'", "''")
    lnk.parent.mkdir(parents=True, exist_ok=True)
    ps = (f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{q(lnk)}');$s.TargetPath='{q(target)}';"
          f"$s.Arguments='\"{q(Path(app) / 'server.py')}\"';$s.WorkingDirectory='{q(app)}';$s.Description='Meridian';$s.IconLocation='{q(Path(app) / 'assets' / 'meridian.ico')},0';$s.Save()")
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], check=True, capture_output=True, timeout=60)
    try: import ctypes; ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)      # SHCNE_ASSOCCHANGED: refresh Explorer's icon cache
    except (AttributeError, OSError, ImportError): pass

def install(src=HERE, python=None, add_path=True):
    P = server.install_paths(); py = Path(python or sys.executable); app = P["app"]
    copy_app(src, app); say("in.copied", path=app)
    write_launcher(P, py, app); say("in.launcher", path=P["launcher"])
    try:
        if P["os"] == "linux": make_linux_menu(P, P["launcher"], src)
        elif P["os"] == "macos": make_mac_app(P["menu"][0], py, app)
        else: make_win_shortcut(P["menu"][0], py, app)
        say("in.menu", path=P["menu"][0])
    except (OSError, subprocess.SubprocessError): say("in.shortcut_failed")
    if P["os"] == "windows" and add_path:
        try: server.win_user_path(add=P["bin"]); say("in.path_added", path=P["bin"])
        except (OSError, ImportError): say("in.path_hint", path=P["bin"])
    elif P["os"] != "windows" and str(P["bin"]) not in os.environ.get("PATH", "").split(os.pathsep): say("in.path_hint", path=P["bin"])
    if not server.find_nmap(): print("nmap: " + server.T("dr.nmap_" + P["os"]))
    say("in.done"); say("in.root_tip_" + P["os"], path=P["launcher"])
    return P

def main(argv=None):
    server.fix_stdio()
    if argv is not None: sys.argv = [sys.argv[0], *argv]
    forced = server.argval("--lang") or os.environ.get("MERIDIAN_LANG", "")
    server.LANG = server.pick_lang(forced, *server.system_langs())
    if "--uninstall" in sys.argv: return server.uninstall()
    if hasattr(os, "geteuid") and os.geteuid() == 0: say("in.root"); return 1
    try: install(add_path="--no-path" not in sys.argv)
    except FileNotFoundError as e: say("in.missing", name=e.args[0]); return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
