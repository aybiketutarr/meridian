#!/usr/bin/env python3
"""Builds dist/meridian_<version>_all.deb: a one-click package for Debian, Ubuntu, Kali, Linux Mint and friends.
Pure Python standard library (no dpkg needed to build), so CI and any machine can run it.

  python3 tools/build_deb.py

Install it by double-clicking the file (the software centre opens) or:   sudo apt install ./dist/meridian_<version>_all.deb
Remove it with:                                                            sudo apt remove meridian
The package puts the program in /opt/meridian, the `meridian` command in /usr/bin and an entry in the application menu.
nmap is a "Recommends": apt installs it by default. User data lives in the home folder and is not removed with the package."""
import gzip, hashlib, io, os, sys, tarfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import server  # noqa: E402

HOME_URL = "https://github.com/aybiketutarr/meridian"
LAUNCHER = "#!/bin/sh\nPYTHONDONTWRITEBYTECODE=1 exec python3 /opt/meridian/server.py \"$@\"\n"

def desktop_entry():
    loc = server.load_locales()
    comments = "".join(f"Comment[{c}]={d['desktop.comment']}\n" for c, d in loc.items() if c != "en" and d.get("desktop.comment"))
    return ("[Desktop Entry]\nType=Application\nName=Meridian\n" f"Comment={loc.get('en', {}).get('desktop.comment', 'Meridian')}\n{comments}"
            "Exec=meridian\nIcon=meridian\nTerminal=false\nCategories=Network;Security;\nKeywords=nmap;scanner;network;security;\n")

def payload():
    """[(path inside the package, bytes, mode)] for everything that is installed."""
    files = [(f"opt/meridian/{n}", (ROOT / n).read_bytes(), 0o644) for n in server.APP_FILES]
    for d in server.APP_DIRS:
        for p in sorted((ROOT / d).rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts and p.suffix not in (".pyc", ".ico", ".icns"):      # .ico/.icns are for Windows/macOS
                files.append((f"opt/meridian/{p.relative_to(ROOT).as_posix()}", p.read_bytes(), 0o644))
    files += [("usr/bin/meridian", LAUNCHER.encode(), 0o755), ("usr/share/applications/meridian.desktop", desktop_entry().encode(), 0o644),
              ("usr/share/icons/hicolor/scalable/apps/meridian.svg", (ROOT / "assets" / "meridian.svg").read_bytes(), 0o644),
              ("usr/share/pixmaps/meridian.png", (ROOT / "assets" / "meridian.png").read_bytes(), 0o644),
              ("usr/share/doc/meridian/copyright", (ROOT / "LICENSE").read_bytes(), 0o644)]
    return files

def control(files):
    size = -(-sum(len(b) for _, b, _ in files) // 1024)
    return (f"Package: meridian\nVersion: {server.VERSION}\nSection: net\nPriority: optional\nArchitecture: all\nInstalled-Size: {size}\n"
            "Depends: python3 (>= 3.10)\nRecommends: nmap, chromium | chromium-browser | google-chrome-stable | brave-browser\n"
            "Maintainer: Meridian <noreply@users.noreply.github.com>\n" f"Homepage: {HOME_URL}\n"
            "Description: Live web interface for nmap\n A local web interface on top of nmap: scan profiles, a topology map, risk scoring,\n known vulnerabilities, a trusted-device list, scan history and branded reports.\n Runs on localhost only. Scan only networks you own or have permission to test.\n")

def tar_gz(entries, epoch):
    """entries: [(name, bytes|None for a directory, mode)]. Everything is owned by root, with a fixed timestamp (reproducible)."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as t:
        for name, data, mode in entries:
            ti = tarfile.TarInfo(name); ti.uid = ti.gid = 0; ti.uname = ti.gname = "root"; ti.mtime = epoch; ti.mode = mode
            if data is None: ti.type = tarfile.DIRTYPE; t.addfile(ti)
            else: ti.size = len(data); t.addfile(ti, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=epoch, compresslevel=9) as g: g.write(raw.getvalue())
    return out.getvalue()

def ar(members, epoch):
    out = b"!<arch>\n"
    for name, data in members:
        out += f"{name + '/':<16}{epoch:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode() + data + (b"\n" if len(data) % 2 else b"")
    return out

def build(dest_dir=None):
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", 0)) or int(time.time())
    files = payload(); dirs = sorted({"./" + "/".join(p.split("/")[:i]) + "/" for p, _, _ in files for i in range(1, len(p.split("/")))})
    data = tar_gz([("./", None, 0o755)] + [(d, None, 0o755) for d in dirs] + [("./" + p, b, m) for p, b, m in files], epoch)
    md5 = "".join(f"{hashlib.md5(b).hexdigest()}  {p}\n" for p, b, _ in files).encode()
    ctl = tar_gz([("./", None, 0o755), ("./control", control(files).encode(), 0o644), ("./md5sums", md5, 0o644)], epoch)
    out = Path(dest_dir or ROOT / "dist"); out.mkdir(parents=True, exist_ok=True)
    deb = out / f"meridian_{server.VERSION}_all.deb"
    deb.write_bytes(ar([("debian-binary", b"2.0\n"), ("control.tar.gz", ctl), ("data.tar.gz", data)], epoch))
    return deb

if __name__ == "__main__":
    d = build(); print(d, f"({d.stat().st_size // 1024} KB)")
