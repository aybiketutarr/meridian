#!/usr/bin/env python3
"""Draws the Meridian emblem (same shape and colours as assets/meridian.svg) and writes the icon files the installers need:
  assets/meridian.png   1024 px, for docs and as a source
  assets/meridian.ico   Windows shortcut icon (16 - 256 px)
  assets/meridian.icns  macOS app icon (with the usual margin, as Apple's icons have)
Developer tool only: needs Pillow (pip install pillow). Meridian itself still has no dependencies, and the generated files are committed.
Usage:  python3 tools/make_icons.py"""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter

OUT = Path(__file__).resolve().parent.parent / "assets"
A, B, INK = (167, 139, 250), (34, 211, 238), (21, 11, 58)      # #a78bfa -> #22d3ee, glyph #150b3a

def gradient(n):
    g = Image.new("RGB", (64, 64))
    g.putdata([tuple(round(a + (b - a) * (x + y) / 126) for a, b in zip(A, B)) for y in range(64) for x in range(64)])
    return g.resize((n, n), Image.BICUBIC)

def emblem(box, ss=2):
    """The rounded square with the radar glyph, drawn at box*ss and returned at box x box (RGBA)."""
    n, k = box * ss, box * ss / 32                                  # the SVG is a 32 x 32 grid
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    mask = Image.new("L", (n, n), 0); ImageDraw.Draw(mask).rounded_rectangle((0, 0, n - 1, n - 1), radius=8 * k, fill=255)
    img.paste(gradient(n), (0, 0), mask)
    d, w = ImageDraw.Draw(img), 2.2 * k
    def arc(r):                                                     # circle of radius r around (16,16), open in the top-right quarter
        e = r * k + w / 2                                           # PIL draws the stroke inward from the box, so grow it by half the width
        d.arc((16 * k - e, 16 * k - e, 16 * k + e, 16 * k + e), 0, 270, fill=INK, width=round(w))
        for x, y in ((16, 16 - r), (16 + r, 16)): d.ellipse((x * k - w / 2, y * k - w / 2, x * k + w / 2, y * k + w / 2), fill=INK)
    arc(10); arc(5)
    d.line((16 * k, 16 * k, 24 * k, 8 * k), fill=INK, width=round(w))
    for x, y in ((16, 16), (24, 8)): d.ellipse((x * k - w / 2, y * k - w / 2, x * k + w / 2, y * k + w / 2), fill=INK)
    return img.resize((box, box), Image.LANCZOS)

def mac_canvas(size=1024):
    """macOS icons sit inside a margin and cast a soft shadow."""
    body, canvas = emblem(round(size * 0.80)), Image.new("RGBA", (size, size), (0, 0, 0, 0))
    off = (size - body.width) // 2
    sh = Image.new("RGBA", (size, size), (0, 0, 0, 0)); sh.paste((0, 0, 0, 110), (off, off + size // 60), body.getchannel("A"))
    canvas.alpha_composite(sh.filter(ImageFilter.GaussianBlur(size / 90))); canvas.alpha_composite(body, (off, off))
    return canvas

if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    big = emblem(1024); big.save(OUT / "meridian.png")
    big.save(OUT / "meridian.ico", sizes=[(s, s) for s in (16, 24, 32, 48, 64, 128, 256)])
    mac_canvas().save(OUT / "meridian.icns")
    for f in ("meridian.png", "meridian.ico", "meridian.icns"): print(f, (OUT / f).stat().st_size, "bytes")
