#!/usr/bin/env python3
"""Draw the Cyber Monitor brand marks and export the rasters HACS and the
brands repository ask for.

The artwork is ORIGINAL and lives here as code rather than as a binary nobody
can diff: Home Assistant's house silhouette and palette wrapped around the
split-shield / circuit-trace / keyhole vocabulary of a security mark. Nothing
is traced from, or embedded out of, a third-party asset, and this is not Home
Assistant's own logo.

Running it is optional -- every file it writes is committed. It needs
`fonttools` (wordmark glyphs are converted to paths, so the lockup does not
depend on a font being installed wherever it is rendered), `pillow`, and a
Chromium binary for the PNG exports. Point CHROME at one, or pass --svg-only.

    python3 brand/generate.py [--chrome /path/to/chrome] [--svg-only]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile

BLUE, SLATE, WHITE, DARK_INK = "#18BCF2", "#44739E", "#ffffff", "#E7EEF5"
HERE = os.path.dirname(os.path.abspath(__file__))

FONT_CANDIDATES = (
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    "/usr/share/fonts/liberation-sans/LiberationSans-Bold.ttf",
    "/usr/share/fonts/TTF/LiberationSans-Bold.ttf",
    "/Library/Fonts/Arial Bold.ttf",
)
CHROME_CANDIDATES = (
    os.environ.get("CHROME", ""),
    "/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
    "/usr/bin/chromium",
    "/usr/bin/google-chrome",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)

# --- the mark -------------------------------------------------------------
# One 512x512 coordinate space. The shield's top corners are placed so they
# meet the 45-degree roof exactly: half-width == (top edge - apex y).
T, BOT = 176, 444
HW = T - 40
L, R = 256 - HW, 256 + HW
SHIELD = (f"M {L+18},{T} H {R-18} A 18,18 0 0 1 {R},{T+18} V 300 "
          f"C {R},374 330,418 256,{BOT} C 182,418 {L},374 {L},300 "
          f"V {T+18} A 18,18 0 0 1 {L+18},{T} Z")


def mark(uid: str) -> tuple[str, str]:
    """Return (defs, body) for the icon artwork."""
    defs = f'<clipPath id="{uid}-shield"><path d="{SHIELD}"/></clipPath>'
    body = f'''<!-- the house: left half Home Assistant blue, right half HA slate -->
    <g fill="none" stroke-width="32" stroke-linecap="round" stroke-linejoin="round">
      <path d="M 256,40 L 40,256 L 40,436 Q 40,470 74,470 L 256,470" stroke="{BLUE}"/>
      <path d="M 256,40 L 472,256 L 472,436 Q 472,470 438,470 L 256,470" stroke="{SLATE}"/>
    </g>
    <!-- the shield is wired to the floor of the house, not floating in it -->
    <path d="M 256,{BOT-12} V 462" stroke="{BLUE}" stroke-width="13" stroke-linecap="round"/>
    <!-- shield: a white keyline lifts it off the roof, then the two halves -->
    <path d="{SHIELD}" fill="{WHITE}" stroke="{WHITE}" stroke-width="20" stroke-linejoin="round"/>
    <g clip-path="url(#{uid}-shield)">
      <rect x="{L-4}" y="{T-4}" width="{260-L}" height="{BOT-T+8}" fill="{BLUE}"/>
      <rect x="256" y="{T-4}" width="{R-252}" height="{BOT-T+8}" fill="{SLATE}"/>
    </g>
    <path d="M 256,{T} V {BOT-6}" stroke="{WHITE}" stroke-width="11"/>
    <!-- what is on the network: routed traces terminating in nodes -->
    <g fill="none" stroke="{WHITE}" stroke-width="13" stroke-linecap="round" stroke-linejoin="round">
      <path d="M 140,214 H 178 L 210,246"/>
      <path d="M 132,272 H 162 L 194,304"/>
      <path d="M 144,338 H 170 L 198,366"/>
      <circle cx="222" cy="258" r="11" stroke-width="10"/>
      <circle cx="206" cy="316" r="11" stroke-width="10"/>
      <circle cx="210" cy="378" r="11" stroke-width="10"/>
    </g>
    <!-- what is being protected -->
    <g fill="{WHITE}">
      <circle cx="324" cy="296" r="22"/>
      <path d="M 313,311 L 306,358 H 342 L 335,311 Z"/>
    </g>
    <circle cx="256" cy="470" r="12" fill="{WHITE}" stroke="{BLUE}" stroke-width="11"/>'''
    return defs, body


# --- the wordmark ---------------------------------------------------------
def _font() -> str:
    for p in FONT_CANDIDATES:
        if p and os.path.exists(p):
            return p
    sys.exit("no bold sans found; edit FONT_CANDIDATES")


def outline(text: str, size: float, x: float = 0.0, y: float = 0.0,
            tracking: float = 0.0) -> tuple[str, float]:
    """Convert a string to an SVG path. y is the baseline; the font's y-axis is
    flipped. Glyphs become paths so the lockup renders identically with no font
    installed -- a <text> element in a logo file is a different logo per host."""
    from fontTools.misc.transform import Transform
    from fontTools.pens.svgPathPen import SVGPathPen
    from fontTools.pens.transformPen import TransformPen
    from fontTools.ttLib import TTFont

    f = TTFont(_font())
    upm = f["head"].unitsPerEm
    cmap, gs, hmtx = f.getBestCmap(), f.getGlyphSet(), f["hmtx"]
    kern = f["kern"].kernTables[0].kernTable if "kern" in f else {}
    scale, pen, cursor, prev = size / upm, SVGPathPen(f.getGlyphSet()), 0.0, None
    for ch in text:
        g = cmap.get(ord(ch))
        if g is None:
            sys.exit(f"no glyph for {ch!r}")
        if prev is not None:
            cursor += kern.get((prev, g), 0)
        gs[g].draw(TransformPen(pen, Transform(scale, 0, 0, -scale,
                                               x + cursor * scale, y)))
        cursor += hmtx[g][0] + tracking * upm
        prev = g
    return pen.getCommands(), cursor * scale


def icon_svg() -> str:
    defs, body = mark("icon")
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512"'
            ' height="512" role="img" aria-label="Cyber Monitor">\n'
            '  <title>Cyber Monitor</title>\n'
            f'  <defs>{defs}</defs>\n  <g>\n    {body}\n  </g>\n</svg>\n')


def logo_svg(word1: str = SLATE, word2: str = BLUE) -> str:
    size, track, icon_h, pad, gap = 122, 0.012, 312, 14, 0.30 * 122
    scale = icon_h / 512
    _, w1 = outline("Cyber", size, tracking=track)
    _, w2 = outline("Monitor", size, tracking=track)
    text_x = pad + icon_h + 56
    baseline = pad + icon_h / 2 + 0.688 * size / 2   # 0.688em is the cap height
    total_w, total_h = text_x + w1 + gap + w2 + pad, icon_h + pad * 2
    d1, _ = outline("Cyber", size, x=text_x, y=baseline, tracking=track)
    d2, _ = outline("Monitor", size, x=text_x + w1 + gap, y=baseline, tracking=track)
    defs, body = mark("logo")
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total_w:.0f} {total_h}"'
            f' width="{total_w:.0f}" height="{total_h}" role="img" aria-label="Cyber Monitor">\n'
            '  <title>Cyber Monitor</title>\n'
            f'  <defs>{defs}</defs>\n'
            f'  <g transform="translate({pad},{pad}) scale({scale:.6f})">\n    {body}\n  </g>\n'
            f'  <path d="{d1}" fill="{word1}"/>\n'
            f'  <path d="{d2}" fill="{word2}"/>\n</svg>\n')


# --- raster export --------------------------------------------------------
def export(chrome: str, svg: str, png: str, w: int, h: int) -> None:
    """Screenshot the SVG at an exact pixel size, on a transparent ground.

    Headless Chromium's screenshot canvas is taller than the laid-out viewport
    it fills, so the window is over-tall on purpose and the result is cropped;
    asking for exactly (w, h) silently returns a page cut off partway down.
    """
    from PIL import Image
    html = (f"<style>html,body{{margin:0;padding:0;background:transparent;overflow:hidden}}"
            f"img{{display:block;width:{w}px;height:{h}px}}</style>"
            f'<img src="file://{os.path.abspath(svg)}">')
    fd, hp = tempfile.mkstemp(suffix=".html")
    os.write(fd, html.encode())
    os.close(fd)
    raw = png + ".raw.png"   # chromium ignores --screenshot without a .png suffix
    subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-sandbox",
                    "--hide-scrollbars", "--force-device-scale-factor=1",
                    "--default-background-color=00000000",
                    f"--window-size={w},{h + 140}", f"--screenshot={raw}",
                    f"file://{hp}"], capture_output=True, check=True)
    im = Image.open(raw).convert("RGBA").crop((0, 0, w, h))
    if im.getbbox() is None:
        sys.exit(f"{png}: rendered empty")
    im.save(png)
    os.remove(raw)
    os.remove(hp)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chrome", default="")
    ap.add_argument("--svg-only", action="store_true")
    args = ap.parse_args()

    files = {"icon.svg": icon_svg(),
             "logo.svg": logo_svg(),
             "logo-dark.svg": logo_svg(word1=DARK_INK)}
    for name, body in files.items():
        with open(os.path.join(HERE, name), "w") as fh:
            fh.write(body)
        print("wrote", name)
    if args.svg_only:
        return

    chrome = next((c for c in (args.chrome,) + CHROME_CANDIDATES
                   if c and os.path.exists(c)), "")
    if not chrome:
        sys.exit("no chromium found; pass --chrome or use --svg-only")

    # icon.png/icon@2x.png are the sizes home-assistant/brands requires, and
    # icon.png at this path is what the HACS brands check looks for when
    # hacs.json sets content_in_root.
    for src, dst, w, h in (("icon.svg", "icon.png", 256, 256),
                           ("icon.svg", "icon@2x.png", 512, 512),
                           ("logo.svg", "logo.png", 512, 140),
                           ("logo.svg", "logo@2x.png", 1024, 280),
                           ("logo-dark.svg", "logo-dark.png", 512, 140),
                           ("logo-dark.svg", "logo-dark@2x.png", 1024, 280)):
        export(chrome, os.path.join(HERE, src), os.path.join(HERE, dst), w, h)
        print("wrote", dst)


if __name__ == "__main__":
    main()
