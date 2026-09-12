#!/usr/bin/env python3
"""Derive every brand raster from the one source artwork.

`source/logo-source.jpg` is the artwork as supplied. This script does the two
things that stand between a JPEG on a white page and an asset Home Assistant,
HACS and the dashboard can all use: it turns the white matte into real
transparency, and it cuts the two crops at the sizes each consumer wants.

Running it is optional -- every file it writes is committed. It needs `pillow`.

    python3 brand/build.py
"""
from __future__ import annotations

import os
from collections import deque

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "source", "logo-source.jpg")

# The source is 1024 square: the mark sits above an empty band of rows, the
# wordmark below it. Measured, not guessed -- see _bands().
MARK_BOTTOM = 780

# A pixel is background only if EVERY channel clears this. The source is a
# JPEG, so flat white arrives as 250-255 with ringing around every edge, and a
# threshold tight enough to be safe on the ink is loose enough to leave a rim.
# The rim is handled below rather than by moving this number.
BG = 240
ENCLOSED = 246
EDGE_LUM = 215        # a pixel this light next to transparency is matte, not ink
CORE_LUM = 190        # a pixel this dark is solid ink and can stand in as one


def _lum(p):
    return 0.2126 * p[0] + 0.7152 * p[1] + 0.0722 * p[2]


def key_out_white(src: str) -> Image.Image:
    """White matte -> alpha, with the mark left exactly as drawn."""
    im = Image.open(src).convert("RGBA")
    W, H = im.size
    px = im.load()
    alpha = bytearray(b"\xff" * (W * H))

    def light(p, thr):
        return p[0] >= thr and p[1] >= thr and p[2] >= thr

    # 1. The OUTSIDE, flooded from the border. Not a global "white is
    #    transparent" pass: that would also dissolve every white the artwork
    #    draws on purpose, and there is no way to tell them apart by colour.
    seen = bytearray(W * H)
    q = deque()
    for x in range(W):
        for y in (0, H - 1):
            if light(px[x, y], BG) and not seen[y * W + x]:
                seen[y * W + x] = 1
                q.append((x, y))
    for y in range(H):
        for x in (0, W - 1):
            if light(px[x, y], BG) and not seen[y * W + x]:
                seen[y * W + x] = 1
                q.append((x, y))
    while q:
        x, y = q.popleft()
        for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nx, ny = x + dx, y + dy
            if 0 <= nx < W and 0 <= ny < H and not seen[ny * W + nx] \
                    and light(px[nx, ny], BG):
                seen[ny * W + nx] = 1
                q.append((nx, ny))
    for i, v in enumerate(seen):
        if v:
            alpha[i] = 0

    # 2. The ENCLOSED whites the flood cannot reach: inside the padlock
    #    shackle, inside the keyhole, inside the trace nodes, inside the
    #    counters of the wordmark's letters. ALL of them go. The mark is two
    #    inks on a white page and a knockout keeps it that way on any page;
    #    keeping some filled and letting the rest knock through is the one
    #    result that is wrong on both grounds -- a light page cannot tell the
    #    difference either way, and a dark one then shows a white keyhole
    #    floating in a shield whose own outline has gone transparent.
    seen2 = bytearray(W * H)
    knocked = 0
    for sy in range(H):
        for sx in range(W):
            i = sy * W + sx
            if seen2[i] or not alpha[i] or not light(px[sx, sy], ENCLOSED):
                continue
            q = deque([(sx, sy)])
            seen2[i] = 1
            pts = []
            while q:
                x, y = q.popleft()
                pts.append((x, y))
                for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                    nx, ny = x + dx, y + dy
                    j = ny * W + nx
                    if 0 <= nx < W and 0 <= ny < H and not seen2[j] \
                            and alpha[j] and light(px[nx, ny], ENCLOSED):
                        seen2[j] = 1
                        q.append((nx, ny))
            if len(pts) < 40:          # JPEG speckle, not a shape
                continue
            knocked += 1
            for x, y in pts:
                alpha[y * W + x] = 0

    # 3. The RIM. Every pixel the original antialiased against white is still
    #    fully opaque and still nearly white, so it reads as a halo the moment
    #    the asset lands on anything dark -- and thresholding it away just
    #    moves the halo one pixel in. Solve its coverage instead: the pixel is
    #    a * ink + (1 - a) * white, so with the nearest solid ink standing in
    #    for `ink`, a falls out by projection.
    core = {(x, y) for y in range(H) for x in range(W)
            if alpha[y * W + x] and _lum(px[x, y]) < CORE_LUM}
    resolved = 0
    for y in range(H):
        for x in range(W):
            i = y * W + x
            if not alpha[i] or _lum(px[x, y]) < EDGE_LUM:
                continue
            if not any(0 <= x + dx < W and 0 <= y + dy < H
                       and alpha[(y + dy) * W + x + dx] == 0
                       for dx in (-2, -1, 0, 1, 2) for dy in (-2, -1, 0, 1, 2)):
                continue
            c = None
            for r in (1, 2, 3):
                near = [(x + dx, y + dy) for dx in range(-r, r + 1)
                        for dy in range(-r, r + 1) if (x + dx, y + dy) in core]
                if near:
                    c = px[min(near, key=lambda n: (n[0] - x) ** 2 + (n[1] - y) ** 2)]
                    break
            resolved += 1
            if c is None:
                alpha[i] = 0
                continue
            p = px[x, y]
            num = sum((255 - p[k]) * (255 - c[k]) for k in range(3))
            den = sum((255 - c[k]) ** 2 for k in range(3)) or 1
            px[x, y] = (c[0], c[1], c[2], 0)
            alpha[i] = int(round(255 * max(0.0, min(1.0, num / den))))

    for y in range(H):
        for x in range(W):
            p = px[x, y]
            px[x, y] = (p[0], p[1], p[2], alpha[y * W + x])
    print(f"  enclosed regions knocked out: {knocked}")
    print(f"  matte rim pixels resolved:    {resolved}")
    return im


def _bands(im: Image.Image) -> list[tuple[int, int]]:
    """Rows with no ink at all -- how MARK_BOTTOM was arrived at."""
    W, H = im.size
    px = im.load()
    rows = [any(px[x, y][3] for x in range(W)) for y in range(H)]
    out, start = [], None
    for y, v in enumerate(rows):
        if not v and start is None:
            start = y
        if v and start is not None:
            if y - start > 3:
                out.append((start, y - 1))
            start = None
    return out


def square(im: Image.Image, pad: float = 1.10) -> Image.Image:
    """Trim to the ink, then centre it in a square with a little air."""
    box = im.crop(im.getbbox())
    w, h = box.size
    side = int(max(w, h) * pad)
    out = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    out.paste(box, ((side - w) // 2, (side - h) // 2))
    return out


def main() -> None:
    print("keying", os.path.relpath(SOURCE, HERE))
    full = key_out_white(SOURCE)
    print("  empty row bands:", _bands(full))

    # THE ICON IS THE MARK ALONE. A 256px square that has to carry a two-line
    # wordmark renders the wordmark as grey mush, and HACS and the Home
    # Assistant sidebar both draw this small.
    mark = square(full.crop((0, 0, full.width, MARK_BOTTOM)))
    lockup = full.crop(full.getbbox())

    for im, name, w in ((mark, "icon.png", 256),         # home-assistant/brands
                        (mark, "icon@2x.png", 512),      # and its @2x
                        (lockup, "logo.png", None),      # docs and the dashboard
                        (lockup, "logo@2x.png", None)):
        if w:
            out = im.resize((w, w), Image.LANCZOS)
        else:
            h = 512 if name == "logo.png" else 1024
            out = im.resize((round(im.width * h / im.height), h), Image.LANCZOS)
        path = os.path.join(HERE, name)
        out.save(path, optimize=True)
        assert out.getbbox(), f"{name} rendered empty"
        print(f"  wrote {name:16} {out.size}")

    # The dashboard's tab icon, from the same mark and nothing else.
    fav = mark.resize((180, 180), Image.LANCZOS)
    fav.save(os.path.join(HERE, "favicon.png"), optimize=True)
    print(f"  wrote {'favicon.png':16} {fav.size}")


if __name__ == "__main__":
    main()
