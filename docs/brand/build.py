"""Rebuild the VisCon1 logos the web app serves (linkwatch/server/static/brand/) from the source SVGs in this folder.

    python docs/brand/build.py && node docs/brand/render-png.js   # the PNG step needs Playwright + Chromium

For each theme family (light, dark, green) it writes:
  viscon1-<family>.svg         animated, transparent corners, stops animating under prefers-reduced-motion
  viscon1-<family>-static.svg  the same without animation (favicons, reduced motion, email-safe)
  favicon-<family>-32.png, icon-<family>-192.png, icon-<family>-512.png   transparent PNG fallbacks
  apple-touch-icon-<family>.png  180x180, opaque square (iOS adds its own rounding)
"""
from __future__ import annotations

import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parent.parent / "linkwatch" / "server" / "static" / "brand"
SOURCES = {"light": "vc1-light.svg", "dark": "viscon1-dark-blue.svg", "green": "viscon1-as400-green.svg"}
REDUCED = "\n    @media (prefers-reduced-motion: reduce) { * { animation: none !important; } }\n"
STATIC = "\n    * { animation: none !important; }\n"


def transparent(svg: str, family: str) -> str:
    """Drop the full-bleed square behind each icon so it sits on any header colour."""
    if family == "light":
        # white square behind a shadowed tile: drop it and crop to the tile (plus room for its shadow)
        svg = re.sub(r'\s*<rect width="512" height="512" fill="#FFFFFF"/>', "", svg, count=1)
        svg = svg.replace('viewBox="0 0 512 512"', 'viewBox="28 28 456 456"', 1)
    else:
        # dark square: keep it, but with the same rounded corners as the tile's own clip path
        svg = re.sub(r'<rect width="512" height="512" fill="(#[0-9A-Fa-f]{6})"/>',
                     r'<rect width="512" height="512" rx="100" ry="100" fill="\1"/>', svg, count=1)
    return svg


def with_style(svg: str, extra: str) -> str:
    return svg.replace("]]></style>", extra + "    ]]></style>", 1)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    built: dict[str, tuple[str, str]] = {}
    for family, name in SOURCES.items():
        src = (HERE / name).read_text()
        t = transparent(src, family)
        (OUT / f"viscon1-{family}.svg").write_text(with_style(t, REDUCED))
        (OUT / f"viscon1-{family}-static.svg").write_text(with_style(t, STATIC))
        built[family] = (with_style(t, STATIC), with_style(src, STATIC))
    # opaque copies for the apple-touch icon (iOS rounds the corners itself); render-png.js turns these into PNGs
    for family, (_, opaque) in built.items():
        (OUT / f".apple-{family}.svg").write_text(opaque)
    print(f"Wrote {len(list(OUT.iterdir()))} files to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
