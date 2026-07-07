#!/usr/bin/env python3
"""Generate a self-contained coverage badge SVG from coverage data.

Dependency-free (stdlib only). Reads the current ``.coverage`` database via the
``coverage`` API if available, else a ``coverage.json`` file, and writes a
shields-style SVG. Used both locally and in CI so the badge in the README
always reflects the real, measured coverage — no external service required.

Usage:
    python tools/make_coverage_badge.py [--out coverage.svg] [--percent 95.5]
"""
from __future__ import annotations

import argparse
import json
import os
import sys


def _percent_from_coverage() -> float:
    try:
        import coverage  # type: ignore

        cov = coverage.Coverage()
        cov.load()
        return round(cov.report(file=open(os.devnull, "w")), 1)
    except Exception:
        pass
    for candidate in ("coverage.json",):
        if os.path.exists(candidate):
            with open(candidate) as fh:
                return round(json.load(fh)["totals"]["percent_covered"], 1)
    raise SystemExit("no coverage data found; run `coverage run -m pytest` first")


def _color(pct: float) -> str:
    if pct >= 90:
        return "#4c1"      # bright green
    if pct >= 80:
        return "#97ca00"   # green
    if pct >= 70:
        return "#a4a61d"   # yellow-green
    if pct >= 60:
        return "#dfb317"   # yellow
    if pct >= 50:
        return "#fe7d37"   # orange
    return "#e05d44"       # red


def make_svg(pct: float) -> str:
    label = "coverage"
    value = f"{pct:.0f}%"
    color = _color(pct)
    # Rough width math (6px/char + padding) — good enough for a crisp badge.
    lw = 6 * len(label) + 10
    vw = 6 * len(value) + 10
    total = lw + vw
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" aria-label="{label}: {value}">
  <title>{label}: {value}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{lw}" height="20" fill="#555"/>
    <rect x="{lw}" width="{vw}" height="20" fill="{color}"/>
    <rect width="{total}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{lw / 2:.0f}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{lw / 2:.0f}" y="14">{label}</text>
    <text x="{lw + vw / 2:.0f}" y="15" fill="#010101" fill-opacity=".3">{value}</text>
    <text x="{lw + vw / 2:.0f}" y="14">{value}</text>
  </g>
</svg>
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="coverage.svg")
    ap.add_argument("--percent", type=float, default=None,
                    help="override measured coverage (for testing)")
    args = ap.parse_args(argv)
    pct = args.percent if args.percent is not None else _percent_from_coverage()
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(make_svg(pct))
    print(f"wrote {args.out} ({pct:.1f}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
