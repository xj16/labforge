#!/usr/bin/env python3
"""Fail CI if the committed coverage badge has drifted from measured coverage.

Compares the integer percentage baked into ``coverage.svg`` against the freshly
measured coverage, allowing a small tolerance so trivial cross-interpreter
branch-coverage differences don't cause spurious failures. Keeps the badge
honest without making it brittle. Stdlib only.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from make_coverage_badge import _percent_from_coverage  # noqa: E402

_BADGE_RE = re.compile(r"coverage:\s*(\d+)%")


def badge_percent(path: str) -> int:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    m = _BADGE_RE.search(text)
    if not m:
        raise SystemExit(f"could not find a coverage percentage in {path}")
    return int(m.group(1))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--badge", default="coverage.svg")
    ap.add_argument("--tolerance", type=int, default=2)
    args = ap.parse_args(argv)

    committed = badge_percent(args.badge)
    measured = round(_percent_from_coverage())
    delta = abs(committed - measured)
    print(f"badge={committed}%  measured={measured}%  delta={delta}  tolerance={args.tolerance}")
    if delta > args.tolerance:
        print("::error::coverage.svg is stale. Regenerate it with:")
        print("  cd siem && coverage run -m pytest && python tools/make_coverage_badge.py")
        return 1
    return 0


if __name__ == "__main__":
    sys.path.insert(0, __file__.rsplit("/", 1)[0] if "/" in __file__ else ".")
    sys.exit(main())
