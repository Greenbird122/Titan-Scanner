#!/usr/bin/env python3
"""tscan — standalone entry point that forces correct titan import.

This file lives OUTSIDE the titan/ namespace, so CWD shadowing can't
redirect it to a local titan-lab/titan/ copy.  It rewrites sys.path
before importing anything from titan.
"""
import os
import sys

# ── Force correct titan package ─────────────────────────────────────────
# Find the installed titan_scanner package's site-packages dir.
# This script lives at:  site-packages/tscan_cli.py
_site = os.path.dirname(os.path.abspath(__file__))

# Put site-packages FIRST so `import titan` resolves to the wheel, not CWD.
if _site not in sys.path[:3]:
    sys.path.insert(0, _site)

# Purge any titan already loaded from the wrong path.
if "titan" in sys.modules:
    loaded = os.path.abspath(
        os.path.join(
            os.path.dirname(sys.modules["titan"].__file__ or ""),
            "..",
        )
    )
    if os.path.normcase(loaded) != os.path.normcase(_site):
        bad = [k for k in sys.modules if k == "titan" or k.startswith("titan.")]
        for k in bad:
            del sys.modules[k]
# ────────────────────────────────────────────────────────────────────────

from titan.cli import main

if __name__ == "__main__":
    main()
