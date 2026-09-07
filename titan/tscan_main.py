#!/usr/bin/env python3
"""tscan entry point — forces correct titan import regardless of CWD.

When run from a directory that contains a titan/ folder (e.g. titan-lab),
Python resolves import titan to the CWD copy instead of the installed
package. This module fixes that BEFORE importing titan.cli.
"""
import os
import sys

# Find site-packages where THIS file lives
_this_dir = os.path.dirname(os.path.abspath(__file__))
# titan/tscan_main.py → titan → site-packages
_site_pkgs = os.path.dirname(_this_dir)

# Step 1: Put site-packages at the FRONT of sys.path
sys.path = [p for p in sys.path if os.path.normcase(p) != os.path.normcase(_site_pkgs)]
sys.path.insert(0, _site_pkgs)

# Step 2: Also remove CWD entries that contain a titan/ folder
cwd = os.getcwd()
new_path = []
for p in sys.path:
    if os.path.normcase(p) == os.path.normcase(cwd):
        # CWD — skip it, it has a local titan/ that shadows us
        continue
    new_path.append(p)
sys.path = new_path

# Step 3: Purge ALL titan modules from cache so they reimport from site-packages
bad_keys = [k for k in sys.modules if k == "titan" or k.startswith("titan.")]
for k in bad_keys:
    del sys.modules[k]

# Step 4: Now import titan from the correct location
import titan  # noqa: E402

assert os.path.normcase(os.path.abspath(os.path.dirname(titan.__file__))) == os.path.normcase(_site_pkgs), \
    f"titan loaded from wrong path: {titan.__file__} (expected in {_site_pkgs})"

from titan.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
