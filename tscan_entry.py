"""tscan entry point — lives OUTSIDE titan/ to avoid CWD shadowing.

When the user runs `tscan` from a directory that contains a `titan/` folder
(e.g. titan-lab), Python resolves `titan.cli` to the CWD copy instead of the
installed package.  This wrapper fixes the path BEFORE any titan import.
"""

from __future__ import annotations

import os
import sys


def _ensure_correct_titan() -> None:
    """Prepend the installed titan-scanner site-packages to sys.path
    so ``import titan`` resolves to the pip-installed package, not a
    local ``titan/`` directory in CWD.
    """
    # Find where THIS file lives (site-packages/tscan_entry.py)
    here = os.path.dirname(os.path.abspath(__file__))
    # site-packages is the parent of here
    site_packages = os.path.dirname(here)
    if site_packages not in sys.path[:5]:
        sys.path.insert(0, site_packages)

    # Force reimport if titan is already loaded from wrong location
    if "titan" in sys.modules:
        titan_file = getattr(sys.modules["titan"], "__file__", "")
        if titan_file and here not in titan_file and site_packages not in titan_file:
            # Wrong titan loaded — remove it and let it reimport
            to_remove = [k for k in sys.modules if k == "titan" or k.startswith("titan.")]
            for k in to_remove:
                del sys.modules[k]


_ensure_correct_titan()

from titan.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
