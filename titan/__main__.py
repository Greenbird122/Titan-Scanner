"""Entry point for `python -m titan`.

Usage:
    python -m titan scan https://example.com
    python -m titan brain https://target.com --budget 600
    python -m titan transport list
"""

import sys
from titan.cli.main import main

sys.exit(main())
