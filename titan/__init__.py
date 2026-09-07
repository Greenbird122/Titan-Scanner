"""Titan — Autonomous Penetration Testing Platform.

Usage:
    from titan import TitanScanner

    scanner = TitanScanner(target="https://example.com")
    result = await scanner.scan()

Or via CLI:
    titan --target https://example.com
    titan scan --target https://example.com --deep
"""

__version__ = "1.0.0"
__author__ = "Titan Security Lab"

from titan.core.engine import TitanEngine
from titan.core.models import AttackType, Finding, Severity

__all__ = [
    "AttackType",
    "Finding",
    "Severity",
    "TitanEngine",
    "__version__",
]
