"""Business logic, parameter tampering, and workflow bypass detection — deep audit.

This module is the package's public surface: ``LogicDetector`` lives in
``service.py`` and its payload tables in ``probes.py``. Import from here so
the internal layout can change without touching callers (the module registry
and the oracle tests both bind to this path).
"""

from titan.modules.logic.service import LogicDetector

__all__ = ["LogicDetector"]
