"""Platform brain registry.

A platform brain specializes the scanner for a detected CMS / framework /
backend.  It does NOT replace the module matrix.  It runs BEFORE the matrix
and:
  1. adds platform-specific endpoints to the crawl queue
  2. adds platform-specific parameters to the fuzzer vocabulary
  3. tags findings with platform context for the report
  4. adjusts module selection based on platform-known sinks
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class PlatformBrain(ABC):
    """Base class for platform-specific scanner brains."""

    name: str = "generic"
    fingerprint_markers: List[str] = []

    @abstractmethod
    def match(self, fingerprint: Dict[str, Any], html: str, headers: Dict[str, str]) -> float:
        """Return confidence 0.0-1.0 that this platform is present."""

    @abstractmethod
    def extra_seed_urls(self, base_url: str) -> List[str]:
        """Paths the crawler should always probe for this platform."""

    @abstractmethod
    def extra_parameters(self) -> List[str]:
        """Parameter names worth fuzzing that are platform-specific."""

    @abstractmethod
    def tag_finding(self, finding: Any) -> None:
        """Annotate a finding with platform context."""


class BrainRegistry:
    """Holds all registered platform brains and selects the best match."""

    def __init__(self) -> None:
        self._brains: List[PlatformBrain] = []

    def register(self, brain: PlatformBrain) -> None:
        self._brains.append(brain)

    def select(self, fingerprint: Dict[str, Any], html: str, headers: Dict[str, str]) -> Optional[PlatformBrain]:
        best, best_score = None, 0.0
        for brain in self._brains:
            try:
                score = brain.match(fingerprint, html, headers)
            except Exception:
                score = 0.0
            if score > best_score:
                best, best_score = brain, score
        return best if best_score >= 0.5 else None
