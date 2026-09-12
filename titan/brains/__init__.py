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
from typing import Any


class PlatformBrain(ABC):
    """Base class for platform-specific scanner brains."""

    name: str = "generic"
    fingerprint_markers: list[str] = []

    @abstractmethod
    def match(self, fingerprint: dict[str, Any], html: str, headers: dict[str, str]) -> float:
        """Return confidence 0.0-1.0 that this platform is present."""

    @abstractmethod
    def extra_seed_urls(self, base_url: str) -> list[str]:
        """Paths the crawler should always probe for this platform."""

    @abstractmethod
    def extra_parameters(self) -> list[str]:
        """Parameter names worth fuzzing that are platform-specific."""

    @abstractmethod
    def tag_finding(self, finding: Any) -> None:
        """Annotate a finding with platform context."""


class BrainRegistry:
    """Holds all registered platform brains and selects the best match."""

    def __init__(self) -> None:
        self._brains: list[PlatformBrain] = []

    def register(self, brain: PlatformBrain) -> None:
        self._brains.append(brain)

    def select(self, fingerprint: dict[str, Any], html: str, headers: dict[str, str]) -> PlatformBrain | None:
        best, best_score = None, 0.0
        for brain in self._brains:
            try:
                score = brain.match(fingerprint, html, headers)
            except Exception:
                score = 0.0
            if score > best_score:
                best, best_score = brain, score
        return best if best_score >= 0.5 else None


# Imported last to avoid a circular import: moodle.py does
# `from titan.brains import PlatformBrain` at module load, so it must run
# after PlatformBrain is defined above.
from titan.brains.moodle import MoodleBrain as MoodleBrain
