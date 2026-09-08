"""Scope, checkpoint, and coverage helpers for TitanEngine.

Extracted from titan/core/engine.py. Supplies fail-closed scope checks,
consent/authorization status, checkpoint detection, coverage finalization,
platform-brain selection, prior-intel lookup, and the API-shape heuristic.
State the helpers read (``config``, ``_scan_target``, ``_coverage``,
``_driver_dead``, ``max_pages``, ``max_depth``) stays on the host engine;
this mixin only supplies behavior.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from titan.core.constants import (
    CHECKPOINT_STATUSES,
    GENERIC_CHECKPOINT_INDICATORS,
    STRONG_CHECKPOINT_INDICATORS,
)
from titan.core.models import ScanResult


class EngineHelpersMixin:
    """Scope, checkpoint, and coverage helpers for TitanEngine."""

    # State supplied by the host engine before any mixin method runs.
    config: dict
    _scan_target: str
    _coverage: dict[str, Any]
    _driver_dead: bool
    max_pages: int
    max_depth: int

    # ==================================================================
    # Scope & authorization
    # ==================================================================

    def _is_in_scope(self, url: str) -> bool:
        """Fail-closed scope check: no target means nothing is in scope."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            target_hostname = urlparse(
                self._scan_target or self.config.get("target", "")
            ).hostname or ""
            if not target_hostname:
                return False
            if not hostname:
                return False
            return hostname == target_hostname or hostname.endswith("." + target_hostname)
        except Exception:
            return False

    def _is_spa_shell(self, url: str) -> bool:
        return "#" in url

    @staticmethod
    def _is_state_changing_path(url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(k in path for k in (
            "update", "create", "delete", "remove", "edit", "register",
            "signup", "add", "save", "set", "change", "reset",
            "upload", "transfer", "send", "approve", "role",
        ))

    def _authorization_status(self, target: str) -> str | None:
        from titan.core.authorization import authorize_target
        status: str | None = authorize_target(
            target,
            consent_dir=self.config.get("exploit", {}).get("consent_dir", "consent"),
            practice_manifest=self.config.get("authorization", {}).get("practice_manifest"),
            key_path=self.config.get("exploit", {}).get("key_path"),
        )
        return status

    def _has_consent(self, target: str) -> bool:
        try:
            from titan.exploit.consent import verify_consent
            verify_consent(
                target,
                consent_dir=self.config.get("exploit", {}).get("consent_dir", "consent"),
            )
            return True
        except Exception:
            return False


    # ==================================================================
    # Checkpoint detection
    # ==================================================================

    def _is_checkpoint(self, title: str, body: str, headers: dict, status: int = 200) -> bool:
        text = f"{title} {body[:5000]}".lower()
        for indicator in STRONG_CHECKPOINT_INDICATORS:
            if indicator in text:
                return True
        if status in CHECKPOINT_STATUSES:
            if "cloudflare" in headers.get("server", "").lower():
                return True
            for indicator in GENERIC_CHECKPOINT_INDICATORS:
                if indicator in text:
                    return True
        return False

    # ==================================================================
    # Coverage & platform
    # ==================================================================

    def _finalize_coverage(self, result: ScanResult) -> dict[str, Any]:
        from titan.verify.coverage import finalize_coverage
        return finalize_coverage(
            self._coverage, driver_dead=self._driver_dead,
            max_pages=self.max_pages, max_depth=self.max_depth,
        )

    def _select_platform_brain(self, fingerprint: dict, html: str, headers: dict) -> Any | None:
        try:
            from titan.brains import BrainRegistry, MoodleBrain
        except ImportError:
            return None
        registry = BrainRegistry()
        registry.register(MoodleBrain())
        return registry.select(fingerprint, html, headers)

    def _prior_observed(self, target: str) -> dict[str, Any] | None:
        try:
            import json as _json
            from pathlib import Path

            from titan.reporting import site_slug as _slug
            out_dir = Path(self.config.get("output_dir", "findings"))
            p = out_dir / _slug(target) / "intel.json"
            if p.exists():
                parsed: dict[str, Any] = _json.loads(p.read_text(encoding="utf-8"))
                return parsed
        except Exception:
            pass
        return None

    def _looks_like_api(self, url: str) -> bool:
        if not self._is_in_scope(url):
            return False
        api_indicators = ["/api/", "/sales/", "/v1/", "/v2/", "/rest/", "/graphql", "api.", ".json"]
        path = urlparse(url.lower()).path
        return any(ind in path for ind in api_indicators)

