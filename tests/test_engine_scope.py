"""Scope checks for TitanEngine — _is_in_scope fails closed.

Covers:
  - no target configured -> nothing in scope
  - same-host and subdomain URLs in scope
  - cross-origin and malformed URLs out of scope (no crash)
"""

from __future__ import annotations

from titan.core.engine import TitanEngine


def _engine(target: str | None = None) -> TitanEngine:
    config = {"crawl": {"profile": "fast"}}
    if target:
        config["target"] = target
    engine = TitanEngine(config)
    engine._scan_target = target or ""
    return engine


class TestIsInScope:
    def test_no_target_means_nothing_in_scope(self):
        engine = _engine(target=None)
        assert engine._is_in_scope("https://anything.example") is False
        assert engine._is_in_scope("https://example.com/") is False

    def test_same_host_in_scope(self):
        engine = _engine(target="https://example.com")
        assert engine._is_in_scope("https://example.com/login") is True

    def test_subdomain_in_scope(self):
        engine = _engine(target="https://example.com")
        assert engine._is_in_scope("https://api.example.com/") is True

    def test_port_variant_still_matches_host(self):
        engine = _engine(target="https://example.com")
        assert engine._is_in_scope("https://example.com:8443/x") is True

    def test_cross_origin_out_of_scope(self):
        engine = _engine(target="https://example.com")
        assert engine._is_in_scope("https://evil.net/") is False

    def test_malformed_url_does_not_crash_and_is_out_of_scope(self):
        engine = _engine(target="https://example.com")
        assert engine._is_in_scope("not a url") is False
        assert engine._is_in_scope("") is False
