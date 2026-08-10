"""Tests for proxy rotation."""

import pytest
from titan.core.proxy import ProxyRotator


class TestProxyRotator:
    def test_no_proxies_returns_none(self):
        rotator = ProxyRotator()
        assert rotator.get_proxy() is None
        assert rotator.rotate() is None

    def test_round_robin_rotation(self):
        rotator = ProxyRotator(proxies=["http://p1", "http://p2", "http://p3"], strategy="round-robin")
        assert rotator.get_proxy() == "http://p1"
        assert rotator.get_proxy() == "http://p2"
        assert rotator.get_proxy() == "http://p3"
        assert rotator.get_proxy() == "http://p1"

    def test_random_rotation(self):
        rotator = ProxyRotator(proxies=["http://p1", "http://p2"], strategy="random")
        results = [rotator.get_proxy() for _ in range(20)]
        assert all(p in ["http://p1", "http://p2"] for p in results)

    def test_sticky_rotation(self):
        rotator = ProxyRotator(proxies=["http://p1", "http://p2"], strategy="sticky")
        p1 = rotator.get_proxy("target1")
        p2 = rotator.get_proxy("target2")
        assert p1 in ["http://p1", "http://p2"]
        assert p2 in ["http://p1", "http://p2"]
        assert rotator.get_proxy("target1") == p1
