"""Tests for the extracted PostScanPhasesMixin.

The optional phase runners (LLM channel, storage, subdomain takeover, cloud
IMDS, SBOM, deep audit) are network-heavy; direct tests here pin the
config-gate short-circuits and pure helpers so the config-gated entry points
behave deterministically without live targets.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from titan.core.engine import TitanEngine


def _engine(config: dict) -> TitanEngine:
    base = {
        "target": "http://localhost:5000",
        "stealth": {"min_delay": 0.01, "max_delay": 0.01},
    }
    base.update(config)
    return TitanEngine(base)


LEAF_NAMES = [
    "_run_llm_channel",
    "_run_storage_probe",
    "_run_subdomain_takeover",
    "_probe_cloud_imds",
    "_run_sbom_analysis",
    "_run_deep_audit",
]


class _Result:
    """Minimal ScanResult stand-in: findings + errors lists."""

    def __init__(self):
        self.findings = []
        self.errors = []


def _result():
    return _Result()

ALL_DISABLED = {
    "llm": {"enabled": False},
    "cloud": {"storage": {"enabled": False}, "imds": {"enabled": False}},
    "subdomain_takeover": {"enabled": False},
    "crawl": {"supplychain": {"enabled": False}},
    "deep_audit": {"enabled": False},
}


def _leaves_patched():
    """Temporarily shadow every leaf runner on the class with a no-op.

    Direct setattr/delattr rather than patch.multiple: the mocked names all
    start with an underscore, which patch.multiple mis-keys.
    """
    mocks = {name: AsyncMock() for name in LEAF_NAMES}
    for name, m in mocks.items():
        setattr(TitanEngine, name, m)

    def _cleanup():
        for name in LEAF_NAMES:
            delattr(TitanEngine, name)

    return mocks, _cleanup


async def test_optional_phases_all_disabled_is_noop():
    """Everything off: the orchestrator must not invoke any leaf runner."""
    engine = _engine(ALL_DISABLED)
    leaves, cleanup = _leaves_patched()
    try:
        await engine._run_optional_phases("http://localhost:5000", _result(), None)
    finally:
        cleanup()
    for name in LEAF_NAMES:
        leaves[name].assert_not_awaited()


async def test_deep_audit_only_enabled_fires_only_its_leaf():
    """Config gates are per-phase: only the enabled runner is dispatched."""
    cfg = dict(ALL_DISABLED)
    cfg["deep_audit"] = {"enabled": True}
    engine = _engine(cfg)
    leaves, cleanup = _leaves_patched()
    try:
        await engine._run_optional_phases("http://localhost:5000", _result(), None)
    finally:
        cleanup()
    leaves["_run_deep_audit"].assert_awaited_once()
    for name in LEAF_NAMES:
        if name != "_run_deep_audit":
            leaves[name].assert_not_awaited()


async def test_llm_channel_disabled_short_circuits():
    engine = _engine({"llm": {"enabled": False}})
    with patch("titan.modules.llm.channel.LLMChannel") as channel:
        await engine._run_llm_channel("http://localhost:5000", object())
    channel.assert_not_called()


async def test_storage_probe_disabled_short_circuits():
    engine = _engine({"cloud": {"storage": {"enabled": False}}})
    with patch("titan.modules.cloud.storage.StorageProbe") as probe:
        await engine._run_storage_probe("http://localhost:5000", object())
    probe.assert_not_called()


async def test_subdomain_takeover_disabled_short_circuits():
    engine = _engine({"subdomain_takeover": {"enabled": False}})
    with patch("titan.modules.subdomain_takeover.detector.SubdomainTakeoverDetector") as det:
        await engine._run_subdomain_takeover("http://localhost:5000", object())
    det.assert_not_called()


async def test_imds_probe_without_ssrf_findings_is_noop():
    engine = _engine({})
    with patch("titan.modules.cloud_control.imds.IMDSProber") as prober:
        await engine._probe_cloud_imds("http://localhost:5000", _result())
    prober.assert_not_called()


class TestIsLLMEndpoint:
    def test_recognizes_chat_and_completions_paths(self):
        assert TitanEngine._is_llm_endpoint("http://localhost:5000/api/chat")
        assert TitanEngine._is_llm_endpoint("http://localhost:5000/v1/completions")
        assert TitanEngine._is_llm_endpoint("https://host.example/api/inference")

    def test_rejects_plain_paths(self):
        assert not TitanEngine._is_llm_endpoint("http://localhost:5000/api/users")
        assert not TitanEngine._is_llm_endpoint("http://localhost:5000/")
