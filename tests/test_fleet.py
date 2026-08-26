"""Tests for the Fleet Coordinator — Multi-agent, multi-target orchestration.

Covers:
  - Agent types and configs
  - FindingMerger: dedup, corroboration, stats
  - FleetCoordinator: dispatch, concurrency, budget
  - Agent runners: recon, identity, learning
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from titan.fleet.agents import (
    AGENT_CONFIGS,
    AGENT_RUNNERS,
    AgentConfig,
    AgentResult,
    AgentType,
    run_learning_agent,
    run_recon_agent,
)
from titan.fleet.coordinator import (
    CoordinatorResult,
    FindingMerger,
    FleetCoordinator,
    MergedFinding,
)


# ---------------------------------------------------------------------------
# Agent type tests
# ---------------------------------------------------------------------------

class TestAgentType:
    def test_all_types_exist(self):
        assert AgentType.RECON.value == "recon"
        assert AgentType.IDENTITY.value == "identity"
        assert AgentType.EXPLOIT.value == "exploit"
        assert AgentType.POST_EXPLOIT.value == "post_exploit"
        assert AgentType.LEARNING.value == "learning"

    def test_all_types_have_configs(self):
        for at in AgentType:
            assert at in AGENT_CONFIGS

    def test_all_types_have_runners(self):
        for at in AgentType:
            assert at in AGENT_RUNNERS

    def test_recon_is_highest_priority(self):
        recon_config = AGENT_CONFIGS[AgentType.RECON]
        for at, config in AGENT_CONFIGS.items():
            if at != AgentType.RECON:
                assert recon_config.priority >= config.priority

    def test_exploit_requires_consent(self):
        assert AGENT_CONFIGS[AgentType.EXPLOIT].requires_consent is True

    def test_recon_no_consent_needed(self):
        assert AGENT_CONFIGS[AgentType.RECON].requires_consent is False


# ---------------------------------------------------------------------------
# AgentResult tests
# ---------------------------------------------------------------------------

class TestAgentResult:
    def test_defaults(self):
        result = AgentResult(agent_type=AgentType.RECON, target="http://test.com")
        assert result.findings == []
        assert result.mutations == []
        assert result.success is True
        assert result.error is None

    def test_error_state(self):
        result = AgentResult(
            agent_type=AgentType.RECON,
            target="http://test.com",
            success=False,
            error="timeout",
        )
        assert result.success is False
        assert result.error == "timeout"


# ---------------------------------------------------------------------------
# FindingMerger tests
# ---------------------------------------------------------------------------

class TestFindingMerger:
    def test_add_single_finding(self):
        merger = FindingMerger()
        merger.add({"type": "sqli", "url": "http://a.com/api", "param": "id"}, "recon")
        assert len(merger.findings) == 1

    def test_dedup_same_finding(self):
        merger = FindingMerger()
        merger.add({"type": "sqli", "url": "http://a.com/api", "param": "id"}, "recon")
        merger.add({"type": "sqli", "url": "http://a.com/api", "param": "id"}, "recon")
        assert len(merger.findings) == 1

    def test_corroboration_from_different_sources(self):
        merger = FindingMerger()
        merger.add({"type": "sqli", "url": "http://a.com/api", "param": "id"}, "recon")
        merger.add({"type": "sqli", "url": "http://a.com/api", "param": "id"}, "identity")
        assert len(merger.findings) == 1
        assert merger.findings[0].is_corroborated is True
        assert len(merger.findings[0].sources) == 2

    def test_different_findings_not_merged(self):
        merger = FindingMerger()
        merger.add({"type": "sqli", "url": "http://a.com/api", "param": "id"}, "recon")
        merger.add({"type": "xss", "url": "http://a.com/api", "param": "name"}, "recon")
        assert len(merger.findings) == 2

    def test_different_urls_not_merged(self):
        merger = FindingMerger()
        merger.add({"type": "sqli", "url": "http://a.com/api", "param": "id"}, "recon")
        merger.add({"type": "sqli", "url": "http://b.com/api", "param": "id"}, "recon")
        assert len(merger.findings) == 2

    def test_corroborated_findings(self):
        merger = FindingMerger()
        merger.add({"type": "sqli", "url": "http://a.com", "param": "id"}, "recon")
        merger.add({"type": "sqli", "url": "http://a.com", "param": "id"}, "identity")
        merger.add({"type": "xss", "url": "http://a.com", "param": "q"}, "recon")
        assert len(merger.corroborated) == 1
        assert merger.corroborated[0].type == "sqli"

    def test_confidence_boost_from_corroboration(self):
        merger = FindingMerger()
        merger.add({"type": "sqli", "url": "http://a.com", "param": "id", "confidence": 0.6}, "recon")
        merger.add({"type": "sqli", "url": "http://a.com", "param": "id", "confidence": 0.7}, "identity")
        finding = merger.findings[0]
        assert finding.effective_confidence > 0.7  # Boosted by corroboration

    def test_confidence_cap_at_99(self):
        merger = FindingMerger()
        for i in range(10):
            merger.add(
                {"type": "sqli", "url": "http://a.com", "param": "id", "confidence": 0.9},
                f"agent_{i}",
            )
        finding = merger.findings[0]
        assert finding.effective_confidence <= 0.99

    def test_add_many(self):
        merger = FindingMerger()
        findings = [
            {"type": "sqli", "url": "http://a.com", "param": "id"},
            {"type": "xss", "url": "http://a.com", "param": "q"},
            {"type": "ssrf", "url": "http://a.com", "param": "url"},
        ]
        merger.add_many(findings, "recon")
        assert len(merger.findings) == 3

    def test_stats(self):
        merger = FindingMerger()
        merger.add({"type": "sqli", "url": "http://a.com", "param": "id", "severity": "high"}, "recon")
        merger.add({"type": "sqli", "url": "http://a.com", "param": "id", "severity": "high"}, "identity")
        merger.add({"type": "xss", "url": "http://b.com", "param": "q", "severity": "medium"}, "recon")

        stats = merger.stats
        assert stats["total"] == 2
        assert stats["corroborated"] == 1
        assert stats["by_type"]["sqli"] == 1
        assert stats["by_type"]["xss"] == 1
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["medium"] == 1

    def test_sorted_by_confidence(self):
        merger = FindingMerger()
        merger.add({"type": "low", "url": "a", "param": "x", "confidence": 0.3}, "r")
        merger.add({"type": "high", "url": "b", "param": "y", "confidence": 0.9}, "r")
        merger.add({"type": "mid", "url": "c", "param": "z", "confidence": 0.6}, "r")
        types = [f.type for f in merger.findings]
        assert types == ["high", "mid", "low"]


# ---------------------------------------------------------------------------
# MergedFinding tests
# ---------------------------------------------------------------------------

class TestMergedFinding:
    def test_not_corroborated(self):
        f = MergedFinding(type="sqli", url="a", param="x", severity="high", evidence="test", sources=["recon"])
        assert f.is_corroborated is False
        assert f.effective_confidence == f.confidence

    def test_corroborated(self):
        f = MergedFinding(type="sqli", url="a", param="x", severity="high", evidence="test", sources=["recon", "identity"])
        assert f.is_corroborated is True
        assert f.effective_confidence > f.confidence


# ---------------------------------------------------------------------------
# Agent runner tests
# ---------------------------------------------------------------------------

class TestAgentRunners:
    @pytest.mark.asyncio
    async def test_recon_agent_returns_result(self):
        result = await run_recon_agent("http://127.0.0.1:5000", timeout=5.0)
        assert isinstance(result, AgentResult)
        assert result.agent_type == AgentType.RECON
        assert result.target == "http://127.0.0.1:5000"
        assert result.elapsed > 0

    @pytest.mark.asyncio
    async def test_learning_agent_no_findings(self):
        result = await run_learning_agent("http://test.com", context={"findings": []}, timeout=5.0)
        assert isinstance(result, AgentResult)
        assert result.mutations == []

    @pytest.mark.asyncio
    async def test_learning_agent_with_findings(self):
        findings = [
            MagicMock(type="novel_vuln", evidence="something", severity="high"),
        ]
        result = await run_learning_agent("http://test.com", context={"findings": findings}, timeout=5.0)
        assert isinstance(result, AgentResult)


# ---------------------------------------------------------------------------
# FleetCoordinator tests
# ---------------------------------------------------------------------------

class TestFleetCoordinator:
    @pytest.fixture
    def coordinator(self):
        return FleetCoordinator(max_concurrent=3)

    def test_init(self, coordinator):
        assert coordinator.max_concurrent == 3
        assert coordinator._merger is not None

    @pytest.mark.asyncio
    async def test_scan_all_single_target(self, coordinator):
        result = await coordinator.scan_all(
            targets=["http://127.0.0.1:5000"],
            agent_types=["recon"],
            budget=30.0,
        )
        assert isinstance(result, CoordinatorResult)
        assert result.elapsed > 0
        assert len(result.agent_results) >= 1

    @pytest.mark.asyncio
    async def test_scan_all_budget_exhausted(self, coordinator):
        result = await coordinator.scan_all(
            targets=["http://127.0.0.1:5000"],
            agent_types=["recon"],
            budget=0.001,
        )
        assert isinstance(result, CoordinatorResult)

    @pytest.mark.asyncio
    async def test_scan_all_multiple_targets(self, coordinator):
        result = await coordinator.scan_all(
            targets=["http://127.0.0.1:5000", "http://127.0.0.1:5001"],
            agent_types=["recon"],
            budget=30.0,
        )
        assert len(result.targets) == 2

    @pytest.mark.asyncio
    async def test_scan_all_merges_findings(self, coordinator):
        result = await coordinator.scan_all(
            targets=["http://127.0.0.1:5000"],
            agent_types=["recon", "learning"],
            budget=30.0,
        )
        # Merged findings should be populated
        assert isinstance(result.merged_findings, list)

    @pytest.mark.asyncio
    async def test_scan_all_stats(self, coordinator):
        result = await coordinator.scan_all(
            targets=["http://127.0.0.1:5000"],
            agent_types=["recon"],
            budget=30.0,
        )
        assert "targets" in result.stats
        assert "agent_types" in result.stats
        assert "findings" in result.stats
        assert result.stats["targets"] == 1

    @pytest.mark.asyncio
    async def test_scan_all_with_context(self, coordinator):
        context = {"findings": []}
        result = await coordinator.scan_all(
            targets=["http://127.0.0.1:5000"],
            agent_types=["recon"],
            budget=30.0,
            context=context,
        )
        assert isinstance(result, CoordinatorResult)

    def test_agent_stats(self, coordinator):
        # Initially empty
        assert coordinator.agent_stats == {}

    @pytest.mark.asyncio
    async def test_scan_all_agent_stats_populated(self, coordinator):
        await coordinator.scan_all(
            targets=["http://127.0.0.1:5000"],
            agent_types=["recon"],
            budget=30.0,
        )
        stats = coordinator.agent_stats
        assert "recon" in stats
        assert stats["recon"]["runs"] >= 1
