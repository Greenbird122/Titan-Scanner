"""Titan Fleet — Multi-agent, multi-target scan orchestration.

The fleet coordinator manages specialized agents working on multiple
targets simultaneously. Uses Thompson Sampling for agent selection and
provides cross-agent finding deduplication.

Usage:
    from titan.fleet import FleetCoordinator, AgentType

    coordinator = FleetCoordinator(max_concurrent=5)
    result = await coordinator.scan_all(
        targets=["https://site1.com", "https://site2.com"],
        agent_types=[AgentType.RECON, AgentType.IDENTITY],
    )
"""

from titan.fleet.agents import (
    AGENT_CONFIGS,
    AGENT_RUNNERS,
    AgentConfig,
    AgentResult,
    AgentType,
)
from titan.fleet.coordinator import (
    CoordinatorResult,
    FindingMerger,
    FleetCoordinator,
    MergedFinding,
)

__all__ = [
    "AGENT_CONFIGS",
    "AGENT_RUNNERS",
    "AgentConfig",
    "AgentResult",
    "AgentType",
    "CoordinatorResult",
    "FindingMerger",
    "FleetCoordinator",
    "MergedFinding",
]
