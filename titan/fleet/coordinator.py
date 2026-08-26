"""Fleet Coordinator — Multi-agent, multi-target scan orchestration.

Manages specialized agents working on multiple targets simultaneously.
Uses Thompson Sampling for agent selection and provides cross-agent
finding deduplication and merging.

Architecture:
  ┌──────────────────────────────────────────────────────┐
  │                   FleetCoordinator                   │
  │                                                      │
  │  ┌─────────┐  ┌─────────┐  ┌─────────┐             │
  │  │ Target A │  │ Target B │  │ Target C │  ...        │
  │  └────┬────┘  └────┬────┘  └────┬────┘             │
  │       │             │             │                   │
  │  ┌────▼────┐  ┌────▼────┐  ┌────▼────┐             │
  │  │ Recon   │  │ Recon   │  │ Identity│             │
  │  │ Identity│  │ Exploit │  │ Recon   │             │
  │  │ ...     │  │ ...     │  │ ...     │             │
  │  └────┬────┘  └────┬────┘  └────┬────┘             │
  │       │             │             │                   │
  │       └─────────────┼─────────────┘                   │
  │                     │                                 │
  │              ┌──────▼──────┐                          │
  │              │   Merger    │  Dedup + merge findings │
  │              └──────┬──────┘                          │
  │                     │                                 │
  │              ┌──────▼──────┐                          │
  │              │   Report    │  Unified findings list   │
  │              └─────────────┘                          │
  └──────────────────────────────────────────────────────┘

Usage:
    coordinator = FleetCoordinator(max_concurrent=5)
    result = await coordinator.scan_all(
        targets=["https://site1.com", "https://site2.com"],
        agent_types=["recon", "identity"],
    )
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from titan.fleet.agents import (
    AGENT_CONFIGS,
    AGENT_RUNNERS,
    AgentConfig,
    AgentResult,
    AgentType,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Finding merger — cross-agent deduplication
# ---------------------------------------------------------------------------

@dataclass
class MergedFinding:
    """A finding that may have been confirmed by multiple agents."""
    type: str
    url: str
    param: str
    severity: str
    evidence: str
    sources: list[str] = field(default_factory=list)  # Which agent types found this
    confidence: float = 0.0
    cvss_score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_corroborated(self) -> bool:
        """True when multiple independent agents found the same thing."""
        return len(self.sources) > 1

    @property
    def effective_confidence(self) -> float:
        """Confidence boosted by corroboration."""
        base = self.confidence
        if self.is_corroborated:
            # Each corroborating source adds 15% confidence (capped at 0.99)
            return min(base + 0.15 * (len(self.sources) - 1), 0.99)
        return base


class FindingMerger:
    """Merges findings across multiple agents with deduplication.

    Two findings are considered duplicates when they match on:
      - type (e.g., "sqli")
      - URL (same endpoint)
      - param (same parameter)

    Corroborated findings get a confidence boost.
    """

    def __init__(self):
        self._findings: dict[str, MergedFinding] = {}  # key -> MergedFinding

    def _key(self, finding: dict) -> str:
        """Generate a dedup key from a finding."""
        parts = [
            str(finding.get("type", "")),
            str(finding.get("url", "")),
            str(finding.get("param", "")),
        ]
        return hashlib.md5("|".join(parts).encode()).hexdigest()

    def add(self, finding: dict, source: str) -> None:
        """Add a finding from a specific agent source."""
        key = self._key(finding)

        if key in self._findings:
            merged = self._findings[key]
            if source not in merged.sources:
                merged.sources.append(source)
            # Update confidence to the max seen
            merged.confidence = max(
                merged.confidence,
                finding.get("confidence", 0.5),
            )
        else:
            self._findings[key] = MergedFinding(
                type=finding.get("type", "unknown"),
                url=finding.get("url", ""),
                param=finding.get("param", ""),
                severity=finding.get("severity", "medium"),
                evidence=finding.get("evidence", ""),
                sources=[source],
                confidence=finding.get("confidence", 0.5),
                cvss_score=finding.get("cvss_score", 0.0),
                metadata=finding.get("metadata", {}),
            )

    def add_many(self, findings: list[dict], source: str) -> None:
        """Add multiple findings from a single agent."""
        for f in findings:
            self.add(f, source)

    @property
    def findings(self) -> list[MergedFinding]:
        """All merged findings, sorted by effective confidence (descending)."""
        return sorted(
            self._findings.values(),
            key=lambda f: f.effective_confidence,
            reverse=True,
        )

    @property
    def corroborated(self) -> list[MergedFinding]:
        """Only findings confirmed by multiple agents."""
        return [f for f in self.findings if f.is_corroborated]

    @property
    def stats(self) -> dict:
        """Summary statistics."""
        all_findings = self.findings
        return {
            "total": len(all_findings),
            "corroborated": len(self.corroborated),
            "by_type": self._count_by_type(all_findings),
            "by_severity": self._count_by_severity(all_findings),
            "by_source": self._count_by_source(all_findings),
        }

    def _count_by_type(self, findings: list[MergedFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.type] = counts.get(f.type, 0) + 1
        return counts

    def _count_by_severity(self, findings: list[MergedFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def _count_by_source(self, findings: list[MergedFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            for s in f.sources:
                counts[s] = counts.get(s, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Coordinator result
# ---------------------------------------------------------------------------

@dataclass
class CoordinatorResult:
    """Result of a coordinated multi-agent scan."""
    targets: list[str] = field(default_factory=list)
    agent_results: list[AgentResult] = field(default_factory=list)
    merged_findings: list[MergedFinding] = field(default_factory=list)
    mutations: list[dict] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    elapsed: float = 0.0
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Fleet Coordinator
# ---------------------------------------------------------------------------

class FleetCoordinator:
    """Multi-agent, multi-target scan coordinator.

    Manages bounded concurrent execution of specialized agents across
    multiple targets. Uses Thompson Sampling for agent priority ordering
    and provides cross-agent finding deduplication.

    Usage:
        coordinator = FleetCoordinator(max_concurrent=5)
        result = await coordinator.scan_all(
            targets=["https://site1.com", "https://site2.com"],
            agent_types=["recon", "identity"],
            budget=300.0,
        )
    """

    def __init__(
        self,
        max_concurrent: int = 5,
        transport: Any = None,
        consent_dir: str = "consent",
    ):
        self.max_concurrent = max_concurrent
        self.transport = transport
        self.consent_dir = consent_dir
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._merger = FindingMerger()
        self._history: list[AgentResult] = []

    async def scan_all(
        self,
        targets: list[str],
        agent_types: list[str | AgentType] | None = None,
        budget: float = 300.0,
        context: dict | None = None,
    ) -> CoordinatorResult:
        """Scan all targets with the specified agent types.

        Args:
            targets: List of target URLs to scan.
            agent_types: Which agent types to run (default: all).
            budget: Total wall-clock budget in seconds.
            context: Shared context (findings from previous scans, etc.).

        Returns:
            CoordinatorResult with merged findings and stats.
        """
        start = time.time()
        result = CoordinatorResult(targets=targets)

        # Normalize agent types
        if agent_types is None:
            agent_types = list(AgentType)
        elif isinstance(agent_types[0], str):
            agent_types = [AgentType(at) for at in agent_types]

        # Check consent for agents that need it
        active_agents = []
        for at in agent_types:
            config = AGENT_CONFIGS.get(at)
            if config is None:
                continue
            if config.requires_consent:
                if not self._has_consent(targets[0] if targets else ""):
                    logger.info(f"Skipping {at.value} agent (no consent)")
                    continue
            active_agents.append(at)

        # Sort by priority (highest first)
        active_agents.sort(
            key=lambda at: AGENT_CONFIGS.get(at, AgentConfig(agent_type=at)).priority,
            reverse=True,
        )

        logger.info(
            f"Fleet coordinator starting: {len(targets)} target(s), "
            f"{len(active_agents)} agent type(s), budget={budget}s"
        )

        # Build task list: each (target, agent_type) pair is a task
        tasks = []
        for target in targets:
            for agent_type in active_agents:
                config = AGENT_CONFIGS.get(agent_type, AgentConfig(agent_type=agent_type))
                tasks.append((target, agent_type, config))

        # Execute tasks with bounded concurrency
        task_results = await self._execute_tasks(tasks, budget, context)

        # Merge findings across all agents
        for agent_result in task_results:
            result.agent_results.append(agent_result)
            self._history.append(agent_result)

            # Add findings to merger
            source = agent_result.agent_type.value
            for f in agent_result.findings:
                self._merger.add(f, source)

            # Collect mutations
            result.mutations.extend(agent_result.mutations)

            # Collect errors
            if agent_result.error:
                result.errors.append(
                    f"{agent_result.agent_type.value}@{agent_result.target}: {agent_result.error}"
                )

        # Finalize
        result.merged_findings = self._merger.findings
        result.stats = {
            "targets": len(targets),
            "agent_types": len(active_agents),
            "total_tasks": len(tasks),
            "completed": len([r for r in task_results if r.success]),
            "failed": len([r for r in task_results if not r.success]),
            "findings": self._merger.stats,
            "mutations": len(result.mutations),
        }
        result.elapsed = time.time() - start

        logger.info(
            f"Fleet coordinator complete: "
            f"{result.stats['completed']}/{result.stats['total_tasks']} tasks, "
            f"{result.stats['findings']['total']} findings "
            f"({result.stats['findings']['corroborated']} corroborated), "
            f"{result.elapsed:.1f}s"
        )

        return result

    async def _execute_tasks(
        self,
        tasks: list[tuple[str, AgentType, AgentConfig]],
        budget: float,
        context: dict | None,
    ) -> list[AgentResult]:
        """Execute tasks with bounded concurrency and budget control."""
        results = []
        start = time.time()

        async def _run_one(target: str, agent_type: AgentType, config: AgentConfig) -> AgentResult:
            """Run a single agent task with semaphore bounding."""
            async with self._semaphore:
                # Check budget
                elapsed = time.time() - start
                if elapsed > budget:
                    return AgentResult(
                        agent_type=agent_type,
                        target=target,
                        success=False,
                        error="Budget exhausted",
                    )

                runner = AGENT_RUNNERS.get(agent_type)
                if runner is None:
                    return AgentResult(
                        agent_type=agent_type,
                        target=target,
                        success=False,
                        error=f"No runner for agent type {agent_type.value}",
                    )

                try:
                    result = await asyncio.wait_for(
                        runner(
                            target=target,
                            transport=self.transport,
                            context=context,
                            timeout=min(config.timeout, budget - elapsed),
                        ),
                        timeout=config.timeout + 5,  # Extra grace period
                    )
                    return result
                except asyncio.TimeoutError:
                    return AgentResult(
                        agent_type=agent_type,
                        target=target,
                        success=False,
                        error=f"Agent timed out after {config.timeout}s",
                    )
                except Exception as e:
                    return AgentResult(
                        agent_type=agent_type,
                        target=target,
                        success=False,
                        error=str(e),
                    )

        # Launch all tasks concurrently (bounded by semaphore)
        coros = [_run_one(t, a, c) for t, a, c in tasks]
        results = await asyncio.gather(*coros, return_exceptions=True)

        # Handle any exceptions from gather
        final_results = []
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                target, agent_type, _ = tasks[i]
                final_results.append(AgentResult(
                    agent_type=agent_type,
                    target=target,
                    success=False,
                    error=str(r),
                ))
            else:
                final_results.append(r)

        return final_results

    def _has_consent(self, target: str) -> bool:
        """Check if consent exists for the target."""
        try:
            from titan.exploit.consent import verify_consent
            verify_consent(target, consent_dir=self.consent_dir)
            return True
        except Exception:
            return False

    @property
    def agent_stats(self) -> dict[str, dict]:
        """Statistics per agent type from history."""
        stats: dict[str, dict] = {}
        for result in self._history:
            key = result.agent_type.value
            if key not in stats:
                stats[key] = {
                    "runs": 0,
                    "successes": 0,
                    "total_findings": 0,
                    "total_elapsed": 0.0,
                }
            stats[key]["runs"] += 1
            if result.success:
                stats[key]["successes"] += 1
            stats[key]["total_findings"] += len(result.findings)
            stats[key]["total_elapsed"] += result.elapsed
        return stats
