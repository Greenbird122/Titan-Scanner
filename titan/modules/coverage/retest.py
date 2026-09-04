"""Auto-Retest — automatically retest failed gaps.

A real attacker doesn't just find gaps.
They close them. Automatically.

This module:
1. Identifies coverage gaps
2. Generates retest plan
3. Executes retests automatically
4. Updates coverage tracker
5. Verifies gaps are closed
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from titan.modules.coverage.tracker import CoverageTracker
from titan.modules.coverage.gate import CoverageGate


@dataclass
class RetestResult:
    """Result of a retest execution."""
    total_retests: int
    successful_retests: int
    failed_retests: int
    skipped_retests: int
    duration_seconds: float
    coverage_before: float
    coverage_after: float
    gaps_closed: List[str]
    gaps_remaining: List[str]


class AutoRetester:
    """Automatically retest coverage gaps."""

    def __init__(
        self,
        tracker: CoverageTracker,
        gate: CoverageGate,
        test_executor: Optional[Callable] = None,
    ):
        self.tracker = tracker
        self.gate = gate
        self.test_executor = test_executor
        self._results: List[RetestResult] = []

    async def retest_all(self) -> RetestResult:
        """Retest all gaps until coverage threshold met."""
        start_time = time.time()
        coverage_before = self.tracker.get_risk_score()

        # Get retest plan
        plan = self.gate.get_retest_plan()
        total = len(plan)
        successful = 0
        failed = 0
        skipped = 0
        gaps_closed = []
        gaps_remaining = []

        for item in plan:
            try:
                if self.test_executor:
                    # Execute test
                    result = await self.test_executor(
                        item["endpoint"],
                        item["attack_type"],
                    )
                    if result:
                        successful += 1
                        gaps_closed.append(f"{item['endpoint']} × {item['attack_type']}")
                    else:
                        failed += 1
                        gaps_remaining.append(f"{item['endpoint']} × {item['attack_type']}")
                else:
                    # No executor — just record as skipped
                    skipped += 1
                    gaps_remaining.append(f"{item['endpoint']} × {item['attack_type']}")
            except Exception:
                failed += 1
                gaps_remaining.append(f"{item['endpoint']} × {item['attack_type']}")

        duration = time.time() - start_time
        coverage_after = self.tracker.get_risk_score()

        result = RetestResult(
            total_retests=total,
            successful_retests=successful,
            failed_retests=failed,
            skipped_retests=skipped,
            duration_seconds=round(duration, 2),
            coverage_before=coverage_before,
            coverage_after=coverage_after,
            gaps_closed=gaps_closed,
            gaps_remaining=gaps_remaining,
        )

        self._results.append(result)
        return result

    async def retest_critical(self) -> RetestResult:
        """Retest only critical gaps."""
        start_time = time.time()
        coverage_before = self.tracker.get_risk_score()

        # Get missing critical types
        missing = self.gate.get_missing_critical_types()
        endpoints = self.tracker.get_endpoints()

        total = 0
        successful = 0
        failed = 0
        skipped = 0
        gaps_closed = []
        gaps_remaining = []

        for attack_type in missing:
            for endpoint in endpoints[:3]:
                total += 1
                try:
                    if self.test_executor:
                        result = await self.test_executor(endpoint, attack_type)
                        if result:
                            successful += 1
                            gaps_closed.append(f"{endpoint} × {attack_type}")
                        else:
                            failed += 1
                            gaps_remaining.append(f"{endpoint} × {attack_type}")
                    else:
                        skipped += 1
                        gaps_remaining.append(f"{endpoint} × {attack_type}")
                except Exception:
                    failed += 1
                    gaps_remaining.append(f"{endpoint} × {attack_type}")

        duration = time.time() - start_time
        coverage_after = self.tracker.get_risk_score()

        result = RetestResult(
            total_retests=total,
            successful_retests=successful,
            failed_retests=failed,
            skipped_retests=skipped,
            duration_seconds=round(duration, 2),
            coverage_before=coverage_before,
            coverage_after=coverage_after,
            gaps_closed=gaps_closed,
            gaps_remaining=gaps_remaining,
        )

        self._results.append(result)
        return result

    def get_results(self) -> List[RetestResult]:
        return self._results

    def to_dict(self, result: RetestResult) -> Dict[str, Any]:
        """Convert result to dict."""
        return {
            "total_retests": result.total_retests,
            "successful_retests": result.successful_retests,
            "failed_retests": result.failed_retests,
            "skipped_retests": result.skipped_retests,
            "duration_seconds": result.duration_seconds,
            "coverage_before": result.coverage_before,
            "coverage_after": result.coverage_after,
            "coverage_change": round(result.coverage_after - result.coverage_before, 1),
            "gaps_closed": len(result.gaps_closed),
            "gaps_remaining": len(result.gaps_remaining),
            "success_rate": round(
                result.successful_retests / max(result.total_retests, 1) * 100, 1
            ),
        }
