"""Scan Comparison — compare coverage between scans.

A real attacker tracks progress over time.
They know what improved, what regressed, what's still missing.

This module:
1. Compares two coverage snapshots
2. Identifies improvements and regressions
3. Tracks coverage trends over time
4. Generates comparison reports
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from titan.modules.coverage.tracker import CoverageTracker, TestRecord


@dataclass
class ScanSnapshot:
    """A snapshot of coverage at a point in time."""
    scan_id: str
    timestamp: str
    target: str
    endpoints: list[str]
    attack_types: list[str]
    records: list[TestRecord]
    summary: dict[str, Any]
    risk_score: float


@dataclass
class ComparisonResult:
    """Result of comparing two scans."""
    scan_a_id: str
    scan_b_id: str
    overall_change: float  # positive = improved
    new_endpoints: list[str]
    removed_endpoints: list[str]
    new_attack_types: list[str]
    removed_attack_types: list[str]
    improved_combinations: list[tuple[str, str]]
    regressed_combinations: list[tuple[str, str]]
    coverage_delta: float
    risk_delta: float
    summary: str


class ScanComparator:
    """Compare coverage between scans."""

    def __init__(self):
        self._snapshots: list[ScanSnapshot] = []
        self._comparisons: list[ComparisonResult] = []

    def create_snapshot(
        self,
        tracker: CoverageTracker,
        scan_id: str,
        target: str,
    ) -> ScanSnapshot:
        """Create a snapshot from current tracker state."""
        summary = tracker.get_summary()
        risk_score = tracker.get_risk_score()

        snapshot = ScanSnapshot(
            scan_id=scan_id,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            target=target,
            endpoints=tracker.get_endpoints(),
            attack_types=tracker.get_attack_types(),
            records=tracker.get_records(),
            summary=summary,
            risk_score=risk_score,
        )

        self._snapshots.append(snapshot)
        return snapshot

    def compare(
        self,
        snapshot_a: ScanSnapshot,
        snapshot_b: ScanSnapshot,
    ) -> ComparisonResult:
        """Compare two snapshots."""
        # Endpoint changes
        endpoints_a = set(snapshot_a.endpoints)
        endpoints_b = set(snapshot_b.endpoints)
        new_endpoints = sorted(endpoints_b - endpoints_a)
        removed_endpoints = sorted(endpoints_a - endpoints_b)

        # Attack type changes
        types_a = set(snapshot_a.attack_types)
        types_b = set(snapshot_b.attack_types)
        new_types = sorted(types_b - types_a)
        removed_types = sorted(types_a - types_b)

        # Combination changes
        combos_a = {(r.endpoint, r.attack_type) for r in snapshot_a.records}
        combos_b = {(r.endpoint, r.attack_type) for r in snapshot_b.records}
        improved = sorted(combos_b - combos_a)
        regressed = sorted(combos_a - combos_b)

        # Score changes
        coverage_a = snapshot_a.summary.get("coverage_percent", 0)
        coverage_b = snapshot_b.summary.get("coverage_percent", 0)
        coverage_delta = coverage_b - coverage_a

        risk_delta = snapshot_b.risk_score - snapshot_a.risk_score

        # Overall change
        overall_change = (coverage_delta + risk_delta) / 2

        # Summary
        if overall_change > 5:
            summary = f"Significant improvement: +{overall_change:.1f}% coverage"
        elif overall_change > 0:
            summary = f"Marginal improvement: +{overall_change:.1f}% coverage"
        elif overall_change == 0:
            summary = "No change in coverage"
        elif overall_change > -5:
            summary = f"Marginal regression: {overall_change:.1f}% coverage"
        else:
            summary = f"Significant regression: {overall_change:.1f}% coverage"

        result = ComparisonResult(
            scan_a_id=snapshot_a.scan_id,
            scan_b_id=snapshot_b.scan_id,
            overall_change=overall_change,
            new_endpoints=new_endpoints,
            removed_endpoints=removed_endpoints,
            new_attack_types=new_types,
            removed_attack_types=removed_types,
            improved_combinations=improved,
            regressed_combinations=regressed,
            coverage_delta=coverage_delta,
            risk_delta=risk_delta,
            summary=summary,
        )

        self._comparisons.append(result)
        return result

    def compare_latest(self) -> ComparisonResult | None:
        """Compare the two most recent snapshots."""
        if len(self._snapshots) < 2:
            return None
        return self.compare(self._snapshots[-2], self._snapshots[-1])

    def get_trend(self) -> dict[str, Any]:
        """Get trend across all snapshots."""
        if len(self._snapshots) < 2:
            return {"trend": "insufficient_data", "snapshots": len(self._snapshots)}

        coverages = [s.summary.get("coverage_percent", 0) for s in self._snapshots]
        risks = [s.risk_score for s in self._snapshots]

        # Calculate trend direction
        if len(coverages) >= 2:
            recent_change = coverages[-1] - coverages[-2]
            if recent_change > 2:
                direction = "improving"
            elif recent_change < -2:
                direction = "declining"
            else:
                direction = "stable"
        else:
            direction = "unknown"

        return {
            "direction": direction,
            "snapshots": len(self._snapshots),
            "coverage_history": coverages,
            "risk_history": risks,
            "latest_coverage": coverages[-1] if coverages else 0,
            "latest_risk": risks[-1] if risks else 0,
            "best_coverage": max(coverages) if coverages else 0,
            "worst_coverage": min(coverages) if coverages else 0,
        }

    def get_snapshots(self) -> list[ScanSnapshot]:
        return self._snapshots

    def get_comparisons(self) -> list[ComparisonResult]:
        return self._comparisons

    def to_dict(self, result: ComparisonResult) -> dict[str, Any]:
        """Convert comparison to dict."""
        return {
            "scan_a": result.scan_a_id,
            "scan_b": result.scan_b_id,
            "overall_change": round(result.overall_change, 1),
            "coverage_delta": round(result.coverage_delta, 1),
            "risk_delta": round(result.risk_delta, 1),
            "new_endpoints": result.new_endpoints,
            "removed_endpoints": result.removed_endpoints,
            "new_attack_types": result.new_attack_types,
            "removed_attack_types": result.removed_attack_types,
            "improved_combinations": len(result.improved_combinations),
            "regressed_combinations": len(result.regressed_combinations),
            "summary": result.summary,
        }
