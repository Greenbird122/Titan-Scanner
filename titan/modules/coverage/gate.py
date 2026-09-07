"""Coverage Gate — don't report until coverage threshold met.

A real attacker doesn't stop when they feel like it.
They stop when they've covered everything.

This module:
1. Sets minimum coverage thresholds
2. Blocks report generation until thresholds met
3. Auto-retests gaps until covered
4. Enforces quality gates (no false positives in report)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from titan.modules.coverage.scorer import CoverageScorer
from titan.modules.coverage.tracker import CoverageTracker


@dataclass
class GateResult:
    """Result of a coverage gate check."""
    passed: bool
    current_score: float
    required_score: float
    gaps: list[str]
    auto_retests_needed: int
    estimated_time_seconds: float


class CoverageGate:
    """Enforce coverage thresholds before reporting."""

    # Default thresholds
    DEFAULT_THRESHOLDS = {
        "overall_score": 70.0,       # Minimum overall score
        "endpoint_coverage": 60.0,   # Minimum endpoint coverage
        "attack_type_coverage": 50.0, # Minimum attack type coverage
        "combination_coverage": 30.0, # Minimum combination coverage
        "quality_score": 50.0,       # Minimum quality (no false positives)
        "risk_score": 40.0,          # Minimum risk-weighted coverage
    }

    # Critical attack types that MUST be tested
    CRITICAL_TYPES = ["sqli", "xss", "idor", "auth_bypass", "ssrf"]

    def __init__(
        self,
        tracker: CoverageTracker,
        thresholds: dict[str, float] | None = None,
    ):
        self.tracker = tracker
        self.scorer = CoverageScorer(tracker)
        self.thresholds = thresholds or self.DEFAULT_THRESHOLDS.copy()

    def check(self) -> GateResult:
        """Check if coverage meets all thresholds."""
        score = self.scorer.calculate()
        gaps = []
        auto_retests = 0

        # Check overall score
        if score.overall_score < self.thresholds["overall_score"]:
            gaps.append(f"Overall score {score.overall_score}% < {self.thresholds['overall_score']}%")
            auto_retests += 5

        # Check endpoint coverage
        if score.endpoint_score < self.thresholds["endpoint_coverage"]:
            gaps.append(f"Endpoint coverage {score.endpoint_score}% < {self.thresholds['endpoint_coverage']}%")
            auto_retests += 3

        # Check attack type coverage
        if score.attack_type_score < self.thresholds["attack_type_coverage"]:
            gaps.append(f"Attack type coverage {score.attack_type_score}% < {self.thresholds['attack_type_coverage']}%")
            auto_retests += 5

        # Check combination coverage
        if score.combination_score < self.thresholds["combination_coverage"]:
            gaps.append(f"Combination coverage {score.combination_score}% < {self.thresholds['combination_coverage']}%")
            auto_retests += 10

        # Check quality score
        if score.quality_score < self.thresholds["quality_score"]:
            gaps.append(f"Quality score {score.quality_score}% < {self.thresholds['quality_score']}%")
            auto_retests += 3

        # Check risk score
        risk_score = self.tracker.get_risk_score()
        if risk_score < self.thresholds["risk_score"]:
            gaps.append(f"Risk score {risk_score}% < {self.thresholds['risk_score']}%")
            auto_retests += 5

        # Check critical types
        tested_types = set(self.tracker.get_attack_types())
        missing_critical = [t for t in self.CRITICAL_TYPES if t not in tested_types]
        if missing_critical:
            gaps.append(f"Missing critical types: {', '.join(missing_critical)}")
            auto_retests += len(missing_critical) * 2

        # Estimate time (assume 5 seconds per retest)
        estimated_time = auto_retests * 5

        return GateResult(
            passed=len(gaps) == 0,
            current_score=score.overall_score,
            required_score=self.thresholds["overall_score"],
            gaps=gaps,
            auto_retests_needed=auto_retests,
            estimated_time_seconds=estimated_time,
        )

    def get_missing_critical_types(self) -> list[str]:
        """Get critical attack types not yet tested."""
        tested = set(self.tracker.get_attack_types())
        return [t for t in self.CRITICAL_TYPES if t not in tested]

    def get_retest_plan(self) -> list[dict[str, Any]]:
        """Generate a plan for retesting gaps."""
        plan = []
        tested = set(self.tracker.get_attack_types())
        endpoints = self.tracker.get_endpoints()

        # Missing critical types
        for attack_type in self.CRITICAL_TYPES:
            if attack_type not in tested:
                for endpoint in endpoints[:3]:  # Top 3 endpoints
                    plan.append({
                        "endpoint": endpoint,
                        "attack_type": attack_type,
                        "priority": "critical",
                        "reason": f"Critical type {attack_type} not tested",
                    })

        # Missing high-priority types
        high_types = ["rce", "csrf", "privilege_escalation", "business_logic"]
        for attack_type in high_types:
            if attack_type not in tested:
                for endpoint in endpoints[:2]:
                    plan.append({
                        "endpoint": endpoint,
                        "attack_type": attack_type,
                        "priority": "high",
                        "reason": f"High-priority type {attack_type} not tested",
                    })

        return plan

    def set_threshold(self, key: str, value: float) -> None:
        """Set a specific threshold."""
        self.thresholds[key] = value

    def get_thresholds(self) -> dict[str, float]:
        """Get current thresholds."""
        return self.thresholds.copy()
