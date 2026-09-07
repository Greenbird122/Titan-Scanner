"""Coverage Scorer — 0-100% representing attack surface coverage.

Calculates a meaningful coverage score based on:
1. Endpoint coverage (what % of endpoints were tested)
2. Attack type coverage (what % of attack types were used)
3. Combination coverage (what % of endpoint×attack combinations were tested)
4. Depth coverage (how many payloads per combination)
5. Quality coverage (how many findings were confirmed)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from titan.modules.coverage.tracker import CoverageMatrix, CoverageTracker


@dataclass
class CoverageScore:
    """A detailed coverage score."""
    overall_score: float  # 0-100
    endpoint_score: float  # 0-100
    attack_type_score: float  # 0-100
    combination_score: float  # 0-100
    depth_score: float  # 0-100
    quality_score: float  # 0-100
    grade: str  # A, B, C, D, F
    breakdown: dict[str, Any]


class CoverageScorer:
    """Calculate coverage scores."""

    # Weights for overall score
    WEIGHTS = {
        "endpoint": 0.20,
        "attack_type": 0.20,
        "combination": 0.25,
        "depth": 0.10,
        "quality": 0.10,
        "risk": 0.15,
    }

    # Grade thresholds
    GRADES = {
        "A+": 95, "A": 90, "A-": 85,
        "B+": 80, "B": 75, "B-": 70,
        "C+": 65, "C": 60, "C-": 55,
        "D+": 50, "D": 45, "D-": 40,
        "F": 0,
    }

    def __init__(self, tracker: CoverageTracker):
        self.tracker = tracker
        self._history: list[CoverageScore] = []

    def calculate(
        self,
        expected_endpoints: list[str] | None = None,
        expected_attack_types: list[str] | None = None,
    ) -> CoverageScore:
        """Calculate comprehensive coverage score."""
        matrix = self.tracker.get_matrix()
        summary = self.tracker.get_summary()

        # Endpoint coverage
        endpoint_score = self._calculate_endpoint_score(
            matrix, expected_endpoints
        )

        # Attack type coverage
        attack_type_score = self._calculate_attack_type_score(
            matrix, expected_attack_types
        )

        # Combination coverage
        combination_score = self._calculate_combination_score(matrix)

        # Depth coverage (avg tests per combination)
        depth_score = self._calculate_depth_score(matrix)

        # Quality coverage (findings confirmed)
        quality_score = self._calculate_quality_score(summary)

        # Risk-weighted coverage
        risk_score = self._calculate_risk_score()

        # Overall score (weighted average)
        overall_score = (
            endpoint_score * self.WEIGHTS["endpoint"] +
            attack_type_score * self.WEIGHTS["attack_type"] +
            combination_score * self.WEIGHTS["combination"] +
            depth_score * self.WEIGHTS["depth"] +
            quality_score * self.WEIGHTS["quality"] +
            risk_score * self.WEIGHTS["risk"]
        )

        # Grade
        grade = self._calculate_grade(overall_score)

        # Trend analysis
        trend = self._calculate_trend(overall_score)

        breakdown = {
            "endpoints": {
                "score": round(endpoint_score, 1),
                "tested": len(matrix.endpoints),
                "expected": len(expected_endpoints) if expected_endpoints else "unknown",
                "weight": self.WEIGHTS["endpoint"],
            },
            "attack_types": {
                "score": round(attack_type_score, 1),
                "tested": len(matrix.attack_types),
                "expected": len(expected_attack_types) if expected_attack_types else "unknown",
                "weight": self.WEIGHTS["attack_type"],
            },
            "combinations": {
                "score": round(combination_score, 1),
                "tested": matrix.tested_combinations,
                "total": matrix.total_combinations,
                "weight": self.WEIGHTS["combination"],
            },
            "depth": {
                "score": round(depth_score, 1),
                "avg_tests_per_combination": round(
                    summary["total_tests"] / max(matrix.tested_combinations, 1), 1
                ),
                "weight": self.WEIGHTS["depth"],
            },
            "quality": {
                "score": round(quality_score, 1),
                "findings_confirmed": summary["status_counts"].get("passed", 0),
                "total_tests": summary["total_tests"],
                "weight": self.WEIGHTS["quality"],
            },
            "risk": {
                "score": round(risk_score, 1),
                "risk_weighted_coverage": risk_score,
                "weight": self.WEIGHTS["risk"],
            },
            "trend": trend,
        }

        score = CoverageScore(
            overall_score=round(overall_score, 1),
            endpoint_score=round(endpoint_score, 1),
            attack_type_score=round(attack_type_score, 1),
            combination_score=round(combination_score, 1),
            depth_score=round(depth_score, 1),
            quality_score=round(quality_score, 1),
            grade=grade,
            breakdown=breakdown,
        )

        self._history.append(score)
        return score

    def _calculate_endpoint_score(
        self,
        matrix: CoverageMatrix,
        expected: list[str] | None,
    ) -> float:
        """Calculate endpoint coverage score."""
        if expected:
            tested = set(matrix.endpoints)
            total = set(expected)
            if not total:
                return 100.0
            return (len(tested & total) / len(total)) * 100
        else:
            # No expected list — score based on unique endpoints tested
            return min(len(matrix.endpoints) * 10, 100)  # 10 endpoints = 100%

    def _calculate_attack_type_score(
        self,
        matrix: CoverageMatrix,
        expected: list[str] | None,
    ) -> float:
        """Calculate attack type coverage score."""
        if expected:
            tested = set(matrix.attack_types)
            total = set(expected)
            if not total:
                return 100.0
            return (len(tested & total) / len(total)) * 100
        else:
            # No expected list — score based on unique attack types tested
            max_types = len(CoverageTracker.ALL_ATTACK_TYPES)
            return (len(matrix.attack_types) / max_types) * 100

    def _calculate_combination_score(self, matrix: CoverageMatrix) -> float:
        """Calculate combination coverage score."""
        if matrix.total_combinations == 0:
            return 0.0
        return (matrix.tested_combinations / matrix.total_combinations) * 100

    def _calculate_depth_score(self, matrix: CoverageMatrix) -> float:
        """Calculate depth score (avg tests per combination)."""
        if matrix.tested_combinations == 0:
            return 0.0
        # Calculate total tests from matrix
        total_tests = sum(1 for _ in matrix.matrix.values())
        avg_tests = total_tests / matrix.tested_combinations
        # Score: 1 test = 50%, 2 tests = 75%, 3+ tests = 100%
        return min(avg_tests * 33.3, 100)

    def _calculate_quality_score(self, summary: dict[str, Any]) -> float:
        """Calculate quality score (findings confirmed)."""
        total = summary.get("total_tests", 0)
        if total == 0:
            return 0.0
        passed = summary.get("status_counts", {}).get("passed", 0)
        return (passed / total) * 100

    def _calculate_risk_score(self) -> float:
        """Calculate risk-weighted coverage score."""
        return self.tracker.get_risk_score()

    def _calculate_trend(self, current_score: float) -> dict[str, Any]:
        """Calculate score trend from history."""
        if len(self._history) < 2:
            return {
                "direction": "stable",
                "change": 0.0,
                "previous_score": None,
                "history_count": len(self._history),
            }

        previous = self._history[-1].overall_score
        change = current_score - previous

        if change > 2:
            direction = "improving"
        elif change < -2:
            direction = "declining"
        else:
            direction = "stable"

        return {
            "direction": direction,
            "change": round(change, 1),
            "previous_score": previous,
            "history_count": len(self._history),
            "all_scores": [s.overall_score for s in self._history],
        }

    def _calculate_grade(self, score: float) -> str:
        """Calculate letter grade from score."""
        for grade, threshold in sorted(self.GRADES.items(), key=lambda x: -x[1]):
            if score >= threshold:
                return grade
        return "F"

    def to_dict(self, score: CoverageScore) -> dict[str, Any]:
        """Convert score to dict."""
        return {
            "overall_score": score.overall_score,
            "grade": score.grade,
            "breakdown": score.breakdown,
        }

    def get_history(self) -> list[dict[str, Any]]:
        """Get score history."""
        return [
            {"score": s.overall_score, "grade": s.grade}
            for s in self._history
        ]
