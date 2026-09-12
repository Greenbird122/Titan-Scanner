"""Gap Identifier — what was NOT tested and why.

A real attacker doesn't just report what they found.
They report what they DIDN'T test — and why.

This module:
1. Identifies untested endpoints
2. Identifies untested attack types
3. Identifies untested combinations
4. Explains why each gap exists
5. Recommends how to close each gap
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from titan.modules.coverage.tracker import CoverageTracker


@dataclass
class CoverageGap:
    """A gap in coverage."""

    gap_type: str  # "endpoint", "attack_type", "combination"
    description: str
    reason: str
    severity: str  # "high", "medium", "low"
    recommendation: str


class GapIdentifier:
    """Identify coverage gaps."""

    # Effort estimation (minutes per test)
    EFFORT_MAP = {
        "sqli": 2,
        "xss": 1,
        "idor": 1,
        "ssrf": 3,
        "rce": 4,
        "csrf": 1,
        "auth_bypass": 2,
        "privilege_escalation": 2,
        "business_logic": 3,
        "info_leak": 1,
        "file_upload": 2,
        "path_traversal": 1,
        "open_redirect": 1,
        "cors": 1,
        "headers": 1,
        "rate_limit": 2,
        "session": 2,
        "jwt": 2,
        "baas_supabase": 3,
        "baas_firebase": 3,
        "baas_appwrite": 3,
        "baas_clerk": 2,
        "baas_auth0": 2,
        "ecommerce": 3,
        "saas": 3,
        "workflow": 4,
        "content_type": 1,
        "method_override": 1,
        "header_injection": 1,
        "post_exploit": 5,
        "chain": 6,
        "lateral_movement": 4,
        "persistence": 3,
        "cover_up": 3,
    }

    # Risk priority (higher = more important)
    RISK_PRIORITY = {
        "sqli": 10,
        "rce": 10,
        "auth_bypass": 9,
        "idor": 9,
        "ssrf": 9,
        "privilege_escalation": 9,
        "xss": 8,
        "csrf": 8,
        "business_logic": 8,
        "file_upload": 7,
        "path_traversal": 7,
        "post_exploit": 8,
        "chain": 9,
        "lateral_movement": 8,
        "persistence": 7,
        "cover_up": 7,
        "info_leak": 6,
        "open_redirect": 5,
        "cors": 5,
        "headers": 4,
        "rate_limit": 4,
        "session": 6,
        "jwt": 6,
        "baas_supabase": 7,
        "baas_firebase": 7,
        "baas_appwrite": 6,
        "baas_clerk": 6,
        "baas_auth0": 6,
        "ecommerce": 7,
        "saas": 7,
        "workflow": 6,
        "content_type": 4,
        "method_override": 5,
        "header_injection": 5,
    }

    def __init__(self, tracker: CoverageTracker):
        self.tracker = tracker

    def identify(
        self,
        expected_endpoints: list[str] | None = None,
        expected_attack_types: list[str] | None = None,
    ) -> list[CoverageGap]:
        """Identify all coverage gaps."""
        gaps = []

        # Endpoint gaps
        gaps.extend(self._identify_endpoint_gaps(expected_endpoints))

        # Attack type gaps
        gaps.extend(self._identify_attack_type_gaps(expected_attack_types))

        # Combination gaps
        gaps.extend(self._identify_combination_gaps(expected_endpoints, expected_attack_types))

        # Sort by severity
        gaps.sort(key=lambda g: {"high": 0, "medium": 1, "low": 2}.get(g.severity, 3))

        return gaps

    def _identify_endpoint_gaps(
        self,
        expected: list[str] | None,
    ) -> list[CoverageGap]:
        """Identify untested endpoints."""
        gaps = []
        tested = set(self.tracker.get_endpoints())

        if expected:
            untested = set(expected) - tested
            for endpoint in untested:
                gaps.append(
                    CoverageGap(
                        gap_type="endpoint",
                        description=f"Endpoint not tested: {endpoint}",
                        reason="Endpoint was discovered but not tested",
                        severity="high",
                        recommendation=f"Run all attack types against {endpoint}",
                    )
                )
        else:
            # No expected list — check if we have reasonable coverage
            if len(tested) < 3:
                gaps.append(
                    CoverageGap(
                        gap_type="endpoint",
                        description=f"Only {len(tested)} endpoints tested",
                        reason="Insufficient endpoint discovery",
                        severity="medium",
                        recommendation="Run endpoint discovery to find more targets",
                    )
                )

        return gaps

    def _identify_attack_type_gaps(
        self,
        expected: list[str] | None,
    ) -> list[CoverageGap]:
        """Identify untested attack types."""
        gaps = []
        tested = set(self.tracker.get_attack_types())

        # Critical attack types that should always be tested
        critical_types = ["sqli", "xss", "idor", "auth_bypass", "ssrf"]
        high_types = ["csrf", "privilege_escalation", "business_logic", "rce"]

        if expected:
            untested = set(expected) - tested
            for attack_type in untested:
                severity = "high" if attack_type in critical_types else "medium"
                gaps.append(
                    CoverageGap(
                        gap_type="attack_type",
                        description=f"Attack type not tested: {attack_type}",
                        reason="Attack type was in scope but not executed",
                        severity=severity,
                        recommendation=f"Run {attack_type} tests against all endpoints",
                    )
                )
        else:
            # Check critical types
            for attack_type in critical_types:
                if attack_type not in tested:
                    gaps.append(
                        CoverageGap(
                            gap_type="attack_type",
                            description=f"Critical attack type not tested: {attack_type}",
                            reason="Critical attack type was not executed",
                            severity="high",
                            recommendation=f"Run {attack_type} tests against all endpoints",
                        )
                    )

            for attack_type in high_types:
                if attack_type not in tested:
                    gaps.append(
                        CoverageGap(
                            gap_type="attack_type",
                            description=f"High-priority attack type not tested: {attack_type}",
                            reason="High-priority attack type was not executed",
                            severity="medium",
                            recommendation=f"Run {attack_type} tests against all endpoints",
                        )
                    )

        return gaps

    def _identify_combination_gaps(
        self,
        expected_endpoints: list[str] | None,
        expected_attack_types: list[str] | None,
    ) -> list[CoverageGap]:
        """Identify untested endpoint×attack_type combinations."""
        gaps = []

        endpoints = expected_endpoints or self.tracker.get_endpoints()
        attack_types = expected_attack_types or self.tracker.get_attack_types()

        tested_pairs = self.tracker.get_tested_pairs()
        all_pairs = {(e, a) for e in endpoints for a in attack_types}
        untested = all_pairs - tested_pairs

        if len(untested) > 0:
            # Group by endpoint
            endpoint_gaps: dict[str, list[str]] = {}
            for endpoint, attack_type in untested:
                if endpoint not in endpoint_gaps:
                    endpoint_gaps[endpoint] = []
                endpoint_gaps[endpoint].append(attack_type)

            # Report top gaps
            for endpoint, attack_types in sorted(endpoint_gaps.items(), key=lambda x: -len(x[1]))[:5]:
                gaps.append(
                    CoverageGap(
                        gap_type="combination",
                        description=f"{endpoint} missing {len(attack_types)} attack types: {', '.join(attack_types[:5])}",
                        reason="Endpoint was not fully tested",
                        severity="high" if len(attack_types) >= 3 else "medium",
                        recommendation=f"Run missing attack types against {endpoint}",
                    )
                )

            if len(endpoint_gaps) > 5:
                gaps.append(
                    CoverageGap(
                        gap_type="combination",
                        description=f"{len(endpoint_gaps) - 5} more endpoints with gaps",
                        reason="Multiple endpoints have incomplete coverage",
                        severity="medium",
                        recommendation="Run full test suite against all endpoints",
                    )
                )

        return gaps

    def get_gaps_by_severity(self, gaps: list[CoverageGap]) -> dict[str, list[CoverageGap]]:
        """Group gaps by severity."""
        result: dict[str, list[CoverageGap]] = {"high": [], "medium": [], "low": []}
        for gap in gaps:
            result[gap.severity].append(gap)
        return result

    def get_gap_summary(self, gaps: list[CoverageGap]) -> dict[str, Any]:
        """Get summary of gaps."""
        by_severity = self.get_gaps_by_severity(gaps)

        # Calculate total effort
        total_effort = 0
        for gap in gaps:
            # Extract attack type from gap description
            for attack_type in self.EFFORT_MAP:
                if attack_type in gap.description.lower():
                    total_effort += self.EFFORT_MAP[attack_type]
                    break

        # Calculate risk score
        risk_score = 0
        for gap in gaps:
            for attack_type in self.RISK_PRIORITY:
                if attack_type in gap.description.lower():
                    risk_score += self.RISK_PRIORITY[attack_type]
                    break

        return {
            "total_gaps": len(gaps),
            "high_gaps": len(by_severity["high"]),
            "medium_gaps": len(by_severity["medium"]),
            "low_gaps": len(by_severity["low"]),
            "total_effort_minutes": total_effort,
            "total_effort_hours": round(total_effort / 60, 1),
            "risk_score": risk_score,
            "top_recommendations": [gap.recommendation for gap in gaps[:5]],
            "priority_order": [
                {
                    "gap": gap.description,
                    "priority": self.RISK_PRIORITY.get(gap.description.split(":")[0].split(" ")[-1], 5),
                }
                for gap in sorted(
                    gaps, key=lambda g: -self.RISK_PRIORITY.get(g.description.split(":")[0].split(" ")[-1], 5)
                )[:5]
            ],
        }

    def get_effort_estimate(self, gaps: list[CoverageGap]) -> dict[str, Any]:
        """Estimate effort to close all gaps."""
        effort_by_type: dict[str, int] = {}
        for gap in gaps:
            for attack_type, minutes in self.EFFORT_MAP.items():
                if attack_type in gap.description.lower():
                    effort_by_type[attack_type] = effort_by_type.get(attack_type, 0) + minutes
                    break

        total = sum(effort_by_type.values())
        return {
            "total_minutes": total,
            "total_hours": round(total / 60, 1),
            "by_type": effort_by_type,
            "estimated_days": round(total / 480, 1),  # 8 hours/day
        }

    def get_risk_ranking(self, gaps: list[CoverageGap]) -> list[dict[str, Any]]:
        """Rank gaps by risk priority."""
        ranked = []
        for gap in gaps:
            priority = 5  # default
            for attack_type in self.RISK_PRIORITY:
                if attack_type in gap.description.lower():
                    priority = self.RISK_PRIORITY[attack_type]
                    break
            ranked.append(
                {
                    "gap": gap.description,
                    "severity": gap.severity,
                    "risk_priority": priority,
                    "recommendation": gap.recommendation,
                }
            )
        return sorted(ranked, key=lambda x: -x["risk_priority"])
