"""Coverage Tracker — track every endpoint × attack type tested.

A real attacker doesn't just test what's easy.
They prove they tested EVERYTHING.

This module:
1. Tracks every (endpoint, attack_type) combination
2. Records which tests were executed
3. Records which tests passed/failed
4. Maintains a coverage matrix
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any

from titan.core.models import Finding


@dataclass
class TestRecord:
    """Record of a single test execution."""

    endpoint: str
    attack_type: str
    payload: str
    status: str  # "executed", "passed", "failed", "blocked", "error"
    response_code: int
    response_hash: str
    timestamp: str
    duration_ms: float
    notes: str = ""


@dataclass
class CoverageMatrix:
    """Matrix of coverage across endpoints and attack types."""

    endpoints: list[str]
    attack_types: list[str]
    matrix: dict[tuple[str, str], TestRecord]
    total_combinations: int
    tested_combinations: int
    passed_combinations: int


class CoverageTracker:
    """Track coverage across all tests."""

    # All attack types Titan can test
    ALL_ATTACK_TYPES = [
        "sqli",
        "xss",
        "idor",
        "ssrf",
        "rce",
        "csrf",
        "auth_bypass",
        "privilege_escalation",
        "business_logic",
        "info_leak",
        "file_upload",
        "path_traversal",
        "open_redirect",
        "cors",
        "headers",
        "rate_limit",
        "session",
        "jwt",
        "baas_supabase",
        "baas_firebase",
        "baas_appwrite",
        "baas_clerk",
        "baas_auth0",
        "ecommerce",
        "saas",
        "workflow",
        "content_type",
        "method_override",
        "header_injection",
        "post_exploit",
        "chain",
        "lateral_movement",
        "persistence",
        "cover_up",
    ]

    # Severity weights for risk-based scoring
    SEVERITY_WEIGHTS = {
        "sqli": 1.0,
        "rce": 1.0,
        "auth_bypass": 0.95,
        "idor": 0.9,
        "ssrf": 0.9,
        "privilege_escalation": 0.9,
        "xss": 0.85,
        "csrf": 0.8,
        "business_logic": 0.8,
        "file_upload": 0.75,
        "path_traversal": 0.75,
        "info_leak": 0.7,
        "open_redirect": 0.65,
        "cors": 0.6,
        "headers": 0.55,
        "rate_limit": 0.5,
        "session": 0.7,
        "jwt": 0.7,
        "baas_supabase": 0.85,
        "baas_firebase": 0.85,
        "baas_appwrite": 0.8,
        "baas_clerk": 0.75,
        "baas_auth0": 0.75,
        "ecommerce": 0.8,
        "saas": 0.8,
        "workflow": 0.75,
        "content_type": 0.6,
        "method_override": 0.65,
        "header_injection": 0.6,
        "post_exploit": 0.9,
        "chain": 0.95,
        "lateral_movement": 0.9,
        "persistence": 0.85,
        "cover_up": 0.8,
    }

    # Test dependencies (which tests should run first)
    DEPENDENCIES = {
        "post_exploit": ["sqli", "xss", "idor", "ssrf", "auth_bypass", "rce"],
        "chain": ["sqli", "xss", "idor", "ssrf", "auth_bypass", "rce", "privilege_escalation"],
        "lateral_movement": ["ssrf", "rce"],
        "persistence": ["auth_bypass", "privilege_escalation", "rce"],
        "cover_up": ["auth_bypass", "privilege_escalation"],
        "privilege_escalation": ["auth_bypass", "idor"],
        "business_logic": ["auth_bypass"],
    }

    def __init__(self):
        self._records: list[TestRecord] = []
        self._endpoints: set[str] = set()
        self._attack_types: set[str] = set()
        self._start_time = time.time()
        self._parallel_groups: dict[str, list[str]] = {}  # group_id -> [endpoints]
        self._dependency_graph: dict[str, list[str]] = dict(self.DEPENDENCIES)

    def record_test(
        self,
        endpoint: str,
        attack_type: str,
        payload: str,
        status: str,
        response_code: int,
        response_body: str = "",
        duration_ms: float = 0.0,
        notes: str = "",
    ) -> None:
        """Record a test execution."""
        # Hash response for proof
        response_hash = hashlib.sha256((response_body or "").encode()).hexdigest()

        record = TestRecord(
            endpoint=endpoint,
            attack_type=attack_type,
            payload=payload[:500],
            status=status,
            response_code=response_code,
            response_hash=response_hash,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            duration_ms=duration_ms,
            notes=notes,
        )

        self._records.append(record)
        self._endpoints.add(endpoint)
        self._attack_types.add(attack_type)

    def record_finding(self, finding: Finding) -> None:
        """Record a finding as a test record."""
        attack_type = self._extract_attack_type(finding)
        self.record_test(
            endpoint=finding.url or "unknown",
            attack_type=attack_type,
            payload=finding.payload or "",
            status="passed",
            response_code=finding.status or 0,
            response_body=finding.body or finding.evidence or "",
            notes=finding.notes or "",
        )

    def record_batch(self, findings: list[Finding]) -> None:
        """Record multiple findings."""
        for finding in findings:
            self.record_finding(finding)

    def get_matrix(self) -> CoverageMatrix:
        """Build coverage matrix."""
        matrix: dict[tuple[str, str], TestRecord] = {}

        for record in self._records:
            key = (record.endpoint, record.attack_type)
            # Keep the most recent record for each combination
            if key not in matrix or record.timestamp > matrix[key].timestamp:
                matrix[key] = record

        endpoints = sorted(self._endpoints)
        attack_types = sorted(self._attack_types)

        total = len(endpoints) * len(attack_types)
        tested = len(matrix)
        passed = sum(1 for r in matrix.values() if r.status == "passed")

        return CoverageMatrix(
            endpoints=endpoints,
            attack_types=attack_types,
            matrix=matrix,
            total_combinations=total,
            tested_combinations=tested,
            passed_combinations=passed,
        )

    def get_tested_pairs(self) -> set[tuple[str, str]]:
        """Get all tested (endpoint, attack_type) pairs."""
        return {(r.endpoint, r.attack_type) for r in self._records}

    def get_untested_pairs(self, all_endpoints: list[str], all_attack_types: list[str]) -> set[tuple[str, str]]:
        """Get all untested (endpoint, attack_type) pairs."""
        tested = self.get_tested_pairs()
        all_pairs = {(e, a) for e in all_endpoints for a in all_attack_types}
        return all_pairs - tested

    def get_records(self) -> list[TestRecord]:
        return self._records

    def get_endpoints(self) -> list[str]:
        return sorted(self._endpoints)

    def get_attack_types(self) -> list[str]:
        return sorted(self._attack_types)

    def get_summary(self) -> dict[str, Any]:
        """Get coverage summary."""
        matrix = self.get_matrix()
        duration = time.time() - self._start_time

        status_counts = {}
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_duration = 0.0
        for record in self._records:
            status_counts[record.status] = status_counts.get(record.status, 0) + 1
            total_duration += record.duration_ms
            # Estimate severity from attack type
            weight = self.SEVERITY_WEIGHTS.get(record.attack_type, 0.5)
            if weight >= 0.9:
                severity_counts["critical"] += 1
            elif weight >= 0.75:
                severity_counts["high"] += 1
            elif weight >= 0.5:
                severity_counts["medium"] += 1
            else:
                severity_counts["low"] += 1

        # Calculate dependency satisfaction
        deps_satisfied = 0
        deps_total = 0
        tested_types = set(self._attack_types)
        for attack_type, required in self.DEPENDENCIES.items():
            if attack_type in tested_types:
                for req in required:
                    deps_total += 1
                    if req in tested_types:
                        deps_satisfied += 1

        return {
            "total_tests": len(self._records),
            "unique_endpoints": len(self._endpoints),
            "unique_attack_types": len(self._attack_types),
            "total_combinations": matrix.total_combinations,
            "tested_combinations": matrix.tested_combinations,
            "passed_combinations": matrix.passed_combinations,
            "coverage_percent": (matrix.tested_combinations / max(matrix.total_combinations, 1)) * 100,
            "status_counts": status_counts,
            "severity_counts": severity_counts,
            "duration_seconds": round(duration, 2),
            "total_test_duration_ms": round(total_duration, 2),
            "avg_test_duration_ms": round(total_duration / max(len(self._records), 1), 2),
            "dependency_satisfaction": round(deps_satisfied / max(deps_total, 1) * 100, 1),
        }

    def get_risk_score(self) -> float:
        """Calculate risk-weighted coverage score (0-100)."""
        if not self._records:
            return 0.0

        total_weight = 0.0
        covered_weight = 0.0

        for attack_type in self.ALL_ATTACK_TYPES:
            weight = self.SEVERITY_WEIGHTS.get(attack_type, 0.5)
            total_weight += weight
            if attack_type in self._attack_types:
                covered_weight += weight

        return round((covered_weight / max(total_weight, 1)) * 100, 1)

    def get_time_analysis(self) -> dict[str, Any]:
        """Analyze test timing."""
        if not self._records:
            return {}

        durations = [r.duration_ms for r in self._records]
        return {
            "total_duration_ms": round(sum(durations), 2),
            "avg_duration_ms": round(sum(durations) / len(durations), 2),
            "min_duration_ms": round(min(durations), 2),
            "max_duration_ms": round(max(durations), 2),
            "slowest_tests": sorted(
                [(r.endpoint, r.attack_type, r.duration_ms) for r in self._records], key=lambda x: -x[2]
            )[:5],
        }

    def get_dependency_analysis(self) -> dict[str, Any]:
        """Analyze test dependencies."""
        tested = set(self._attack_types)
        satisfied = {}
        unsatisfied = {}

        for attack_type, required in self.DEPENDENCIES.items():
            if attack_type in tested:
                met = [r for r in required if r in tested]
                unmet = [r for r in required if r not in tested]
                satisfied[attack_type] = met
                if unmet:
                    unsatisfied[attack_type] = unmet

        return {
            "satisfied": satisfied,
            "unsatisfied": unsatisfied,
            "satisfaction_rate": round(
                sum(len(v) for v in satisfied.values())
                / max(sum(len(v) for v in satisfied.values()) + sum(len(v) for v in unsatisfied.values()), 1)
                * 100,
                1,
            ),
        }

    def _extract_attack_type(self, finding: Finding) -> str:
        """Extract attack type from a finding."""
        tags = str(finding.tags or "").lower()
        notes = (finding.notes or "").lower()

        type_map = {
            "sqli": ["sqli", "sql injection", "sql_injection"],
            "xss": ["xss", "cross-site scripting"],
            "idor": ["idor", "insecure direct object"],
            "ssrf": ["ssrf", "server-side request forgery"],
            "rce": ["rce", "remote code execution", "command injection"],
            "csrf": ["csrf", "cross-site request forgery"],
            "auth_bypass": ["auth_bypass", "authentication bypass", "auth bypass"],
            "privilege_escalation": ["privesc", "privilege escalation", "escalation"],
            "business_logic": ["business_logic", "business logic"],
            "info_leak": ["info_leak", "information disclosure", "info leak"],
            "file_upload": ["file_upload", "upload", "file upload"],
            "path_traversal": ["path_traversal", "path traversal", "directory traversal"],
            "open_redirect": ["open_redirect", "open redirect", "redirect"],
            "cors": ["cors", "cross-origin"],
            "headers": ["header", "headers", "security headers"],
            "rate_limit": ["rate_limit", "rate limit", "throttle"],
            "session": ["session", "cookie"],
            "jwt": ["jwt", "token"],
            "baas_supabase": ["supabase"],
            "baas_firebase": ["firebase"],
            "baas_appwrite": ["appwrite"],
            "baas_clerk": ["clerk"],
            "baas_auth0": ["auth0"],
            "ecommerce": ["ecommerce", "e-commerce", "cart", "checkout", "payment"],
            "saas": ["saas", "subscription", "billing", "credit"],
            "workflow": ["workflow", "step skipping", "state manipulation"],
            "content_type": ["content_type", "content type", "content-type"],
            "method_override": ["method_override", "method override", "_method"],
            "header_injection": ["header_injection", "header injection"],
            "post_exploit": ["post_exploit", "post-exploit", "post exploit"],
            "chain": ["chain", "kill chain", "attack chain"],
            "lateral_movement": ["lateral", "internal", "metadata"],
            "persistence": ["persistence", "webhook", "backdoor"],
            "cover_up": ["cover", "audit", "log"],
        }

        for attack_type, keywords in type_map.items():
            for kw in keywords:
                if kw in tags or kw in notes:
                    return attack_type

        return "other"
