"""Coverage Pipeline — wire tracker into scan engine.

The final piece: a unified pipeline that:
1. Maps the attack surface
2. Runs all tests
3. Tracks coverage in real-time
4. Enforces coverage gates
5. Generates reports with proof
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from titan.core.models import Finding
from titan.modules.coverage.tracker import CoverageTracker
from titan.modules.coverage.scorer import CoverageScorer
from titan.modules.coverage.gapidentifier import GapIdentifier
from titan.modules.coverage.proof import CoverageProof
from titan.modules.coverage.report import CoverageReportGenerator
from titan.modules.coverage.gate import CoverageGate
from titan.modules.coverage.comparison import ScanComparator, ScanSnapshot
from titan.modules.coverage.retest import AutoRetester
from titan.modules.coverage.surfacemapper import AttackSurfaceMapper


@dataclass
class PipelineResult:
    """Result of a full coverage pipeline run."""
    target: str
    scan_id: str
    duration_seconds: float
    surface_mapped: int
    tests_executed: int
    findings_recorded: int
    coverage_score: float
    coverage_grade: str
    gate_passed: bool
    report_generated: bool
    proof_hash: str
    gaps_remaining: int
    risk_score: float


class CoveragePipeline:
    """Unified coverage pipeline."""

    def __init__(self, test_executor: Optional[Callable] = None):
        self.tracker = CoverageTracker()
        self.scorer = CoverageScorer(self.tracker)
        self.gap_identifier = GapIdentifier(self.tracker)
        self.proof_generator = CoverageProof(self.tracker)
        self.report_generator = CoverageReportGenerator(self.tracker)
        self.gate = CoverageGate(self.tracker)
        self.comparator = ScanComparator()
        self.retester = AutoRetester(self.tracker, self.gate, test_executor)
        self.surface_mapper = AttackSurfaceMapper(self.tracker)
        self.test_executor = test_executor

    async def run(
        self,
        target_url: str,
        page_source: str = "",
        scan_id: Optional[str] = None,
    ) -> PipelineResult:
        """Run the full coverage pipeline."""
        start_time = time.time()
        scan_id = scan_id or f"scan_{int(time.time())}"

        # Step 1: Map attack surface
        surface = await self.surface_mapper.map_surface(target_url, page_source)
        self.surface_mapper.feed_into_tracker()

        # Step 2: Run tests (if executor provided)
        tests_executed = 0
        if self.test_executor:
            for endpoint in self.surface_mapper.get_surface():
                for attack_type in endpoint.relevant_attacks:
                    try:
                        result = await self.test_executor(endpoint.url, attack_type)
                        if result:
                            tests_executed += 1
                    except Exception:
                        pass

        # Step 3: Create snapshot
        snapshot = self.comparator.create_snapshot(
            self.tracker, scan_id, target_url
        )

        # Step 4: Check gate
        gate_result = self.gate.check()

        # Step 5: Retest if gate failed
        if not gate_result.passed:
            retest_result = await self.retester.retest_critical()

        # Step 6: Calculate final score
        score = self.scorer.calculate()

        # Step 7: Generate proof
        proof = self.proof_generator.generate()
        verification = self.proof_generator.verify_proof(proof)

        # Step 8: Generate report
        report = self.report_generator.generate(target_url)

        duration = time.time() - start_time

        return PipelineResult(
            target=target_url,
            scan_id=scan_id,
            duration_seconds=round(duration, 2),
            surface_mapped=len(surface),
            tests_executed=tests_executed,
            findings_recorded=self.tracker.get_summary()["total_tests"],
            coverage_score=score.overall_score,
            coverage_grade=score.grade,
            gate_passed=gate_result.passed,
            report_generated=True,
            proof_hash=proof.root_hash,
            gaps_remaining=len(gate_result.gaps),
            risk_score=self.tracker.get_risk_score(),
        )

    def record_finding(self, finding: Finding) -> None:
        """Record a finding into the pipeline."""
        self.tracker.record_finding(finding)

    def record_findings(self, findings: List[Finding]) -> None:
        """Record multiple findings."""
        self.tracker.record_batch(findings)

    def get_coverage_report(self, target_url: str) -> str:
        """Get HTML coverage report."""
        report = self.report_generator.generate(target_url)
        return self.report_generator.to_html(report)

    def get_markdown_report(self, target_url: str) -> str:
        """Get Markdown coverage report."""
        report = self.report_generator.generate(target_url)
        return self.report_generator.to_markdown(report)

    def get_proof(self) -> Dict[str, Any]:
        """Get coverage proof."""
        proof = self.proof_generator.generate()
        return self.proof_generator.to_dict(proof)

    def get_gate_status(self) -> Dict[str, Any]:
        """Get gate status."""
        result = self.gate.check()
        return {
            "passed": result.passed,
            "current_score": result.current_score,
            "required_score": result.required_score,
            "gaps": result.gaps,
            "retests_needed": result.auto_retests_needed,
        }

    def compare_with_previous(self) -> Optional[Dict[str, Any]]:
        """Compare with previous scan."""
        comparison = self.comparator.compare_latest()
        if comparison:
            return self.comparator.to_dict(comparison)
        return None

    def to_dict(self, result: PipelineResult) -> Dict[str, Any]:
        """Convert result to dict."""
        return {
            "target": result.target,
            "scan_id": result.scan_id,
            "duration_seconds": result.duration_seconds,
            "surface_mapped": result.surface_mapped,
            "tests_executed": result.tests_executed,
            "findings_recorded": result.findings_recorded,
            "coverage_score": result.coverage_score,
            "coverage_grade": result.coverage_grade,
            "gate_passed": result.gate_passed,
            "report_generated": result.report_generated,
            "proof_hash": result.proof_hash,
            "gaps_remaining": result.gaps_remaining,
            "risk_score": result.risk_score,
        }
