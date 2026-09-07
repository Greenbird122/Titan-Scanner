"""Coverage Report — matrix showing all tests and results.

Generates professional coverage reports with:
1. Coverage matrix (endpoint × attack type)
2. Coverage score with grade
3. Gap analysis with recommendations
4. Proof bundle with verification
5. Executive summary
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from titan.modules.coverage.gapidentifier import CoverageGap, GapIdentifier
from titan.modules.coverage.proof import CoverageProof, CoverageProofBundle
from titan.modules.coverage.scorer import CoverageScore, CoverageScorer
from titan.modules.coverage.tracker import CoverageTracker


@dataclass
class CoverageReport:
    """A complete coverage report."""
    target: str
    timestamp: str
    executive_summary: str
    coverage_score: CoverageScore
    matrix: dict[str, Any]
    gaps: list[dict[str, Any]]
    proof: dict[str, Any]
    recommendations: list[str]
    raw_data: dict[str, Any]


class CoverageReportGenerator:
    """Generate coverage reports."""

    def __init__(self, tracker: CoverageTracker):
        self.tracker = tracker
        self.scorer = CoverageScorer(tracker)
        self.gap_identifier = GapIdentifier(tracker)
        self.proof_generator = CoverageProof(tracker)

    def generate(
        self,
        target_url: str,
        expected_endpoints: list[str] | None = None,
        expected_attack_types: list[str] | None = None,
    ) -> CoverageReport:
        """Generate complete coverage report."""
        # Calculate score
        score = self.scorer.calculate(expected_endpoints, expected_attack_types)

        # Identify gaps
        gaps = self.gap_identifier.identify(expected_endpoints, expected_attack_types)

        # Generate proof
        proof = self.proof_generator.generate()

        # Build matrix
        matrix = self._build_matrix()

        # Generate executive summary
        summary = self._generate_summary(score, gaps, proof)

        # Generate recommendations
        recommendations = self._generate_recommendations(score, gaps)

        # Raw data
        raw_data = self.tracker.get_summary()

        return CoverageReport(
            target=target_url,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            executive_summary=summary,
            coverage_score=score,
            matrix=matrix,
            gaps=[self._gap_to_dict(g) for g in gaps],
            proof=self.proof_generator.to_dict(proof),
            recommendations=recommendations,
            raw_data=raw_data,
        )

    def _build_matrix(self) -> dict[str, Any]:
        """Build coverage matrix for report."""
        coverage_matrix = self.tracker.get_matrix()

        matrix_data = {}
        for endpoint in coverage_matrix.endpoints:
            matrix_data[endpoint] = {}
            for attack_type in coverage_matrix.attack_types:
                key = (endpoint, attack_type)
                if key in coverage_matrix.matrix:
                    record = coverage_matrix.matrix[key]
                    matrix_data[endpoint][attack_type] = {
                        "status": record.status,
                        "response_code": record.response_code,
                        "timestamp": record.timestamp,
                    }
                else:
                    matrix_data[endpoint][attack_type] = {"status": "not_tested"}

        return {
            "endpoints": coverage_matrix.endpoints,
            "attack_types": coverage_matrix.attack_types,
            "matrix": matrix_data,
            "total_combinations": coverage_matrix.total_combinations,
            "tested_combinations": coverage_matrix.tested_combinations,
            "passed_combinations": coverage_matrix.passed_combinations,
        }

    def _generate_summary(
        self,
        score: CoverageScore,
        gaps: list[CoverageGap],
        proof: CoverageProofBundle,
    ) -> str:
        """Generate executive summary."""
        high_gaps = sum(1 for g in gaps if g.severity == "high")
        medium_gaps = sum(1 for g in gaps if g.severity == "medium")

        summary = (
            f"Coverage assessment: {score.overall_score}% (Grade: {score.grade}). "
            f"Tested {self.tracker.get_summary()['total_tests']} tests across "
            f"{self.tracker.get_summary()['unique_endpoints']} endpoints and "
            f"{self.tracker.get_summary()['unique_attack_types']} attack types. "
        )

        if high_gaps > 0:
            summary += f"Found {high_gaps} high-severity coverage gaps. "
        if medium_gaps > 0:
            summary += f"Found {medium_gaps} medium-severity coverage gaps. "

        summary += f"Root hash: {proof.root_hash[:16]}... for verification."

        return summary

    def _generate_recommendations(
        self,
        score: CoverageScore,
        gaps: list[CoverageGap],
    ) -> list[str]:
        """Generate recommendations."""
        recommendations = []

        # Score-based recommendations
        if score.overall_score < 50:
            recommendations.append("Coverage is below 50% — run full test suite")
        elif score.overall_score < 75:
            recommendations.append("Coverage is below 75% — fill identified gaps")
        elif score.overall_score < 90:
            recommendations.append("Coverage is above 75% — fill remaining gaps for A grade")

        # Gap-based recommendations
        for gap in gaps[:5]:
            recommendations.append(gap.recommendation)

        # General recommendations
        if score.breakdown.get("quality", {}).get("score", 0) < 50:
            recommendations.append("Low quality score — verify findings with proof")

        if score.breakdown.get("depth", {}).get("score", 0) < 50:
            recommendations.append("Low depth score — run more payloads per combination")

        return recommendations[:10]

    def _gap_to_dict(self, gap: CoverageGap) -> dict[str, Any]:
        """Convert gap to dict."""
        return {
            "gap_type": gap.gap_type,
            "description": gap.description,
            "reason": gap.reason,
            "severity": gap.severity,
            "recommendation": gap.recommendation,
        }

    def to_json(self, report: CoverageReport) -> str:
        """Convert report to JSON."""
        return json.dumps({
            "target": report.target,
            "timestamp": report.timestamp,
            "executive_summary": report.executive_summary,
            "coverage_score": self.scorer.to_dict(report.coverage_score),
            "matrix": report.matrix,
            "gaps": report.gaps,
            "proof": report.proof,
            "recommendations": report.recommendations,
            "raw_data": report.raw_data,
        }, indent=2)

    def to_html(self, report: CoverageReport) -> str:
        """Convert report to HTML with visualization."""
        score = report.coverage_score
        matrix = report.matrix

        # Build coverage heatmap HTML
        heatmap_rows = ""
        for endpoint in matrix["endpoints"][:20]:  # Limit to 20 endpoints
            row = f"<tr><td class='endpoint'>{endpoint[:50]}</td>"
            for attack_type in matrix["attack_types"]:
                cell = matrix["matrix"].get(endpoint, {}).get(attack_type, {})
                status = cell.get("status", "not_tested")
                if status == "passed":
                    css_class = "tested-pass"
                elif status == "failed":
                    css_class = "tested-fail"
                elif status == "blocked":
                    css_class = "tested-blocked"
                else:
                    css_class = "not-tested"
                row += f"<td class='{css_class}'></td>"
            row += "</tr>"
            heatmap_rows += row

        # Build attack type headers
        attack_headers = "".join(
            f"<th class='attack-header'>{at[:10]}</th>"
            for at in matrix["attack_types"]
        )

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Coverage Report: {report.target}</title>
    <style>
        body {{ font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
        h1 {{ color: #00ff41; }}
        h2 {{ color: #00ff41; border-bottom: 1px solid #333; padding-bottom: 5px; }}
        .score-box {{ display: inline-block; background: #16213e; padding: 20px; margin: 10px; border-radius: 8px; border: 1px solid #0f3460; }}
        .score-big {{ font-size: 48px; color: #00ff41; font-weight: bold; }}
        .grade {{ font-size: 36px; color: #00ff41; }}
        table {{ border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #333; padding: 4px 8px; font-size: 11px; }}
        th {{ background: #16213e; color: #00ff41; }}
        .endpoint {{ max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .attack-header {{ writing-mode: vertical-lr; text-orientation: mixed; height: 80px; }}
        .tested-pass {{ background: #00ff41; width: 20px; }}
        .tested-fail {{ background: #ff4444; width: 20px; }}
        .tested-blocked {{ background: #ffaa00; width: 20px; }}
        .not-tested {{ background: #333; width: 20px; }}
        .gap-high {{ color: #ff4444; }}
        .gap-medium {{ color: #ffaa00; }}
        .gap-low {{ color: #00ff41; }}
        .recommendation {{ background: #16213e; padding: 10px; margin: 5px 0; border-left: 3px solid #00ff41; }}
    </style>
</head>
<body>
    <h1>Coverage Report</h1>
    <p>Target: {report.target}</p>
    <p>Generated: {report.timestamp}</p>

    <div class='score-box'>
        <div class='score-big'>{score.overall_score}%</div>
        <div class='grade'>Grade: {score.grade}</div>
    </div>
    <div class='score-box'>
        <div>Endpoints: {matrix["tested_combinations"]}/{matrix["total_combinations"]}</div>
        <div>Attack Types: {len(matrix["attack_types"])}</div>
        <div>Tests: {report.raw_data["total_tests"]}</div>
    </div>

    <h2>Coverage Matrix</h2>
    <div style='overflow-x: auto;'>
    <table>
        <tr><th>Endpoint</th>{attack_headers}</tr>
        {heatmap_rows}
    </table>
    </div>

    <h2>Score Breakdown</h2>
    <table>
        <tr><th>Dimension</th><th>Score</th><th>Weight</th><th>Details</th></tr>
        <tr><td>Endpoints</td><td>{score.breakdown['endpoints']['score']}%</td><td>{score.breakdown['endpoints']['weight']}</td><td>{score.breakdown['endpoints']['tested']} tested</td></tr>
        <tr><td>Attack Types</td><td>{score.breakdown['attack_types']['score']}%</td><td>{score.breakdown['attack_types']['weight']}</td><td>{score.breakdown['attack_types']['tested']} tested</td></tr>
        <tr><td>Combinations</td><td>{score.breakdown['combinations']['score']}%</td><td>{score.breakdown['combinations']['weight']}</td><td>{score.breakdown['combinations']['tested']}/{score.breakdown['combinations']['total']}</td></tr>
        <tr><td>Depth</td><td>{score.breakdown['depth']['score']}%</td><td>{score.breakdown['depth']['weight']}</td><td>{score.breakdown['depth']['avg_tests_per_combination']} avg tests/comb</td></tr>
        <tr><td>Quality</td><td>{score.breakdown['quality']['score']}%</td><td>{score.breakdown['quality']['weight']}</td><td>{score.breakdown['quality']['findings_confirmed']}/{score.breakdown['quality']['total_tests']} confirmed</td></tr>
        <tr><td>Risk</td><td>{score.breakdown['risk']['score']}%</td><td>{score.breakdown['risk']['weight']}</td><td>Risk-weighted coverage</td></tr>
    </table>

    <h2>Gaps ({len(report.gaps)} found)</h2>
    {''.join(f"<div class='gap-{g['severity']}'>[{g['severity'].upper()}] {g['description']}<br><small>{g['recommendation']}</small></div>" for g in report.gaps[:10])}

    <h2>Recommendations</h2>
    {''.join(f"<div class='recommendation'>{r}</div>" for r in report.recommendations)}

    <h2>Proof</h2>
    <p>Root Hash: <code>{report.proof['root_hash']}</code></p>
    <p>Tests Proven: {report.proof['test_proofs_count']}</p>
    <p>Merkle Tree Depth: {report.proof['merkle_tree_depth']}</p>

</body>
</html>"""
        return html

    def to_markdown(self, report: CoverageReport) -> str:
        """Convert report to Markdown."""
        score = report.coverage_score
        matrix = report.matrix

        md = f"""
# Coverage Report: {report.target}

**Generated:** {report.timestamp}
**Grade:** {score.grade}
**Score:** {score.overall_score}%

## Score Breakdown

| Dimension | Score | Weight | Details |
|-----------|-------|--------|----------|
| Endpoints | {score.breakdown['endpoints']['score']}% | {score.breakdown['endpoints']['weight']} | {score.breakdown['endpoints']['tested']} tested |
| Attack Types | {score.breakdown['attack_types']['score']}% | {score.breakdown['attack_types']['weight']} | {score.breakdown['attack_types']['tested']} tested |
| Combinations | {score.breakdown['combinations']['score']}% | {score.breakdown['combinations']['weight']} | {score.breakdown['combinations']['tested']}/{score.breakdown['combinations']['total']} |
| Depth | {score.breakdown['depth']['score']}% | {score.breakdown['depth']['weight']} | {score.breakdown['depth']['avg_tests_per_combination']} avg tests/comb |
| Quality | {score.breakdown['quality']['score']}% | {score.breakdown['quality']['weight']} | {score.breakdown['quality']['findings_confirmed']}/{score.breakdown['quality']['total_tests']} confirmed |
| Risk | {score.breakdown['risk']['score']}% | {score.breakdown['risk']['weight']} | Risk-weighted coverage |

## Coverage Matrix

| Endpoint | {' | '.join(matrix['attack_types'][:10])} |
|----------|{'|'.join(['---'] * min(len(matrix['attack_types']), 10))}|
"""

        for endpoint in matrix["endpoints"][:15]:
            cells = []
            for at in matrix["attack_types"][:10]:
                cell = matrix["matrix"].get(endpoint, {}).get(at, {})
                status = cell.get("status", "not_tested")
                if status == "passed":
                    cells.append("✅")
                elif status == "failed":
                    cells.append("❌")
                elif status == "blocked":
                    cells.append("⚠️")
                else:
                    cells.append("⬜")
            md += f"| {endpoint[:40]} | {' | '.join(cells)} |\n"

        md += f"\n## Gaps ({len(report.gaps)} found)\n\n"
        for gap in report.gaps[:10]:
            severity_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(gap["severity"], "⚪")
            md += f"{severity_emoji} **{gap['severity'].upper()}**: {gap['description']}\n"
            md += f"   - Recommendation: {gap['recommendation']}\n\n"

        md += "\n## Recommendations\n\n"
        for rec in report.recommendations:
            md += f"- {rec}\n"

        md += "\n## Proof\n\n"
        md += f"- Root Hash: `{report.proof['root_hash']}`\n"
        md += f"- Tests Proven: {report.proof['test_proofs_count']}\n"
        md += f"- Merkle Tree Depth: {report.proof['merkle_tree_depth']}\n"

        return md

    def to_csv(self, report: CoverageReport) -> str:
        """Convert report to CSV."""
        matrix = report.matrix
        lines = ["Endpoint,Attack Type,Status,Response Code,Timestamp"]

        for endpoint in matrix["endpoints"]:
            for attack_type in matrix["attack_types"]:
                cell = matrix["matrix"].get(endpoint, {}).get(attack_type, {})
                status = cell.get("status", "not_tested")
                code = cell.get("response_code", "")
                ts = cell.get("timestamp", "")
                lines.append(f"{endpoint},{attack_type},{status},{code},{ts}")

        return "\n".join(lines)
