"""Tests for Phase 8: Reporting upgrade — executive summary, estate rollup, remediation patches."""

import json
import time
from pathlib import Path
from unittest.mock import MagicMock

from titan.core.models import (
    AttackType, Finding, ScanResult, Severity,
)
from titan.reporting import (
    SiteReportWriter, estate_rollup, remediation_rollup,
    generate_remediation, REMEDIATION_MAP, site_slug,
)


def _make_finding(
    severity=Severity.MEDIUM,
    confidence=0.8,
    verified=False,
    url="https://example.com/test",
    param="q",
    payload="test",
    attack_type_value="headers",
):
    """Create a minimal Finding for testing."""
    atk = MagicMock()
    atk.value = attack_type_value
    return Finding(
        target="https://example.com",
        attack_type=atk,
        severity=severity,
        confidence=confidence,
        verified=verified,
        tier="confirmed" if verified else "suspicious",
        method="GET",
        url=url,
        param=param,
        location="query",
        payload=payload,
        status=200,
    )


def _make_result(findings=None, target="https://example.com"):
    """Create a minimal ScanResult for testing."""
    r = ScanResult(target=target, started_at=time.time())
    r.findings = findings or []
    return r


class TestExecutiveSummaryEnhancements:
    """Phase 8a: Top 3 risks, remediation time, estate comparison."""

    def test_top3_risks_in_report(self):
        """Report includes top 3 verified/high-confidence findings."""
        findings = [
            _make_finding(Severity.CRITICAL, 0.95, verified=True),
            _make_finding(Severity.HIGH, 0.9, verified=True),
            _make_finding(Severity.HIGH, 0.85, verified=False),
            _make_finding(Severity.MEDIUM, 0.7),
            _make_finding(Severity.LOW, 0.5),
        ]
        result = _make_result(findings)
        writer = SiteReportWriter(output_dir="/tmp/test_p8")
        md = writer._markdown(result)
        assert "Top risks" in md
        # Should have exactly 3 top risks listed
        lines = [l for l in md.split("\n") if l.strip().startswith(("1.", "2.", "3."))]
        assert len(lines) >= 3

    def test_remediation_time_estimate(self):
        """Report includes estimated remediation time."""
        findings = [
            _make_finding(Severity.CRITICAL, 0.9),
            _make_finding(Severity.HIGH, 0.8),
            _make_finding(Severity.MEDIUM, 0.7),
        ]
        result = _make_result(findings)
        writer = SiteReportWriter(output_dir="/tmp/test_p8")
        md = writer._markdown(result)
        assert "Est. remediation" in md
        assert "h" in md  # Should show hours

    def test_estate_comparison_shows_when_data_exists(self):
        """Report shows estate comparison when sites.json exists."""
        # Create a temporary findings dir with sites.json
        import tempfile, shutil
        tmp = Path(tempfile.mkdtemp())
        try:
            sites = {"sites": [
                {"slug": "a", "target": "https://a.com", "findings": 5},
                {"slug": "b", "target": "https://b.com", "findings": 10},
                {"slug": "c", "target": "https://c.com", "findings": 15},
            ]}
            (tmp / "sites.json").write_text(json.dumps(sites))
            writer = SiteReportWriter(output_dir=str(tmp))
            result = _make_result(
                [_make_finding(Severity.MEDIUM, 0.7)],
                target="https://d.com",
            )
            md = writer._markdown(result)
            assert "Estate comparison" in md
        finally:
            shutil.rmtree(tmp)

    def test_estate_comparison_absent_when_no_index(self):
        """Report omits estate comparison when no sites.json."""
        result = _make_result([_make_finding(Severity.MEDIUM, 0.7)])
        writer = SiteReportWriter(output_dir="/tmp/test_p8_empty")
        md = writer._markdown(result)
        # Estate comparison should NOT appear
        assert "Estate comparison" not in md


class TestEstateRollup:
    """Phase 8b: Cross-site estate report."""

    def test_empty_estate(self):
        """Empty findings dir produces valid report."""
        import tempfile, shutil
        tmp = Path(tempfile.mkdtemp())
        try:
            report = estate_rollup(str(tmp))
            assert "No sites scanned yet" in report
        finally:
            shutil.rmtree(tmp)

    def test_estate_with_sites(self):
        """Estate rollup aggregates findings across sites."""
        import tempfile, shutil
        tmp = Path(tempfile.mkdtemp())
        try:
            # Create sites index
            sites = {"sites": [
                {"slug": "site-a", "target": "https://a.com", "findings": 3,
                 "verified": 1, "critical": 1, "high": 0, "chains": 0},
                {"slug": "site-b", "target": "https://b.com", "findings": 5,
                 "verified": 2, "critical": 0, "high": 2, "chains": 1},
            ]}
            (tmp / "sites.json").write_text(json.dumps(sites))

            # Create findings for site-a
            (tmp / "site-a").mkdir()
            fa = [
                {"attack_type": "sqli", "severity": "critical", "url": "/api", "param": "id",
                 "verified": True, "confidence": 0.9},
                {"attack_type": "headers", "severity": "medium", "url": "/", "param": "Headers",
                 "verified": False, "confidence": 0.8},
                {"attack_type": "cors", "severity": "low", "url": "/", "param": "Origin",
                 "verified": False, "confidence": 0.6},
            ]
            (tmp / "site-a" / "findings.json").write_text(json.dumps(fa))

            # Create findings for site-b
            (tmp / "site-b").mkdir()
            fb = [
                {"attack_type": "sqli", "severity": "high", "url": "/search", "param": "q",
                 "verified": True, "confidence": 0.85},
                {"attack_type": "xss", "severity": "high", "url": "/comment", "param": "text",
                 "verified": True, "confidence": 0.9},
                {"attack_type": "headers", "severity": "medium", "url": "/", "param": "Headers",
                 "verified": False, "confidence": 0.8},
                {"attack_type": "sqli", "severity": "medium", "url": "/login", "param": "user",
                 "verified": False, "confidence": 0.7},
                {"attack_type": "idor", "severity": "low", "url": "/api/user/1", "param": "id",
                 "verified": False, "confidence": 0.5},
            ]
            (tmp / "site-b" / "findings.json").write_text(json.dumps(fb))

            report = estate_rollup(str(tmp))
            assert "2 sites scanned" in report
            assert "Total findings" in report
            assert "sqli" in report.lower()
            assert "Most common attack types" in report
            assert "Per-site summary" in report
        finally:
            shutil.rmtree(tmp)

    def test_cross_site_patterns(self):
        """Patterns appearing on 3+ sites are highlighted."""
        import tempfile, shutil
        tmp = Path(tempfile.mkdtemp())
        try:
            sites = {"sites": [
                {"slug": f"site-{i}", "target": f"https://{i}.com", "findings": 1}
                for i in range(4)
            ]}
            (tmp / "sites.json").write_text(json.dumps(sites))

            # All 4 sites have headers findings
            for i in range(4):
                d = tmp / f"site-{i}"
                d.mkdir()
                (d / "findings.json").write_text(json.dumps([
                    {"attack_type": "headers", "severity": "medium", "url": "/",
                     "param": "Headers", "verified": False, "confidence": 0.8},
                ]))

            report = estate_rollup(str(tmp))
            assert "Cross-site patterns" in report
            assert "headers" in report
        finally:
            shutil.rmtree(tmp)


class TestRemediationPatches:
    """Phase 8c: Auto-generated remediation patches."""

    def test_remediation_map_covers_common_types(self):
        """REMEDIATION_MAP covers the most common finding types."""
        common = ["headers", "cors", "sqli", "xss", "ssrf", "lfi", "ssti", "idor"]
        for atk in common:
            assert atk in REMEDIATION_MAP, f"Missing remediation for {atk}"
            assert "title" in REMEDIATION_MAP[atk]
            assert "fix" in REMEDIATION_MAP[atk]

    def test_generate_remediation_for_known_type(self):
        """generate_remediation returns a patch for known finding types."""
        f = MagicMock()
        f.attack_type = MagicMock()
        f.attack_type.value = "sqli"
        f.url = "https://example.com/api"
        f.param = "id"
        patch = generate_remediation(f)
        assert "SQL Injection" in patch
        assert "parameterized" in patch.lower() or "prepared" in patch.lower()

    def test_generate_remediation_for_unknown_type(self):
        """generate_remediation returns a fallback for unknown types."""
        f = MagicMock()
        f.attack_type = MagicMock()
        f.attack_type.value = "obscure_vuln"
        f.url = "https://example.com"
        f.param = "x"
        patch = generate_remediation(f)
        assert "No automated patch" in patch

    def test_remediation_rollup_empty(self):
        """Empty estate produces valid remediation report."""
        import tempfile, shutil
        tmp = Path(tempfile.mkdtemp())
        try:
            report = remediation_rollup(str(tmp))
            assert "No sites scanned yet" in report
        finally:
            shutil.rmtree(tmp)

    def test_remediation_rollup_with_findings(self):
        """Remediation rollup groups patches by frequency."""
        import tempfile, shutil
        tmp = Path(tempfile.mkdtemp())
        try:
            sites = {"sites": [
                {"slug": "site-a", "target": "https://a.com", "findings": 3},
                {"slug": "site-b", "target": "https://b.com", "findings": 2},
            ]}
            (tmp / "sites.json").write_text(json.dumps(sites))

            # site-a has headers + sqli
            (tmp / "site-a").mkdir()
            (tmp / "site-a" / "findings.json").write_text(json.dumps([
                {"attack_type": "headers", "severity": "medium", "url": "/",
                 "param": "Headers", "verified": False, "confidence": 0.8},
                {"attack_type": "sqli", "severity": "high", "url": "/api",
                 "param": "id", "verified": True, "confidence": 0.9},
                {"attack_type": "sqli", "severity": "medium", "url": "/search",
                 "param": "q", "verified": False, "confidence": 0.7},
            ]))

            # site-b has headers
            (tmp / "site-b").mkdir()
            (tmp / "site-b" / "findings.json").write_text(json.dumps([
                {"attack_type": "headers", "severity": "medium", "url": "/",
                 "param": "Headers", "verified": False, "confidence": 0.8},
                {"attack_type": "xss", "severity": "low", "url": "/comment",
                 "param": "text", "verified": False, "confidence": 0.5},
            ]))

            report = remediation_rollup(str(tmp))
            assert "Priority remediation" in report
            # headers appears 2x → should be in priority
            assert "headers" in report.lower()
            assert "Missing Security Headers" in report
        finally:
            shutil.rmtree(tmp)


class TestExecutiveSummaryEdgeCases:
    """Edge cases for the enhanced executive summary."""

    def test_no_findings(self):
        """Empty findings list produces valid summary."""
        result = _make_result([])
        writer = SiteReportWriter(output_dir="/tmp/test_p8_edge")
        md = writer._markdown(result)
        assert "No findings recorded" in md
        assert "Risk posture" in md

    def test_only_suspicious_findings(self):
        """All unverified findings → no top risks listed."""
        findings = [
            _make_finding(Severity.MEDIUM, 0.5, verified=False),
            _make_finding(Severity.LOW, 0.4, verified=False),
        ]
        result = _make_result(findings)
        writer = SiteReportWriter(output_dir="/tmp/test_p8_edge")
        md = writer._markdown(result)
        assert "Risk posture" in md

    def test_remediation_time_zero(self):
        """No findings → ~0m remediation."""
        result = _make_result([])
        writer = SiteReportWriter(output_dir="/tmp/test_p8_edge")
        md = writer._markdown(result)
        assert "Est. remediation" in md
