"""Tests for CVSS scoring engine."""

import pytest
from titan.core.models import Finding, Severity, AttackType
from titan.core.cvss import CVSSScorer


class TestCVSSScorer:
    def test_critical_rce_scores_high(self):
        finding = Finding(
            target="https://example.com",
            url="https://example.com/api",
            method="POST",
            param="cmd",
            location="body",
            payload=";id",
            attack_type=AttackType.RCE,
            severity=Severity.CRITICAL,
            verified=True,
            confidence=0.95,
        )
        result = CVSSScorer.score(finding)
        assert result["cvss_score"] >= 9.0

    def test_unverified_info_leak_scores_low(self):
        finding = Finding(
            target="https://example.com",
            url="https://example.com/",
            method="GET",
            param="Headers",
            location="header",
            payload="Missing HSTS",
            attack_type=AttackType.INFO_LEAK,
            severity=Severity.MEDIUM,
            verified=False,
            confidence=0.5,
        )
        result = CVSSScorer.score(finding)
        assert result["cvss_score"] < 7.0

    def test_cvss_vector_format(self):
        finding = Finding(
            target="https://example.com",
            url="https://example.com/api",
            method="POST",
            param="data",
            location="body",
            payload="test",
            attack_type=AttackType.SQLI,
            severity=Severity.HIGH,
            verified=True,
            confidence=0.9,
        )
        result = CVSSScorer.score(finding)
        assert result["cvss_vector"].startswith("CVSS:3.1/")

    def test_severity_from_cvss(self):
        assert CVSSScorer.get_severity_from_cvss(10.0) == Severity.CRITICAL
        assert CVSSScorer.get_severity_from_cvss(7.5) == Severity.HIGH
        assert CVSSScorer.get_severity_from_cvss(5.0) == Severity.MEDIUM
        assert CVSSScorer.get_severity_from_cvss(0.0) == Severity.UNCONFIRMED
