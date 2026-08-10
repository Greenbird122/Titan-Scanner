"""Tests for PoC generator."""

import pytest
from titan.core.models import Finding, Severity, AttackType
from titan.core.poc import PoCGenerator


class TestPoCGenerator:
    def test_generates_curl_and_python(self):
        finding = Finding(
            target="https://example.com",
            url="https://example.com/api/search",
            method="GET",
            param="q",
            location="query",
            payload="test",
            attack_type=AttackType.SQLI,
            severity=Severity.HIGH,
            verified=True,
            confidence=0.9,
            headers={"Content-Type": "application/json"},
        )
        poc = PoCGenerator.generate(finding)
        assert "curl" in poc["curl"].lower()
        assert "requests" in poc["python"]
        assert "example.com" in poc["curl"]
        assert "example.com" in poc["python"]

    def test_post_payload_in_body(self):
        finding = Finding(
            target="https://example.com",
            url="https://example.com/api/login",
            method="POST",
            param="username",
            location="body",
            payload="admin' OR 1=1--",
            attack_type=AttackType.SQLI,
            severity=Severity.CRITICAL,
            verified=True,
            confidence=0.95,
        )
        poc = PoCGenerator.generate(finding)
        assert "-d" in poc["curl"]
        assert "data" in poc["python"]
