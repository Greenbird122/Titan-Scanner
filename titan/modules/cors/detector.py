"""CORS Deep Module — beyond wildcard testing.

A real attacker doesn't just test for wildcard CORS.
They test for misconfigured CORS that enables data theft.

This module:
1. Origin reflection testing
2. Null origin bypass
3. Subdomain matching
4. Protocol downgrade
5. Special characters in origin
6. Pre-flight abuse
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType


@dataclass
class CORSPayload:
    """A CORS test payload."""
    name: str
    origin: str
    expected_effect: str
    severity: Severity
    confidence: float


class CORSTester:
    """Deep CORS testing."""

    BYPASS_PAYLOADS = [
        CORSPayload(
            name="origin_reflection",
            origin="https://evil.com",
            expected_effect="origin_reflected",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        CORSPayload(
            name="null_origin",
            origin="null",
            expected_effect="null_accepted",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        CORSPayload(
            name="subdomain_match",
            origin="https://evil.target.com",
            expected_effect="subdomain_accepted",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        CORSPayload(
            name="protocol_downgrade",
            origin="http://target.com",
            expected_effect="http_accepted",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        CORSPayload(
            name="special_chars",
            origin="https://target.com.evil.com",
            expected_effect="special_accepted",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        CORSPayload(
            name="underscore_bypass",
            origin="https://target_com.evil.com",
            expected_effect="underscore_accepted",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        CORSPayload(
            name="dash_bypass",
            origin="https://target-com.evil.com",
            expected_effect="dash_accepted",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        CORSPayload(
            name="port_bypass",
            origin="https://target.com:443",
            expected_effect="port_accepted",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        CORSPayload(
            name="prefix_match",
            origin="https://target.com.attacker.com",
            expected_effect="prefix_accepted",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        CORSPayload(
            name="suffix_match",
            origin="https://notarget.com",
            expected_effect="suffix_accepted",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: List[Finding] = []

    async def test_cors(
        self,
        target_url: str,
        url: str,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test CORS configuration."""
        findings = []

        # First check if CORS is enabled at all
        baseline = await self._send_cors_request(url, "https://legitimate.com", auth_headers)
        if not baseline:
            return findings

        acao = baseline.get("headers", {}).get("access-control-allow-origin", "")
        if not acao:
            return findings

        # Check for wildcard
        if acao == "*":
            finding = Finding(
                target=target_url,
                url=url,
                method="OPTIONS",
                param="cors_wildcard",
                location="header",
                payload="Origin: *",
                attack_type=AttackType.INFO_LEAK,
                severity=Severity.MEDIUM,
                verified=True,
                confidence=0.95,
                status=baseline.get("status", 0),
                body=f"Access-Control-Allow-Origin: {acao}",
                diffs=["cors:wildcard"],
                notes="CORS allows all origins (wildcard)",
            )
            findings.append(finding)

        # Test bypasses
        for payload in self.BYPASS_PAYLOADS:
            try:
                response = await self._send_cors_request(url, payload.origin, auth_headers)
                if not response:
                    continue

                resp_acao = response.get("headers", {}).get("access-control-allow-origin", "")
                resp_acac = response.get("headers", {}).get("access-control-allow-credentials", "")

                if resp_acao == payload.origin:
                    severity = Severity.CRITICAL if resp_acac == "true" else payload.severity
                    confidence = payload.confidence + 0.1 if resp_acac == "true" else payload.confidence

                    finding = Finding(
                        target=target_url,
                        url=url,
                        method="OPTIONS",
                        param="cors_bypass",
                        location="header",
                        payload=f"Origin: {payload.origin}",
                        attack_type=AttackType.INFO_LEAK,
                        severity=severity,
                        verified=True,
                        confidence=confidence,
                        status=response.get("status", 0),
                        body=f"ACAO: {resp_acao}, ACAC: {resp_acac}",
                        diffs=[f"cors:{payload.name}"],
                        notes=f"CORS bypass: {payload.name} — Origin reflected with credentials={resp_acac}",
                    )
                    findings.append(finding)

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def _send_cors_request(
        self,
        url: str,
        origin: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        try:
            import aiohttp
            h = {**(headers or {}), "Origin": origin}
            async with aiohttp.ClientSession() as session:
                async with session.options(url, headers=h, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
        except Exception:
            return None

    def get_findings(self) -> List[Finding]:
        return self._findings
