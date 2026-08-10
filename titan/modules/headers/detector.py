"""Security header analysis module for Titan Scanner."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType


class HeadersDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        finding = await self._analyze_headers(context, target, url)
        if finding:
            findings.append(finding)

        return findings

    async def _analyze_headers(self, context, target: str, url: str) -> Optional[Finding]:
        try:
            resp = await context.request.get(url, timeout=3000)
            headers = dict(resp.headers)
            
            missing = []
            weak = []
            
            if "x-frame-options" not in headers:
                missing.append("X-Frame-Options")
            elif headers.get("x-frame-options", "").upper() not in ("DENY", "SAMEORIGIN"):
                weak.append("X-Frame-Options")
            
            if "x-content-type-options" not in headers:
                missing.append("X-Content-Type-Options")
            elif headers.get("x-content-type-options", "").lower() != "nosniff":
                weak.append("X-Content-Type-Options")
            
            if "strict-transport-security" not in headers:
                missing.append("Strict-Transport-Security")
            
            if "content-security-policy" not in headers:
                missing.append("Content-Security-Policy")
            else:
                csp = headers.get("content-security-policy", "")
                if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                    weak.append("Content-Security-Policy")
            
            if "x-xss-protection" not in headers:
                missing.append("X-XSS-Protection")
            
            if "referrer-policy" not in headers:
                missing.append("Referrer-Policy")
            
            if "permissions-policy" not in headers:
                missing.append("Permissions-Policy")
            
            if missing or weak:
                severity = Severity.MEDIUM if missing else Severity.LOW
                return Finding(
                    target=target,
                    url=url,
                    method="GET",
                    param="Headers",
                    location="header",
                    payload=f"Missing: {', '.join(missing)}; Weak: {', '.join(weak)}",
                    attack_type=AttackType.INFO_LEAK,
                    severity=severity,
                    verified=True,
                    confidence=0.9,
                    status=resp.status,
                    headers=headers,
                    body="",
                    diffs=["headers:missing"] + [f"missing:{h}" for h in missing] + [f"weak:{h}" for h in weak],
                    verification_body="",
                    verification_status=resp.status,
                )
        except Exception:
            pass
        return None
