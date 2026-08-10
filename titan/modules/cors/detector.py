"""CORS misconfiguration detection module for Titan Scanner."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType


class CORSDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        finding = await self._test_cors(context, target, url)
        if finding:
            findings.append(finding)

        return findings

    async def _test_cors(self, context, target: str, url: str) -> Optional[Finding]:
        try:
            test_origins = [
                "https://evil.com",
                "https://attacker.com",
                "null",
                "https://repairai.co.ke",
                "https://repairai.co.ke.evil.com",
            ]
            
            for origin in test_origins:
                try:
                    resp = await context.request.get(url, headers={"Origin": origin, "Referer": target}, timeout=3000)
                    headers = dict(resp.headers)
                    acao = headers.get("access-control-allow-origin", "")
                    acac = headers.get("access-control-allow-credentials", "")
                    acah = headers.get("access-control-allow-headers", "")
                    acam = headers.get("access-control-allow-methods", "")
                    
                    if acao == origin or acao == "*":
                        # Access-Control-Allow-Origin: * WITHOUT credentials is
                        # the OWASP-recommended policy for public resources
                        # (GitHub Pages / Cloudflare set it on every static
                        # site) — NOT a misconfiguration. Only the wildcard+
                        # credentials combo is dangerous; a reflected origin is
                        # always a misconfiguration.
                        if acao == "*" and acac.lower() != "true":
                            continue
                        severity = Severity.CRITICAL if acac.lower() == "true" else Severity.HIGH
                        return Finding(
                            target=target,
                            url=url,
                            method="GET",
                            param="Origin",
                            location="header",
                            payload=f"CORS misconfiguration: Origin={origin}",
                            attack_type=AttackType.INFO_LEAK,
                            severity=severity,
                            verified=True,
                            confidence=0.95,
                            status=resp.status,
                            headers=headers,
                            body="",
                            diffs=["cors:misconfigured", f"acao:{acao}", f"acac:{acac}"],
                            verification_body="",
                            verification_status=resp.status,
                        )
                except Exception:
                    continue
        except Exception:
            pass
        return None
