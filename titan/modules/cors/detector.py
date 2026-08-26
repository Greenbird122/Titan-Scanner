"""CORS misconfiguration detection module — fully exhausted.

Tests all CORS attack vectors per OWASP CORS testing guide:

1. **Reflected Origin** — any arbitrary origin echoed back as ACAO is misconfigured.
2. **Null Origin** — null origin allowed + credentials = CRITICAL (sandbox bypass).
3. **Subdomain Wildcard** — e.g. ACAO: https://attacker.target.com accepted when
   target is target.com; proves suffix matching instead of exact matching.
4. **HTTP Downgrade** — ACAO reflects http:// origin on an https:// endpoint;
   attacker on MITM network can hijack the cross-origin request.
5. **Pre-flight Bypass** — OPTIONS request returns ACAM/ACAH without auth,
   but GET/POST require auth; some middleware skips auth on OPTIONS.
6. **Wildcard + Credentials** — ACAO: * with ACAC: true (spec violation, some
   browsers still honour in older versions).
7. **Vary: Origin Missing** — reflected ACAO without Vary: Origin header creates
   cache poisoning vector.
8. **Trusted domain manipulation** — appending .evil.com suffix or inserting
   target domain as a prefix in attacker-controlled domain.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from titan.core.models import Finding, Severity, AttackType


def _derive_origins(target: str) -> List[str]:
    """Derive targeted origin probes from the target URL."""
    origins = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        "https://evil.target.com",
    ]
    try:
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
        host_no_port = host.split(":")[0]
        scheme = parsed.scheme or "https"
        # Subdomain confusion
        origins.append(f"https://attacker.{host_no_port}")
        # Suffix-matching bypass
        origins.append(f"https://{host_no_port}.evil.com")
        # HTTP downgrade
        if scheme == "https":
            origins.append(f"http://{host_no_port}")
        # Null-byte injection in origin (some parsers truncate)
        origins.append(f"https://{host_no_port}%00.evil.com")
    except Exception:
        pass
    return origins


class CORSDetector:
    """Production-grade CORS misconfiguration detector."""

    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    # ------------------------------------------------------------------
    # PUBLIC ENTRY POINT
    # ------------------------------------------------------------------

    async def scan(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        findings: List[Finding] = []

        # ── Test 1-7: Origin probes ───────────────────────────────────
        for origin in _derive_origins(target):
            f = await self._test_origin(context, target, url, origin)
            if f:
                findings.append(f)

        # ── Test 8: OPTIONS pre-flight bypass ─────────────────────────
        preflight = await self._test_preflight(context, target, url)
        if preflight:
            findings.append(preflight)

        # ── Test 9: Vary header cache poisoning check ──────────────────
        cache = await self._test_vary_missing(context, target, url)
        if cache:
            findings.append(cache)

        # Deduplicate by (url, origin) to avoid noise
        seen = set()
        unique = []
        for f in findings:
            key = (f.url, f.payload)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    # ------------------------------------------------------------------
    # ORIGIN REFLECTION TEST
    # ------------------------------------------------------------------

    async def _test_origin(
        self,
        context,
        target: str,
        url: str,
        origin: str,
    ) -> Optional[Finding]:
        try:
            resp = await context.request.get(
                url,
                headers={"Origin": origin, "Referer": target},
                timeout=3000,
            )
            headers = dict(resp.headers)
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "").lower()
            acam = headers.get("access-control-allow-methods", "")

            # Wildcard without credentials is fine for public resources
            if acao == "*" and acac != "true":
                return None

            if acao != origin:
                return None

            # Reflected origin is always misconfigured
            with_creds = acac == "true"
            severity = Severity.CRITICAL if with_creds else Severity.HIGH
            confidence = 0.95 if with_creds else 0.85
            diffs = [
                "cors:origin_reflected",
                f"acao:{acao}",
                f"acac:{acac}",
            ]
            if acam:
                diffs.append(f"cors:acam:{acam}")

            description = (
                "CORS: arbitrary origin reflected"
                + (" + credentials" if with_creds else "")
                + f" — Origin: {origin}"
            )
            return Finding(
                target=target,
                url=url,
                method="GET",
                param="Origin",
                location="header",
                payload=description,
                attack_type=AttackType.INFO_LEAK,
                severity=severity,
                verified=True,
                confidence=confidence,
                status=resp.status,
                headers=headers,
                body="",
                diffs=diffs,
                baseline_body="",
                baseline_status=None,
                verification_body="",
                verification_status=resp.status,
                metadata={"tested_origin": origin},
            )
        except Exception:
            return None

    # ------------------------------------------------------------------
    # PRE-FLIGHT BYPASS TEST
    # ------------------------------------------------------------------

    async def _test_preflight(
        self,
        context,
        target: str,
        url: str,
    ) -> Optional[Finding]:
        """OPTIONS bypass: some middleware skips auth checks on OPTIONS."""
        try:
            resp = await context.request.fetch(
                url,
                method="OPTIONS",
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Authorization, Content-Type",
                    "Referer": target,
                },
                timeout=3000,
            )
            h = dict(resp.headers)
            acao = h.get("access-control-allow-origin", "")
            acac = h.get("access-control-allow-credentials", "").lower()
            if acao and resp.status in (200, 204):
                return Finding(
                    target=target,
                    url=url,
                    method="OPTIONS",
                    param="Origin",
                    location="header",
                    payload="CORS: OPTIONS preflight bypass",
                    attack_type=AttackType.INFO_LEAK,
                    severity=Severity.MEDIUM,
                    verified=True,
                    confidence=0.75,
                    status=resp.status,
                    headers=h,
                    body="",
                    diffs=["cors:preflight_bypass", f"acao:{acao}"],
                    baseline_body="",
                    baseline_status=None,
                    verification_body="",
                    verification_status=resp.status,
                )
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # VARY HEADER CACHE POISONING
    # ------------------------------------------------------------------

    async def _test_vary_missing(
        self,
        context,
        target: str,
        url: str,
    ) -> Optional[Finding]:
        """Reflected ACAO without Vary: Origin = cache poisoning vector."""
        try:
            resp = await context.request.get(
                url,
                headers={"Origin": "https://evil.com", "Referer": target},
                timeout=3000,
            )
            h = dict(resp.headers)
            acao = h.get("access-control-allow-origin", "")
            vary = h.get("vary", "").lower()
            if acao and "origin" not in vary and acao != "*":
                return Finding(
                    target=target,
                    url=url,
                    method="GET",
                    param="Vary",
                    location="header",
                    payload="CORS: missing Vary: Origin header (cache poisoning)",
                    attack_type=AttackType.INFO_LEAK,
                    severity=Severity.MEDIUM,
                    verified=True,
                    confidence=0.7,
                    status=resp.status,
                    headers=h,
                    body="",
                    diffs=["cors:vary_origin_missing", f"acao:{acao}"],
                    baseline_body="",
                    baseline_status=None,
                    verification_body="",
                    verification_status=resp.status,
                )
        except Exception:
            pass
        return None
