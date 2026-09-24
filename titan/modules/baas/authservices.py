"""Auth Services Deep Testing — deep testing of Auth0, Clerk, Firebase Auth, and generic OAuth.

This module tests:
1. Auth0: Tenant enumeration, OIDC discovery, management API, attack surface
2. Clerk: Session hijacking, JWT manipulation, webhook abuse
3. Generic OAuth: Redirect URI manipulation, state parameter, token exchange
4. Session management: Fixation, rotation, invalidation
5. Token abuse: Replay, confusion, injection
6. MFA bypass: Downgrade, recovery code abuse

Payload catalogs live in ``titan/modules/baas/auth_payloads.py`` (pure data);
this module owns the request/verdict logic that consumes them.
"""

from __future__ import annotations

import json
from typing import Any

from titan.core.logger import get_logger
from titan.core.models import AttackType, Finding
from titan.modules.baas.auth_payloads import (
    AUTH0_PAYLOADS,
    CLERK_PAYLOADS,
    MFA_BYPASS_PAYLOADS,
    OAUTH_ABUSE_PAYLOADS,
    SESSION_MANAGEMENT_PAYLOADS,
    AuthPayload,
)

__all__ = ["AuthServicesTester", "AuthPayload"]

logger = get_logger("authservices")


class AuthServicesTester:
    """Deep Auth Services testing."""

    # ── Payload tables (extracted to auth_payloads.py, re-exported for
    #    backward compatibility with code that referenced them from here) ──

    AUTH0_PAYLOADS = AUTH0_PAYLOADS
    CLERK_PAYLOADS = CLERK_PAYLOADS
    OAUTH_ABUSE_PAYLOADS = OAUTH_ABUSE_PAYLOADS
    SESSION_MANAGEMENT_PAYLOADS = SESSION_MANAGEMENT_PAYLOADS
    MFA_BYPASS_PAYLOADS = MFA_BYPASS_PAYLOADS

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: list[Finding] = []

    async def test_auth0(
        self,
        target_url: str,
        auth0_domain: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test Auth0 configuration."""
        findings = []

        for payload in self.AUTH0_PAYLOADS:
            try:
                url = f"https://{auth0_domain}{payload.endpoint}"
                if payload.headers:
                    url = url.replace("{domain}", auth0_domain)

                response = await self._send_request(url, payload.method, payload.payload, auth_headers)

                if response and self._check_auth_response(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=url,
                        method=payload.method,
                        param=payload.name,
                        location="auth0",
                        payload=json.dumps(payload.payload) if payload.payload else "",
                        attack_type=AttackType.INFO_LEAK if "enum" in payload.category else AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        evidence=response.get("body", "")[:500],
                        tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                        tags=["baas", "auth0", payload.category, payload.name],
                        notes=f"Auth0: {payload.name}",
                    )
                    findings.append(finding)

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        self._findings.extend(findings)
        return findings

    async def test_clerk(
        self,
        target_url: str,
        clerk_domain: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test Clerk configuration."""
        findings = []

        for payload in self.CLERK_PAYLOADS:
            try:
                url = f"https://{clerk_domain}{payload.endpoint}"

                response = await self._send_request(url, payload.method, payload.payload, auth_headers)

                if response and self._check_auth_response(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=url,
                        method=payload.method,
                        param=payload.name,
                        location="clerk",
                        payload=json.dumps(payload.payload) if payload.payload else "",
                        attack_type=AttackType.INFO_LEAK if "enum" in payload.category else AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        evidence=response.get("body", "")[:500],
                        tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                        tags=["baas", "clerk", payload.category, payload.name],
                        notes=f"Clerk: {payload.name}",
                    )
                    findings.append(finding)

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        self._findings.extend(findings)
        return findings

    async def test_oauth(
        self,
        target_url: str,
        auth_endpoint: str,
        token_endpoint: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test OAuth flow abuse."""
        findings = []

        for payload in self.OAUTH_ABUSE_PAYLOADS:
            try:
                if "authorize" in payload.endpoint:
                    url = auth_endpoint
                elif "token" in payload.endpoint:
                    url = token_endpoint
                else:
                    url = f"{target_url}{payload.endpoint}"

                response = await self._send_request(url, payload.method, payload.payload, auth_headers)

                if response and self._check_auth_response(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=url,
                        method=payload.method,
                        param=payload.name,
                        location="oauth",
                        payload=json.dumps(payload.payload) if payload.payload else "",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        evidence=response.get("body", "")[:500],
                        tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                        tags=["auth", "oauth", payload.name],
                        notes=f"OAuth abuse: {payload.name}",
                    )
                    findings.append(finding)

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        self._findings.extend(findings)
        return findings

    async def test_mfa_bypass(
        self,
        target_url: str,
        auth_endpoint: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test MFA bypass."""
        findings = []

        for payload in self.MFA_BYPASS_PAYLOADS:
            try:
                url = f"{target_url}{payload.endpoint}"

                response = await self._send_request(url, payload.method, payload.payload, auth_headers)

                if response and self._check_auth_response(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=url,
                        method=payload.method,
                        param=payload.name,
                        location="mfa",
                        payload=json.dumps(payload.payload) if payload.payload else "",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        evidence=response.get("body", "")[:500],
                        tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                        tags=["auth", "mfa", payload.name],
                        notes=f"MFA bypass: {payload.name}",
                    )
                    findings.append(finding)

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        self._findings.extend(findings)
        return findings

    # ── Helpers ────────────────────────────────────────────────────────

    async def _send_request(
        self,
        url: str,
        method: str,
        payload: Any,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """Send HTTP request."""
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                req_headers = headers or {}
                req_headers.setdefault("Content-Type", "application/json")
                req_headers.setdefault("Accept", "application/json")

                if method.upper() == "GET":
                    async with session.get(url, headers=req_headers, params=payload) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "POST":
                    async with session.post(url, json=payload, headers=req_headers) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
        except Exception:
            return None

    def _check_auth_response(self, response: dict[str, Any], payload: AuthPayload) -> bool:
        """Check if auth endpoint responded with useful data."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status == 200:
            if body and body not in ("null", ""):
                # Check for meaningful data
                if any(
                    kw in body.lower()
                    for kw in [
                        "email",
                        "user",
                        "session",
                        "token",
                        "role",
                        "admin",
                        "oidc",
                        "jwks",
                        "issuer",
                        "authorization_endpoint",
                        "refresh_token",
                        "access_token",
                        "id_token",
                    ]
                ):
                    return True
                # Check for JSON with data
                try:
                    data = json.loads(body)
                    if isinstance(data, (dict, list)) and len(str(data)) > 50:
                        return True
                except json.JSONDecodeError as exc:
                    logger.debug(f"suppressed exception: {exc}")
                    pass

        elif status == 401:
            # Check for useful error info
            if any(kw in body.lower() for kw in ["invalid_client", "invalid_grant", "unauthorized"]):
                return True

        return False

    def get_findings(self) -> list[Finding]:
        """Get all findings."""
        return self._findings
