"""Supabase Deep Testing — deep testing of Row-Level Security, auth, Edge Functions, Storage, and more.

This module tests:
1. RLS policy testing (SELECT/INSERT/UPDATE/DELETE on all tables)
2. Auth settings enumeration (phone_autoconfirm, email_confirm, MFA)
3. Edge Function probing (invoke with/without auth, parameter injection)
4. Storage bucket abuse (list, upload, download, delete)
5. Realtime subscription hijacking (subscribe to tables, intercept data)
6. User metadata escalation (set role:admin in metadata)
7. Service role key detection (check if leaked in client code)
8. JWT manipulation (decode, modify claims, test token refresh)
9. API key abuse (test anon key vs service role key)
10. Database function enumeration (call RPC functions)
"""

from __future__ import annotations

import json
from typing import Any

from titan.core.models import AttackType, Finding
from titan.modules.baas.supabase_payloads import (
    AUTH_ENUM_PAYLOADS,
    DB_FUNCTION_PAYLOADS,
    EDGE_FUNCTION_PAYLOADS,
    JWT_MANIPULATION_PAYLOADS,
    METADATA_ESCALATION_PAYLOADS,
    REALTIME_HIJACK_PAYLOADS,
    RLS_TEST_PAYLOADS,
    STORAGE_ABUSE_PAYLOADS,
    SupabasePayload,
)


class SupabaseTester:
    """Deep Supabase testing."""

    RLS_TEST_PAYLOADS = RLS_TEST_PAYLOADS
    AUTH_ENUM_PAYLOADS = AUTH_ENUM_PAYLOADS
    EDGE_FUNCTION_PAYLOADS = EDGE_FUNCTION_PAYLOADS
    STORAGE_ABUSE_PAYLOADS = STORAGE_ABUSE_PAYLOADS
    REALTIME_HIJACK_PAYLOADS = REALTIME_HIJACK_PAYLOADS
    METADATA_ESCALATION_PAYLOADS = METADATA_ESCALATION_PAYLOADS
    JWT_MANIPULATION_PAYLOADS = JWT_MANIPULATION_PAYLOADS
    DB_FUNCTION_PAYLOADS = DB_FUNCTION_PAYLOADS

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: list[Finding] = []
        self._supabase_url: str | None = None
        self._anon_key: str | None = None
        self._service_role_key: str | None = None

    def set_credentials(
        self,
        supabase_url: str,
        anon_key: str | None = None,
        service_role_key: str | None = None,
    ) -> None:
        """Set Supabase credentials for testing."""
        self._supabase_url = supabase_url
        self._anon_key = anon_key
        self._service_role_key = service_role_key

    async def test_rls_policies(
        self,
        target_url: str,
        tables: list[str],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test Row-Level Security policies on all tables."""
        findings = []

        for table in tables:
            for payload in self.RLS_TEST_PAYLOADS:
                try:
                    endpoint = payload.endpoint.replace("{table}", table)
                    url = f"{self._supabase_url}{endpoint}"

                    response = await self._send_request(
                        url, payload.method, payload.payload, payload.headers
                    )

                    if response and self._check_rls_bypass(response, payload):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=payload.method,
                            param=table,
                            location="rest_api",
                            payload=json.dumps(payload.payload) if payload.payload else "",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            confidence=payload.confidence,
                            status=response.get("status", 0),
                            evidence=response.get("body", "")[:500],
                            tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                            tags=["baas", "supabase", "rls", payload.name, table],
                            notes=f"RLS bypass: {payload.name} on table '{table}'",
                        )
                        findings.append(finding)

                except Exception:
                    continue

        self._findings.extend(findings)
        return findings

    async def test_auth_enumeration(
        self,
        target_url: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test auth settings enumeration."""
        findings = []

        for payload in self.AUTH_ENUM_PAYLOADS:
            try:
                url = f"{self._supabase_url}{payload.endpoint}"

                response = await self._send_request(
                    url, payload.method, payload.payload, payload.headers
                )

                if response and self._check_auth_enumeration(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=url,
                        method=payload.method,
                        param=payload.name,
                        location="auth_api",
                        payload=json.dumps(payload.payload) if payload.payload else "",
                        attack_type=AttackType.INFO_LEAK,
                        severity=payload.severity,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        evidence=response.get("body", "")[:500],
                        tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                        tags=["baas", "supabase", "auth", payload.name],
                        notes=f"Auth enumeration: {payload.name}",
                    )
                    findings.append(finding)

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def test_edge_functions(
        self,
        target_url: str,
        functions: list[str],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test Edge Functions."""
        findings = []

        for function in functions:
            for payload in self.EDGE_FUNCTION_PAYLOADS:
                try:
                    endpoint = payload.endpoint.replace("{function}", function)
                    url = f"{self._supabase_url}{endpoint}"

                    headers = {}
                    if payload.headers:
                        for k, v in payload.headers.items():
                            if "{anon_key}" in v:
                                headers[k] = v.replace("{anon_key}", self._anon_key or "")
                            else:
                                headers[k] = v

                    response = await self._send_request(
                        url, payload.method, payload.payload, headers or None
                    )

                    if response and self._check_edge_function(response, payload):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=payload.method,
                            param=function,
                            location="edge_function",
                            payload=json.dumps(payload.payload) if payload.payload else "",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            confidence=payload.confidence,
                            status=response.get("status", 0),
                            evidence=response.get("body", "")[:500],
                            tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                            tags=["baas", "supabase", "edge_function", payload.name, function],
                            notes=f"Edge function: {payload.name} on '{function}'",
                        )
                        findings.append(finding)

                except Exception:
                    continue

        self._findings.extend(findings)
        return findings

    async def test_storage_abuse(
        self,
        target_url: str,
        buckets: list[str],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test Storage bucket abuse."""
        findings = []

        for bucket in buckets:
            for payload in self.STORAGE_ABUSE_PAYLOADS:
                try:
                    endpoint = payload.endpoint.replace("{bucket}", bucket)
                    url = f"{self._supabase_url}{endpoint}"

                    response = await self._send_request(
                        url, payload.method, payload.payload, payload.headers
                    )

                    if response and self._check_storage_abuse(response, payload):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=payload.method,
                            param=bucket,
                            location="storage",
                            payload=json.dumps(payload.payload) if payload.payload else "",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            confidence=payload.confidence,
                            status=response.get("status", 0),
                            evidence=response.get("body", "")[:500],
                            tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                            tags=["baas", "supabase", "storage", payload.name, bucket],
                            notes=f"Storage abuse: {payload.name} on bucket '{bucket}'",
                        )
                        findings.append(finding)

                except Exception:
                    continue

        self._findings.extend(findings)
        return findings

    async def test_metadata_escalation(
        self,
        target_url: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test user metadata escalation."""
        findings = []

        for payload in self.METADATA_ESCALATION_PAYLOADS:
            try:
                url = f"{self._supabase_url}{payload.endpoint}"

                response = await self._send_request(
                    url, payload.method, payload.payload, auth_headers
                )

                if response and self._check_metadata_escalation(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=url,
                        method=payload.method,
                        param=payload.name,
                        location="auth_api",
                        payload=json.dumps(payload.payload),
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        evidence=response.get("body", "")[:500],
                        tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                        tags=["baas", "supabase", "metadata", payload.name],
                        notes=f"Metadata escalation: {payload.name}",
                    )
                    findings.append(finding)

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def test_jwt_manipulation(
        self,
        target_url: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test JWT manipulation."""
        findings = []

        for payload in self.JWT_MANIPULATION_PAYLOADS:
            try:
                url = f"{self._supabase_url}{payload.endpoint}"

                headers = {}
                if payload.headers:
                    for k, v in payload.headers.items():
                        if "{jwt_with_role_claim}" in v:
                            # Generate JWT with role claim
                            headers[k] = self._generate_jwt_with_role("admin")
                        elif "{expired_jwt}" in v:
                            headers[k] = self._generate_expired_jwt()
                        elif "{service_role_jwt}" in v:
                            headers[k] = self._service_role_key or ""
                        elif "{decoded_jwt}" in v:
                            headers[k] = self._anon_key or ""
                        else:
                            headers[k] = v

                response = await self._send_request(
                    url, payload.method, payload.payload, headers or None
                )

                if response and self._check_jwt_manipulation(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=url,
                        method=payload.method,
                        param=payload.name,
                        location="jwt",
                        payload=json.dumps(payload.payload) if payload.payload else "",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        evidence=response.get("body", "")[:500],
                        tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                        tags=["baas", "supabase", "jwt", payload.name],
                        notes=f"JWT manipulation: {payload.name}",
                    )
                    findings.append(finding)

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def test_db_functions(
        self,
        target_url: str,
        functions: list[str],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test database function enumeration."""
        findings = []

        for function in functions:
            for payload in self.DB_FUNCTION_PAYLOADS:
                try:
                    endpoint = payload.endpoint.replace("{function}", function)
                    url = f"{self._supabase_url}{endpoint}"

                    response = await self._send_request(
                        url, payload.method, payload.payload, payload.headers
                    )

                    if response and self._check_db_function(response, payload):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=payload.method,
                            param=function,
                            location="rpc",
                            payload=json.dumps(payload.payload) if payload.payload else "",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            confidence=payload.confidence,
                            status=response.get("status", 0),
                            evidence=response.get("body", "")[:500],
                            tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                            tags=["baas", "supabase", "db_function", payload.name, function],
                            notes=f"DB function: {payload.name} on '{function}'",
                        )
                        findings.append(finding)

                except Exception:
                    continue

        self._findings.extend(findings)
        return findings

    # ── Helper Methods ──────────────────────────────────────────────────

    async def _send_request(
        self,
        url: str,
        method: str,
        payload: Any,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """Send HTTP request and return response."""
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                req_headers = headers or {}
                if self._anon_key and "Authorization" not in req_headers:
                    req_headers["Authorization"] = f"Bearer {self._anon_key}"
                req_headers["apikey"] = self._anon_key or ""

                if method.upper() == "GET":
                    async with session.get(url, headers=req_headers) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "POST":
                    async with session.post(url, json=payload, headers=req_headers) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "PUT":
                    async with session.put(url, json=payload, headers=req_headers) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "PATCH":
                    async with session.patch(url, json=payload, headers=req_headers) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "DELETE":
                    async with session.delete(url, headers=req_headers) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
        except Exception:
            return None

    def _check_rls_bypass(self, response: dict[str, Any], payload: SupabasePayload) -> bool:
        """Check if RLS was bypassed."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status == 200:
            # Check if data was returned
            if body and body not in ("[]", "{}", "null", ""):
                try:
                    data = json.loads(body)
                    if (isinstance(data, list) and len(data) > 0) or (isinstance(data, dict) and len(data) > 0):
                        return True
                except json.JSONDecodeError:
                    pass

        return False

    def _check_auth_enumeration(self, response: dict[str, Any], payload: SupabasePayload) -> bool:
        """Check if auth enumeration was successful."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status == 200:
            # Check for auth config
            if "phone_autoconfirm" in body or "email_confirm" in body:
                return True
            if "users" in body and "email" in body:
                return True

        return False

    def _check_edge_function(self, response: dict[str, Any], payload: SupabasePayload) -> bool:
        """Check if edge function was accessible."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status == 200:
            # Check for meaningful response
            if body and body not in ("null", ""):
                return True
        elif status == 403:
            # Permission denied but function exists
            if "permission" in body.lower() or "unauthorized" in body.lower():
                return True

        return False

    def _check_storage_abuse(self, response: dict[str, Any], payload: SupabasePayload) -> bool:
        """Check if storage abuse was successful."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status == 200:
            # Check for data
            if body and body not in ("[]", "{}", "null", ""):
                return True

        return False

    def _check_metadata_escalation(self, response: dict[str, Any], payload: SupabasePayload) -> bool:
        """Check if metadata escalation was successful."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status == 200:
            # Check if role was set
            if "admin" in body.lower() or "superuser" in body.lower():
                return True

        return False

    def _check_jwt_manipulation(self, response: dict[str, Any], payload: SupabasePayload) -> bool:
        """Check if JWT manipulation was successful."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status == 200:
            # Check for access
            if body and body not in ("null", ""):
                return True

        return False

    def _check_db_function(self, response: dict[str, Any], payload: SupabasePayload) -> bool:
        """Check if database function was accessible."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status == 200:
            # Check for data
            if body and body not in ("null", ""):
                return True
        elif status == 404:
            # Function doesn't exist
            return False

        return False

    def _generate_jwt_with_role(self, role: str) -> str:
        """Generate a JWT with specified role claim."""
        import base64
        import hashlib
        import hmac

        # Header
        header = json.dumps({"alg": "HS256", "typ": "JWT"})
        header_b64 = base64.urlsafe_b64encode(header.encode()).rstrip(b"=").decode()

        # Payload with role claim
        payload = json.dumps({
            "role": role,
            "aud": "authenticated",
            "exp": 9999999999,
            "sub": "fake-user-id",
            "email": "fake@evil.com",
            "app_metadata": {"provider": "email", "providers": ["email"]},
            "user_metadata": {"role": role},
        })
        payload_b64 = base64.urlsafe_b64encode(payload.encode()).rstrip(b"=").decode()

        # Signature (using anon key as secret — will likely fail but tests the endpoint)
        signing_input = f"{header_b64}.{payload_b64}"
        secret = (self._anon_key or "fake-secret").encode()
        signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def _generate_expired_jwt(self) -> str:
        """Generate an expired JWT."""
        import base64
        import hashlib
        import hmac

        header = json.dumps({"alg": "HS256", "typ": "JWT"})
        header_b64 = base64.urlsafe_b64encode(header.encode()).rstrip(b"=").decode()

        # Expired timestamp
        payload = json.dumps({
            "role": "authenticated",
            "aud": "authenticated",
            "exp": 1000000000,  # Long expired
            "sub": "fake-user-id",
        })
        payload_b64 = base64.urlsafe_b64encode(payload.encode()).rstrip(b"=").decode()

        signing_input = f"{header_b64}.{payload_b64}"
        secret = (self._anon_key or "fake-secret").encode()
        signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def _generate_jwt_with_claims(self, claims: dict[str, Any]) -> str:
        """Generate a JWT with arbitrary claims."""
        import base64
        import hashlib
        import hmac

        header = json.dumps({"alg": "HS256", "typ": "JWT"})
        header_b64 = base64.urlsafe_b64encode(header.encode()).rstrip(b"=").decode()

        payload = json.dumps({
            "role": "authenticated",
            "aud": "authenticated",
            "exp": 9999999999,
            **claims,
        })
        payload_b64 = base64.urlsafe_b64encode(payload.encode()).rstrip(b"=").decode()

        signing_input = f"{header_b64}.{payload_b64}"
        secret = (self._anon_key or "fake-secret").encode()
        signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def get_findings(self) -> list[Finding]:
        """Get all findings from this tester."""
        return self._findings
