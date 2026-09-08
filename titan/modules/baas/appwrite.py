"""AppWrite Deep Testing — deep testing of database, auth, storage, and functions.

This module tests:
1. Database permissions (read/write on all collections)
2. Authentication settings (providers, MFA, sessions)
3. Storage permissions (upload/download/delete)
4. Cloud Functions (enumerate, invoke)
5. Team/Workspace abuse (cross-team access)
6. API key abuse (test key restrictions)
7. Document-level permissions
8. User role escalation
"""


from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from titan.core.logger import get_logger
from titan.core.models import AttackType, Finding, Severity

logger = get_logger("appwrite")



@dataclass
class AppWritePayload:
    """An AppWrite-specific test payload."""
    name: str
    category: str
    endpoint: str
    method: str
    payload: Any
    expected_effect: str
    severity: Severity
    confidence: float
    headers: dict[str, str] | None = None


class AppWriteTester:
    """Deep AppWrite testing."""

    # ── Database Permission Payloads ────────────────────────────────────

    DB_PERMISSION_PAYLOADS = [
        AppWritePayload(
            name="list_collections",
            category="database",
            endpoint="/databases",
            method="GET",
            payload=None,
            expected_effect="collection_list",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        AppWritePayload(
            name="list_documents",
            category="database",
            endpoint="/databases/{database}/collections/{collection}/documents",
            method="GET",
            payload=None,
            expected_effect="document_list",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        AppWritePayload(
            name="read_document",
            category="database",
            endpoint="/databases/{database}/collections/{collection}/documents/{document}",
            method="GET",
            payload=None,
            expected_effect="document_read",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        AppWritePayload(
            name="create_document",
            category="database",
            endpoint="/databases/{database}/collections/{collection}/documents",
            method="POST",
            payload={"documentId": "unique()", "data": {"role": "admin"}},
            expected_effect="unauthorized_create",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        AppWritePayload(
            name="update_document",
            category="database",
            endpoint="/databases/{database}/collections/{collection}/documents/{document}",
            method="PATCH",
            payload={"data": {"role": "admin"}},
            expected_effect="unauthorized_update",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        AppWritePayload(
            name="delete_document",
            category="database",
            endpoint="/databases/{database}/collections/{collection}/documents/{document}",
            method="DELETE",
            payload=None,
            expected_effect="unauthorized_delete",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        AppWritePayload(
            name="cross_tenant_documents",
            category="database",
            endpoint="/databases/{database}/collections/{collection}/documents",
            method="GET",
            payload=None,
            headers={"X-Appwrite-Key": "{service_key}"},
            expected_effect="cross_tenant",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
    ]

    # ── Authentication Payloads ─────────────────────────────────────────

    AUTH_PAYLOADS = [
        AppWritePayload(
            name="list_sessions",
            category="auth",
            endpoint="/account/sessions",
            method="GET",
            payload=None,
            expected_effect="session_list",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        AppWritePayload(
            name="create_session",
            category="auth",
            endpoint="/account/sessions",
            method="POST",
            payload={"email": "test@test.com", "password": "test123"},
            expected_effect="session_create",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        AppWritePayload(
            name="list_users",
            category="auth",
            endpoint="/users",
            method="GET",
            payload=None,
            expected_effect="user_list",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        AppWritePayload(
            name="get_user",
            category="auth",
            endpoint="/users/{user_id}",
            method="GET",
            payload=None,
            expected_effect="user_read",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        AppWritePayload(
            name="update_user_role",
            category="auth",
            endpoint="/users/{user_id}",
            payload={"name": "admin", "password": "hacked123"},
            method="PATCH",
            expected_effect="role_escalation",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        AppWritePayload(
            name="delete_user",
            category="auth",
            endpoint="/users/{user_id}",
            method="DELETE",
            payload=None,
            expected_effect="user_deletion",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        AppWritePayload(
            name="create_user",
            category="auth",
            endpoint="/users",
            method="POST",
            payload={"userId": "unique()", "email": "admin@evil.com", "password": "hacked123", "name": "Admin"},
            expected_effect="user_creation",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
    ]

    # ── Storage Permission Payloads ─────────────────────────────────────

    STORAGE_PAYLOADS = [
        AppWritePayload(
            name="list_buckets",
            category="storage",
            endpoint="/storage/buckets",
            method="GET",
            payload=None,
            expected_effect="bucket_list",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        AppWritePayload(
            name="list_files",
            category="storage",
            endpoint="/storage/buckets/{bucket}/files",
            method="GET",
            payload=None,
            expected_effect="file_list",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        AppWritePayload(
            name="get_file",
            category="storage",
            endpoint="/storage/buckets/{bucket}/files/{file}",
            method="GET",
            payload=None,
            expected_effect="file_read",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        AppWritePayload(
            name="upload_file",
            category="storage",
            endpoint="/storage/buckets/{bucket}/files",
            method="POST",
            payload={"fileId": "unique()", "file": "test"},
            expected_effect="unauthorized_upload",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        AppWritePayload(
            name="delete_file",
            category="storage",
            endpoint="/storage/buckets/{bucket}/files/{file}",
            method="DELETE",
            payload=None,
            expected_effect="unauthorized_delete",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        AppWritePayload(
            name="create_bucket",
            category="storage",
            endpoint="/storage/buckets",
            method="POST",
            payload={"bucketId": "evil-bucket", "name": "evil-bucket", "permissions": ["read('*')", "write('*')"]},
            expected_effect="bucket_creation",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
    ]

    # ── Team/Workspace Abuse Payloads ───────────────────────────────────

    TEAM_ABUSE_PAYLOADS = [
        AppWritePayload(
            name="list_teams",
            category="teams",
            endpoint="/teams",
            method="GET",
            payload=None,
            expected_effect="team_list",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        AppWritePayload(
            name="create_team",
            category="teams",
            endpoint="/teams",
            method="POST",
            payload={"teamId": "unique()", "name": "evil-team"},
            expected_effect="team_creation",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        AppWritePayload(
            name="update_team",
            category="teams",
            endpoint="/teams/{team_id}",
            method="PATCH",
            payload={"name": "hacked-team"},
            expected_effect="team_modification",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        AppWritePayload(
            name="delete_team",
            category="teams",
            endpoint="/teams/{team_id}",
            method="DELETE",
            payload=None,
            expected_effect="team_deletion",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        AppWritePayload(
            name="create_membership",
            category="teams",
            endpoint="/teams/{team_id}/memberships",
            method="POST",
            payload={"email": "admin@evil.com", "role": "owner"},
            expected_effect="membership_escalation",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
    ]

    # ── Function Abuse Payloads ─────────────────────────────────────────

    FUNCTION_ABUSE_PAYLOADS = [
        AppWritePayload(
            name="list_functions",
            category="functions",
            endpoint="/functions",
            method="GET",
            payload=None,
            expected_effect="function_list",
            severity=Severity.MEDIUM,
            confidence=0.80,
        ),
        AppWritePayload(
            name="get_function",
            category="functions",
            endpoint="/functions/{function_id}",
            method="GET",
            payload=None,
            expected_effect="function_info",
            severity=Severity.LOW,
            confidence=0.75,
        ),
        AppWritePayload(
            name="invoke_function",
            category="functions",
            endpoint="/functions/{function_id}/executions",
            method="POST",
            payload={"async": False},
            expected_effect="function_invoke",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        AppWritePayload(
            name="list_executions",
            category="functions",
            endpoint="/functions/{function_id}/executions",
            method="GET",
            payload=None,
            expected_effect="execution_list",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: list[Finding] = []
        self._endpoint: str | None = None
        self._api_key: str | None = None
        self._project_id: str | None = None

    def set_credentials(
        self,
        endpoint: str,
        api_key: str | None = None,
        project_id: str | None = None,
    ) -> None:
        """Set AppWrite credentials for testing."""
        self._endpoint = endpoint
        self._api_key = api_key
        self._project_id = project_id

    async def test_database_permissions(
        self,
        target_url: str,
        databases: list[str],
        collections: list[str],
        documents: list[str],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test database permissions."""
        findings = []

        for db in databases:
            for collection in collections:
                for doc in documents:
                    for payload in self.DB_PERMISSION_PAYLOADS:
                        try:
                            endpoint = payload.endpoint.replace("{database}", db)
                            endpoint = endpoint.replace("{collection}", collection)
                            endpoint = endpoint.replace("{document}", doc)
                            url = f"{self._endpoint}/v1{endpoint}"

                            response = await self._send_request(
                                url, payload.method, payload.payload, auth_headers
                            )

                            if response and self._check_permission(response, payload):
                                finding = Finding(
                                    target=target_url,
                                    url=url,
                                    method=payload.method,
                                    param=f"{db}/{collection}/{doc}",
                                    location="database",
                                    payload=json.dumps(payload.payload) if payload.payload else "",
                                    attack_type=AttackType.BUSINESS_LOGIC,
                                    severity=payload.severity,
                                    confidence=payload.confidence,
                                    status=response.get("status", 0),
                                    evidence=response.get("body", "")[:500],
                                    tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                                    tags=["baas", "appwrite", "database", payload.name],
                                    notes=f"AppWrite DB: {payload.name} on {db}/{collection}",
                                )
                                findings.append(finding)

                        except Exception as exc:
                            logger.debug(f"variant failed, continuing: {exc}")
                            continue

        self._findings.extend(findings)
        return findings

    async def test_auth_permissions(
        self,
        target_url: str,
        user_ids: list[str],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test authentication permissions."""
        findings = []

        for payload in self.AUTH_PAYLOADS:
            try:
                endpoint = payload.endpoint
                if "{user_id}" in endpoint and user_ids:
                    endpoint = endpoint.replace("{user_id}", user_ids[0])
                url = f"{self._endpoint}/v1{endpoint}"

                response = await self._send_request(
                    url, payload.method, payload.payload, auth_headers
                )

                if response and self._check_permission(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=url,
                        method=payload.method,
                        param=payload.name,
                        location="auth",
                        payload=json.dumps(payload.payload) if payload.payload else "",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        evidence=response.get("body", "")[:500],
                        tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                        tags=["baas", "appwrite", "auth", payload.name],
                        notes=f"AppWrite Auth: {payload.name}",
                    )
                    findings.append(finding)

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        self._findings.extend(findings)
        return findings

    async def test_storage_permissions(
        self,
        target_url: str,
        buckets: list[str],
        files: list[str],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test storage permissions."""
        findings = []

        for bucket in buckets:
            for payload in self.STORAGE_PAYLOADS:
                try:
                    endpoint = payload.endpoint.replace("{bucket}", bucket)
                    if "{file}" in endpoint and files:
                        endpoint = endpoint.replace("{file}", files[0])
                    url = f"{self._endpoint}/v1{endpoint}"

                    response = await self._send_request(
                        url, payload.method, payload.payload, auth_headers
                    )

                    if response and self._check_permission(response, payload):
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
                            tags=["baas", "appwrite", "storage", payload.name, bucket],
                            notes=f"AppWrite Storage: {payload.name} on '{bucket}'",
                        )
                        findings.append(finding)

                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue

        self._findings.extend(findings)
        return findings

    async def test_team_abuse(
        self,
        target_url: str,
        team_ids: list[str],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test team/workspace abuse."""
        findings = []

        for payload in self.TEAM_ABUSE_PAYLOADS:
            try:
                endpoint = payload.endpoint
                if "{team_id}" in endpoint and team_ids:
                    endpoint = endpoint.replace("{team_id}", team_ids[0])
                url = f"{self._endpoint}/v1{endpoint}"

                response = await self._send_request(
                    url, payload.method, payload.payload, auth_headers
                )

                if response and self._check_permission(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=url,
                        method=payload.method,
                        param=payload.name,
                        location="teams",
                        payload=json.dumps(payload.payload) if payload.payload else "",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        evidence=response.get("body", "")[:500],
                        tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                        tags=["baas", "appwrite", "teams", payload.name],
                        notes=f"AppWrite Teams: {payload.name}",
                    )
                    findings.append(finding)

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        self._findings.extend(findings)
        return findings

    async def test_function_abuse(
        self,
        target_url: str,
        function_ids: list[str],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test function abuse."""
        findings = []

        for function_id in function_ids:
            for payload in self.FUNCTION_ABUSE_PAYLOADS:
                try:
                    endpoint = payload.endpoint.replace("{function_id}", function_id)
                    url = f"{self._endpoint}/v1{endpoint}"

                    response = await self._send_request(
                        url, payload.method, payload.payload, auth_headers
                    )

                    if response and self._check_permission(response, payload):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=payload.method,
                            param=function_id,
                            location="functions",
                            payload=json.dumps(payload.payload) if payload.payload else "",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            confidence=payload.confidence,
                            status=response.get("status", 0),
                            evidence=response.get("body", "")[:500],
                            tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                            tags=["baas", "appwrite", "functions", payload.name, function_id],
                            notes=f"AppWrite Functions: {payload.name} on '{function_id}'",
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
                if self._api_key and "X-Appwrite-Key" not in req_headers:
                    req_headers["X-Appwrite-Key"] = self._api_key
                if self._project_id and "X-Appwrite-Project" not in req_headers:
                    req_headers["X-Appwrite-Project"] = self._project_id
                req_headers["Content-Type"] = "application/json"

                if method.upper() == "GET":
                    async with session.get(url, headers=req_headers) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "POST":
                    async with session.post(url, json=payload, headers=req_headers) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "PATCH":
                    async with session.patch(url, json=payload, headers=req_headers) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "DELETE":
                    async with session.delete(url, headers=req_headers) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
        except Exception:
            return None

    def _check_permission(self, response: dict[str, Any], payload: AppWritePayload) -> bool:
        """Check if permission was bypassed."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status == 200:
            if body and body not in ("{}", "[]", "null", ""):
                try:
                    data = json.loads(body)
                    if isinstance(data, (dict, list)) and (
                        (isinstance(data, dict) and len(data) > 0) or
                        (isinstance(data, list) and len(data) > 0)
                    ):
                        return True
                except json.JSONDecodeError as exc:
                    logger.debug(f"suppressed exception: {exc}")
                    pass
        elif status == 403:
            # Permission denied but endpoint exists
            if "permission" in body.lower() or "unauthorized" in body.lower():
                return True

        return False

    def get_findings(self) -> list[Finding]:
        """Get all findings."""
        return self._findings
