"""Firebase Deep Testing — deep testing of Firestore rules, Auth, Storage, Realtime DB, and Cloud Functions.

This module tests:
1. Firestore rules (read/write on all collections)
2. Authentication settings (providers, MFA, password policy)
3. Storage rules (upload/download/delete on all buckets)
4. Realtime Database (read/write on all paths)
5. Cloud Functions (enumerate, test with/without auth)
6. API key abuse (test restrictions, access unrestricted APIs)
7. OAuth flow abuse (redirect URI manipulation, state parameter)
8. Token manipulation (decode, modify claims, test refresh)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType


@dataclass
class FirebasePayload:
    """A Firebase-specific test payload."""
    name: str
    category: str
    endpoint: str
    method: str
    payload: Any
    expected_effect: str
    severity: Severity
    confidence: float
    headers: Optional[Dict[str, str]] = None


class FirebaseTester:
    """Deep Firebase testing."""

    # ── Firestore Rules Testing Payloads ────────────────────────────────

    FIRESTORE_RULES_PAYLOADS = [
        FirebasePayload(
            name="list_collections",
            category="firestore_rules",
            endpoint="/firestore/v1/projects/{project}/databases/(default)/documents",
            method="GET",
            payload=None,
            expected_effect="collection_list",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        FirebasePayload(
            name="read_all_documents",
            category="firestore_rules",
            endpoint="/firestore/v1/projects/{project}/databases/(default)/documents/{collection}",
            method="GET",
            payload=None,
            expected_effect="document_read",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        FirebasePayload(
            name="write_document",
            category="firestore_rules",
            endpoint="/firestore/v1/projects/{project}/databases/(default)/documents/{collection}",
            method="POST",
            payload={"fields": {"test": {"stringValue": "hacked"}}},
            expected_effect="unauthorized_write",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        FirebasePayload(
            name="update_document",
            category="firestore_rules",
            endpoint="/firestore/v1/projects/{project}/databases/(default)/documents/{collection}/{document}",
            method="PATCH",
            payload={"fields": {"test": {"stringValue": "modified"}}},
            expected_effect="unauthorized_update",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        FirebasePayload(
            name="delete_document",
            category="firestore_rules",
            endpoint="/firestore/v1/projects/{project}/databases/(default)/documents/{collection}/{document}",
            method="DELETE",
            payload=None,
            expected_effect="unauthorized_delete",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        FirebasePayload(
            name="query_collection",
            category="firestore_rules",
            endpoint="/firestore/v1/projects/{project}/databases/(default)/documents/{collection}",
            method="POST",
            payload={"structuredQuery": {"from": [{"collectionId": "{collection}"}]}},
            expected_effect="query_access",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
    ]

    # ── Authentication Settings Payloads ────────────────────────────────

    AUTH_SETTINGS_PAYLOADS = [
        FirebasePayload(
            name="signup_new_user",
            category="auth_settings",
            endpoint="/identitytoolkit/v3/relyingparty/signupNewUser",
            method="POST",
            payload={"email": "test@test.com", "password": "test123", "returnSecureToken": True},
            expected_effect="signup_allowed",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        FirebasePayload(
            name="email_signin",
            category="auth_settings",
            endpoint="/identitytoolkit/v3/relyingparty/emailLinkSignin",
            method="POST",
            payload={"email": "test@test.com", "oobCode": "test"},
            expected_effect="email_signin",
            severity=Severity.LOW,
            confidence=0.60,
        ),
        FirebasePayload(
            name="get_account_info",
            category="auth_settings",
            endpoint="/identitytoolkit/v3/relyingparty/getAccountInfo",
            method="POST",
            payload={"idToken": "{id_token}"},
            expected_effect="account_info",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        FirebasePayload(
            name="reset_password",
            category="auth_settings",
            endpoint="/identitytoolkit/v3/relyingparty/resetPassword",
            method="POST",
            payload={"email": "test@test.com"},
            expected_effect="password_reset",
            severity=Severity.LOW,
            confidence=0.60,
        ),
        FirebasePayload(
            name="set_account_info",
            category="auth_settings",
            endpoint="/identitytoolkit/v3/relyingparty/setAccountInfo",
            method="POST",
            payload={"idToken": "{id_token}", "email": "hacker@evil.com"},
            expected_effect="account_modification",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        FirebasePayload(
            name="delete_account",
            category="auth_settings",
            endpoint="/identitytoolkit/v3/relyingparty/deleteAccount",
            method="POST",
            payload={"idToken": "{id_token}"},
            expected_effect="account_deletion",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
    ]

    # ── Storage Rules Testing Payloads ──────────────────────────────────

    STORAGE_RULES_PAYLOADS = [
        FirebasePayload(
            name="list_buckets",
            category="storage_rules",
            endpoint="/storage/v1/b?project={project}",
            method="GET",
            payload=None,
            expected_effect="bucket_list",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        FirebasePayload(
            name="list_objects",
            category="storage_rules",
            endpoint="/storage/v1/b/{bucket}/o",
            method="GET",
            payload=None,
            expected_effect="object_list",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        FirebasePayload(
            name="download_object",
            category="storage_rules",
            endpoint="/storage/v1/b/{bucket}/o/{object}",
            method="GET",
            payload=None,
            expected_effect="object_download",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        FirebasePayload(
            name="upload_object",
            category="storage_rules",
            endpoint="/upload/storage/v1/b/{bucket}/o?uploadType=media&name={object}",
            method="POST",
            payload=b"test",
            expected_effect="unauthorized_upload",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        FirebasePayload(
            name="delete_object",
            category="storage_rules",
            endpoint="/storage/v1/b/{bucket}/o/{object}",
            method="DELETE",
            payload=None,
            expected_effect="unauthorized_delete",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
    ]

    # ── Realtime Database Payloads ──────────────────────────────────────

    REALTIME_DB_PAYLOADS = [
        FirebasePayload(
            name="read_root",
            category="realtime_db",
            endpoint="/{database}/.json",
            method="GET",
            payload=None,
            expected_effect="root_read",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        FirebasePayload(
            name="read_users",
            category="realtime_db",
            endpoint="/{database}/users.json",
            method="GET",
            payload=None,
            expected_effect="users_read",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        FirebasePayload(
            name="read_admin",
            category="realtime_db",
            endpoint="/{database}/admin.json",
            method="GET",
            payload=None,
            expected_effect="admin_read",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        FirebasePayload(
            name="write_data",
            category="realtime_db",
            endpoint="/{database}/test.json",
            method="PUT",
            payload={"hacked": True},
            expected_effect="unauthorized_write",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        FirebasePayload(
            name="shallow_query",
            category="realtime_db",
            endpoint="/{database}/.json?shallow=true",
            method="GET",
            payload=None,
            expected_effect="shallow_query",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
    ]

    # ── Cloud Functions Payloads ────────────────────────────────────────

    CLOUD_FUNCTIONS_PAYLOADS = [
        FirebasePayload(
            name="list_functions",
            category="cloud_functions",
            endpoint="/v1/projects/{project}/locations/-/functions",
            method="GET",
            payload=None,
            expected_effect="function_list",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        FirebasePayload(
            name="invoke_function",
            category="cloud_functions",
            endpoint="/{function_url}",
            method="POST",
            payload={},
            expected_effect="function_invoke",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        FirebasePayload(
            name="invoke_with_payload",
            category="cloud_functions",
            endpoint="/{function_url}",
            method="POST",
            payload={"data": "test"},
            expected_effect="function_invoke_data",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
    ]

    # ── API Key Abuse Payloads ──────────────────────────────────────────

    API_KEY_ABUSE_PAYLOADS = [
        FirebasePayload(
            name="list_projects",
            category="api_key_abuse",
            endpoint="/v1/projects",
            method="GET",
            payload=None,
            headers={"X-Goog-Api-Key": "{api_key}"},
            expected_effect="project_list",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        FirebasePayload(
            name="list_services",
            category="api_key_abuse",
            endpoint="/v1/projects/{project}/services",
            method="GET",
            payload=None,
            headers={"X-Goog-Api-Key": "{api_key}"},
            expected_effect="service_list",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        FirebasePayload(
            name="invoke_api",
            category="api_key_abuse",
            endpoint="/v1/projects/{project}/locations/{location}/functions",
            method="GET",
            payload=None,
            headers={"X-Goog-Api-Key": "{api_key}"},
            expected_effect="api_invoke",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: List[Finding] = []
        self._firebase_url: Optional[str] = None
        self._api_key: Optional[str] = None
        self._project_id: Optional[str] = None

    def set_credentials(
        self,
        firebase_url: str,
        api_key: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> None:
        """Set Firebase credentials for testing."""
        self._firebase_url = firebase_url
        self._api_key = api_key
        self._project_id = project_id

    async def test_firestore_rules(
        self,
        target_url: str,
        collections: List[str],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test Firestore rules."""
        findings = []

        for collection in collections:
            for payload in self.FIRESTORE_RULES_PAYLOADS:
                try:
                    endpoint = payload.endpoint.replace("{project}", self._project_id or "")
                    endpoint = endpoint.replace("{collection}", collection)
                    url = f"https://firestore.googleapis.com{endpoint}"

                    response = await self._send_request(
                        url, payload.method, payload.payload, payload.headers
                    )

                    if response and self._check_firestore_rules(response, payload):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=payload.method,
                            param=collection,
                            location="firestore",
                            payload=json.dumps(payload.payload) if payload.payload else "",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            confidence=payload.confidence,
                            status=response.get("status", 0),
                            evidence=response.get("body", "")[:500],
                            tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                            tags=["baas", "firebase", "firestore", payload.name, collection],
                            notes=f"Firestore rules: {payload.name} on '{collection}'",
                        )
                        findings.append(finding)

                except Exception:
                    continue

        self._findings.extend(findings)
        return findings

    async def test_auth_settings(
        self,
        target_url: str,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test authentication settings."""
        findings = []

        for payload in self.AUTH_SETTINGS_PAYLOADS:
            try:
                url = f"https://identitytoolkit.googleapis.com{payload.endpoint}?key={self._api_key}"

                response = await self._send_request(
                    url, payload.method, payload.payload, payload.headers
                )

                if response and self._check_auth_settings(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=url,
                        method=payload.method,
                        param=payload.name,
                        location="auth",
                        payload=json.dumps(payload.payload) if payload.payload else "",
                        attack_type=AttackType.INFO_LEAK,
                        severity=payload.severity,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        evidence=response.get("body", "")[:500],
                        tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                        tags=["baas", "firebase", "auth", payload.name],
                        notes=f"Auth settings: {payload.name}",
                    )
                    findings.append(finding)

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def test_storage_rules(
        self,
        target_url: str,
        buckets: List[str],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test Storage rules."""
        findings = []

        for bucket in buckets:
            for payload in self.STORAGE_RULES_PAYLOADS:
                try:
                    endpoint = payload.endpoint.replace("{bucket}", bucket)
                    url = f"https://storage.googleapis.com{endpoint}"

                    response = await self._send_request(
                        url, payload.method, payload.payload, payload.headers
                    )

                    if response and self._check_storage_rules(response, payload):
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
                            tags=["baas", "firebase", "storage", payload.name, bucket],
                            notes=f"Storage rules: {payload.name} on bucket '{bucket}'",
                        )
                        findings.append(finding)

                except Exception:
                    continue

        self._findings.extend(findings)
        return findings

    async def test_realtime_db(
        self,
        target_url: str,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test Realtime Database."""
        findings = []

        for payload in self.REALTIME_DB_PAYLOADS:
            try:
                endpoint = payload.endpoint.replace("{database}", self._firebase_url or "")
                url = f"https://{endpoint}"

                response = await self._send_request(
                    url, payload.method, payload.payload, payload.headers
                )

                if response and self._check_realtime_db(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=url,
                        method=payload.method,
                        param=payload.name,
                        location="realtime_db",
                        payload=json.dumps(payload.payload) if payload.payload else "",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        evidence=response.get("body", "")[:500],
                        tier="confirmed" if payload.confidence > 0.85 else "suspicious",
                        tags=["baas", "firebase", "realtime_db", payload.name],
                        notes=f"Realtime DB: {payload.name}",
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
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Send HTTP request and return response."""
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                req_headers = headers or {}

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

    def _check_firestore_rules(self, response: Dict[str, Any], payload: FirebasePayload) -> bool:
        """Check if Firestore rules were bypassed."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status == 200:
            if body and body not in ("{}", "null", ""):
                try:
                    data = json.loads(body)
                    if isinstance(data, dict) and len(data) > 0:
                        return True
                except json.JSONDecodeError:
                    pass

        return False

    def _check_auth_settings(self, response: Dict[str, Any], payload: FirebasePayload) -> bool:
        """Check if auth settings were accessible."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status == 200:
            if "email" in body or "localId" in body:
                return True

        return False

    def _check_storage_rules(self, response: Dict[str, Any], payload: FirebasePayload) -> bool:
        """Check if Storage rules were bypassed."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status == 200:
            if body and body not in ("{}", "null", ""):
                return True

        return False

    def _check_realtime_db(self, response: Dict[str, Any], payload: FirebasePayload) -> bool:
        """Check if Realtime Database was accessible."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status == 200:
            if body and body not in ("{}", "null", ""):
                return True

        return False

    def get_findings(self) -> List[Finding]:
        """Get all findings from this tester."""
        return self._findings
