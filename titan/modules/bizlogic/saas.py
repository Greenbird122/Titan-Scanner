"""SaaS Business Logic Testing — deep testing of subscription, billing, and access control.

This module tests:
1. Subscription bypass (tier upgrade without payment)
2. Credit manipulation (add credits, modify balance)
3. Role escalation (admin access without authorization)
4. Workspace abuse (cross-workspace access)
5. Billing bypass (skip billing, modify invoice)
6. Rate limit abuse (exceed quotas, bypass throttling)
7. Feature gating bypass (access premium features)
8. Trial abuse (extend trial, multiple trials)
"""


from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from titan.core.logger import get_logger
from titan.core.models import AttackType, Finding, Severity

logger = get_logger("saas")



@dataclass
class SaaSPayload:
    """A SaaS business logic test payload."""
    name: str
    category: str
    payload: Any
    expected_effect: str
    severity: Severity
    confidence: float


class SaaSTester:
    """Deep SaaS business logic testing."""

    # ── Subscription Bypass Payloads ────────────────────────────────────

    SUBSCRIPTION_BYPASS_PAYLOADS = [
        # Tier upgrade without payment
        SaaSPayload(
            name="tier_upgrade",
            category="subscription_bypass",
            payload={"tier": "premium", "plan": "enterprise", "subscription": "pro"},
            expected_effect="tier_upgrade",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        # Modify subscription status
        SaaSPayload(
            name="status_modification",
            category="subscription_bypass",
            payload={"status": "active", "subscription_status": "paid", "billing_status": "current"},
            expected_effect="status_bypass",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        # Subscription expiry bypass
        SaaSPayload(
            name="expiry_bypass",
            category="subscription_bypass",
            payload={"expires_at": "2099-12-31", "expiry": "never", "valid_until": "2099-12-31"},
            expected_effect="expiry_bypass",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        # Cancel and retain access
        SaaSPayload(
            name="cancel_retain",
            category="subscription_bypass",
            payload={"cancel": True, "refund": True, "retain_access": True},
            expected_effect="cancel_retain_access",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
    ]

    # ── Credit Manipulation Payloads ────────────────────────────────────

    CREDIT_MANIPULATION_PAYLOADS = [
        # Add credits
        SaaSPayload(
            name="add_credits",
            category="credit_manipulation",
            payload={"credits": 999999, "balance": 999999, "credits_to_add": 999999},
            expected_effect="credit_addition",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        # Negative credits (adds to balance)
        SaaSPayload(
            name="negative_credits",
            category="credit_manipulation",
            payload={"credits": -100, "balance": -100, "credits_to_add": -100},
            expected_effect="negative_credit",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        # Modify credit balance
        SaaSPayload(
            name="modify_balance",
            category="credit_manipulation",
            payload={"balance": 999999, "credits_remaining": 999999},
            expected_effect="balance_modification",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        # Credit overflow
        SaaSPayload(
            name="credit_overflow",
            category="credit_manipulation",
            payload={"credits": 2147483648, "balance": 2147483648},
            expected_effect="overflow",
            severity=Severity.HIGH,
            confidence=0.70,
        ),
        # Free credits via promo
        SaaSPayload(
            name="promo_credits",
            category="credit_manipulation",
            payload={"promo_code": "FREECREDITS", "coupon": "FREE1000", "voucher": "UNLIMITED"},
            expected_effect="free_credits",
            severity=Severity.HIGH,
            confidence=0.75,
        ),
    ]

    # ── Role Escalation Payloads ────────────────────────────────────────

    ROLE_ESCALATION_PAYLOADS = [
        # Admin role
        SaaSPayload(
            name="admin_role",
            category="role_escalation",
            payload={"role": "admin", "is_admin": True, "admin": True, "permissions": ["admin"]},
            expected_effect="admin_access",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        # Superuser role
        SaaSPayload(
            name="superuser_role",
            category="role_escalation",
            payload={"role": "superuser", "is_superuser": True, "level": 999},
            expected_effect="superuser_access",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        # Moderator role
        SaaSPayload(
            name="moderator_role",
            category="role_escalation",
            payload={"role": "moderator", "is_moderator": True, "mod": True},
            expected_effect="moderator_access",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        # Owner role
        SaaSPayload(
            name="owner_role",
            category="role_escalation",
            payload={"role": "owner", "is_owner": True, "creator": True},
            expected_effect="owner_access",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        # Nested role injection
        SaaSPayload(
            name="nested_role",
            category="role_escalation",
            payload={"user": {"role": "admin"}, "profile": {"permissions": ["admin"]}},
            expected_effect="nested_role_access",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
    ]

    # ── Workspace Abuse Payloads ────────────────────────────────────────

    WORKSPACE_ABUSE_PAYLOADS = [
        # Cross-workspace access
        SaaSPayload(
            name="cross_workspace",
            category="workspace_abuse",
            payload={"workspace_id": 1, "org_id": 1, "team_id": 1},
            expected_effect="cross_workspace_access",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        # Modify workspace settings
        SaaSPayload(
            name="workspace_settings",
            category="workspace_abuse",
            payload={"settings": {"admin_email": "attacker@evil.com"}},
            expected_effect="settings_modification",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        # Delete workspace data
        SaaSPayload(
            name="delete_workspace",
            category="workspace_abuse",
            payload={"action": "delete", "confirm": True},
            expected_effect="data_deletion",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        # Invite to workspace
        SaaSPayload(
            name="invite_workspace",
            category="workspace_abuse",
            payload={"email": "attacker@evil.com", "role": "admin"},
            expected_effect="unauthorized_invite",
            severity=Severity.HIGH,
            confidence=0.75,
        ),
    ]

    # ── Billing Bypass Payloads ─────────────────────────────────────────

    BILLING_BYPASS_PAYLOADS = [
        # Skip billing step
        SaaSPayload(
            name="skip_billing",
            category="billing_bypass",
            payload={"billing_status": "paid", "invoice_status": "paid"},
            expected_effect="billing_skip",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        # Modify invoice amount
        SaaSPayload(
            name="modify_invoice",
            category="billing_bypass",
            payload={"amount": 0, "total": 0, "invoice_amount": 0},
            expected_effect="invoice_modification",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        # Apply fake discount
        SaaSPayload(
            name="fake_discount",
            category="billing_bypass",
            payload={"discount": 100, "discount_percent": 100, "coupon": "FREE"},
            expected_effect="free_billing",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        # Payment method bypass
        SaaSPayload(
            name="payment_method_bypass",
            category="billing_bypass",
            payload={"payment_method": "free", "payment_type": "comp", "payment_status": "waived"},
            expected_effect="free_payment",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
    ]

    # ── Rate Limit Abuse Payloads ───────────────────────────────────────

    RATE_LIMIT_ABUSE_PAYLOADS = [
        # Exceed quota
        SaaSPayload(
            name="exceed_quota",
            category="rate_limit_abuse",
            payload={"quota": 999999, "rate_limit": 999999, "requests_per_minute": 999999},
            expected_effect="quota_bypass",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        # Bypass throttle
        SaaSPayload(
            name="bypass_throttle",
            category="rate_limit_abuse",
            payload={"throttle": False, "rate_limit_enabled": False},
            expected_effect="throttle_bypass",
            severity=Severity.MEDIUM,
            confidence=0.65,
        ),
        # Reset rate limit
        SaaSPayload(
            name="reset_rate_limit",
            category="rate_limit_abuse",
            payload={"reset_rate_limit": True, "clear_throttle": True},
            expected_effect="rate_limit_reset",
            severity=Severity.LOW,
            confidence=0.60,
        ),
    ]

    # ── Feature Gating Bypass Payloads ──────────────────────────────────

    FEATURE_GATING_PAYLOADS = [
        # Access premium features
        SaaSPayload(
            name="premium_features",
            category="feature_gating",
            payload={"features": ["premium", "enterprise", "unlimited"]},
            expected_effect="premium_access",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        # Modify feature flags
        SaaSPayload(
            name="feature_flags",
            category="feature_gating",
            payload={"feature_flags": {"premium": True, "enterprise": True}},
            expected_effect="feature_flag_bypass",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        # Enable beta features
        SaaSPayload(
            name="beta_features",
            category="feature_gating",
            payload={"beta": True, "experimental": True, "early_access": True},
            expected_effect="beta_access",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
    ]

    # ── Trial Abuse Payloads ────────────────────────────────────────────

    TRIAL_ABUSE_PAYLOADS = [
        # Extend trial
        SaaSPayload(
            name="extend_trial",
            category="trial_abuse",
            payload={"trial_end": "2099-12-31", "trial_extended": True},
            expected_effect="trial_extension",
            severity=Severity.MEDIUM,
            confidence=0.75,
        ),
        # Multiple trials
        SaaSPayload(
            name="multiple_trials",
            category="trial_abuse",
            payload={"email": "new+1@evil.com", "trial_count": 0},
            expected_effect="multiple_trial",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        # Trial to paid conversion bypass
        SaaSPayload(
            name="trial_conversion_bypass",
            category="trial_abuse",
            payload={"subscription_status": "active", "trial_converted": True},
            expected_effect="trial_conversion_bypass",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: list[Finding] = []

    async def test_subscription_bypass(
        self,
        target_url: str,
        endpoints: list[dict[str, Any]],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test for subscription bypass vulnerabilities."""
        findings = []

        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "POST")
            params = endpoint.get("params", {})

            for payload in self.SUBSCRIPTION_BYPASS_PAYLOADS:
                try:
                    test_params = {**params, **payload.payload}

                    response = await self._send_request(url, method, test_params, auth_headers)

                    if response and self._check_subscription_bypass(response, payload):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=method,
                            param=str(list(payload.payload.keys())[0]),
                            location="body",
                            payload=json.dumps(payload.payload),
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            confidence=payload.confidence,
                            status=response.get("status", 0),
                            evidence=response.get("body", "")[:500],
                            tier="confirmed" if payload.confidence > 0.8 else "suspicious",
                            tags=["business_logic", "saas", "subscription_bypass", payload.name],
                            notes=f"Subscription bypass: {payload.name} - {payload.expected_effect}",
                        )
                        findings.append(finding)

                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue

        self._findings.extend(findings)
        return findings

    async def test_credit_manipulation(
        self,
        target_url: str,
        endpoints: list[dict[str, Any]],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test for credit manipulation vulnerabilities."""
        findings = []

        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "POST")
            params = endpoint.get("params", {})

            for payload in self.CREDIT_MANIPULATION_PAYLOADS:
                try:
                    test_params = {**params, **payload.payload}

                    response = await self._send_request(url, method, test_params, auth_headers)

                    if response and self._check_credit_manipulation(response, payload):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=method,
                            param=str(list(payload.payload.keys())[0]),
                            location="body",
                            payload=json.dumps(payload.payload),
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            confidence=payload.confidence,
                            status=response.get("status", 0),
                            evidence=response.get("body", "")[:500],
                            tier="confirmed" if payload.confidence > 0.8 else "suspicious",
                            tags=["business_logic", "saas", "credit_manipulation", payload.name],
                            notes=f"Credit manipulation: {payload.name} - {payload.expected_effect}",
                        )
                        findings.append(finding)

                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue

        self._findings.extend(findings)
        return findings

    async def test_role_escalation(
        self,
        target_url: str,
        endpoints: list[dict[str, Any]],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test for role escalation vulnerabilities."""
        findings = []

        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "POST")
            params = endpoint.get("params", {})

            for payload in self.ROLE_ESCALATION_PAYLOADS:
                try:
                    test_params = {**params, **payload.payload}

                    response = await self._send_request(url, method, test_params, auth_headers)

                    if response and self._check_role_escalation(response, payload):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=method,
                            param=str(list(payload.payload.keys())[0]),
                            location="body",
                            payload=json.dumps(payload.payload),
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            confidence=payload.confidence,
                            status=response.get("status", 0),
                            evidence=response.get("body", "")[:500],
                            tier="confirmed" if payload.confidence > 0.8 else "suspicious",
                            tags=["business_logic", "saas", "role_escalation", payload.name],
                            notes=f"Role escalation: {payload.name} - {payload.expected_effect}",
                        )
                        findings.append(finding)

                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue

        self._findings.extend(findings)
        return findings

    async def test_workspace_abuse(
        self,
        target_url: str,
        endpoints: list[dict[str, Any]],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test for workspace abuse vulnerabilities."""
        findings = []

        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "POST")
            params = endpoint.get("params", {})

            for payload in self.WORKSPACE_ABUSE_PAYLOADS:
                try:
                    test_params = {**params, **payload.payload}

                    response = await self._send_request(url, method, test_params, auth_headers)

                    if response and self._check_workspace_abuse(response, payload):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=method,
                            param=str(list(payload.payload.keys())[0]),
                            location="body",
                            payload=json.dumps(payload.payload),
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            confidence=payload.confidence,
                            status=response.get("status", 0),
                            evidence=response.get("body", "")[:500],
                            tier="confirmed" if payload.confidence > 0.8 else "suspicious",
                            tags=["business_logic", "saas", "workspace_abuse", payload.name],
                            notes=f"Workspace abuse: {payload.name} - {payload.expected_effect}",
                        )
                        findings.append(finding)

                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue

        self._findings.extend(findings)
        return findings

    async def test_billing_bypass(
        self,
        target_url: str,
        endpoints: list[dict[str, Any]],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test for billing bypass vulnerabilities."""
        findings = []

        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "POST")
            params = endpoint.get("params", {})

            for payload in self.BILLING_BYPASS_PAYLOADS:
                try:
                    test_params = {**params, **payload.payload}

                    response = await self._send_request(url, method, test_params, auth_headers)

                    if response and self._check_billing_bypass(response, payload):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=method,
                            param=str(list(payload.payload.keys())[0]),
                            location="body",
                            payload=json.dumps(payload.payload),
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            confidence=payload.confidence,
                            status=response.get("status", 0),
                            evidence=response.get("body", "")[:500],
                            tier="confirmed" if payload.confidence > 0.8 else "suspicious",
                            tags=["business_logic", "saas", "billing_bypass", payload.name],
                            notes=f"Billing bypass: {payload.name} - {payload.expected_effect}",
                        )
                        findings.append(finding)

                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue

        self._findings.extend(findings)
        return findings

    # ── Helper Methods ──────────────────────────────────────────────────

    async def _send_request(
        self,
        url: str,
        method: str,
        params: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """Send HTTP request and return response."""
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                if method.upper() == "GET":
                    async with session.get(url, params=params, headers=headers or {}) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "POST":
                    async with session.post(url, json=params, headers=headers or {}) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "PUT":
                    async with session.put(url, json=params, headers=headers or {}) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "PATCH":
                    async with session.patch(url, json=params, headers=headers or {}) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
        except Exception:
            return None

    def _check_subscription_bypass(self, response: dict[str, Any], payload: SaaSPayload) -> bool:
        """Check if subscription bypass was accepted."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status in (200, 201, 202):
            if payload.expected_effect == "tier_upgrade":
                if re.search(r'"tier":\s*"(premium|enterprise|pro)"', body):
                    return True
            elif payload.expected_effect == "status_bypass":
                if re.search(r'"status":\s*"active"', body):
                    return True
            elif payload.expected_effect == "expiry_bypass":
                if "2099" in body or "never" in body.lower():
                    return True

        return False

    def _check_credit_manipulation(self, response: dict[str, Any], payload: SaaSPayload) -> bool:
        """Check if credit manipulation was accepted."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status in (200, 201, 202):
            if payload.expected_effect == "credit_addition":
                if re.search(r'"credits":\s*\d{6,}', body) or re.search(r'"balance":\s*\d{6,}', body):
                    return True
            elif payload.expected_effect == "negative_credit":
                if re.search(r'"credits":\s*-\d+', body) or re.search(r'"balance":\s*-\d+', body):
                    return True

        return False

    def _check_role_escalation(self, response: dict[str, Any], payload: SaaSPayload) -> bool:
        """Check if role escalation was accepted."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status in (200, 201, 202):
            if payload.expected_effect == "admin_access":
                if re.search(r'"role":\s*"admin"', body) or re.search(r'"is_admin":\s*true', body):
                    return True
            elif payload.expected_effect == "superuser_access":
                if re.search(r'"role":\s*"superuser"', body) or re.search(r'"is_superuser":\s*true', body):
                    return True

        return False

    def _check_workspace_abuse(self, response: dict[str, Any], payload: SaaSPayload) -> bool:
        """Check if workspace abuse was accepted."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status in (200, 201, 202):
            if payload.expected_effect == "cross_workspace_access":
                if "workspace" in body and "id" in body:
                    return True
            elif payload.expected_effect == "settings_modification":
                if "evil" in body.lower() or "attacker" in body.lower():
                    return True

        return False

    def _check_billing_bypass(self, response: dict[str, Any], payload: SaaSPayload) -> bool:
        """Check if billing bypass was accepted."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status in (200, 201, 202):
            if payload.expected_effect == "billing_skip":
                if re.search(r'"status":\s*"paid"', body):
                    return True
            elif payload.expected_effect == "invoice_modification":
                if re.search(r'"amount":\s*0', body) or re.search(r'"total":\s*0', body):
                    return True

        return False

    async def test_rate_limit_abuse(
        self,
        target_url: str,
        endpoints: list[dict[str, Any]],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test for rate limit abuse vulnerabilities."""
        findings = []

        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "GET")
            params = endpoint.get("params", {})

            # Test: Send rapid requests to check for rate limiting
            import asyncio
            try:
                tasks = [
                    self._send_request(url, method, params, auth_headers)
                    for _ in range(50)
                ]
                responses = await asyncio.gather(*tasks, return_exceptions=True)

                success_count = sum(
                    1 for r in responses
                    if not isinstance(r, Exception) and r and r.get("status", 0) in (200, 201, 202)
                )
                rate_limited = sum(
                    1 for r in responses
                    if not isinstance(r, Exception) and r and r.get("status", 0) == 429
                )

                if success_count >= 45 and rate_limited == 0:
                    finding = Finding(
                        target=target_url,
                        url=url,
                        method=method,
                        param="rate_limit",
                        location="body",
                        payload="50 rapid requests, 0 rate limited",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.MEDIUM,
                        confidence=0.75,
                        status=200,
                        evidence=f"{success_count}/50 requests succeeded, 0 rate limited",
                        tier="suspicious",
                        tags=["business_logic", "saas", "rate_limit_abuse", endpoint.get("name", "unknown")],
                        notes=f"No rate limiting: {success_count} of 50 rapid requests succeeded without throttling",
                    )
                    findings.append(finding)

                # Test: Bypass via header manipulation
                for header_payload in [
                    {"X-Forwarded-For": "1.2.3.4"},
                    {"X-Real-IP": "5.6.7.8"},
                    {"X-Client-IP": "9.10.11.12"},
                    {"CF-Connecting-IP": "13.14.15.16"},
                ]:
                    try:
                        bypass_headers = {**(auth_headers or {}), **header_payload}
                        rapid_resp = await self._send_request(url, method, params, bypass_headers)
                        if rapid_resp and rapid_resp.get("status", 0) in (200, 201, 202):
                            finding = Finding(
                                target=target_url,
                                url=url,
                                method=method,
                                param="rate_limit_bypass",
                                location="header",
                                payload=json.dumps(header_payload),
                                attack_type=AttackType.BUSINESS_LOGIC,
                                severity=Severity.HIGH,
                                confidence=0.70,
                                status=rapid_resp.get("status", 0),
                                evidence=rapid_resp.get("body", "")[:500],
                                tier="suspicious",
                                tags=["business_logic", "saas", "rate_limit_bypass"],
                                notes=f"Rate limit bypass via header manipulation: {list(header_payload.keys())[0]}",
                            )
                            findings.append(finding)
                            break  # Found bypass, no need to test more headers
                    except Exception as exc:
                        logger.debug(f"variant failed, continuing: {exc}")
                        continue

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        self._findings.extend(findings)
        return findings

    async def test_feature_gating(
        self,
        target_url: str,
        endpoints: list[dict[str, Any]],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test for feature gating bypass vulnerabilities."""
        findings = []

        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "GET")
            params = endpoint.get("params", {})

            for payload in self.FEATURE_GATING_PAYLOADS:
                try:
                    test_params = {**params, **payload.payload}

                    response = await self._send_request(url, method, test_params, auth_headers)

                    if response and self._check_feature_gating(response, payload):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=method,
                            param=str(list(payload.payload.keys())[0]),
                            location="body",
                            payload=json.dumps(payload.payload),
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            confidence=payload.confidence,
                            status=response.get("status", 0),
                            evidence=response.get("body", "")[:500],
                            tier="confirmed" if payload.confidence > 0.8 else "suspicious",
                            tags=["business_logic", "saas", "feature_gating", payload.name],
                            notes=f"Feature gating bypass: {payload.name} - {payload.expected_effect}",
                        )
                        findings.append(finding)

                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue

        self._findings.extend(findings)
        return findings

    async def test_trial_abuse(
        self,
        target_url: str,
        endpoints: list[dict[str, Any]],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test for trial abuse vulnerabilities."""
        findings = []

        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "POST")
            params = endpoint.get("params", {})

            for payload in self.TRIAL_ABUSE_PAYLOADS:
                try:
                    test_params = {**params, **payload.payload}

                    response = await self._send_request(url, method, test_params, auth_headers)

                    if response and self._check_trial_abuse(response, payload):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=method,
                            param=str(list(payload.payload.keys())[0]),
                            location="body",
                            payload=json.dumps(payload.payload),
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            confidence=payload.confidence,
                            status=response.get("status", 0),
                            evidence=response.get("body", "")[:500],
                            tier="confirmed" if payload.confidence > 0.8 else "suspicious",
                            tags=["business_logic", "saas", "trial_abuse", payload.name],
                            notes=f"Trial abuse: {payload.name} - {payload.expected_effect}",
                        )
                        findings.append(finding)

                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue

        self._findings.extend(findings)
        return findings

    # ── Additional Helper Methods ───────────────────────────────────────

    def _check_feature_gating(self, response: dict[str, Any], payload: SaaSPayload) -> bool:
        """Check if feature gating was bypassed."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status in (200, 201, 202):
            if payload.expected_effect == "premium_access":
                if any(kw in body.lower() for kw in ["premium", "enterprise", "unlimited", "pro"]):
                    return True
            elif payload.expected_effect == "feature_flag_bypass":
                if "premium" in body.lower() and "true" in body.lower():
                    return True
            elif payload.expected_effect == "beta_access":
                if any(kw in body.lower() for kw in ["beta", "experimental", "early_access"]):
                    return True

        return False

    def _check_trial_abuse(self, response: dict[str, Any], payload: SaaSPayload) -> bool:
        """Check if trial abuse was accepted."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status in (200, 201, 202):
            if payload.expected_effect == "trial_extension":
                if "2099" in body or "extended" in body.lower():
                    return True
            elif payload.expected_effect == "multiple_trial":
                if "trial" in body.lower() and "active" in body.lower():
                    return True
            elif payload.expected_effect == "trial_conversion_bypass":
                if re.search(r'"status":\s*"active"', body) or "converted" in body.lower():
                    return True

        return False

    def get_findings(self) -> list[Finding]:
        """Get all findings from this tester."""
        return self._findings
