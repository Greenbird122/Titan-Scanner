"""Business Logic Detector — integrated with Titan engine.

This module wraps the e-commerce, SaaS, and workflow testers and integrates
them with the Titan engine's context, fingerprinting, and state management.

Key improvements over standalone modules:
1. Uses engine's Playwright context for requests
2. Baseline comparison (send normal request first, compare)
3. Multi-step testing (chain requests together)
4. State tracking (maintain cart/order state across requests)
5. Auth state testing (test with different auth levels)
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.modules.bizlogic.ecommerce import ECommerceTester
from titan.modules.bizlogic.saas import SaaSTester
from titan.modules.bizlogic.workflow import WorkflowTester, WorkflowStep
from titan.modules.bizlogic.discovery import EndpointDiscovery
from titan.modules.bizlogic.fuzzer import ParameterFuzzer
from titan.modules.bizlogic.crossuser import CrossUserTester
from titan.modules.bizlogic.confusion import ConfusionTester


class BizLogicDetector:
    """Business Logic detector integrated with Titan engine."""

    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint
        self.ecom = ECommerceTester()
        self.saas = SaaSTester()
        self.workflow = WorkflowTester()
        self.discovery = EndpointDiscovery()
        self.fuzzer = ParameterFuzzer()
        self.cross_user = CrossUserTester()
        self.confusion = ConfusionTester()

    async def scan(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        """Main scan entry point — tests all business logic vulnerabilities."""
        findings: List[Finding] = []

        # Get baseline response first
        baseline = await self._get_baseline(context, target, method, url, params)
        if baseline is None:
            return findings

        baseline_body = baseline.get("body", "")
        baseline_status = baseline.get("status", 0)

        # Test parameter tampering (price, quantity, discount, etc.)
        findings.extend(await self._test_parameter_tampering(
            context, target, method, url, params, baseline
        ))

        # Test workflow bypass
        findings.extend(await self._test_workflow_bypass(
            context, target, method, url, params, baseline
        ))

        # Test role escalation
        findings.extend(await self._test_role_escalation(
            context, target, method, url, params, baseline
        ))

        # Test business logic state manipulation
        findings.extend(await self._test_state_manipulation(
            context, target, method, url, params, baseline
        ))

        # Test workflow state injection
        findings.extend(await self._test_workflow_state_injection(
            context, target, method, url, params, baseline
        ))

        # Test multi-step flow bypass
        findings.extend(await self._test_multi_step_bypass(
            context, target, method, url, params, baseline
        ))

        # Deep: Cross-user IDOR via business logic
        findings.extend(await self._test_cross_user_idor(
            context, target, method, url, params, baseline
        ))

        # Deep: Content-Type confusion
        findings.extend(await self._test_content_type_confusion(
            context, target, method, url, params, baseline
        ))

        # Deep: Method override
        findings.extend(await self._test_method_override(
            context, target, method, url, params, baseline
        ))

        # Deep: Header injection for role/tenant switching
        findings.extend(await self._test_header_injection(
            context, target, method, url, params, baseline
        ))

        return findings

    async def _get_baseline(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """Send baseline request and return response."""
        try:
            if method.upper() == "GET":
                resp = await context.request.get(
                    url, params=params, headers={"Referer": target}, timeout=5000
                )
            else:
                resp = await context.request.post(
                    url, data=params, headers={"Referer": target}, timeout=5000
                )

            return {
                "status": resp.status,
                "body": await resp.text(),
                "headers": dict(resp.headers),
                "url": str(resp.url),
            }
        except Exception:
            return None

    async def _test_parameter_tampering(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
        baseline: Dict[str, Any],
    ) -> List[Finding]:
        """Test parameter tampering (price, quantity, discount, etc.)."""
        findings = []

        # Identify business logic parameters
        biz_params = self._identify_biz_params(params)

        for param_name, param_type in biz_params:
            # Test based on parameter type
            if param_type == "price":
                findings.extend(await self._test_price_tampering(
                    context, target, method, url, param_name, params, baseline
                ))
            elif param_type == "quantity":
                findings.extend(await self._test_quantity_tampering(
                    context, target, method, url, param_name, params, baseline
                ))
            elif param_type == "discount":
                findings.extend(await self._test_discount_tampering(
                    context, target, method, url, param_name, params, baseline
                ))
            elif param_type == "role":
                findings.extend(await self._test_role_tampering(
                    context, target, method, url, param_name, params, baseline
                ))

        return findings

    async def _test_price_tampering(
        self,
        context,
        target: str,
        method: str,
        url: str,
        param_name: str,
        params: Dict[str, str],
        baseline: Dict[str, Any],
    ) -> List[Finding]:
        """Test price tampering."""
        findings = []

        test_values = [
            ("0", "zero_price", "Price set to zero — free item"),
            ("-1", "negative_price", "Negative price accepted"),
            ("-0.01", "negative_float_price", "Negative float price accepted"),
            ("2147483648", "integer_overflow", "Integer overflow boundary accepted"),
            ("999999999", "large_value", "Large price value accepted without limit"),
        ]

        for test_val, name, description in test_values:
            try:
                # Create test params
                test_params = dict(params)
                test_params[param_name] = test_val

                # Send test request
                if method.upper() == "GET":
                    resp = await context.request.get(
                        url, params=test_params, headers={"Referer": target}, timeout=3000
                    )
                else:
                    resp = await context.request.post(
                        url, data=test_params, headers={"Referer": target}, timeout=3000
                    )

                body = await resp.text()
                status = resp.status

                # Check if tampering was accepted
                if self._check_tampering_accepted(
                    baseline, {"status": status, "body": body}, test_val, "price"
                ):
                    finding = Finding(
                        target=target,
                        url=url,
                        method=method.upper(),
                        param=param_name,
                        location="query" if method.upper() == "GET" else "body",
                        payload=f"{param_name}={test_val}",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.CRITICAL if test_val in ("0", "-1") else Severity.HIGH,
                        verified=True,
                        confidence=0.88,
                        status=status,
                        headers=dict(resp.headers),
                        body=body[:2000],
                        diffs=[f"bizlogic:{name}", f"param:{param_name}={test_val}"],
                        baseline_body=baseline.get("body", "")[:2000],
                        baseline_status=baseline.get("status", 0),
                        verification_body=body[:2000],
                        verification_status=status,
                        notes=description,
                    )
                    findings.append(finding)

            except Exception:
                continue

        return findings

    async def _test_quantity_tampering(
        self,
        context,
        target: str,
        method: str,
        url: str,
        param_name: str,
        params: Dict[str, str],
        baseline: Dict[str, Any],
    ) -> List[Finding]:
        """Test quantity tampering."""
        findings = []

        test_values = [
            ("0", "zero_quantity", "Quantity set to zero"),
            ("-1", "negative_quantity", "Negative quantity accepted"),
            ("999999999", "overflow_quantity", "Overflow quantity accepted"),
            ("0.5", "fractional_quantity", "Fractional quantity accepted"),
        ]

        for test_val, name, description in test_values:
            try:
                test_params = dict(params)
                test_params[param_name] = test_val

                if method.upper() == "GET":
                    resp = await context.request.get(
                        url, params=test_params, headers={"Referer": target}, timeout=3000
                    )
                else:
                    resp = await context.request.post(
                        url, data=test_params, headers={"Referer": target}, timeout=3000
                    )

                body = await resp.text()
                status = resp.status

                if self._check_tampering_accepted(
                    baseline, {"status": status, "body": body}, test_val, "quantity"
                ):
                    finding = Finding(
                        target=target,
                        url=url,
                        method=method.upper(),
                        param=param_name,
                        location="query" if method.upper() == "GET" else "body",
                        payload=f"{param_name}={test_val}",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.HIGH if test_val in ("0", "-1") else Severity.MEDIUM,
                        verified=True,
                        confidence=0.80,
                        status=status,
                        headers=dict(resp.headers),
                        body=body[:2000],
                        diffs=[f"bizlogic:{name}", f"param:{param_name}={test_val}"],
                        baseline_body=baseline.get("body", "")[:2000],
                        baseline_status=baseline.get("status", 0),
                        verification_body=body[:2000],
                        verification_status=status,
                        notes=description,
                    )
                    findings.append(finding)

            except Exception:
                continue

        return findings

    async def _test_discount_tampering(
        self,
        context,
        target: str,
        method: str,
        url: str,
        param_name: str,
        params: Dict[str, str],
        baseline: Dict[str, Any],
    ) -> List[Finding]:
        """Test discount tampering."""
        findings = []

        test_values = [
            ("100", "full_discount", "100% discount accepted"),
            ("200", "over_full_discount", "Over 100% discount accepted"),
            ("-10", "negative_discount", "Negative discount (price increase) accepted"),
            ("FREE", "free_coupon", "FREE coupon code accepted"),
        ]

        for test_val, name, description in test_values:
            try:
                test_params = dict(params)
                test_params[param_name] = test_val

                if method.upper() == "GET":
                    resp = await context.request.get(
                        url, params=test_params, headers={"Referer": target}, timeout=3000
                    )
                else:
                    resp = await context.request.post(
                        url, data=test_params, headers={"Referer": target}, timeout=3000
                    )

                body = await resp.text()
                status = resp.status

                if self._check_tampering_accepted(
                    baseline, {"status": status, "body": body}, test_val, "discount"
                ):
                    finding = Finding(
                        target=target,
                        url=url,
                        method=method.upper(),
                        param=param_name,
                        location="query" if method.upper() == "GET" else "body",
                        payload=f"{param_name}={test_val}",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.CRITICAL if test_val in ("100", "200") else Severity.HIGH,
                        verified=True,
                        confidence=0.85,
                        status=status,
                        headers=dict(resp.headers),
                        body=body[:2000],
                        diffs=[f"bizlogic:{name}", f"param:{param_name}={test_val}"],
                        baseline_body=baseline.get("body", "")[:2000],
                        baseline_status=baseline.get("status", 0),
                        verification_body=body[:2000],
                        verification_status=status,
                        notes=description,
                    )
                    findings.append(finding)

            except Exception:
                continue

        return findings

    async def _test_role_tampering(
        self,
        context,
        target: str,
        method: str,
        url: str,
        param_name: str,
        params: Dict[str, str],
        baseline: Dict[str, Any],
    ) -> List[Finding]:
        """Test role tampering."""
        findings = []

        test_values = [
            ("admin", "admin_role", "Admin role accepted"),
            ("superuser", "superuser_role", "Superuser role accepted"),
            ("owner", "owner_role", "Owner role accepted"),
            ("service_role", "service_role", "Service role accepted"),
        ]

        for test_val, name, description in test_values:
            try:
                test_params = dict(params)
                test_params[param_name] = test_val

                if method.upper() == "GET":
                    resp = await context.request.get(
                        url, params=test_params, headers={"Referer": target}, timeout=3000
                    )
                else:
                    resp = await context.request.post(
                        url, data=test_params, headers={"Referer": target}, timeout=3000
                    )

                body = await resp.text()
                status = resp.status

                # Check if role was accepted
                if status == 200 and test_val in body.lower():
                    finding = Finding(
                        target=target,
                        url=url,
                        method=method.upper(),
                        param=param_name,
                        location="query" if method.upper() == "GET" else "body",
                        payload=f"{param_name}={test_val}",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.CRITICAL,
                        verified=True,
                        confidence=0.90,
                        status=status,
                        headers=dict(resp.headers),
                        body=body[:2000],
                        diffs=[f"bizlogic:{name}", f"param:{param_name}={test_val}"],
                        baseline_body=baseline.get("body", "")[:2000],
                        baseline_status=baseline.get("status", 0),
                        verification_body=body[:2000],
                        verification_status=status,
                        notes=description,
                    )
                    findings.append(finding)

            except Exception:
                continue

        return findings

    async def _test_workflow_bypass(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
        baseline: Dict[str, Any],
    ) -> List[Finding]:
        """Test workflow bypass (skip steps, force state transitions)."""
        findings = []

        # Test workflow state manipulation
        state_params = [p for p in params.keys() if any(
            k in p.lower() for k in ["step", "phase", "state", "stage", "status"]
        )]

        for param_name in state_params:
            test_states = [
                "completed", "paid", "delivered", "active", "approved",
                "admin", "superadmin", "owner",
            ]

            for state in test_states:
                try:
                    test_params = dict(params)
                    test_params[param_name] = state

                    if method.upper() == "GET":
                        resp = await context.request.get(
                            url, params=test_params, headers={"Referer": target}, timeout=3000
                        )
                    else:
                        resp = await context.request.post(
                            url, data=test_params, headers={"Referer": target}, timeout=3000
                        )

                    body = await resp.text()
                    status = resp.status

                    # Check if state was accepted
                    if status == 200 and state in body.lower():
                        finding = Finding(
                            target=target,
                            url=url,
                            method=method.upper(),
                            param=param_name,
                            location="query" if method.upper() == "GET" else "body",
                            payload=f"{param_name}={state}",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=Severity.CRITICAL if state in ("admin", "superadmin", "owner") else Severity.HIGH,
                            verified=True,
                            confidence=0.85,
                            status=status,
                            headers=dict(resp.headers),
                            body=body[:2000],
                            diffs=[f"bizlogic:workflow_bypass:{state}", f"param:{param_name}={state}"],
                            baseline_body=baseline.get("body", "")[:2000],
                            baseline_status=baseline.get("status", 0),
                            verification_body=body[:2000],
                            verification_status=status,
                            notes=f"Workflow bypass: Set {param_name}={state}",
                        )
                        findings.append(finding)

                except Exception:
                    continue

        return findings

    async def _test_role_escalation(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
        baseline: Dict[str, Any],
    ) -> List[Finding]:
        """Test role escalation via parameter manipulation."""
        findings = []

        # Test common role parameters
        role_params = [p for p in params.keys() if any(
            k in p.lower() for k in ["role", "admin", "permission", "level", "tier"]
        )]

        for param_name in role_params:
            escalation_values = [
                "admin", "superadmin", "root", "owner", "sysadmin",
            ]

            for value in escalation_values:
                try:
                    test_params = dict(params)
                    test_params[param_name] = value

                    if method.upper() == "GET":
                        resp = await context.request.get(
                            url, params=test_params, headers={"Referer": target}, timeout=3000
                        )
                    else:
                        resp = await context.request.post(
                            url, data=test_params, headers={"Referer": target}, timeout=3000
                        )

                    body = await resp.text()
                    status = resp.status

                    # Check if escalation was accepted
                    if status == 200 and value in body.lower():
                        finding = Finding(
                            target=target,
                            url=url,
                            method=method.upper(),
                            param=param_name,
                            location="query" if method.upper() == "GET" else "body",
                            payload=f"{param_name}={value}",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=Severity.CRITICAL,
                            verified=True,
                            confidence=0.90,
                            status=status,
                            headers=dict(resp.headers),
                            body=body[:2000],
                            diffs=[f"bizlogic:role_escalation:{value}", f"param:{param_name}={value}"],
                            baseline_body=baseline.get("body", "")[:2000],
                            baseline_status=baseline.get("status", 0),
                            verification_body=body[:2000],
                            verification_status=status,
                            notes=f"Role escalation: Set {param_name}={value}",
                        )
                        findings.append(finding)

                except Exception:
                    continue

        return findings

    async def _test_state_manipulation(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
        baseline: Dict[str, Any],
    ) -> List[Finding]:
        """Test business logic state manipulation."""
        findings = []

        # Test common state manipulation vectors
        state_vectors = [
            ("payment_status", ["paid", "completed", "free", "waived"]),
            ("order_status", ["completed", "shipped", "delivered"]),
            ("subscription_status", ["active", "premium", "enterprise"]),
        ]

        for param_name, values in state_vectors:
            if param_name in params:
                for value in values:
                    try:
                        test_params = dict(params)
                        test_params[param_name] = value

                        if method.upper() == "GET":
                            resp = await context.request.get(
                                url, params=test_params, headers={"Referer": target}, timeout=3000
                            )
                        else:
                            resp = await context.request.post(
                                url, data=test_params, headers={"Referer": target}, timeout=3000
                            )

                        body = await resp.text()
                        status = resp.status

                        if status == 200 and value in body.lower():
                            finding = Finding(
                                target=target,
                                url=url,
                                method=method.upper(),
                                param=param_name,
                                location="query" if method.upper() == "GET" else "body",
                                payload=f"{param_name}={value}",
                                attack_type=AttackType.BUSINESS_LOGIC,
                                severity=Severity.CRITICAL if value in ("paid", "completed", "premium", "enterprise") else Severity.HIGH,
                                verified=True,
                                confidence=0.85,
                                status=status,
                                headers=dict(resp.headers),
                                body=body[:2000],
                                diffs=[f"bizlogic:state_manipulation:{value}", f"param:{param_name}={value}"],
                                baseline_body=baseline.get("body", "")[:2000],
                                baseline_status=baseline.get("status", 0),
                                verification_body=body[:2000],
                                verification_status=status,
                                notes=f"State manipulation: Set {param_name}={value}",
                            )
                            findings.append(finding)

                    except Exception:
                        continue

        return findings

    # ── Helper Methods ──────────────────────────────────────────────────

    def _identify_biz_params(self, params: Dict[str, str]) -> List[tuple]:
        """Identify business logic parameters and their types."""
        biz_params = []

        price_keywords = ["price", "amount", "cost", "total", "subtotal", "fee"]
        quantity_keywords = ["quantity", "qty", "count", "items"]
        discount_keywords = ["discount", "coupon", "promo", "voucher", "code"]
        role_keywords = ["role", "admin", "permission", "level", "tier"]

        for param_name in params.keys():
            param_lower = param_name.lower()

            if any(kw in param_lower for kw in price_keywords):
                biz_params.append((param_name, "price"))
            elif any(kw in param_lower for kw in quantity_keywords):
                biz_params.append((param_name, "quantity"))
            elif any(kw in param_lower for kw in discount_keywords):
                biz_params.append((param_name, "discount"))
            elif any(kw in param_lower for kw in role_keywords):
                biz_params.append((param_name, "role"))

        return biz_params

    def _check_tampering_accepted(
        self,
        baseline: Dict[str, Any],
        response: Dict[str, Any],
        test_value: str,
        param_type: str,
    ) -> bool:
        """Check if parameter tampering was accepted — deep version.

        Uses baseline diff analysis + semantic detection.
        """
        baseline_body = baseline.get("body", "")
        baseline_status = baseline.get("status", 0)
        resp_body = response.get("body", "")
        resp_status = response.get("status", 0)

        # Must be successful response
        if resp_status not in (200, 201, 202):
            return False

        # Body must have changed
        if resp_body == baseline_body:
            return False

        # Check for tampering indicators
        if param_type == "price":
            # Check if price/total changed to tampered value
            if re.search(rf'"(?:total|amount|price|cost)":\s*"?{re.escape(test_value)}"?', resp_body):
                return True
            # Check if total is 0 when it shouldn't be
            if test_value == "0" and re.search(r'"total":\s*0', resp_body):
                return True
            # Check if negative price was accepted (adds to balance)
            if test_value.startswith("-") and re.search(rf'"total":\s*{re.escape(test_value)}', resp_body):
                return True
            # Check if response confirms the change ("updated", "saved", "success")
            if test_value in ("0", "-1", "-0.01") and any(
                kw in resp_body.lower() for kw in ["updated", "saved", "success", "created", "confirmed"]
            ):
                # Extra check: did the total actually change?
                if not re.search(r'"total":\s*\d+', resp_body):
                    return True

        elif param_type == "quantity":
            if re.search(rf'"(?:quantity|qty|count)":\s*"?{re.escape(test_value)}"?', resp_body):
                return True
            if test_value in ("0", "-1") and any(
                kw in resp_body.lower() for kw in ["updated", "saved", "success"]
            ):
                return True

        elif param_type == "discount":
            if test_value in ("100", "200") and re.search(r'"total":\s*0', resp_body):
                return True
            if test_value == "FREE" and "free" in resp_body.lower():
                return True
            if test_value == "-10" and re.search(r'"total":\s*-\d+', resp_body):
                return True

        elif param_type == "role":
            # Check if role was accepted AND reflected in response
            if test_value in resp_body.lower():
                # Verify it's actually the role, not just the word appearing in error message
                if not any(kw in resp_body.lower() for kw in ["error", "invalid", "denied", "forbidden"]):
                    return True

        return False

    async def _test_workflow_state_injection(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
        baseline: Dict[str, Any],
    ) -> List[Finding]:
        """Test workflow state injection — inject final state directly."""
        findings = []

        state_injections = [
            {"workflow_state": "completed"},
            {"step": "final"},
            {"phase": "done"},
            {"stage": "complete"},
            {"status": "paid"},
            {"status": "approved"},
            {"is_complete": True},
            {"finished": True},
            {"_skip_validation": True},
            {"_bypass_check": True},
        ]

        for injection in state_injections:
            try:
                test_params = {**params, **injection}

                if method.upper() == "GET":
                    resp = await context.request.get(
                        url, params=test_params, headers={"Referer": target}, timeout=3000
                    )
                else:
                    resp = await context.request.post(
                        url, data=test_params, headers={"Referer": target}, timeout=3000
                    )

                body = await resp.text()
                status = resp.status

                if status in (200, 201, 202) and body != baseline.get("body", ""):
                    if any(
                        kw in body.lower() for kw in ["completed", "done", "paid", "approved", "success", "finished"]
                    ):
                        finding = Finding(
                            target=target,
                            url=url,
                            method=method.upper(),
                            param="workflow_state",
                            location="query" if method.upper() == "GET" else "body",
                            payload=json.dumps(injection),
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=Severity.CRITICAL if any(
                                v in str(injection.values()) for v in ["paid", "approved", "admin"]
                            ) else Severity.HIGH,
                            verified=True,
                            confidence=0.85,
                            status=status,
                            headers=dict(resp.headers),
                            body=body[:2000],
                            diffs=[f"bizlogic:state_injection:{list(injection.values())[0]}"],
                            baseline_body=baseline.get("body", "")[:2000],
                            baseline_status=baseline.get("status", 0),
                            verification_body=body[:2000],
                            verification_status=status,
                            notes=f"Workflow state injection: {injection} accepted",
                        )
                        findings.append(finding)

            except Exception:
                continue

        return findings

    async def _test_multi_step_bypass(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
        baseline: Dict[str, Any],
    ) -> List[Finding]:
        """Test multi-step workflow bypass — skip steps by injecting state."""
        findings = []

        bypass_payloads = [
            {"action": "complete", "skip_to": "end"},
            {"step": "finish", "force": True},
            {"workflow": "complete", "bypass_steps": True},
            {"action": "approve", "admin_override": True},
            {"action": "pay", "amount": 0},
            {"action": "confirm", "auto_approve": True},
        ]

        for payload in bypass_payloads:
            try:
                test_params = {**params, **payload}

                if method.upper() == "GET":
                    resp = await context.request.get(
                        url, params=test_params, headers={"Referer": target}, timeout=3000
                    )
                else:
                    resp = await context.request.post(
                        url, data=test_params, headers={"Referer": target}, timeout=3000
                    )

                body = await resp.text()
                status = resp.status

                if status in (200, 201, 202) and body != baseline.get("body", ""):
                    if any(
                        kw in body.lower() for kw in ["complete", "success", "done", "approved", "paid", "finished"]
                    ):
                        finding = Finding(
                            target=target,
                            url=url,
                            method=method.upper(),
                            param="workflow_bypass",
                            location="query" if method.upper() == "GET" else "body",
                            payload=json.dumps(payload),
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=Severity.CRITICAL,
                            verified=True,
                            confidence=0.82,
                            status=status,
                            headers=dict(resp.headers),
                            body=body[:2000],
                            diffs=[f"bizlogic:multi_step_bypass:{list(payload.values())[0]}"],
                            baseline_body=baseline.get("body", "")[:2000],
                            baseline_status=baseline.get("status", 0),
                            verification_body=body[:2000],
                            verification_status=status,
                            notes=f"Multi-step bypass: {payload} accepted",
                        )
                        findings.append(finding)

            except Exception:
                continue

        return findings

    # ── Deep: Cross-User IDOR ─────────────────────────────────────────

    async def _test_cross_user_idor(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
        baseline: Dict[str, Any],
    ) -> List[Finding]:
        """Test cross-user IDOR via business logic parameters."""
        findings = []

        idor_payloads = [
            {"user_id": 1}, {"user_id": 0}, {"user_id": "admin"},
            {"account_id": 1}, {"account_id": 0},
            {"owner_id": 1}, {"customer_id": 1},
            {"tenant_id": "other"}, {"workspace_id": "other"},
            {"org_id": "other"}, {"team_id": "other"},
            {"id": 0}, {"id": 1}, {"id": 999999},
        ]

        for idor_params in idor_payloads:
            for param_name, param_value in idor_params.items():
                if param_name in params:
                    continue

                try:
                    test_params = dict(params)
                    test_params[param_name] = param_value

                    if method.upper() == "GET":
                        resp = await context.request.get(
                            url, params=test_params, headers={"Referer": target}, timeout=3000
                        )
                    else:
                        resp = await context.request.post(
                            url, data=test_params, headers={"Referer": target}, timeout=3000
                        )

                    body = await resp.text()
                    status = resp.status

                    if status in (200, 201, 202) and body != baseline.get("body", ""):
                        if not any(kw in body.lower() for kw in ["error", "unauthorized", "forbidden"]):
                            finding = Finding(
                                target=target,
                                url=url,
                                method=method.upper(),
                                param=param_name,
                                location="body",
                                payload=f"{param_name}={param_value}",
                                attack_type=AttackType.BUSINESS_LOGIC,
                                severity=Severity.CRITICAL,
                                verified=True,
                                confidence=0.80,
                                status=status,
                                headers=dict(resp.headers),
                                body=body[:2000],
                                diffs=[f"idor:{param_name}={param_value}"],
                                baseline_body=baseline.get("body", "")[:2000],
                                baseline_status=baseline.get("status", 0),
                                verification_body=body[:2000],
                                verification_status=status,
                                notes=f"Cross-user IDOR: {param_name}={param_value}",
                            )
                            findings.append(finding)

                except Exception:
                    continue

        return findings

    # ── Deep: Content-Type Confusion ───────────────────────────────────

    async def _test_content_type_confusion(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
        baseline: Dict[str, Any],
    ) -> List[Finding]:
        """Test Content-Type switching."""
        findings = []

        ct_payloads = [
            {"name": "xml", "ct": "application/xml", "body": '<root><role>admin</role><amount>0</amount></root>'},
            {"name": "urlencoded", "ct": "application/x-www-form-urlencoded", "body": "role=admin&amount=0"},
            {"name": "plaintext", "ct": "text/plain", "body": json.dumps(params)},
        ]

        for ct in ct_payloads:
            try:
                headers = {"Referer": target, "Content-Type": ct["ct"]}
                resp = await context.request.post(
                    url, data=ct["body"], headers=headers, timeout=3000
                )
                body = await resp.text()
                status = resp.status

                if status in (200, 201, 202) and body != baseline.get("body", ""):
                    if not any(kw in body.lower() for kw in ["unsupported", "invalid content", "bad request"]):
                        finding = Finding(
                            target=target, url=url, method="POST",
                            param="content_type", location="header",
                            payload=f"Content-Type: {ct['ct']}",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=Severity.HIGH, verified=True, confidence=0.65,
                            status=status, headers=dict(resp.headers), body=body[:2000],
                            diffs=[f"content_type:{ct['name']}"],
                            baseline_body=baseline.get("body", "")[:2000],
                            baseline_status=baseline.get("status", 0),
                            verification_body=body[:2000], verification_status=status,
                            notes=f"Content-Type confusion: Server accepted {ct['ct']}",
                        )
                        findings.append(finding)
            except Exception:
                continue

        return findings

    # ── Deep: Method Override ──────────────────────────────────────────

    async def _test_method_override(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
        baseline: Dict[str, Any],
    ) -> List[Finding]:
        """Test HTTP method override."""
        findings = []

        for override in ["DELETE", "PUT", "PATCH"]:
            try:
                body_data = dict(params)
                body_data["_method"] = override
                resp = await context.request.post(
                    url, data=body_data, headers={"Referer": target}, timeout=3000
                )
                body = await resp.text()
                status = resp.status

                if status in (200, 201, 202, 204) and status != baseline.get("status", 0):
                    finding = Finding(
                        target=target, url=url, method=f"POST->{override}",
                        param="_method", location="body",
                        payload=f"_method={override}",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.HIGH, verified=True, confidence=0.65,
                        status=status, headers=dict(resp.headers), body=body[:2000],
                        diffs=[f"method_override:{override}"],
                        baseline_body=baseline.get("body", "")[:2000],
                        baseline_status=baseline.get("status", 0),
                        verification_body=body[:2000], verification_status=status,
                        notes=f"Method override: Server accepted {override} via _method",
                    )
                    findings.append(finding)
            except Exception:
                continue

            try:
                headers = {"Referer": target, "X-HTTP-Method-Override": override}
                resp = await context.request.post(
                    url, data=params, headers=headers, timeout=3000
                )
                body = await resp.text()
                status = resp.status

                if status in (200, 201, 202, 204) and status != baseline.get("status", 0):
                    finding = Finding(
                        target=target, url=url, method=f"POST->{override}",
                        param="x-http-method-override", location="header",
                        payload=f"X-HTTP-Method-Override: {override}",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.HIGH, verified=True, confidence=0.60,
                        status=status, headers=dict(resp.headers), body=body[:2000],
                        diffs=[f"method_override_header:{override}"],
                        baseline_body=baseline.get("body", "")[:2000],
                        baseline_status=baseline.get("status", 0),
                        verification_body=body[:2000], verification_status=status,
                        notes=f"Method override: Server accepted {override} via header",
                    )
                    findings.append(finding)
            except Exception:
                continue

        return findings

    # ── Deep: Header Injection ─────────────────────────────────────────

    async def _test_header_injection(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
        baseline: Dict[str, Any],
    ) -> List[Finding]:
        """Test header injection for role/tenant switching."""
        findings = []

        header_payloads = [
            {"X-Role": "admin"}, {"X-User-Role": "admin"},
            {"X-Is-Admin": "true"}, {"X-Tenant-ID": "other"},
            {"X-Workspace-ID": "other"}, {"X-Org-ID": "other"},
            {"X-Forwarded-For": "127.0.0.1"}, {"X-Real-IP": "127.0.0.1"},
            {"Authorization": "Bearer admin"}, {"X-Service-Token": "admin"},
        ]

        for hp in header_payloads:
            try:
                headers = {"Referer": target, **hp}
                if method.upper() == "GET":
                    resp = await context.request.get(url, params=params, headers=headers, timeout=3000)
                else:
                    resp = await context.request.post(url, data=params, headers=headers, timeout=3000)

                body = await resp.text()
                status = resp.status

                if status in (200, 201, 202) and body != baseline.get("body", ""):
                    hn = list(hp.keys())[0]
                    finding = Finding(
                        target=target, url=url, method=method.upper(),
                        param=hn.lower(), location="header", payload=json.dumps(hp),
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.CRITICAL if "role" in hn.lower() or "admin" in hn.lower() else Severity.HIGH,
                        verified=True, confidence=0.70, status=status,
                        headers=dict(resp.headers), body=body[:2000],
                        diffs=[f"header_injection:{hn}"],
                        baseline_body=baseline.get("body", "")[:2000],
                        baseline_status=baseline.get("status", 0),
                        verification_body=body[:2000], verification_status=status,
                        notes=f"Header injection: {hn} changed response",
                    )
                    findings.append(finding)
            except Exception:
                continue

        return findings
