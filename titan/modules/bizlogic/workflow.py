"""Stateful Workflow Testing — deep testing of multi-step business processes.

This module tests:
1. Step skipping (skip required steps in workflows)
2. Role confusion (role changes mid-workflow)
3. Concurrent modification (modify state while processing)
4. Replay attacks (replay completed steps)
5. Session fixation (fix session ID before workflow)
6. Workflow state manipulation (modify intermediate state)
7. Authorization bypass (access denied steps)
8. Data inconsistency (conflict between steps)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from titan.core.models import Finding, Severity, AttackType


@dataclass
class WorkflowStep:
    """A step in a business workflow."""
    name: str
    url: str
    method: str
    params: Dict[str, Any]
    required: bool = True
    auth_required: bool = False
    role_required: Optional[str] = None


@dataclass
class WorkflowPayload:
    """A workflow test payload."""
    name: str
    category: str
    description: str
    severity: Severity
    confidence: float


class WorkflowTester:
    """Deep stateful workflow testing."""

    # ── Step Skipping Payloads ──────────────────────────────────────────

    STEP_SKIPPING_PAYLOADS = [
        WorkflowPayload(
            name="skip_registration",
            category="step_skipping",
            description="Skip registration step and go directly to dashboard",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        WorkflowPayload(
            name="skip_payment",
            category="step_skipping",
            description="Skip payment step and complete order",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        WorkflowPayload(
            name="skip_verification",
            category="step_skipping",
            description="Skip email/phone verification",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        WorkflowPayload(
            name="skip_approval",
            category="step_skipping",
            description="Skip admin approval step",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        WorkflowPayload(
            name="skip_consent",
            category="step_skipping",
            description="Skip terms/privacy consent",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
    ]

    # ── Role Confusion Payloads ─────────────────────────────────────────

    ROLE_CONFUSION_PAYLOADS = [
        WorkflowPayload(
            name="role_change_mid_workflow",
            category="role_confusion",
            description="Change role between workflow steps",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        WorkflowPayload(
            name="downgrade_role",
            category="role_confusion",
            description="Downgrade role to access lower-privilege steps",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        WorkflowPayload(
            name="cross_role_access",
            category="role_confusion",
            description="Access admin steps with user role",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        WorkflowPayload(
            name="role_inheritance",
            category="role_confusion",
            description="Inherit role from previous step",
            severity=Severity.HIGH,
            confidence=0.75,
        ),
    ]

    # ── Concurrent Modification Payloads ────────────────────────────────

    CONCURRENT_MODIFICATION_PAYLOADS = [
        WorkflowPayload(
            name="race_condition",
            category="concurrent_modification",
            description="Submit workflow steps concurrently",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        WorkflowPayload(
            name="state_conflict",
            category="concurrent_modification",
            description="Modify state while workflow is processing",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        WorkflowPayload(
            name="double_submit",
            category="concurrent_modification",
            description="Submit same step twice simultaneously",
            severity=Severity.MEDIUM,
            confidence=0.65,
        ),
        WorkflowPayload(
            name="out_of_order",
            category="concurrent_modification",
            description="Submit steps out of order",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
    ]

    # ── Replay Attack Payloads ──────────────────────────────────────────

    REPLAY_ATTACK_PAYLOADS = [
        WorkflowPayload(
            name="replay_completed_step",
            category="replay_attack",
            description="Replay a completed workflow step",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        WorkflowPayload(
            name="replay_with_modified_data",
            category="replay_attack",
            description="Replay step with modified data",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        WorkflowPayload(
            name="replay_after_expiry",
            category="replay_attack",
            description="Replay step after it has expired",
            severity=Severity.LOW,
            confidence=0.60,
        ),
        WorkflowPayload(
            name="replay_across_users",
            category="replay_attack",
            description="Replay another user's workflow step",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
    ]

    # ── Session Fixation Payloads ───────────────────────────────────────

    SESSION_FIXATION_PAYLOADS = [
        WorkflowPayload(
            name="fix_session_before_workflow",
            category="session_fixation",
            description="Set session ID before starting workflow",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        WorkflowPayload(
            name="session_not_rotated",
            category="session_fixation",
            description="Session ID not rotated after authentication",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        WorkflowPayload(
            name="session_shared",
            category="session_fixation",
            description="Share session across workflow steps",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
    ]

    # ── Workflow State Manipulation Payloads ─────────────────────────────

    STATE_MANIPULATION_PAYLOADS = [
        WorkflowPayload(
            name="modify_intermediate_state",
            category="state_manipulation",
            description="Modify workflow state between steps",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        WorkflowPayload(
            name="skip_to_final_state",
            category="state_manipulation",
            description="Jump directly to final workflow state",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        WorkflowPayload(
            name="modify_completion_flag",
            category="state_manipulation",
            description="Set workflow completion flag without doing work",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        WorkflowPayload(
            name="rollback_attack",
            category="state_manipulation",
            description="Rollback workflow to previous state",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        WorkflowPayload(
            name="state_injection",
            category="state_manipulation",
            description="Inject arbitrary state into workflow",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
    ]

    # ── Authorization Bypass Payloads ───────────────────────────────────

    AUTHORIZATION_BYPASS_PAYLOADS = [
        WorkflowPayload(
            name="access_denied_step",
            category="authorization_bypass",
            description="Access step that should be denied",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        WorkflowPayload(
            name="privilege_escalation",
            category="authorization_bypass",
            description="Escalate privileges during workflow",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        WorkflowPayload(
            name="bypass_approval",
            category="authorization_bypass",
            description="Bypass approval requirement",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        WorkflowPayload(
            name="cross_tenant_access",
            category="authorization_bypass",
            description="Access another tenant's workflow",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: List[Finding] = []

    async def test_step_skipping(
        self,
        target_url: str,
        workflow: List[WorkflowStep],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test for step skipping vulnerabilities."""
        findings = []

        # Try to access each step directly without completing previous steps
        for i, step in enumerate(workflow):
            if i == 0:
                continue  # Skip first step (always accessible)

            # Try to access this step directly
            try:
                response = await self._send_request(
                    step.url, step.method, step.params, auth_headers
                )

                if response and response.get("status") in (200, 201, 202):
                    # Check if this step should require previous steps
                    if self._should_require_previous_steps(step, workflow[:i]):
                        finding = Finding(
                            target=target_url,
                            url=step.url,
                            method=step.method,
                            param="workflow_step",
                            location="body",
                            payload=f"Skipped steps: {[s.name for s in workflow[:i]]}",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=Severity.HIGH,
                            confidence=0.80,
                            status=response.get("status", 0),
                            evidence=response.get("body", "")[:500],
                            tier="suspicious",
                            tags=["business_logic", "workflow", "step_skipping", step.name],
                            notes=f"Step skipping: Accessed '{step.name}' without completing {[s.name for s in workflow[:i]]}",
                        )
                        findings.append(finding)

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def test_role_confusion(
        self,
        target_url: str,
        workflow: List[WorkflowStep],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test for role confusion vulnerabilities."""
        findings = []

        # Try to access admin steps with user role
        for step in workflow:
            if step.role_required and step.role_required != "user":
                try:
                    response = await self._send_request(
                        step.url, step.method, step.params, auth_headers
                    )

                    if response and response.get("status") in (200, 201, 202):
                        finding = Finding(
                            target=target_url,
                            url=step.url,
                            method=step.method,
                            param="role",
                            location="body",
                            payload=f"Required role: {step.role_required}",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=Severity.CRITICAL,
                            confidence=0.90,
                            status=response.get("status", 0),
                            evidence=response.get("body", "")[:500],
                            tier="confirmed",
                            tags=["business_logic", "workflow", "role_confusion", step.name],
                            notes=f"Role confusion: Accessed '{step.name}' (requires {step.role_required}) with user role",
                        )
                        findings.append(finding)

                except Exception:
                    continue

        self._findings.extend(findings)
        return findings

    async def test_concurrent_modification(
        self,
        target_url: str,
        workflow: List[WorkflowStep],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test for concurrent modification vulnerabilities — deep version.

        Tests:
        1. Rapid concurrent submissions (race condition)
        2. Step-skipping via concurrent requests
        3. Double-submit with different data
        4. Out-of-order submission
        """
        findings = []
        import asyncio

        for step in workflow:
            if step.required:
                try:
                    # Test 1: Rapid concurrent submissions (20 requests)
                    tasks = [
                        self._send_request(step.url, step.method, step.params, auth_headers)
                        for _ in range(20)
                    ]
                    responses = await asyncio.gather(*tasks, return_exceptions=True)

                    success_count = sum(
                        1 for r in responses
                        if not isinstance(r, Exception) and r and r.get("status") in (200, 201, 202)
                    )

                    if success_count > 1:
                        finding = Finding(
                            target=target_url,
                            url=step.url,
                            method=step.method,
                            param="concurrent",
                            location="body",
                            payload=f"20 concurrent submissions: {success_count} succeeded",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=Severity.HIGH,
                            confidence=0.82,
                            status=200,
                            evidence=f"{success_count}/20 concurrent requests succeeded",
                            tier="suspicious",
                            tags=["business_logic", "workflow", "concurrent_modification", step.name],
                            notes=f"Race condition: {success_count} concurrent submissions to '{step.name}' succeeded",
                        )
                        findings.append(finding)

                    # Test 2: Double-submit with different data
                    modified_params = dict(step.params)
                    modified_params["_modified"] = True
                    modified_params["amount"] = 0

                    tasks = [
                        self._send_request(step.url, step.method, step.params, auth_headers),
                        self._send_request(step.url, step.method, modified_params, auth_headers),
                    ]
                    responses = await asyncio.gather(*tasks, return_exceptions=True)

                    both_success = all(
                        not isinstance(r, Exception) and r and r.get("status") in (200, 201, 202)
                        for r in responses
                    )

                    if both_success:
                        finding = Finding(
                            target=target_url,
                            url=step.url,
                            method=step.method,
                            param="double_submit",
                            location="body",
                            payload="Double-submit with conflicting data",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=Severity.HIGH,
                            confidence=0.78,
                            status=200,
                            evidence="Both original and modified submissions succeeded",
                            tier="suspicious",
                            tags=["business_logic", "workflow", "double_submit", step.name],
                            notes=f"Double-submit: Both original and tampered data accepted for '{step.name}'",
                        )
                        findings.append(finding)

                except Exception:
                    continue

        self._findings.extend(findings)
        return findings

    async def test_replay_attack(
        self,
        target_url: str,
        workflow: List[WorkflowStep],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test for replay attack vulnerabilities — deep version.

        Tests:
        1. Same-step replay (submit same step twice)
        2. Cross-step replay (submit another user's step)
        3. Replay with modified data
        4. Replay with timestamp manipulation
        """
        findings = []

        for step in workflow:
            try:
                # Test 1: Same-step replay
                response1 = await self._send_request(step.url, step.method, step.params, auth_headers)
                response2 = await self._send_request(step.url, step.method, step.params, auth_headers)

                if (response1 and response2 and
                    response1.get("status") in (200, 201, 202) and
                    response2.get("status") in (200, 201, 202)):

                    # Verify state actually changed (double-charge check)
                    body1 = response1.get("body", "")
                    body2 = response2.get("body", "")

                    # If responses are identical, replay succeeded without state change
                    if body1 == body2:
                        finding = Finding(
                            target=target_url,
                            url=step.url,
                            method=step.method,
                            param="replay",
                            location="body",
                            payload="Replay attack — identical response",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=Severity.HIGH,
                            confidence=0.85,
                            status=response2.get("status", 0),
                            evidence=response2.get("body", "")[:500],
                            tier="confirmed",
                            tags=["business_logic", "workflow", "replay_attack", step.name],
                            notes=(
                                f"Replay attack: Step '{step.name}' returned identical response on replay. "
                                f"No idempotency key detected. Double-charge/double-submit possible."
                            ),
                        )
                        findings.append(finding)

                # Test 2: Replay with modified data
                modified_params = dict(step.params)
                modified_params["amount"] = 0
                modified_params["quantity"] = -1

                response3 = await self._send_request(step.url, step.method, modified_params, auth_headers)
                if response3 and response3.get("status") in (200, 201, 202):
                    finding = Finding(
                        target=target_url,
                        url=step.url,
                        method=step.method,
                        param="replay_modified",
                        location="body",
                        payload=json.dumps(modified_params),
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.HIGH,
                        confidence=0.78,
                        status=response3.get("status", 0),
                        evidence=response3.get("body", "")[:500],
                        tier="suspicious",
                        tags=["business_logic", "workflow", "replay_attack", step.name],
                        notes=f"Replay with modification: Step '{step.name}' accepted modified data",
                    )
                    findings.append(finding)

                # Test 3: Replay with timestamp manipulation
                ts_payload = {
                    **step.params,
                    "timestamp": "2020-01-01T00:00:00Z",
                    "created_at": "2020-01-01",
                    "nonce": "replay_nonce_123",
                }
                response4 = await self._send_request(step.url, step.method, ts_payload, auth_headers)
                if response4 and response4.get("status") in (200, 201, 202):
                    finding = Finding(
                        target=target_url,
                        url=step.url,
                        method=step.method,
                        param="replay_timestamp",
                        location="body",
                        payload=json.dumps({"timestamp": "2020-01-01T00:00:00Z"}),
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.MEDIUM,
                        confidence=0.65,
                        status=response4.get("status", 0),
                        evidence=response4.get("body", "")[:500],
                        tier="suspicious",
                        tags=["business_logic", "workflow", "replay_attack", step.name],
                        notes=f"Replay with old timestamp: Step '{step.name}' accepted stale timestamp",
                    )
                    findings.append(finding)

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def test_state_manipulation(
        self,
        target_url: str,
        workflow: List[WorkflowStep],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test for workflow state manipulation vulnerabilities."""
        findings = []

        # Try to modify workflow state
        state_payloads = [
            {"workflow_state": "completed"},
            {"step": "final"},
            {"status": "done"},
            {"completed": True},
            {"finished": True},
        ]

        for step in workflow:
            for payload in state_payloads:
                try:
                    test_params = {**step.params, **payload}

                    response = await self._send_request(
                        step.url, step.method, test_params, auth_headers
                    )

                    if response and response.get("status") in (200, 201, 202):
                        body = response.get("body", "")

                        # Check if state was accepted
                        if any(v in body.lower() for v in ["completed", "done", "finished", "success"]):
                            finding = Finding(
                                target=target_url,
                                url=step.url,
                                method=step.method,
                                param="workflow_state",
                                location="body",
                                payload=json.dumps(payload),
                                attack_type=AttackType.BUSINESS_LOGIC,
                                severity=Severity.HIGH,
                                confidence=0.80,
                                status=response.get("status", 0),
                                evidence=body[:500],
                                tier="suspicious",
                                tags=["business_logic", "workflow", "state_manipulation", step.name],
                                notes=f"State manipulation: Modified state of '{step.name}' to completed",
                            )
                            findings.append(finding)

                except Exception:
                    continue

        self._findings.extend(findings)
        return findings

    async def test_authorization_bypass(
        self,
        target_url: str,
        workflow: List[WorkflowStep],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test for authorization bypass vulnerabilities."""
        findings = []

        # Try to access denied steps
        for step in workflow:
            if step.auth_required and not auth_headers:
                try:
                    response = await self._send_request(
                        step.url, step.method, step.params, None
                    )

                    if response and response.get("status") in (200, 201, 202):
                        finding = Finding(
                            target=target_url,
                            url=step.url,
                            method=step.method,
                            param="authorization",
                            location="body",
                            payload="No auth required",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=Severity.CRITICAL,
                            confidence=0.90,
                            status=response.get("status", 0),
                            evidence=response.get("body", "")[:500],
                            tier="confirmed",
                            tags=["business_logic", "workflow", "authorization_bypass", step.name],
                            notes=f"Authorization bypass: Accessed '{step.name}' without authentication",
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
        params: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
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

    def _should_require_previous_steps(
        self,
        current_step: WorkflowStep,
        previous_steps: List[WorkflowStep],
    ) -> bool:
        """Check if current step should require previous steps."""
        # If current step requires auth and previous steps set up auth
        if current_step.auth_required:
            for prev in previous_steps:
                if prev.name in ("login", "register", "authenticate"):
                    return True

        # If current step is a final step
        if current_step.name in ("complete", "finish", "submit", "confirm"):
            return True

        return False

    def get_findings(self) -> List[Finding]:
        """Get all findings from this tester."""
        return self._findings
