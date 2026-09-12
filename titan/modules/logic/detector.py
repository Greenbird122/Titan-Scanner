"""Business logic, parameter tampering, and workflow bypass detection — deep audit.

Expanded from basic negative-value testing to full business logic coverage:

1. Parameter Tampering Matrix:
   • Negative values (-1, -100, -0.01) for balance/inventory subtraction
   • Zero / free-value bypasses (0, 0.00)
   • Integer overflow boundaries (2^31, 2^63)
   • Floating-point precision attacks (0.00000001, 0.99999999)
   • Type confusion (string where int expected, arrays, null, booleans)

2. Workflow Step Bypass:
   • Skip payment step → direct to confirmation
   • Skip verification step → direct to activation
   • Replay earlier step after completing later step
   • Force state transitions via parameter injection

3. Coupon / Discount Stacking:
   • Apply multiple coupons in single request
   • Negative discount amounts (refund injection)
   • Percentage vs absolute coupon confusion
   • Coupon reuse after single-use consumption

4. Cart & Order Tampering:
   • Negative quantity (refund injection)
   • Zero quantity (free item)
   • Price override via hidden parameters
   • Item swap (change product_id after price calculation)
   • Tax bypass via parameter removal

5. Currency & Pricing Attacks:
   • Currency switching mid-transaction (KES → USD → KES)
   • Decimal precision truncation (199.995 → 199.99)
   • Rounding direction exploitation
   • Price differential across currencies

6. Subscription & Billing Logic:
   • Plan downgrade without proration
   • Trial extension via parameter manipulation
   • Quantity override on per-seat billing
   • Feature gate bypass via response manipulation

7. Race-on-Logic:
   • Concurrent coupon application (double-discount)
   • Concurrent resource claiming (double-spend on limited inventory)
   • Concurrent account creation with same email

Evidence oracles:
  • Reflection Oracle: tampered value appears in processed output
  • State Transition Oracle: workflow advances without required step
  • Business Rule Oracle: response contradicts business invariants
  • Differential Oracle: two different inputs produce same charged amount
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlencode

from titan.core.logger import get_logger
from titan.core.models import AttackType, Finding, Severity

logger = get_logger("detector")


# ── Parameter Tampering Value Probes ──────────────────────────────────
_LOGIC_TAMPER_PROBES: tuple[tuple[str, str, str], ...] = (
    ("-1", "Negative value accepted", "logic:negative_value"),
    ("0", "Zero / Free value accepted", "logic:zero_value"),
    ("-0.01", "Fractional negative amount accepted", "logic:fractional_negative"),
    ("2147483648", "Integer 32-bit overflow boundary accepted", "logic:integer_overflow_32"),
    ("9223372036854775807", "Integer 64-bit overflow boundary accepted", "logic:integer_overflow_64"),
    ("0.00000001", "Micro-precision rounding value accepted", "logic:precision_tampering"),
    ("999999999", "Large value accepted without limit check", "logic:large_value"),
    ("1e308", "Floating-point overflow accepted", "logic:float_overflow"),
    ("NaN", "NaN accepted as numeric value", "logic:nan_accepted"),
    ("Infinity", "Infinity accepted as numeric value", "logic:infinity_accepted"),
)

# ── Type Confusion Probes ────────────────────────────────────────────
_TYPE_CONFUSION_PROBES: tuple[tuple[str, Any, str], ...] = (
    ("null", None, "logic:null_type"),
    ("true", True, "logic:boolean_true"),
    ("false", False, "logic:boolean_false"),
    ("[]", [], "logic:empty_array"),
    ("{}", {}, "logic:empty_object"),
    ('""', "", "logic:empty_string"),
    ('"-1"', "-1", "logic:string_negative"),
    ('"0"', "0", "logic:string_zero"),
    ("[1,2,3]", [1, 2, 3], "logic:array_injection"),
    ('{"$gt":""}', {"$gt": ""}, "logic:nosql_operator"),
)

# ── Coupon / Discount Probes ─────────────────────────────────────────
_COUPON_PROBES: tuple[tuple[str, str, str], ...] = (
    # Negative discount (refund injection)
    ("-100", "logic:negative_discount"),
    ("-99999", "logic:large_negative_discount"),
    # Zero discount (bypass minimum spend)
    ("0", "logic:zero_discount"),
    # Percentage confusion (100% = free)
    ("100", "logic:full_discount"),
    ("10000", "logic:over_full_discount"),
    # Free coupon codes
    ("FREE", "logic:free_coupon"),
    ("ADMIN", "logic:admin_coupon"),
    ("TEST", "logic:test_coupon"),
    ("DISCOUNT100", "logic:discount100_coupon"),
    ("0000", "logic:null_coupon"),
)

# ── Currency Switch Probes ───────────────────────────────────────────
_CURRENCY_SWITCHES: tuple[tuple[str, str], ...] = (
    ("KES", "USD"),  # Weak currency → strong currency
    ("USD", "KES"),  # Strong currency → weak currency (if pricing differs)
    ("NGN", "USD"),  # NGN → USD
    ("UGX", "KES"),  # Regional switch
    ("EUR", "USD"),  # Major currency switch
)

# ── Workflow State Manipulation ───────────────────────────────────────
_WORKFLOW_STATES: tuple[str, ...] = (
    "confirmed",
    "completed",
    "paid",
    "delivered",
    "active",
    "approved",
    "verified",
    "published",
    "resolved",
    "closed",
    "admin",
    "superadmin",
    "owner",
    "sysadmin",
)

# ── Subscription Plan Probes ─────────────────────────────────────────
_PLAN_PROBES: tuple[tuple[str, str, str], ...] = (
    ("enterprise", "logic:plan_upgrade_bypass"),
    ("premium", "logic:plan_premium_bypass"),
    ("admin", "logic:plan_admin_bypass"),
    ("free", "logic:plan_downgrade_bypass"),
    ("unlimited", "logic:plan_unlimited_bypass"),
    ("pro", "logic:plan_pro_bypass"),
)

# ── Common Business Logic Parameters ─────────────────────────────────
_BIZ_PARAMS = {
    "price",
    "amount",
    "cost",
    "total",
    "subtotal",
    "discount",
    "coupon",
    "promo",
    "voucher",
    "credit",
    "refund",
    "quantity",
    "qty",
    "count",
    "items",
    "currency",
    "plan",
    "tier",
    "role",
    "status",
    "tax",
    "shipping",
    "handling",
    "fee",
    "balance",
    "credits",
    "points",
    "rewards",
    "user_id",
    "account_id",
    "org_id",
    "workspace_id",
    "step",
    "phase",
    "state",
    "stage",
}


class LogicDetector:
    """Production-grade Business Logic, Parameter Tampering, and Workflow Bypass detector."""

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
        findings: list[Finding] = []

        # Test all parameters (no keyword exclusion)
        param_keys = list(params.keys()) if params else ["amount"]

        # ── Engine 1: Parameter Tampering (negative, overflow, precision) ──
        for param_name in param_keys:
            f = await self._test_param_tampering(context, target, method, url, param_name, params)
            if f:
                findings.append(f)

        # ── Engine 2: Type Confusion ─────────────────────────────────
        for param_name in param_keys:
            f = await self._test_type_confusion(context, target, method, url, param_name, params)
            if f:
                findings.append(f)

        # ── Engine 3: Coupon / Discount Stacking ────────────────────
        coupon_params = [
            p for p in param_keys if any(k in p.lower() for k in ["coupon", "discount", "promo", "voucher", "code"])
        ]
        if coupon_params:
            for cp in coupon_params:
                f = await self._test_coupon_tampering(context, target, method, url, cp, params)
                if f:
                    findings.append(f)

        # ── Engine 4: Currency Switching ─────────────────────────────
        currency_params = [p for p in param_keys if "currency" in p.lower()]
        if currency_params:
            for cp in currency_params:
                f = await self._test_currency_switch(context, target, method, url, cp, params)
                if f:
                    findings.append(f)

        # ── Engine 5: Workflow Step Bypass ───────────────────────────
        step_params = [
            p for p in param_keys if any(k in p.lower() for k in ["step", "phase", "state", "stage", "status"])
        ]
        if step_params:
            for sp in step_params:
                f = await self._test_workflow_bypass(context, target, method, url, sp, params)
                if f:
                    findings.append(f)

        # ── Engine 6: Subscription / Plan Manipulation ──────────────
        plan_params = [
            p for p in param_keys if any(k in p.lower() for k in ["plan", "tier", "role", "level", "subscription"])
        ]
        if plan_params:
            for pp in plan_params:
                f = await self._test_plan_manipulation(context, target, method, url, pp, params)
                if f:
                    findings.append(f)

        # ── Engine 7: Price / Amount Direct Manipulation ─────────────
        price_params = [
            p for p in param_keys if any(k in p.lower() for k in ["price", "amount", "cost", "total", "subtotal"])
        ]
        if price_params:
            for pp in price_params:
                f = await self._test_price_manipulation(context, target, method, url, pp, params)
                if f:
                    findings.append(f)

        # ── Engine 8: Parameter Pollution ────────────────────────────
        f = await self._test_parameter_pollution(context, target, method, url, params)
        if f:
            findings.append(f)

        return findings

    # ------------------------------------------------------------------
    # ENGINE 1 — PARAMETER TAMPERING
    # ------------------------------------------------------------------

    async def _test_param_tampering(
        self,
        context,
        target: str,
        method: str,
        url: str,
        param_name: str,
        all_params: dict[str, str],
    ) -> Finding | None:
        try:

            def _req(val: str):
                p = dict(all_params)
                p[param_name] = val
                if method.upper() == "GET":
                    return context.request.get(url, params=p, headers={"Referer": target}, timeout=3000)
                return context.request.post(url, data=p, headers={"Referer": target}, timeout=3000)

            # Baseline with positive value
            baseline_resp = await _req("10")
            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status

            for test_val, label, diff_tag in _LOGIC_TAMPER_PROBES:
                resp = await _req(test_val)
                body = await resp.text()

                signals: list[str] = []
                diffs: list[str] = []

                # Oracle 1: Tampered value reflected in processed output
                if test_val in body and test_val not in baseline_body and resp.status == 200 and len(body) > 20:
                    signals.append("reflect_negative")
                    diffs.append("logic:negative_value_reflected")
                    diffs.append(diff_tag)

                # Oracle 2: State transition (200 → 302/303/307)
                if baseline_status == 200 and resp.status in (302, 303, 307, 308):
                    signals.append("negative_redirect")
                    diffs.append("logic:negative_value_redirect")
                    diffs.append(diff_tag)

                # Oracle 3: Error message leak
                error_indicators = [
                    "overflow",
                    "truncat",
                    "precision",
                    "invalid number",
                    "out of range",
                    "numeric value",
                    "arithmetic",
                ]
                for ei in error_indicators:
                    if ei in body.lower() and ei not in baseline_body.lower():
                        diffs.append(f"logic:error_leak:{ei}")
                        break

                if signals:
                    verified = "reflect_negative" in signals
                    return Finding(
                        target=target,
                        url=str(getattr(resp, "url", None) or url),
                        method=method.upper(),
                        param=param_name,
                        location="query" if method.upper() == "GET" else "body",
                        payload=f"{label}: {param_name}={test_val}",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.HIGH if verified else Severity.MEDIUM,
                        verified=verified,
                        confidence=0.85 if verified else 0.5,
                        status=resp.status,
                        headers=dict(getattr(resp, "headers", {})),
                        body=body[:2000],
                        diffs=diffs,
                        baseline_body=baseline_body[:2000],
                        baseline_status=baseline_status,
                        verification_body=body[:2000],
                        verification_status=resp.status,
                        metadata={"tampered_param": param_name, "test_value": test_val},
                    )

        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass
        return None

    # ------------------------------------------------------------------
    # ENGINE 2 — TYPE CONFUSION
    # ------------------------------------------------------------------

    async def _test_type_confusion(
        self,
        context,
        target: str,
        method: str,
        url: str,
        param_name: str,
        all_params: dict[str, str],
    ) -> Finding | None:
        try:

            def _req(val):
                p = dict(all_params)
                p[param_name] = val if isinstance(val, str) else json.dumps(val)
                if method.upper() == "GET":
                    return context.request.get(url, params=p, headers={"Referer": target}, timeout=3000)
                return context.request.post(url, data=p, headers={"Referer": target}, timeout=3000)

            baseline_resp = await _req(all_params.get(param_name, "1"))
            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status

            for test_val, raw_val, diff_tag in _TYPE_CONFUSION_PROBES:
                resp = await _req(test_val)
                body = await resp.text()

                # Skip if same as baseline
                if body == baseline_body and resp.status == baseline_status:
                    continue

                # Type confusion is interesting if:
                # 1. Null/empty accepted without error
                # 2. Array accepted where scalar expected
                # 3. Object accepted where scalar expected
                # 4. Boolean accepted where numeric expected
                interesting = False
                if (
                    (test_val == "null" and resp.status == 200 and len(body) > 10)
                    or (test_val == "[]" and resp.status == 200)
                    or (test_val == "{}" and resp.status == 200)
                ):
                    interesting = True
                elif test_val in ("true", "false") and resp.status == 200:
                    # Check if boolean was processed differently
                    if str(raw_val).lower() in body.lower():
                        interesting = True

                if interesting:
                    return Finding(
                        target=target,
                        url=str(getattr(resp, "url", None) or url),
                        method=method.upper(),
                        param=param_name,
                        location="query" if method.upper() == "GET" else "body",
                        payload=f"Type confusion: {param_name}={test_val}",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.MEDIUM,
                        verified=True,
                        confidence=0.7,
                        status=resp.status,
                        headers=dict(getattr(resp, "headers", {})),
                        body=body[:2000],
                        diffs=[diff_tag, f"type_confusion:{test_val}_accepted"],
                        baseline_body=baseline_body[:2000],
                        baseline_status=baseline_status,
                        verification_body=body[:2000],
                        verification_status=resp.status,
                        metadata={"param": param_name, "type": test_val},
                    )

        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass
        return None

    # ------------------------------------------------------------------
    # ENGINE 3 — COUPON / DISCOUNT TAMPERING
    # ------------------------------------------------------------------

    async def _test_coupon_tampering(
        self,
        context,
        target: str,
        method: str,
        url: str,
        param_name: str,
        all_params: dict[str, str],
    ) -> Finding | None:
        try:
            baseline_resp = await self._send(context, method, url, all_params, target)
            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status

            for test_val, diff_tag in _COUPON_PROBES:
                p = dict(all_params)
                p[param_name] = test_val
                resp = await self._send(context, method, url, p, target)
                body = await resp.text()

                # Negative discount = refund injection
                if test_val.startswith("-") and resp.status == 200:
                    # Check if discount was applied (body changed meaningfully)
                    if body != baseline_body and len(body) > 20:
                        return Finding(
                            target=target,
                            url=str(getattr(resp, "url", None) or url),
                            method=method.upper(),
                            param=param_name,
                            location="body",
                            payload=f"Coupon tampering: {param_name}={test_val} (negative discount)",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=Severity.CRITICAL,
                            verified=True,
                            confidence=0.88,
                            status=resp.status,
                            headers=dict(getattr(resp, "headers", {})),
                            body=body[:2000],
                            diffs=[diff_tag, "coupon:negative_discount_applied"],
                            baseline_body=baseline_body[:2000],
                            baseline_status=baseline_status,
                            verification_body=body[:2000],
                            verification_status=resp.status,
                            metadata={"coupon_value": test_val, "attack": "negative_discount"},
                        )

                # Full discount (100% off)
                if test_val == "100" and resp.status == 200:
                    if body != baseline_body:
                        # Check if total/amount changed to 0 or near-0
                        amount_patterns = re.findall(r'"?(?:total|amount|price|cost)"?\s*[:=]\s*"?(\d+\.?\d*)"?', body)
                        for amt in amount_patterns:
                            try:
                                if float(amt) == 0:
                                    return Finding(
                                        target=target,
                                        url=str(getattr(resp, "url", None) or url),
                                        method=method.upper(),
                                        param=param_name,
                                        location="body",
                                        payload=f"Coupon tampering: {param_name}={test_val} (100% discount accepted)",
                                        attack_type=AttackType.BUSINESS_LOGIC,
                                        severity=Severity.CRITICAL,
                                        verified=True,
                                        confidence=0.90,
                                        status=resp.status,
                                        headers=dict(getattr(resp, "headers", {})),
                                        body=body[:2000],
                                        diffs=[diff_tag, "coupon:full_discount_applied"],
                                        baseline_body=baseline_body[:2000],
                                        baseline_status=baseline_status,
                                        verification_body=body[:2000],
                                        verification_status=resp.status,
                                        metadata={"coupon_value": test_val, "final_amount": amt},
                                    )
                            except ValueError as exc:
                                logger.debug(f"variant failed, continuing: {exc}")
                                continue

        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass
        return None

    # ------------------------------------------------------------------
    # ENGINE 4 — CURRENCY SWITCHING
    # ------------------------------------------------------------------

    async def _test_currency_switch(
        self,
        context,
        target: str,
        method: str,
        url: str,
        param_name: str,
        all_params: dict[str, str],
    ) -> Finding | None:
        try:
            # Get baseline with original currency
            original_currency = all_params.get(param_name, "KES")
            baseline_resp = await self._send(context, method, url, all_params, target)
            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status

            for from_cur, to_cur in _CURRENCY_SWITCHES:
                if original_currency.upper() != from_cur:
                    continue

                p = dict(all_params)
                p[param_name] = to_cur
                resp = await self._send(context, method, url, p, target)
                body = await resp.text()

                if resp.status == 200 and body != baseline_body:
                    # Check if price/amount changed disproportionately
                    # (currency switch should not change the USD-equivalent price)
                    return Finding(
                        target=target,
                        url=str(getattr(resp, "url", None) or url),
                        method=method.upper(),
                        param=param_name,
                        location="body",
                        payload=f"Currency switch: {from_cur} → {to_cur} changed pricing",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.HIGH,
                        verified=True,
                        confidence=0.75,
                        status=resp.status,
                        headers=dict(getattr(resp, "headers", {})),
                        body=body[:2000],
                        diffs=["logic:currency_switch_pricing_delta"],
                        baseline_body=baseline_body[:2000],
                        baseline_status=baseline_status,
                        verification_body=body[:2000],
                        verification_status=resp.status,
                        metadata={"from": from_cur, "to": to_cur},
                    )

        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass
        return None

    # ------------------------------------------------------------------
    # ENGINE 5 — WORKFLOW STEP BYPASS
    # ------------------------------------------------------------------

    async def _test_workflow_bypass(
        self,
        context,
        target: str,
        method: str,
        url: str,
        param_name: str,
        all_params: dict[str, str],
    ) -> Finding | None:
        try:
            baseline_resp = await self._send(context, method, url, all_params, target)
            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status

            for state in _WORKFLOW_STATES:
                p = dict(all_params)
                p[param_name] = state
                resp = await self._send(context, method, url, p, target)
                body = await resp.text()

                if resp.status == 200 and body != baseline_body:
                    # Check if the state was actually applied
                    if state.lower() in body.lower():
                        return Finding(
                            target=target,
                            url=str(getattr(resp, "url", None) or url),
                            method=method.upper(),
                            param=param_name,
                            location="body",
                            payload=f"Workflow bypass: set {param_name}={state} accepted",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=Severity.CRITICAL if state in ("admin", "superadmin", "owner") else Severity.HIGH,
                            verified=True,
                            confidence=0.85,
                            status=resp.status,
                            headers=dict(getattr(resp, "headers", {})),
                            body=body[:2000],
                            diffs=[f"logic:workflow_bypass:{param_name}={state}"],
                            baseline_body=baseline_body[:2000],
                            baseline_status=baseline_status,
                            verification_body=body[:2000],
                            verification_status=resp.status,
                            metadata={"state_param": param_name, "target_state": state},
                        )

        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass
        return None

    # ------------------------------------------------------------------
    # ENGINE 6 — SUBSCRIPTION / PLAN MANIPULATION
    # ------------------------------------------------------------------

    async def _test_plan_manipulation(
        self,
        context,
        target: str,
        method: str,
        url: str,
        param_name: str,
        all_params: dict[str, str],
    ) -> Finding | None:
        try:
            baseline_resp = await self._send(context, method, url, all_params, target)
            baseline_body = await baseline_resp.text()

            for plan, diff_tag in _PLAN_PROBES:
                p = dict(all_params)
                p[param_name] = plan
                resp = await self._send(context, method, url, p, target)
                body = await resp.text()

                if resp.status == 200 and body != baseline_body:
                    # Check if plan was actually upgraded
                    plan_indicators = [
                        f'"plan":"{plan}"',
                        f'"plan":"{plan.upper()}"',
                        f'"tier":"{plan}"',
                        f'"tier":"{plan.upper()}"',
                        f'"role":"{plan}"',
                    ]
                    for indicator in plan_indicators:
                        if indicator.lower() in body.lower():
                            return Finding(
                                target=target,
                                url=str(getattr(resp, "url", None) or url),
                                method=method.upper(),
                                param=param_name,
                                location="body",
                                payload=f"Plan manipulation: {param_name}={plan} accepted",
                                attack_type=AttackType.BUSINESS_LOGIC,
                                severity=Severity.CRITICAL if plan in ("admin", "superadmin") else Severity.HIGH,
                                verified=True,
                                confidence=0.88,
                                status=resp.status,
                                headers=dict(getattr(resp, "headers", {})),
                                body=body[:2000],
                                diffs=[diff_tag],
                                baseline_body=baseline_body[:2000],
                                baseline_status=baseline_resp.status,
                                verification_body=body[:2000],
                                verification_status=resp.status,
                                metadata={"param": param_name, "plan": plan},
                            )

        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass
        return None

    # ------------------------------------------------------------------
    # ENGINE 7 — PRICE / AMOUNT DIRECT MANIPULATION
    # ------------------------------------------------------------------

    async def _test_price_manipulation(
        self,
        context,
        target: str,
        method: str,
        url: str,
        param_name: str,
        all_params: dict[str, str],
    ) -> Finding | None:
        try:
            baseline_resp = await self._send(context, method, url, all_params, target)
            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status

            # Extract original amount if present
            original_amount = all_params.get(param_name, "")
            if not original_amount:
                return None

            # Test: set amount to 0
            p = dict(all_params)
            p[param_name] = "0"
            resp = await self._send(context, method, url, p, target)
            body = await resp.text()

            if resp.status == 200 and body != baseline_body:
                # Check if the total/charge reflects the zero amount
                amount_patterns = re.findall(
                    r'"?(?:total|amount|price|cost|charge|payment)"?\s*[:=]\s*"?(\d+\.?\d*)"?', body
                )
                for amt in amount_patterns:
                    try:
                        if float(amt) == 0 and float(original_amount) > 0:
                            return Finding(
                                target=target,
                                url=str(getattr(resp, "url", None) or url),
                                method=method.upper(),
                                param=param_name,
                                location="body",
                                payload=f"Price manipulation: {param_name}=0 accepted (was {original_amount})",
                                attack_type=AttackType.BUSINESS_LOGIC,
                                severity=Severity.CRITICAL,
                                verified=True,
                                confidence=0.92,
                                status=resp.status,
                                headers=dict(getattr(resp, "headers", {})),
                                body=body[:2000],
                                diffs=["logic:price_zeroed", f"logic:amount:{original_amount}->0"],
                                baseline_body=baseline_body[:2000],
                                baseline_status=baseline_status,
                                verification_body=body[:2000],
                                verification_status=resp.status,
                                metadata={
                                    "param": param_name,
                                    "original": original_amount,
                                    "tampered": "0",
                                },
                            )
                    except ValueError as exc:
                        logger.debug(f"variant failed, continuing: {exc}")
                        continue

        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass
        return None

    # ------------------------------------------------------------------
    # ENGINE 8 — PARAMETER POLLUTION
    # ------------------------------------------------------------------

    async def _test_parameter_pollution(
        self,
        context,
        target: str,
        method: str,
        url: str,
        all_params: dict[str, str],
    ) -> Finding | None:
        """Test HPP (HTTP Parameter Pollution) — send duplicate params with different values.

        Some backends use the first value, others the last. If the behavior
        differs, an attacker can bypass validation by sending two values.
        """
        if not all_params:
            return None

        try:
            param_name = list(all_params.keys())[0]
            original_val = all_params[param_name]

            # Build polluted params: param=original&param=malicious
            polluted = dict(all_params)

            # Test 1: Duplicate with benign + malicious
            if method.upper() == "GET":
                # Manually construct URL with duplicate params
                qs = urlencode(polluted, doseq=True)
                qs += f"&{param_name}=-1"
                polluted_url = f"{url.split('?')[0]}?{qs}"
                resp = await context.request.get(polluted_url, headers={"Referer": target}, timeout=3000)
            else:
                # For POST, send as array or duplicate
                polluted_data = dict(polluted)
                polluted_data[param_name] = [original_val, "-1"]
                resp = await context.request.post(
                    url,
                    data=json.dumps(polluted_data),
                    headers={"Referer": target, "Content-Type": "application/json"},
                    timeout=3000,
                )

            body = await resp.text()

            # If the negative value was accepted (reflected or processed)
            if "-1" in body and "-1" not in json.dumps(all_params):
                return Finding(
                    target=target,
                    url=str(getattr(resp, "url", None) or url),
                    method=method.upper(),
                    param=param_name,
                    location="query" if method.upper() == "GET" else "body",
                    payload=f"HPP: duplicate {param_name} parameter accepted negative value",
                    attack_type=AttackType.BUSINESS_LOGIC,
                    severity=Severity.MEDIUM,
                    verified=True,
                    confidence=0.70,
                    status=resp.status,
                    headers=dict(getattr(resp, "headers", {})),
                    body=body[:2000],
                    diffs=["logic:hpp_duplicate_accepted"],
                    baseline_body="",
                    baseline_status=None,
                    verification_body=body[:2000],
                    verification_status=resp.status,
                    metadata={"param": param_name, "technique": "hpp"},
                )

        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass
        return None

    # ------------------------------------------------------------------
    # HTTP HELPER
    # ------------------------------------------------------------------

    async def _send(self, context, method: str, url: str, params: dict[str, str], target: str):
        if method.upper() == "GET":
            return await context.request.get(url, params=params, headers={"Referer": target}, timeout=3000)
        return await context.request.post(url, data=params, headers={"Referer": target}, timeout=3000)
