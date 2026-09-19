"""Probe payload tables for the business-logic detector.

The value sets, workflow state names and business parameters the logic
detector fires with. Pure data, separate from ``service.py`` so a probe can
be added or audited without reading detection code — and vice versa.

Private to this package; the underscore names are part of the contract with
``service.py`` only.
"""

from __future__ import annotations

from typing import Any

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
_COUPON_PROBES: tuple[tuple[str, str], ...] = (
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
_PLAN_PROBES: tuple[tuple[str, str], ...] = (
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
