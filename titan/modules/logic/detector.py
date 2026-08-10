"""Business logic detection module for Titan Scanner."""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer


class LogicDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    @staticmethod
    def _matches_param(param: str, keywords: List[str]) -> bool:
        param_lower = param.lower()
        return any(re.search(r'\b' + re.escape(k) + r'\b', param_lower) for k in keywords)

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        price_params = [p for p in params if self._matches_param(p, ["price", "amount", "total", "cost", "fee", "discount", "tax", "balance", "payment", "salary", "wage"])]
        if price_params:
            for param_name in price_params:
                finding = await self._test_negative_price(context, target, method, url, param_name, params)
                if finding:
                    findings.append(finding)

        quantity_params = [p for p in params if self._matches_param(p, ["quantity", "qty", "count", "number", "amount", "stock", "inventory"])]
        if quantity_params:
            for param_name in quantity_params:
                finding = await self._test_negative_quantity(context, target, method, url, param_name, params)
                if finding:
                    findings.append(finding)

        return findings

    async def _test_negative_price(self, context, target, method, url, param_name, all_params) -> Optional[Finding]:
        return await self._test_negative_value(
            context, target, method, url, param_name, all_params,
            label="Negative price accepted", payload="Negative price accepted: -1",
        )

    async def _test_negative_quantity(self, context, target, method, url, param_name, all_params) -> Optional[Finding]:
        return await self._test_negative_value(
            context, target, method, url, param_name, all_params,
            label="Negative quantity accepted", payload="Negative quantity accepted: -1",
        )

    async def _test_negative_value(self, context, target, method, url, param_name, all_params,
                                   label: str, payload: str) -> Optional[Finding]:
        """A negative price/quantity is only evidence when the app actually
        PROCESSES the value. Merely responding 200 to ``?amount=-1`` proves
        nothing — every static page (owasp.org's donate form) does that.

        Two evidence paths:
        1. Reflection: the negative value appears in the test body but not in
           a baseline request with ``1`` — the app echoed the accepted value
           into a total/cart line.
        2. Redirect differential: the baseline (positive) request stays 200
           while the negative request is forwarded (302/303/307) — the app
           accepted the negative value and proceeded to the next step with it.
        """
        try:
            def _req(values):
                p = dict(all_params)
                p[param_name] = values
                if method == "GET":
                    return context.request.get(url, params=p, headers={"Referer": target}, timeout=3000)
                return context.request.post(url, data=p, headers={"Referer": target}, timeout=3000)

            baseline_resp = await _req("1")
            baseline_body = await baseline_resp.text()

            resp = await _req("-1")
            body = await resp.text()

            signals: List[str] = []
            diffs: List[str] = []

            if "-1" in body and "-1" not in baseline_body and resp.status == 200 and len(body) > 20:
                signals.append("reflect_negative")
                diffs.append("logic:negative_value_reflected")
            if (
                baseline_resp.status == 200
                and resp.status in (302, 303, 307)
            ):
                signals.append("negative_redirect")
                diffs.append("logic:negative_value_redirect")

            if signals:
                verified = "reflect_negative" in signals
                return Finding(
                    target=target,
                    url=str(resp.url or url),
                    method=method.upper(),
                    param=param_name,
                    location="query" if method == "GET" else "body",
                    payload=payload,
                    attack_type=AttackType.BUSINESS_LOGIC,
                    severity=Severity.HIGH if verified else Severity.MEDIUM,
                    verified=verified,
                    confidence=0.85 if verified else 0.5,
                    status=resp.status,
                    headers=dict(resp.headers),
                    body=body[:2000],
                    diffs=diffs,
                    baseline_body=baseline_body[:2000],
                    baseline_status=baseline_resp.status,
                    verification_body=body[:2000],
                    verification_status=resp.status,
                )
        except Exception:
            pass
        return None
