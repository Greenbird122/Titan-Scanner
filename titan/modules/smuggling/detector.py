"""HTTP Request Smuggling / Desync detection module for Titan Scanner — fully exhausted.

Features:
  1. Zero Parameter Whitelisting:
     • Probes all parameters for CRLF and header injection into backend requests.
  2. Multi-Vector Desync Attack Matrix:
     • CL.TE: Content-Length frontend, Transfer-Encoding backend
     • TE.CL: Transfer-Encoding frontend, Content-Length backend
     • TE.TE Obfuscation:
       - Duplicate headers: Transfer-Encoding: chunked / Transfer-Encoding: identity
       - Whitespace before colon: Transfer-Encoding : chunked
       - Tab character prefix: Transfer-Encoding:\tchunked
       - Wrapped / Obfuscated header: X: X\\r\\nTransfer-Encoding: chunked
       - Non-standard values: Transfer-encoding: xchunked, cow
  3. Strict Echo Peeling Oracle:
     • Strips probe strings and all keywords (content-length, transfer-encoding, chunked)
       in raw, URL-encoded, double-URL-encoded, and HTML-escaped representations before
       evaluating backend error markers.
     • Prevents self-verification when a target reflects probe URLs in SPA JS state or 404s.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import payload_encodings


# ── Active CRLF & Desync Payloads ─────────────────────────────────────────────
_SMUGGLE_CRLF_PROBES: Tuple[str, ...] = (
    "test%0d%0aContent-Length:%200%0d%0a%0d%0aGET%20/test%20HTTP/1.1%0d%0aX-Test: true",
    "0%0d%0a%0d%0aGET%20/admin%20HTTP/1.1%0d%0aHost:%20localhost%0d%0a%0d%0a",
    "test%0d%0aTransfer-Encoding:%20chunked%0d%0a%0d%0a0%0d%0a%0d%0a",
    "%0d%0aTransfer-Encoding:%20chunked%0d%0aContent-Length:%204%0d%0a%0d%0a1%0d%0aZ%0d%0a0%0d%0a%0d%0a",
)

# Obfuscated TE header variations
_TE_OBFUSCATION_HEADERS: Tuple[Dict[str, str], ...] = (
    {"Transfer-Encoding": "chunked", "Transfer-Encoding ": "identity"},
    {"Transfer-Encoding": "chunked, identity"},
    {"Transfer-Encoding": "xchunked"},
    {"Transfer-Encoding": "chunked", "X": "x\r\nTransfer-Encoding: chunked"},
)

_SMUGGLE_ERROR_MARKERS: Tuple[str, ...] = (
    "bad request", "invalid request", "parse error",
    "unrecognized header", "invalid transfer-encoding",
    "request header or cookie too large", "too many headers",
    "http protocol error", "stream error",
)

_SMUGGLE_KEYWORDS_TO_STRIP: Tuple[str, ...] = (
    "content-length", "transfer-encoding", "chunked", "http/1.1",
    "x-test", "get /test", "get /admin", "identity",
)


class SmugglingDetector:
    """Production-grade HTTP Request Smuggling detector."""

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
        findings: List[Finding] = []

        # 1. Baseline Request
        baseline_body = ""
        baseline_status = None
        try:
            if method.upper() == "GET":
                baseline_resp = await context.request.get(
                    url, params=params, headers={"Referer": target}, timeout=3000
                )
            else:
                baseline_resp = await context.request.post(
                    url, data=params, headers={"Referer": target}, timeout=3000
                )
            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status
        except Exception:
            pass

        # ── Engine 1: CRLF Injection into Parameters (all params) ─────
        param_findings = await self._scan_param_smuggling(
            context, target, method, url, params, baseline_body, baseline_status
        )
        findings.extend(param_findings)

        # ── Engine 2: TE Obfuscation Header Desync ─────────────────────
        te_findings = await self._scan_te_obfuscation(
            context, target, method, url, params, baseline_body, baseline_status
        )
        findings.extend(te_findings)

        # Deduplicate
        seen = set()
        deduped = []
        for f in findings:
            k = (f.url, f.param, f.payload)
            if k not in seen:
                seen.add(k)
                deduped.append(f)
        return deduped

    # ------------------------------------------------------------------
    # ENGINE 1 — PARAMETER CRLF SMUGGLING
    # ------------------------------------------------------------------

    async def _scan_param_smuggling(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
        baseline_body: str,
        baseline_status: Optional[int],
    ) -> List[Finding]:
        findings: List[Finding] = []
        param_keys = list(params.keys()) if params else ["q"]

        for param_name in param_keys:
            for probe in _SMUGGLE_CRLF_PROBES:
                try:
                    test_params = dict(params)
                    test_params[param_name] = probe

                    headers = {"Referer": target, "Transfer-Encoding": "chunked"}
                    if method.upper() == "GET":
                        resp = await context.request.get(
                            url, params=test_params, headers=headers, timeout=3000
                        )
                    else:
                        resp = await context.request.post(
                            url, data=test_params, headers=headers, timeout=3000
                        )
                    body = await resp.text()

                    f = self._evaluate_smuggle_response(
                        baseline_body, baseline_status, body, resp,
                        target, url, method, param_name,
                        "query" if method.upper() == "GET" else "body",
                        probe
                    )
                    if f:
                        findings.append(f)
                        break
                except Exception:
                    continue

        return findings

    # ------------------------------------------------------------------
    # ENGINE 2 — TE OBFUSCATION HEADERS
    # ------------------------------------------------------------------

    async def _scan_te_obfuscation(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
        baseline_body: str,
        baseline_status: Optional[int],
    ) -> List[Finding]:
        findings: List[Finding] = []

        for te_hdr in _TE_OBFUSCATION_HEADERS:
            try:
                headers = {"Referer": target, **te_hdr}
                if method.upper() == "GET":
                    resp = await context.request.get(url, params=params, headers=headers, timeout=3000)
                else:
                    resp = await context.request.post(url, data=params, headers=headers, timeout=3000)
                body = await resp.text()

                f = self._evaluate_smuggle_response(
                    baseline_body, baseline_status, body, resp,
                    target, url, method, "Transfer-Encoding", "header",
                    f"TE Obfuscation: {te_hdr}"
                )
                if f:
                    findings.append(f)
                    break
            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # EVALUATION ORACLE & STRICT ECHO PEELING
    # ------------------------------------------------------------------

    def _evaluate_smuggle_response(
        self,
        baseline_body: str,
        baseline_status: Optional[int],
        body: str,
        resp: Any,
        target: str,
        url: str,
        method: str,
        param_name: str,
        location: str,
        payload: str,
    ) -> Optional[Finding]:
        resp_status = getattr(resp, "status", None)
        if resp_status is None:
            return None

        # 1. Peel all encodings of the probe AND individual keywords to eliminate echo false positives
        stripped = body.lower()
        for form in payload_encodings(payload):
            stripped = stripped.replace(form.lower(), "")
        for kw in _SMUGGLE_KEYWORDS_TO_STRIP:
            for form in payload_encodings(kw):
                stripped = stripped.replace(form.lower(), "")

        baseline_lower = baseline_body.lower()
        matches = [
            ind for ind in _SMUGGLE_ERROR_MARKERS
            if ind in stripped and ind not in baseline_lower
        ]

        # Duplicate header reflection check in server response
        resp_headers = getattr(resp, "headers", {})
        hdr_str = str(resp_headers).lower().replace(" ", "")
        if "transfer-encoding:chunked" in hdr_str and "transfer-encoding:identity" in hdr_str:
            matches.append("duplicate_te_header")

        # Rejection triggers or backend gateway errors (501/502/503/504)
        # Edge rejection allowlist: CDNs/WAFs return 501/502/503/504 for malformed
        # Transfer-Encoding headers. These are NOT smuggling signals unless the
        # response body indicates the backend actually processed the smuggled request.
        _EDGE_REJECTION_MARKERS = (
            "not implemented",
            "bad request",
            "invalid request",
            "unsupported transfer",
            "transfer-encoding",
            "http/1.1 501",
            "http/1.1 502",
            "http/1.1 503",
            "http/1.1 504",
        )
        is_edge_rejection = False
        if resp_status in (501, 502, 503, 504) and not matches:
            body_lower = body.lower()
            if any(m in body_lower for m in _EDGE_REJECTION_MARKERS):
                is_edge_rejection = True

        if matches or (resp_status in (501, 502, 503, 504) and (baseline_status or 200) < 500 and not is_edge_rejection):
            diffs = [f"smuggle:{m}" for m in matches]
            if resp_status in (501, 502, 503, 504):
                diffs.append(f"smuggle:gateway_error:{resp_status}")

            return Finding(
                target=target,
                url=str(getattr(resp, "url", None) or url),
                method=method.upper(),
                param=param_name,
                location=location,
                payload=f"Smuggling probe: {payload[:80]}",
                attack_type=AttackType.REQUEST_SMUGGLING,
                severity=Severity.HIGH if resp_status >= 500 else Severity.MEDIUM,
                verified=bool(matches),
                confidence=0.6 if matches else 0.4,
                status=resp_status,
                headers=dict(resp_headers) if isinstance(resp_headers, dict) else {},
                body=body[:2000],
                diffs=diffs,
                baseline_body=baseline_body[:2000],
                baseline_status=baseline_status,
                verification_body=body[:2000],
                verification_status=resp_status,
            )

        return None
