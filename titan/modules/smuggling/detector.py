"""HTTP request smuggling detection module for Titan Scanner."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import payload_encodings


class SmugglingDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        smuggly_params = [p for p in params if any(k in p.lower() for k in ["path", "url", "redirect", "next", "return", "callback", "file", "load", "resource", "api"])]
        if not smuggly_params:
            return findings

        for param_name in smuggly_params[:2]:
            finding = await self._test_smuggling(context, target, method, url, param_name, params)
            if finding:
                findings.append(finding)
                break

        return findings

    async def _test_smuggling(self, context, target, method, url, param_name, all_params) -> Optional[Finding]:
        try:
            test_params = dict(all_params)

            te_cl_payload = "test%0d%0aContent-Length:%200%0d%0a%0d%0aGET%20/test%20HTTP/1.1%0d%0aX-Test: true"
            test_params[param_name] = te_cl_payload

            if method == "GET":
                resp = await context.request.get(url, params=test_params, headers={"Referer": target, "Transfer-Encoding": "chunked"}, timeout=3000)
            else:
                resp = await context.request.post(url, data=test_params, headers={"Referer": target, "Transfer-Encoding": "chunked"}, timeout=3000)
            body = await resp.text()

            baseline_body = ""
            baseline_status = None
            try:
                if method == "GET":
                    baseline_resp = await context.request.get(url, params=all_params, headers={"Referer": target}, timeout=3000)
                else:
                    baseline_resp = await context.request.post(url, data=all_params, headers={"Referer": target}, timeout=3000)
                baseline_body = await baseline_resp.text()
                baseline_status = baseline_resp.status
            except Exception:
                pass

            indicators = [
                "bad request", "invalid request", "parse error",
                "chunked", "transfer-encoding", "content-length",
                "400", "501", "502", "503",
                "request header or cookie too large",
                "too many headers",
            ]
            # Echo guard: the probe payload itself contains "content-length"
            # and "HTTP/1.1" — an app that reflects it would self-verify. Strip
            # the payload (in EVERY form it can come back: raw, URL-encoded,
            # double-encoded into SPA JS state, HTML-escaped) from the body
            # before matching indicators. The github.com /login?return_to finding
            # was exactly this: GitHub embeds the request URL (with the encoded
            # probe) in its page state, so a raw-only strip left
            # "content-length" alive inside the %25-encoded echo.
            stripped = body.lower()
            for form in payload_encodings(te_cl_payload):
                stripped = stripped.replace(form.lower(), "")
            baseline_lower = baseline_body.lower()
            matches = [ind for ind in indicators if ind in stripped and ind not in baseline_lower]

            # NOTE: the TE:chunked probe goes through Playwright's request API,
            # which may strip hop-by-hop headers (Transfer-Encoding) before the
            # request leaves the browser. This module is therefore best-effort
            # for CL.TE detection on server-side rejection signals; a raw-socket
            # transport would be needed for full coverage.

            te_duplicate = "Transfer-Encoding: chunked" + "Transfer-Encoding: identity"
            if te_duplicate.lower().replace(" ", "") in str(resp.headers).lower().replace(" ", ""):
                matches.append("duplicate_te_header")

            if matches or resp.status >= 500:
                severity = Severity.HIGH if resp.status >= 500 else Severity.MEDIUM
                return Finding(
                    target=target,
                    url=str(resp.url or url),
                    method=method.upper(),
                    param=param_name,
                    location="query" if method == "GET" else "body",
                    payload=f"Smuggling probe: {te_cl_payload[:80]}",
                    attack_type=AttackType.REQUEST_SMUGGLING,
                    severity=severity,
                    verified=bool(matches),
                    confidence=0.6 if matches else 0.4,
                    status=resp.status,
                    headers=dict(resp.headers),
                    body=body[:2000],
                    diffs=[f"smuggle:{m}" for m in matches],
                    baseline_body=baseline_body[:2000],
                    baseline_status=baseline_status,
                    verification_body=body[:2000],
                    verification_status=resp.status,
                )
        except Exception:
            pass
        return None
