"""IDOR detection module for Titan Scanner."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import json_differential, json_value_changes


SENSITIVE_INDICATORS = [
    "email", "phone", "address", "ssn", "password", "secret", "token",
    "api_key", "credit", "payment", "medical", "health", "diagnosis",
    "prescription", "salary", "dob", "national_id", "passport",
]


class IDORDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        id_params = [p for p in params if any(k in p.lower() for k in ["id", "user", "account", "profile", "order", "invoice", "document", "file", "uuid", "guid", "pk", "key", "token", "number"])]
        if not id_params:
            return findings

        for param_name in id_params[:3]:
            original_value = params.get(param_name, "1")

            test_values = []
            if original_value.isdigit():
                test_values = [str(int(original_value) + 1)]
            else:
                test_values = ["2"]

            for test_value in test_values:
                if str(test_value) == str(original_value):
                    continue
                finding = await self._test_idor(context, target, method, url, param_name, params, test_value, original_value)
                if finding:
                    findings.append(finding)
                    break

        return findings

    async def _test_idor(self, context, target, method, url, param_name, all_params, test_value, original_value) -> Optional[Finding]:
        try:
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

            test_params = dict(all_params)
            test_params[param_name] = str(test_value)
            if method == "GET":
                resp = await context.request.get(url, params=test_params, headers={"Referer": target}, timeout=3000)
            else:
                resp = await context.request.post(url, data=test_params, headers={"Referer": target}, timeout=3000)
            body = await resp.text()

            diffs = BaselineAnalyzer.diff_responses(baseline_body, body, str(test_value))

            # A failed baseline leaves no reference point — a "finding" here
            # would be comparing against nothing and is guaranteed noise.
            if not baseline_body:
                return None

            if resp.status == 200 and body != baseline_body and len(body) > 10:
                # Structural oracle: a different identifier returning a *different
                # record's values* (not just an empty/missing resource) is the
                # core IDOR signal. Requires field-level value changes.
                structural = json_differential(baseline_body, body)
                for s in structural:
                    diffs.append(f"idor:{s}")

                # Fields that merely echo the injected identifier (e.g. a
                # "query" field containing the new id) are input reflection,
                # not record data — they must not count as IDOR evidence.
                changes = json_value_changes(baseline_body, body)
                value_changes = [
                    (p, o, n) for p, o, n in changes
                    if str(test_value) not in str(n) and str(test_value) not in str(o)
                ]
                for p, _o, _n in value_changes:
                    diffs.append(f"idor:value_changed:{p}")

                # Sensitive data present in the test response but NOT the baseline:
                # we're seeing another user's protected fields.
                baseline_lower = baseline_body.lower()
                sensitive_new = [ind for ind in SENSITIVE_INDICATORS if ind in body.lower() and ind not in baseline_lower]

                if value_changes or sensitive_new:
                    verified = True
                    severity = Severity.CRITICAL if sensitive_new else Severity.HIGH
                    confidence = 0.85
                    return Finding(
                        target=target,
                        url=str(resp.url or url),
                        method=method.upper(),
                        param=param_name,
                        location="query" if method == "GET" else "body",
                        payload=f"IDOR: {original_value} -> {test_value}",
                        attack_type=AttackType.IDOR,
                        severity=severity,
                        verified=verified,
                        confidence=confidence,
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body[:2000],
                        diffs=diffs + [f"idor:{param_name}:{original_value}->{test_value}"],
                        baseline_body=baseline_body[:2000],
                        baseline_status=baseline_status,
                        verification_body=body[:2000],
                        verification_status=resp.status,
                    )
                # Conservative fallback for non-JSON endpoints: a large,
                # unexplained response change is *suspicious* but not verified.
                elif abs(len(body) - len(baseline_body)) > 200 and len(body) > 500:
                    return Finding(
                        target=target,
                        url=str(resp.url or url),
                        method=method.upper(),
                        param=param_name,
                        location="query" if method == "GET" else "body",
                        payload=f"IDOR?: {original_value} -> {test_value}",
                        attack_type=AttackType.IDOR,
                        severity=Severity.LOW,
                        verified=False,
                        confidence=0.45,
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body[:2000],
                        diffs=diffs + [f"idor:{param_name}:{original_value}->{test_value}"],
                        baseline_body=baseline_body[:2000],
                        baseline_status=baseline_status,
                        verification_body=body[:2000],
                        verification_status=resp.status,
                    )
        except Exception:
            pass
        return None
