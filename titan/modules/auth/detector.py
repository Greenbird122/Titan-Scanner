"""Authentication bypass detection module for Titan Scanner."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer


class AuthDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        auth_params = [p for p in params if any(k in p.lower() for k in [
            "user", "pass", "login", "auth", "token", "session", "email",
            "admin", "password", "username", "account", "credential",
            "secret", "key", "api_key", "apikey", "access", "bearer",
        ])]
        if not auth_params:
            return findings

        context_data = {
            "fingerprint": self.fingerprint,
            "attack_type": "auth_bypass",
            "param_type": "text",
            "location": "query" if method == "GET" else "body",
        }
        base_payloads = self.payload_smith.get_base_payloads("auth_bypass", context_data)[:6]
        waf = self.payload_smith.detect_waf({}, "", 0) or self.fingerprint.get("waf", "unknown")
        if waf != "unknown":
            base_payloads.extend(self.payload_smith.get_waf_bypass_payloads(base_payloads[:3], waf)[:3])
        payloads = await self.payload_smith.mutate(base_payloads, context_data)
        all_payloads = list(dict.fromkeys(base_payloads + payloads))[:6]

        for param_name in auth_params[:3]:
            finding = await self._test_param(context, target, method, url, param_name, params, all_payloads)
            if finding:
                findings.append(finding)

        return findings

    async def _test_param(self, context, target, method, url, param_name, all_params, payloads) -> Optional[Finding]:
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

        success_indicators = [
            "welcome", "dashboard", "logout", "profile", "account",
            "success", "authenticated", "token", "session", "home",
            "admin panel", "control panel", "settings", "my account",
            "logged in", "sign out", "user panel", "member",
            "redirect", "location:", "set-cookie",
        ]
        failure_indicators = [
            "invalid", "incorrect", "wrong", "failed", "error",
            "denied", "unauthorized", "401", "403", "not found",
            "login failed", "authentication failed", "bad credentials",
        ]

        for payload in payloads:
            try:
                test_params = dict(all_params)
                test_params[param_name] = payload
                if method == "GET":
                    resp = await context.request.get(url, params=test_params, headers={"Referer": target}, timeout=3000)
                else:
                    resp = await context.request.post(url, data=test_params, headers={"Referer": target}, timeout=3000)
                body = await resp.text()

                diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)

                body_lower = body.lower()
                is_success = (
                    resp.status in (200, 301, 302, 303, 307, 308) and
                    any(ind in body_lower for ind in success_indicators) and
                    not any(ind in body_lower for ind in failure_indicators)
                )
                is_redirect = resp.status in (301, 302, 303, 307, 308)
                is_cookie_set = "set-cookie" in (resp.headers or {}).lower()

                if is_success or (diffs and is_redirect) or is_cookie_set:
                    severity = Severity.CRITICAL if is_success else Severity.HIGH
                    return Finding(
                        target=target,
                        url=str(resp.url or url),
                        method=method.upper(),
                        param=param_name,
                        location="query" if method == "GET" else "body",
                        payload=payload,
                        attack_type=AttackType.AUTH_BYPASS,
                        severity=severity,
                        verified=is_success or is_redirect,
                        confidence=0.9 if is_success else 0.6,
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body[:2000],
                        diffs=diffs,
                        baseline_body=baseline_body[:2000],
                        baseline_status=baseline_status,
                        verification_body=body[:2000],
                        verification_status=resp.status,
                    )
            except Exception:
                continue
        return None


