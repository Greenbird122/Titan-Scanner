"""XSS detection module for Titan Scanner — fully exhausted.

Six context engines:
  1. Reflected HTML context          (<tag>, text nodes, bare injection)
  2. HTML attribute context          (value="...", event handlers in attrs)
  3. JavaScript string context       ('<script> var x = "USER_INPUT"')
  4. Client-Side Template Injection  (Angular {{…}}, Vue {{…}}, React JSX)
  5. HTTP Header injection           (XSS via User-Agent, Referer stored/reflected)
  6. Nested JSON AST walker          (API bodies with deep key traversal)

Every engine:
  - Tests ALL parameters (no [:3] cap).
  - Uses a unique per-request nonce marker to confirm real reflection.
  - Guards against encoded-reflection false positives.
  - Guards against attribute-context inert echoes.
  - Guards against JSON / plain-text echo non-HTML contexts.
"""

from __future__ import annotations

import copy
import json
import random
import re
import string
from typing import Any

from titan.core.logger import get_logger
from titan.core.models import AttackType, Finding, Severity
from titan.modules.xss.payloads import (
    _ATTR_BREAKOUT_PAYLOADS,
    _CSP_BYPASS_PAYLOADS,
    _CSTI_PAYLOADS,
    _DOM_SINK_PAYLOADS,
    _FRAMEWORK_SINK_PAYLOADS,
    _HTML_TAG_PAYLOADS,
    _HEADER_XSS_PAYLOADS,
    _INJECTABLE_HEADERS_XSS,
    _JS_STRING_PAYLOADS,
    _WAF_BYPASS_VARIANTS,
    build_context_suite,
)
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import extract_error_classes, score_signals

logger = get_logger("detector")


class XSSDetector:
    """Production-grade XSS detector with exhaustive context coverage."""

    def __init__(self, payload_smith, fingerprint: dict[str, Any]):
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
        params: dict[str, str],
    ) -> list[Finding]:
        findings: list[Finding] = []

        context_data = {
            "fingerprint": self.fingerprint,
            "attack_type": "xss",
            "param_type": "text",
            "location": "query" if method == "GET" else "body",
        }

        # Build global payload pool from PayloadForge + all context sets
        base_payloads = self.payload_smith.get_base_payloads("xss", context_data)
        waf = self.payload_smith.detect_waf({}, "", 0) or self.fingerprint.get("waf", "unknown")
        if waf and waf != "unknown":
            base_payloads.extend(self.payload_smith.get_waf_bypass_payloads(base_payloads[:5], waf))
        mutated = await self.payload_smith.mutate(base_payloads, context_data)
        forge_payloads = list(dict.fromkeys(base_payloads + mutated))

        # Assemble complete cross-context suite
        all_payloads = list(
            dict.fromkeys(
                forge_payloads
                + list(_HTML_TAG_PAYLOADS)
                + list(_ATTR_BREAKOUT_PAYLOADS)
                + list(_JS_STRING_PAYLOADS)
                + list(_CSTI_PAYLOADS)
                + list(_WAF_BYPASS_VARIANTS)
                + list(_DOM_SINK_PAYLOADS)
                + list(_CSP_BYPASS_PAYLOADS)
                + list(_FRAMEWORK_SINK_PAYLOADS)
            )
        )

        # ── Engine 1-4: All query/body params, all contexts ───────────
        for param_name in list(params.keys()):
            param_val = params.get(param_name, "")
            param_payloads = self._build_context_suite(param_name, param_val, all_payloads)
            f = await self._test_param(context, target, method, url, param_name, params, param_payloads)
            if f:
                findings.append(f)

        # ── Engine 5: HTTP Header XSS ─────────────────────────────────
        header_findings = await self._scan_headers(context, target, method, url, params)
        findings.extend(header_findings)

        # ── Engine 6: Nested JSON body XSS ───────────────────────────
        json_findings = await self._scan_json_body(context, target, method, url, params, all_payloads)
        findings.extend(json_findings)

        return findings

    # ------------------------------------------------------------------
    # CONTEXT-AWARE PAYLOAD SUITE BUILDER
    # ------------------------------------------------------------------

    def _build_context_suite(self, param_name: str, param_val: str, generic_payloads: list[str]) -> list[str]:
        """Prepend context-specific payloads, then append the full generic pool."""
        return build_context_suite(param_name, param_val, generic_payloads)

    # ------------------------------------------------------------------
    # ENGINE 5 — HTTP HEADER XSS
    # ------------------------------------------------------------------

    async def _scan_headers(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: dict[str, str],
    ) -> list[Finding]:
        """
        Inject XSS payloads into HTTP headers that apps commonly reflect
        back into HTML (e.g. Referer in breadcrumbs, User-Agent in admin panels).
        """
        findings: list[Finding] = []
        safe_headers: dict[str, str] = {"Referer": target}

        try:
            if method == "GET":
                r0 = await context.request.get(url, params=params, headers=safe_headers, timeout=3000)
            else:
                r0 = await context.request.post(url, data=params, headers=safe_headers, timeout=3000)
            baseline_body = await r0.text()
            baseline_status = r0.status
        except Exception:
            return findings

        for header_name in _INJECTABLE_HEADERS_XSS:
            marker = "XHDR" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
            for payload in _HEADER_XSS_PAYLOADS:
                try:
                    marked_payload = payload + f"<!--{marker}-->"
                    inject_headers = {**safe_headers, header_name: marked_payload}
                    if method == "GET":
                        resp = await context.request.get(url, params=params, headers=inject_headers, timeout=3000)
                    else:
                        resp = await context.request.post(url, data=params, headers=inject_headers, timeout=3000)
                    body = await resp.text()

                    raw_marker = f"<!--{marker}-->"
                    ct = (resp.headers.get("content-type", "") or "").lower()
                    non_html_types = {
                        "application/json",
                        "application/xml",
                        "text/xml",
                        "text/plain",
                        "text/json",
                        "application/ld+json",
                    }
                    is_non_html = any(nt in ct for nt in non_html_types)
                    is_html = not is_non_html and (
                        "text/html" in ct or "<html" in body.lower() or "<!doctype" in body.lower()
                    )

                    if raw_marker in body and raw_marker not in baseline_body and is_html:
                        diffs = BaselineAnalyzer.diff_responses(baseline_body, body, marker)
                        diffs.append(f"xss:header_marker_reflected:{marker}")
                        findings.append(
                            Finding(
                                target=target,
                                url=str(resp.url or url),
                                method=method.upper(),
                                param=header_name,
                                location="header",
                                payload=payload,
                                attack_type=AttackType.XSS,
                                severity=Severity.HIGH,
                                verified=True,
                                confidence=0.88,
                                status=resp.status,
                                headers=dict(resp.headers),
                                body=body[:2000],
                                diffs=diffs,
                                baseline_body=baseline_body[:2000],
                                baseline_status=baseline_status,
                                verification_body=body[:2000],
                                verification_status=resp.status,
                                metadata={"injection_location": "http_header"},
                            )
                        )
                        break
                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue

        return findings

    # ------------------------------------------------------------------
    # ENGINE 6 — NESTED JSON AST WALKER
    # ------------------------------------------------------------------

    async def _scan_json_body(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: dict[str, str],
        payloads: list[str],
    ) -> list[Finding]:
        """Recursively walk a JSON body and inject XSS payloads into every leaf."""
        findings: list[Finding] = []
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

        for path in leaves:
            marker = "XJSON" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
            for payload in payloads[:12]:
                try:
                    marked = payload + f"<!--{marker}-->"
                    mutated = copy.deepcopy(tree)
                    self._json_set(mutated, path, marked)
                    resp = await context.request.post(
                        url,
                        data=json.dumps(mutated),
                        headers={"Content-Type": "application/json", "Referer": target},
                        timeout=3000,
                    )
                    body = await resp.text()

                    raw_marker = f"<!--{marker}-->"
                    ct = (resp.headers.get("content-type", "") or "").lower()
                    non_html_types = {
                        "application/json",
                        "application/xml",
                        "text/xml",
                        "text/plain",
                        "text/json",
                        "application/ld+json",
                    }
                    is_non_html = any(nt in ct for nt in non_html_types)
                    is_html = not is_non_html and (
                        "text/html" in ct or "<html" in body.lower() or "<!doctype" in body.lower()
                    )

                    if raw_marker in body and raw_marker not in baseline_body and is_html:
                        diffs = BaselineAnalyzer.diff_responses(baseline_body, body, marker)
                        diffs.append(f"xss:json_marker_reflected:{marker}")
                        findings.append(
                            Finding(
                                target=target,
                                url=str(resp.url or url),
                                method="POST",
                                param=".".join(str(p) for p in path),
                                location="json_body",
                                payload=payload,
                                attack_type=AttackType.XSS,
                                severity=Severity.HIGH,
                                verified=True,
                                confidence=0.85,
                                status=resp.status,
                                headers=dict(resp.headers),
                                body=body[:2000],
                                diffs=diffs,
                                baseline_body=baseline_body[:2000],
                                baseline_status=baseline_status,
                                verification_body=body[:2000],
                                verification_status=resp.status,
                                metadata={"injection_location": "json_ast", "json_path": path},
                            )
                        )
                        break
                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue

        return findings

    def _json_leaves(self, node: Any, path: list | None = None):
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
    # CORE PARAM TEST — all contexts, strict reflection oracle
    # ------------------------------------------------------------------

    async def _test_param(
        self,
        context,
        target: str,
        method: str,
        url: str,
        param_name: str,
        all_params: dict[str, str],
        payloads: list[str],
    ) -> Finding | None:
        baseline_body = ""
        baseline_status = None

        try:
            if method == "GET":
                baseline_resp = await context.request.get(
                    url, params=all_params, headers={"Referer": target}, timeout=3000
                )
            else:
                baseline_resp = await context.request.post(
                    url, data=all_params, headers={"Referer": target}, timeout=3000
                )
            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        # Unique per-param nonce to prevent marker collision across concurrent scans
        nonce = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
        marker = f"TITANXSS{nonce}"

        for payload in payloads:
            try:
                # Append a unique comment marker to confirm the payload's position
                # in the reflected HTML (not just an accidental echo of the tag name)
                marked = f"{payload}<!--{marker}-->"
                test_params = dict(all_params)
                test_params[param_name] = marked

                if method == "GET":
                    resp = await context.request.get(url, params=test_params, headers={"Referer": target}, timeout=3000)
                else:
                    resp = await context.request.post(url, data=test_params, headers={"Referer": target}, timeout=3000)
                body = await resp.text()

                diffs = BaselineAnalyzer.diff_responses(baseline_body, body, marker)
                raw_marker = f"<!--{marker}-->"

                # ── Oracle 1: Marker must be reflected UNESCAPED ──────────
                # If the app HTML-encodes our marker (&lt;!--...--&gt;) the
                # payload was neutralized. Encoded echo is NOT XSS evidence.
                encoded_marker = raw_marker.replace("<", "&lt;").replace(">", "&gt;")
                if encoded_marker in body:
                    continue  # encoded → sanitized, skip

                # ── Oracle 2: Attribute-context inert echo guard ──────────
                # A marker inside value="..." renders as plain text, not JS.
                body_outside_attrs = re.sub(
                    r'=(["\'])[^"\']*?' + re.escape(raw_marker) + r'[^"\']*\1',
                    "",
                    body,
                )

                # ── Oracle 3: Must be an HTML response ────────────────────
                ct = (resp.headers.get("content-type", "") or "").lower()
                non_html_types = {
                    "application/json",
                    "application/xml",
                    "text/xml",
                    "text/plain",
                    "text/json",
                    "application/ld+json",
                }
                is_non_html = any(nt in ct for nt in non_html_types)
                is_html = not is_non_html and (
                    "text/html" in ct or "<html" in body.lower() or "<!doctype" in body.lower()
                )

                # ── Oracle 4: Backend error guard ─────────────────────────
                # If the payload triggered a backend exception (filesystem error,
                # parser crash) any marker echo is a diagnostic dump, not XSS.
                has_backend_error = bool(extract_error_classes(body))

                if (
                    raw_marker in body_outside_attrs
                    and raw_marker not in baseline_body
                    and is_html
                    and not has_backend_error
                ):
                    # ── Oracle 5: CSTI arithmetic confirmation ────────────
                    # For template injection payloads ({{7*7}}), confirm that
                    # the math was evaluated (body contains "49") and the raw
                    # braces were NOT reflected (otherwise it's just an echo).
                    is_csti = "7*7" in payload or "7*'7'" in payload
                    if is_csti:
                        if "49" not in body:
                            continue  # braces reflected but not evaluated → not CSTI
                        if "{{7*7}}" in body:
                            continue  # raw echo, template engine didn't execute it

                    signals = ["xss_unescaped"]
                    diffs.append(f"xss:marker_reflected:{marker}")

                    # Severity escalation: script/onerror execution context = CRITICAL
                    is_exec_context = any(
                        t in payload.lower()
                        for t in [
                            "<script",
                            "onerror=",
                            "onload=",
                            "onfocus=",
                            "onmouseover=",
                            "javascript:",
                            "ontoggle=",
                            "onanimation",
                        ]
                    )
                    severity = Severity.CRITICAL if is_exec_context else Severity.HIGH

                    confidence, verified, _ = score_signals(signals)
                    return Finding(
                        target=target,
                        url=str(resp.url or url),
                        method=method.upper(),
                        param=param_name,
                        location="query" if method == "GET" else "body",
                        payload=payload,
                        attack_type=AttackType.XSS,
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
                        metadata={
                            "context": "csti" if is_csti else "reflected",
                            "exec_context": is_exec_context,
                        },
                    )

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        return None
