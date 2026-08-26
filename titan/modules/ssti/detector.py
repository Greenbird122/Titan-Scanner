"""SSTI detection module for Titan Scanner — fully exhausted.

Features:
  1. Multi-Engine Syntax & Discrimination:
     • Jinja2 / Twig / Nunjucks ({{7*7}}, {{777*777}}, {{7*'7'}})
     • Freemarker / SpEL / Mako (${7*7}, ${777*777}, #{7*7})
     • Smarty ({7*7}, {777*777}, {$smarty.version})
     • ERB / EJS (<%= 7*7 %>, <%= 777*777 %>)
     • Thymeleaf ([[${7*7}]], __${7*7}__)
  2. Zero Parameter Whitelisting: tests all parameters without caps.
  3. HTTP Header Injection: tests template injection in high-risk headers.
  4. Nested JSON AST Walker: recursively injects into deep API JSON bodies.
  5. Strict Nonce & Word-Bounded Math Oracles:
     • Standalone word-boundary math evaluation (49, 603729, 7777777)
     • Raw template echo guard (rejects echo without eval)
     • Multi-engine error signature identification
     • Cross-module FP isolation (eval errors only, no filesystem errors)
"""

from __future__ import annotations

import copy
import json
import random
import re
import string
from typing import Any, Dict, List, Optional, Tuple

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import extract_error_classes, score_signals


# ---------------------------------------------------------------------------
# Multi-Engine Template Injection Probes
# ---------------------------------------------------------------------------

_SSTI_MATH_PROBES: Tuple[Tuple[str, str, str], ...] = (
    # (payload, expected_standalone_result, engine_family)
    ("{{777*777}}", "603729", "jinja2/twig/nunjucks"),
    ("{{7*'7'}}", "7777777", "jinja2_discriminator"),
    ("{{7*7}}", "49", "jinja2/twig/nunjucks"),
    ("${777*777}", "603729", "freemarker/spel/mako"),
    ("${7*7}", "49", "freemarker/spel/mako"),
    ("#{777*777}", "603729", "freemarker/thymeleaf"),
    ("#{7*7}", "49", "freemarker/thymeleaf"),
    ("{777*777}", "603729", "smarty"),
    ("{7*7}", "49", "smarty"),
    ("<%= 777*777 %>", "603729", "erb/ejs"),
    ("<%= 7*7 %>", "49", "erb/ejs"),
    ("[[${777*777}]]", "603729", "thymeleaf"),
    ("[[${7*7}]]", "49", "thymeleaf"),
    ("*{777*777}", "603729", "thymeleaf"),
)

_SSTI_ESCAPE_PROBES: Tuple[str, ...] = (
    "{{config}}",
    "{{self.__init__.__globals__.__builtins__}}",
    "{{_self.env.registerUndefinedFilterCallback('exec')}}",
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>",
    "{$smarty.version}",
    "${T(java.lang.Runtime).getRuntime()}",
)

_INJECTABLE_HEADERS_SSTI: Tuple[str, ...] = (
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Template-Name",
    "X-Custom-Template",
)


class SSTIDetector:
    """Production-grade SSTI detector with exhaustive template engine coverage."""

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
            "attack_type": "ssti",
            "param_type": "template",
            "location": "query" if method == "GET" else "body",
        }

        # Build payload pool
        base_payloads = self.payload_smith.get_base_payloads("ssti", context_data)
        waf = (
            self.payload_smith.detect_waf({}, "", 0)
            or self.fingerprint.get("waf", "unknown")
        )
        if waf and waf != "unknown":
            base_payloads.extend(
                self.payload_smith.get_waf_bypass_payloads(base_payloads[:3], waf)
            )

        math_payloads = [p[0] for p in _SSTI_MATH_PROBES]
        all_payloads = list(dict.fromkeys(math_payloads + list(_SSTI_ESCAPE_PROBES) + base_payloads))

        # ── Engine 1: Query & Form Parameters (all params, no keyword whitelist) ──
        for param_name in list(params.keys()):
            f = await self._test_param(context, target, method, url, param_name, params, all_payloads)
            if f:
                findings.append(f)

        # ── Engine 2: HTTP Header SSTI ─────────────────────────────────
        header_findings = await self._scan_headers(context, target, method, url, params, all_payloads)
        findings.extend(header_findings)

        # ── Engine 3: Nested JSON Body SSTI ───────────────────────────
        json_findings = await self._scan_json_body(context, target, method, url, params, all_payloads)
        findings.extend(json_findings)

        return findings

    # ------------------------------------------------------------------
    # ENGINE 2 — HTTP HEADER SSTI
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

        for header_name in _INJECTABLE_HEADERS_SSTI:
            for probe, answer, engine in _SSTI_MATH_PROBES[:6]:
                try:
                    inject_headers = {**safe_headers, header_name: probe}
                    if method == "GET":
                        resp = await context.request.get(url, params=params, headers=inject_headers, timeout=3000)
                    else:
                        resp = await context.request.post(url, data=params, headers=inject_headers, timeout=3000)
                    body = await resp.text()

                    if self._has_answer(body, answer) and not self._has_answer(baseline_body, answer) and probe not in body:
                        diffs = BaselineAnalyzer.diff_responses(baseline_body, body, probe)
                        diffs.append(f"ssti:header_math_eval:{probe}={answer}")
                        diffs.append(f"ssti:engine:{engine}")
                        findings.append(Finding(
                            target=target,
                            url=str(resp.url or url),
                            method=method.upper(),
                            param=header_name,
                            location="header",
                            payload=probe,
                            attack_type=AttackType.SSTI,
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
                            metadata={"injection_location": "http_header", "engine": engine},
                        ))
                        break
                except Exception:
                    continue

        return findings

    # ------------------------------------------------------------------
    # ENGINE 3 — NESTED JSON AST SSTI
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

        for path in leaves:
            for probe, answer, engine in _SSTI_MATH_PROBES[:6]:
                try:
                    mutated = copy.deepcopy(tree)
                    self._json_set(mutated, path, probe)
                    resp = await context.request.post(
                        url,
                        data=json.dumps(mutated),
                        headers={"Content-Type": "application/json", "Referer": target},
                        timeout=3000,
                    )
                    body = await resp.text()

                    if self._has_answer(body, answer) and not self._has_answer(baseline_body, answer) and probe not in body:
                        diffs = BaselineAnalyzer.diff_responses(baseline_body, body, probe)
                        diffs.append(f"ssti:json_math_eval:{probe}={answer}")
                        diffs.append(f"ssti:engine:{engine}")
                        findings.append(Finding(
                            target=target,
                            url=str(resp.url or url),
                            method="POST",
                            param=".".join(str(p) for p in path),
                            location="json_body",
                            payload=probe,
                            attack_type=AttackType.SSTI,
                            severity=Severity.CRITICAL,
                            verified=True,
                            confidence=0.90,
                            status=resp.status,
                            headers=dict(resp.headers),
                            body=body[:2000],
                            diffs=diffs,
                            baseline_body=baseline_body[:2000],
                            baseline_status=baseline_status,
                            verification_body=body[:2000],
                            verification_status=resp.status,
                            metadata={"injection_location": "json_ast", "json_path": path, "engine": engine},
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
            if method == "GET":
                baseline_resp = await context.request.get(url, params=all_params, headers={"Referer": target}, timeout=3000)
            else:
                baseline_resp = await context.request.post(url, data=all_params, headers={"Referer": target}, timeout=3000)
            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status
        except Exception:
            pass

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
                signals: List[str] = []

                # Math-eval deterministic oracle:
                # 1. Probe 777*777 -> 603729
                if "777*777" in payload and self._has_answer(body, "603729") and not self._has_answer(baseline_body, "603729"):
                    if payload not in body:  # Ensure raw template source wasn't just echoed
                        signals.append("sanity_pair")
                        diffs.append("ssti:math_eval:777*777=603729")
                # 2. Probe 7*'7' -> 7777777 (Jinja2 discriminator)
                elif "7*'7'" in payload and self._has_answer(body, "7777777") and not self._has_answer(baseline_body, "7777777"):
                    if payload not in body:
                        signals.append("sanity_pair")
                        diffs.append("ssti:math_eval:7*'7'=7777777")
                # 3. Probe 7*7 -> 49
                elif "7*7" in payload and self._has_answer(body, "49") and not self._has_answer(baseline_body, "49"):
                    if payload not in body:
                        signals.append("sanity_pair")
                        diffs.append("ssti:math_eval:7*7=49")

                # Template-engine error classes (jinja2, twig, freemarker, etc.)
                # IMPORTANT: Strip payload from body first so keywords in the payload itself (e.g. 'undefined') aren't mistaken for engine errors
                body_without_payload = body.replace(payload, "")
                for label in self._detect_error_class(body_without_payload, baseline_body):
                    signals.append("error:template")
                    diffs.append(label)

                # Generic eval error classes (isolated from filesystem errors)
                ALLOWED = {"generic", "python", "java", "ruby", "php"}
                for error_class in extract_error_classes(body_without_payload):
                    if error_class in ALLOWED:
                        signals.append(f"error:{error_class}")
                        diffs.append(f"ssti:error_class:{error_class}")

                if resp.status >= 500:
                    signals.append("status_500")

                # If the payload is simply reflected in the body without evaluation or actual error, skip it
                if payload in body and "sanity_pair" not in signals and "error:template" not in signals and resp.status < 500:
                    continue

                if signals:
                    confidence, verified, _ = score_signals(signals)
                    if confidence >= 0.7 or verified:
                        severity = Severity.CRITICAL if verified else Severity.HIGH
                        return Finding(
                            target=target,
                            url=str(resp.url or url),
                            method=method.upper(),
                            param=param_name,
                            location="query" if method == "GET" else "body",
                            payload=payload,
                            attack_type=AttackType.SSTI,
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

    @staticmethod
    def _has_answer(body: str, answer: str) -> bool:
        """True if ``answer`` appears in ``body`` as a standalone token."""
        if not body:
            return False
        return re.search(rf"(?<![0-9A-Za-z]){re.escape(answer)}(?![0-9A-Za-z])", body) is not None

    def _detect_error_class(self, body: str, baseline: str) -> List[str]:
        """Detect template engine error classes."""
        bl = baseline.lower() if baseline else ""
        tl = body.lower()
        if tl == bl:
            return []

        indicators = []
        error_patterns = [
            ("templateerror", "template_error"),
            ("templatenotfound", "template_not_found"),
            ("undefined", "template_undefined"),
            ("jinja2", "jinja2_error"),
            ("twig", "twig_error"),
            ("freemarker", "freemarker_error"),
            ("velocity", "velocity_error"),
            ("struts", "struts_error"),
            ("smarty", "smarty_error"),
            ("mako", "mako_error"),
            ("thymeleaf", "thymeleaf_error"),
            ("expression", "template_expression"),
            ("could not resolve", "template_resolve_error"),
            ("syntax error", "template_syntax_error"),
        ]
        for pattern, label in error_patterns:
            if pattern in tl and pattern not in bl:
                indicators.append(f"error_class:{label}")
        return indicators



