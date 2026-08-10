"""SSTI detection module for Titan Scanner."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import extract_error_classes, score_signals


class SSTIDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        ssti_params = [p for p in params if any(k in p.lower() for k in ["name", "username", "page", "template", "view", "path", "dir", "folder", "file", "load", "include"])]
        if not ssti_params:
            return findings

        context_data = {
            "fingerprint": self.fingerprint,
            "attack_type": "ssti",
            "param_type": "template",
            "location": "query" if method == "GET" else "body",
        }
        base_payloads = self.payload_smith.get_base_payloads("ssti", context_data)[:6]
        waf = self.payload_smith.detect_waf({}, "", 0) or self.fingerprint.get("waf", "unknown")
        if waf != "unknown":
            base_payloads.extend(self.payload_smith.get_waf_bypass_payloads(base_payloads[:3], waf)[:3])
        # Distinctive math-eval probes: 777*777 -> 603729 is unambiguous (the
        # plain 7*7 -> 49 answer can collide with benign page content), and
        # 7*'7' -> 7777777 is the Jinja2 string-multiplication discriminator.
        base_payloads = base_payloads + ["{{777*777}}", "{{7*'7'}}"]
        payloads = list(dict.fromkeys(base_payloads))[:8]

        for param_name in ssti_params[:3]:
            finding = await self._test_param(context, target, method, url, param_name, params, payloads)
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

                # Evidence signals.
                signals: List[str] = []

                # Deterministic math-eval oracle: a template engine that
                # *executed* our expression returns the computed answer. Order
                # matters: the distinctive probes (603729, 7777777) are checked
                # before the canonical 7*7 -> 49 so a benign page that happens
                # to contain "49" can never verify on its own.
                #
                # Answers must be STANDALONE tokens (word-bounded): a per-request
                # session hash / nonce can contain the substring "49" (github.com
                # /signup's SPA state verified a CRITICAL SSTI off the '49' inside
                # its random hex token). An engine that executed 7*7 outputs the
                # number 49 alone, never embedded in a longer token.
                if "777*777" in payload and self._has_answer(body, "603729") and not self._has_answer(baseline_body, "603729"):
                    signals.append("sanity_pair")
                    diffs.append("ssti:math_eval:777*777=603729")
                elif "7*'7'" in payload and self._has_answer(body, "7777777") and not self._has_answer(baseline_body, "7777777"):
                    signals.append("sanity_pair")
                    diffs.append("ssti:math_eval:7*'7'=7777777")
                elif "7*7" in payload and self._has_answer(body, "49") and not self._has_answer(baseline_body, "49"):
                    signals.append("sanity_pair")
                    diffs.append("ssti:math_eval:7*7=49")

                # Template-engine error classes (jinja2, twig, freemarker, ...).
                for label in self._detect_error_class(body, baseline_body):
                    signals.append("error:template")
                    diffs.append(label)

                # Generic error classes — only sinks that belong to an *eval*
                # context (a filesystem error means the parameter hit open(),
                # not a template engine — that evidence belongs to LFI).
                ALLOWED = {"generic", "python", "java"}
                for error_class in extract_error_classes(body):
                    if error_class in ALLOWED:
                        signals.append(f"error:{error_class}")
                        diffs.append(f"ssti:error_class:{error_class}")

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
        """True if ``answer`` appears in ``body`` as a standalone token (not
        embedded in a longer alphanumeric string). Random per-request tokens
        (session hashes, nonces) routinely contain the substring "49" — only a
        template engine that executed ``7*7`` emits the number 49 alone."""
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
            ("expression", "template_expression"),
            ("could not resolve", "template_resolve_error"),
            ("syntax error", "template_syntax_error"),
        ]
        for pattern, label in error_patterns:
            if pattern in tl and pattern not in bl:
                indicators.append(f"error_class:{label}")
        return indicators
