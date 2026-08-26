"""CSP audit — browser-context module (Track A).

Parses the Content-Security-Policy (header or meta tag) and evaluates its
semantics: does script execution have guardrails, is there a default-src,
are unsafe-inline/unsafe-eval/'*' allowed in script-src, is there a
frame-ancestors (clickjacking), object-src (plugin execution), base-uri
(dangling markup). Pure policy analysis — the oracle is the policy text, so
it is deterministic.

A page with NO CSP at all is the strongest signal (MEDIUM). A weak CSP
(unsafe-inline in script-src) is a HIGH finding because it nullifies XSS
protections. A strong CSP produces no finding.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType


class CSPDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, page, target: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []
        try:
            # Header CSP first (authoritative), meta CSP second.
            csp_header = ""
            try:
                resp = await page.request.get(url, timeout=10000)
                csp_header = (resp.headers or {}).get("content-security-policy", "") or ""
            except Exception:
                pass

            meta_csp = ""
            try:
                meta_csp = await page.evaluate(
                    """() => {
                        const el = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
                        return el ? el.getAttribute('content') || '' : '';
                    }"""
                ) or ""
            except Exception:
                pass

            policy = csp_header or meta_csp
            if not policy:
                findings.append(self._finding(target, url, "", "No Content-Security-Policy header or meta tag present",
                                              Severity.MEDIUM, 0.7, ["csp:missing"]))
                return findings

            directive_sources = self._parse_directives(policy)
            script_src = directive_sources.get("script-src", []) or directive_sources.get("default-src", [])

            # CSP source values are written WITH their quote characters
            # ("'unsafe-inline'"), so the membership check must use the
            # quoted forms — matching "unsafe-inline" alone never fires.
            if "'unsafe-inline'" in script_src or "unsafe-inline" in script_src:
                findings.append(self._finding(target, url, policy, "script-src allows unsafe-inline — inline XSS is executable",
                                              Severity.HIGH, 0.85, ["csp:script-unsafe-inline"]))
            if "'unsafe-eval'" in script_src or "unsafe-eval" in script_src:
                findings.append(self._finding(target, url, policy, "script-src allows unsafe-eval — eval() based attacks are not blocked",
                                              Severity.MEDIUM, 0.75, ["csp:script-unsafe-eval"]))
            if "'*'" in script_src or "*" in script_src:
                findings.append(self._finding(target, url, policy, "script-src allows wildcard origin — any domain can load scripts",
                                              Severity.HIGH, 0.8, ["csp:script-wildcard"]))
            if not directive_sources.get("frame-ancestors"):
                findings.append(self._finding(target, url, policy, "CSP lacks frame-ancestors — clickjacking not blocked by CSP",
                                              Severity.LOW, 0.6, ["csp:no-frame-ancestors"]))
            if not directive_sources.get("object-src"):
                findings.append(self._finding(target, url, policy, "CSP lacks object-src — plugin/media injection not blocked",
                                              Severity.MEDIUM, 0.6, ["csp:no-object-src"]))
            if not directive_sources.get("base-uri"):
                findings.append(self._finding(target, url, policy, "CSP lacks base-uri — dangling markup / base-tag hijack possible",
                                              Severity.LOW, 0.55, ["csp:no-base-uri"]))

        except Exception:
            return findings
        return findings

    @staticmethod
    def _parse_directives(policy: str) -> Dict[str, List[str]]:
        """Parse a CSP policy into {directive: [sources]}."""
        directives: Dict[str, List[str]] = {}
        for segment in re.split(r";", policy):
            segment = segment.strip()
            if not segment:
                continue
            parts = segment.split()
            if not parts:
                continue
            directive = parts[0].lower()
            sources = [p for p in parts[1:] if p]
            directives[directive] = sources
        return directives

    def _finding(self, target, url, policy, note, severity, confidence, diffs) -> Finding:
        return Finding(
            target=target,
            url=url,
            method="GET",
            param="Content-Security-Policy",
            location="header",
            payload=f"CSP weakness: {note}",
            attack_type=AttackType.CSP_WEAKNESS,
            severity=severity,
            verified=True,
            confidence=confidence,
            status=200,
            body=policy[:2000],
            diffs=diffs,
            verification_body=policy[:2000],
            verification_status=200,
            metadata={"csp_policy": policy[:1000]},
        )
