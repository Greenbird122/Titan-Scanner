"""SSRF detection module for Titan Scanner."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import extract_error_classes, payload_encodings, score_signals


class SSRFDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint
        self.interactsh = fingerprint.get("interactsh")

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        context_data = {
            "fingerprint": self.fingerprint,
            "attack_type": "ssrf",
            "param_type": "url",
            "location": "query",
        }
        base_payloads = self.payload_smith.get_base_payloads("ssrf", context_data)[:6]
        waf = self.payload_smith.detect_waf({}, "", 0) or self.fingerprint.get("waf", "unknown")
        if waf and waf != "unknown":
            base_payloads.extend(self.payload_smith.get_waf_bypass_payloads(base_payloads[:3], waf)[:3])
        payloads = list(dict.fromkeys(base_payloads))[:6]

        url_like = ["url", "link", "redirect", "site", "page", "fetch", "load", "uri", "src", "href", "callback", "return", "next", "continue", "path", "file", "resource"]
        for param_name in params:
            if not any(k in param_name.lower() for k in url_like):
                continue
            if not params.get(param_name):
                continue
            finding = await self._test_param(context, target, method, url, param_name, params, payloads[:3])
            if finding:
                findings.append(finding)
                break

        return findings

    async def _test_param(self, context, target, method, url, param_name, all_params, payloads) -> Optional[Finding]:
        baseline_body = ""
        baseline_status = None

        try:
            baseline_resp = await context.request.get(url, params=all_params, headers={"Referer": target}, timeout=3000)
            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status
        except Exception:
            pass

        oob_url = None
        if self.interactsh:
            try:
                oob_url = self.interactsh.generate_oob_url("ssrf")
            except Exception:
                pass

        for payload in payloads + ([oob_url] if oob_url else []):
            try:
                test_params = dict(all_params)
                test_params[param_name] = payload
                resp = await context.request.get(url, params=test_params, headers={"Referer": target}, timeout=3000)
                body = await resp.text()

                diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)

                # Evidence signals. Content-leak markers are checked against the
                # body *minus the payload in every form the server may have
                # echoed it back* (raw, fully URL-encoded, plus-as-space,
                # entity-escaped): an app that merely echoes the URL would
                # otherwise self-verify (the payload string contains
                # "169.254" and "meta-data"). GitHub's branded 404 page
                # reflects the *encoded* request URL
                # (page=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F)
                # into its body, so a raw-only strip left the markers alive
                # inside the echo and self-verified 12 CRITICAL SSRF findings.
                signals: List[str] = []
                stripped = body.lower()
                for form in payload_encodings(payload):
                    stripped = stripped.replace(form.lower(), "")
                content_indicators = [
                    "ami-id", "meta-data", "meta data", "169.254",
                    "100.100.100.200", "metadata.google",
                    "sshd", "openssh", "root:", "daemon:",
                ]
                content_matches = [ind for ind in content_indicators if ind in stripped]
                if content_matches:
                    signals.append("content_leak")
                    for m in content_matches:
                        diffs.append(f"ssrf:content:{m}")

                # Error classes — only sinks that belong to a *URL fetch*
                # context.  A filesystem error means the parameter reached
                # open(), not urllib — that evidence belongs to LFI.
                ALLOWED = {"generic", "python", "java"}
                for error_class in extract_error_classes(body):
                    if error_class in ALLOWED:
                        signals.append(f"error:{error_class}")
                        diffs.append(f"ssrf:error_class:{error_class}")

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
                            location="query",
                            payload=payload,
                            attack_type=AttackType.SSRF,
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

        if oob_url and self.interactsh:
            try:
                await self.interactsh.register()
                test_params = dict(all_params)
                test_params[param_name] = oob_url
                await context.request.get(url, params=test_params, headers={"Referer": target}, timeout=3000)
                await asyncio.sleep(2)
                oob_results = await self.interactsh.poll(timeout=10)
                if oob_results:
                    return Finding(
                        target=target,
                        url=url,
                        method=method.upper(),
                        param=param_name,
                        location="query",
                        payload=f"OOB SSRF: {oob_url}",
                        attack_type=AttackType.SSRF,
                        severity=Severity.CRITICAL,
                        verified=True,
                        confidence=0.95,
                        status=200,
                        headers={},
                        body="",
                        diffs=["ssrf:oob_confirmed"],
                        baseline_body=baseline_body[:2000],
                        baseline_status=baseline_status,
                        verification_body="OOB interaction confirmed",
                        verification_status=200,
                    )
            except Exception:
                pass

        return None
