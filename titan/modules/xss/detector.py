"""XSS detection module for Titan Scanner."""

from __future__ import annotations

import random
import re
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import score_signals


class XSSDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        context_data = {
            "fingerprint": self.fingerprint,
            "attack_type": "xss",
            "param_type": "text",
            "location": "query" if method == "GET" else "body",
        }
        base_payloads = self.payload_smith.get_base_payloads("xss", context_data)[:6]
        waf = self.payload_smith.detect_waf({}, "", 0) or self.fingerprint.get("waf", "unknown")
        if waf != "unknown":
            base_payloads.extend(self.payload_smith.get_waf_bypass_payloads(base_payloads[:3], waf)[:3])
        payloads = await self.payload_smith.mutate(base_payloads, context_data)
        all_payloads = list(dict.fromkeys(base_payloads + payloads))[:6]

        for param_name in list(params.keys())[:3]:
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

        marker = f"TITANXSS{random.randint(1000,9999)}"
        
        for payload in payloads:
            try:
                marked = f"{payload}<!--{marker}-->"
                test_params = dict(all_params)
                test_params[param_name] = marked
                if method == "GET":
                    resp = await context.request.get(url, params=test_params, headers={"Referer": target}, timeout=3000)
                else:
                    resp = await context.request.post(url, data=test_params, headers={"Referer": target}, timeout=3000)
                body = await resp.text()

                diffs = BaselineAnalyzer.diff_responses(baseline_body, body, marker)

                # Evidence signals. XSS confirmation requires the *raw* marker
                # (real angle brackets) to come back unescaped. If the app
                # HTML-encodes it (&lt;!--...--&gt;) the payload was neutralized
                # and there is no XSS — a body diff alone is never evidence.
                #
                # Three additional guards prevent false positives:
                # 1. The marker must appear outside a quoted attribute value
                #    (inside an attribute it renders as inert text).
                # 2. The response must be HTML (JSON / plain-text echo of the
                #    marker is not an executable context).
                # 3. Error classes indicate the payload hit a backend sink
                #    (filesystem, parser, etc.), making any marker echo a
                #    diagnostic dump, not rendered HTML.
                signals: List[str] = []
                raw_marker = f"<!--{marker}-->"

                # Guard 1: strip attribute-context occurrences.
                body_outside_attrs = re.sub(
                    r'=(["\'])[^"\']*?' + re.escape(raw_marker) + r'[^"\']*\1',
                    "", body,
                )

                # Guard 2: response must be HTML (content-type or DOCTYPE).
                ct = (resp.headers.get("content-type", "") or "").lower()
                is_html = "text/html" in ct or "<html" in body.lower() or "<!doctype" in body.lower()

                # Guard 3: payload must not have touched a backend sink.
                from titan.verify.oracles import extract_error_classes
                has_error = bool(extract_error_classes(body))

                if raw_marker in body_outside_attrs and raw_marker not in baseline_body and is_html and not has_error:
                    signals.append("xss_unescaped")
                    diffs.append(f"xss:marker_reflected:{marker}")

                if signals:
                    confidence, verified, _ = score_signals(signals)
                    return Finding(
                        target=target,
                        url=str(resp.url or url),
                        method=method.upper(),
                        param=param_name,
                        location="query" if method == "GET" else "body",
                        payload=payload,
                        attack_type=AttackType.XSS,
                        severity=Severity.HIGH,
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


