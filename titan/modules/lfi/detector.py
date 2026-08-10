"""Path traversal / LFI detection module for Titan Scanner."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import extract_error_classes, score_signals


class LFIDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        file_params = [p for p in params if any(k in p.lower() for k in ["file", "path", "page", "template", "include", "doc", "view", "load", "read", "source", "content", "dir", "folder"])]
        if not file_params:
            return findings

        context_data = {
            "fingerprint": self.fingerprint,
            "attack_type": "lfi",
            "param_type": "path",
            "location": "query" if method == "GET" else "body",
        }
        base_payloads = self.payload_smith.get_base_payloads("lfi", context_data)[:6]
        waf = self.payload_smith.detect_waf({}, "", 0) or self.fingerprint.get("waf", "unknown")
        if waf and waf != "unknown":
            base_payloads.extend(self.payload_smith.get_waf_bypass_payloads(base_payloads[:3], waf)[:3])
        payloads = await self.payload_smith.mutate(base_payloads, context_data)
        all_payloads = list(dict.fromkeys(base_payloads + payloads))[:6]

        for param_name in file_params[:3]:
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

                # Content leak: known file/secret markers appearing in the body.
                lfi_indicators = [
                    "root:", "daemon:", "bin:", "sys:", "home:", "etc/passwd",
                    "apache", "nginx", "www-data", "var/www", "program files",
                    "windows", "system32", "users/admin", "web server",
                    "error_log", "access_log", "auth.log", "mysql",
                    "extension_dir", "upload_tmp_dir", "session.save_path",
                    "open_basedir", "safe_mode", "disable_functions",
                ]
                matches = [ind for ind in lfi_indicators if ind in body.lower()]

                # Evidence signals: content leak, error classes (filesystem sink),
                # reflection, status, generic change.
                signals: List[str] = []
                if matches:
                    signals.append("content_leak")
                for error_class in extract_error_classes(body):
                    signals.append(f"error:{error_class}")
                    diffs.append(f"lfi:error_class:{error_class}")
                if payload.lower() in body.lower() and payload.lower() not in baseline_body.lower():
                    signals.append("reflection")
                if resp.status >= 500:
                    signals.append("status_500")
                if len(body) != len(baseline_body):
                    signals.append("content_change")

                if signals:
                    confidence, verified, _ = score_signals(signals)
                    if confidence >= 0.3:
                        severity = Severity.CRITICAL if (matches or verified) else Severity.HIGH
                        return Finding(
                            target=target,
                            url=str(resp.url or url),
                            method=method.upper(),
                            param=param_name,
                            location="query" if method == "GET" else "body",
                            payload=payload,
                            attack_type=AttackType.LFI,
                            severity=severity,
                            verified=verified or bool(matches),
                            confidence=confidence,
                            status=resp.status,
                            headers=dict(resp.headers),
                            body=body[:2000],
                            diffs=diffs + [f"lfi:{m}" for m in matches],
                            baseline_body=baseline_body[:2000],
                            baseline_status=baseline_status,
                            verification_body=body[:2000],
                            verification_status=resp.status,
                        )
            except Exception:
                continue
        return None
