"""NoSQLi detection module for Titan Scanner."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import extract_error_classes, is_echo_differential, score_signals


class NoSQLiDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        nosqli_params = [p for p in params if any(k in p.lower() for k in ["id", "user", "query", "filter", "search", "where", "data", "json", "api", "graphql"])]
        if not nosqli_params:
            return findings

        context_data = {
            "fingerprint": self.fingerprint,
            "attack_type": "nosqli",
            "param_type": "json",
            "location": "query" if method == "GET" else "body",
        }
        base_payloads = self.payload_smith.get_base_payloads("nosqli", context_data)[:6]
        waf = self.payload_smith.detect_waf({}, "", 0) or self.fingerprint.get("waf", "unknown")
        if waf != "unknown":
            base_payloads.extend(self.payload_smith.get_waf_bypass_payloads(base_payloads[:3], waf)[:3])
        payloads = list(dict.fromkeys(base_payloads))[:6]

        for param_name in nosqli_params[:3]:
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

                # Boolean-differential oracle: the logical opposite operator must
                # return a different record set. `{"$ne": null}` returning more
                # rows than `{"$eq": null}` is the NoSQLi equivalent of a
                # SQL boolean oracle.
                #
                # Echo guard: subtract the payload and its opposite from their
                # respective bodies. If the *only* difference was the echoed
                # input string (e.g. a reflected "query" field), the cleaned
                # bodies are identical and no injection happened.
                sanity_confirmed = False
                opposite = self._get_opposite_payload(payload)
                if opposite:
                    opp_params = dict(all_params)
                    opp_params[param_name] = opposite
                    if method == "GET":
                        opp_resp = await context.request.get(url, params=opp_params, headers={"Referer": target}, timeout=3000)
                    else:
                        opp_resp = await context.request.post(url, data=opp_params, headers={"Referer": target}, timeout=3000)
                    opp_body = await opp_resp.text()
                    # Echo-clean before comparing: from the JSON structure
                    # perspective, if the ONLY differences are fields whose
                    # values contain the payload or opposite strings, it's
                    # pure echo (no injection occurred).
                    if not is_echo_differential(body, opp_body, payload, opposite):
                        sanity_confirmed = True
                        diffs.append("sanity_pair:boolean_confirmed")

                # Evidence signals.
                signals: List[str] = []
                if sanity_confirmed:
                    signals.append("sanity_pair")

                # Error classes — only sinks that belong to a *NoSQL eval*
                # context.  A filesystem error means the parameter reached
                # open(), not MongoDB — that evidence belongs to LFI.
                ALLOWED = {"generic", "python", "java"}
                for error_class in extract_error_classes(body):
                    if error_class in ALLOWED:
                        signals.append(f"error:{error_class}")
                        diffs.append(f"nosqli:error_class:{error_class}")

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
                            attack_type=AttackType.NO_SQLI,
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

    def _get_opposite_payload(self, payload: str) -> Optional[str]:
        """Logical opposite for the boolean-differential oracle.

        Each swap derives from the ORIGINAL string: chaining ``replace`` calls
        (e.g. ``$gt`` then ``$lt`` on the same result) would undo itself and
        return the payload unchanged, silently disabling the sanity oracle.
        """
        pl = payload.lower()
        if "$ne" in pl:
            return payload.replace("$ne", "$eq")
        if "$gt" in pl and "$lt" not in pl:
            return payload.replace("$gt", "$lt")
        if "$lt" in pl and "$gt" not in pl:
            return payload.replace("$lt", "$gt")
        if "$exists" in pl:
            return payload.replace("true", "false")
        if "$regex" in pl:
            return payload.replace("$regex", "$eq")
        return None
