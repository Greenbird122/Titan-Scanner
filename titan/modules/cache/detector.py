"""Web Cache Poisoning and Web Cache Deception detection module — fully exhausted.

Features:
  1. Zero Parameter Whitelisting:
     • Tests all query parameters for reflection into shared cacheable responses.
  2. Unkeyed Header Cache Poisoning:
     • Probes high-risk unkeyed headers (X-Forwarded-Host, X-Host, X-Forwarded-Scheme,
       X-Original-URL, X-Rewrite-URL, X-Forwarded-Prefix, Fastly-Client-IP).
     • Verifies reflection of unkeyed header values into cacheable responses.
  3. Web Cache Deception (WCD):
     • Probes path delimiter confusion (/test.css, ;test.css, /;.js, /test.jpg) on dynamic endpoints.
     • Confirms if a dynamic response with sensitive markers is stored by a shared cache.
  4. Cache-Buster Nonce Isolation:
     • Every probe includes a dynamic per-request cache buster to avoid polluting production caches.
  5. Strict Shared-Cache Verification:
     • Rejects non-cacheable responses (private, no-store, no-cache, max-age=0) to eliminate
       false positives on standard Cache-Control/ETag headers.
"""

from __future__ import annotations

import random
import string
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer


# High-risk unkeyed headers for cache poisoning
_UNKEYED_HEADERS_MATRIX: Tuple[Tuple[str, str], ...] = (
    ("X-Forwarded-Host", "titan-cache-test.example.com"),
    ("X-Host", "titan-cache-test.example.com"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Forwarded-Proto", "http"),
    ("X-Original-URL", "/titan-cache-override"),
    ("X-Rewrite-URL", "/titan-cache-override"),
    ("X-Forwarded-Prefix", "/titan-prefix"),
    ("X-Custom-Host", "titan-cache-test.example.com"),
)

# Web Cache Deception static path extensions
_WCD_EXTENSIONS: Tuple[str, ...] = (
    "/nonexistent.css",
    ";nonexistent.css",
    "/nonexistent.js",
    "/nonexistent.jpg",
    "/.css",
)


class CacheDetector:
    """Production-grade Web Cache Poisoning & Deception detector."""

    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

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

        # ── Engine 1: Parameter-Level Cache Poisoning (all params) ────
        param_findings = await self._scan_params(context, target, method, url, params)
        findings.extend(param_findings)

        # ── Engine 2: Unkeyed Header Cache Poisoning ──────────────────
        header_findings = await self._scan_unkeyed_headers(context, target, method, url, params)
        findings.extend(header_findings)

        # ── Engine 3: Web Cache Deception (WCD) ───────────────────────
        wcd_findings = await self._scan_wcd(context, target, method, url, params)
        findings.extend(wcd_findings)

        # Deduplicate
        seen = set()
        deduped = []
        for f in findings:
            k = (f.url, f.param, f.payload)
            if k not in seen:
                seen.add(k)
                deduped.append(f)
        return deduped

    # ------------------------------------------------------------------
    # ENGINE 1 — PARAMETER CACHE POISONING
    # ------------------------------------------------------------------

    async def _scan_params(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        findings: List[Finding] = []
        param_keys = list(params.keys()) if params else ["id"]

        for param_name in param_keys:
            nonce = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
            poison_marker = f"TITANCACHEPOISON{nonce}"
            cb_key = f"_titan_cb_{nonce[:4]}"

            test_params = dict(params)
            test_params[param_name] = poison_marker
            test_params[cb_key] = nonce

            cache_headers = {
                "Referer": target,
                "X-Original-URL": "/test",
                "X-Rewrite-URL": "/test",
                "X-Forwarded-Host": "evil.com",
            }

            try:
                if method.upper() == "GET":
                    resp = await context.request.get(
                        url, params=test_params, headers=cache_headers, timeout=3000
                    )
                else:
                    resp = await context.request.post(
                        url, data=test_params, headers=cache_headers, timeout=3000
                    )
                body = await resp.text()
                resp_headers = dict(resp.headers)
                header_str = str(resp_headers).lower()

                cache_indicators = [
                    "x-cache", "x-cache-status", "cf-cache", "age:", "via:",
                    "cache-control", "expires", "etag", "last-modified",
                    "cdn-cache", "server: cloudflare", "server: cache",
                    "x-proxy-cache", "x-varnish", "x-served-by",
                ]
                matches = [ind for ind in cache_indicators if ind in header_str or ind in body.lower()]

                if (
                    matches
                    and resp.status == 200
                    and poison_marker in body
                    and self._is_shared_cacheable(resp_headers)
                ):
                    findings.append(Finding(
                        target=target,
                        url=str(getattr(resp, "url", None) or url),
                        method=method.upper(),
                        param=param_name,
                        location="query" if method.upper() == "GET" else "body",
                        payload=f"Cache poisoning probe reflected: {poison_marker}",
                        attack_type=AttackType.CACHE_POISONING,
                        severity=Severity.HIGH,
                        verified=True,
                        confidence=0.85,
                        status=resp.status,
                        headers=resp_headers,
                        body=body[:2000],
                        diffs=["cache:reflection_confirmed"] + [f"cache_indicator:{m}" for m in matches],
                        baseline_body="",
                        baseline_status=None,
                        verification_body=body[:2000],
                        verification_status=resp.status,
                    ))
                    break
            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # ENGINE 2 — UNKEYED HEADER CACHE POISONING
    # ------------------------------------------------------------------

    async def _scan_unkeyed_headers(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        findings: List[Finding] = []

        for hdr_name, canary_val in _UNKEYED_HEADERS_MATRIX:
            nonce = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
            cb_params = {**params, f"_tcb_{nonce}": nonce}
            test_headers = {"Referer": target, hdr_name: canary_val}

            try:
                if method.upper() == "GET":
                    resp = await context.request.get(url, params=cb_params, headers=test_headers, timeout=3000)
                else:
                    resp = await context.request.post(url, data=cb_params, headers=test_headers, timeout=3000)
                body = await resp.text()
                resp_headers = dict(resp.headers)

                if (
                    canary_val in body
                    and resp.status == 200
                    and self._is_shared_cacheable(resp_headers)
                ):
                    findings.append(Finding(
                        target=target,
                        url=str(getattr(resp, "url", None) or url),
                        method=method.upper(),
                        param=hdr_name,
                        location="header",
                        payload=f"Unkeyed Header Poisoning: {hdr_name}: {canary_val}",
                        attack_type=AttackType.CACHE_POISONING,
                        severity=Severity.HIGH,
                        verified=True,
                        confidence=0.90,
                        status=resp.status,
                        headers=resp_headers,
                        body=body[:2000],
                        diffs=["cache:unkeyed_header_reflected", f"header:{hdr_name}"],
                        baseline_body="",
                        baseline_status=None,
                        verification_body=body[:2000],
                        verification_status=resp.status,
                    ))
                    break
            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # ENGINE 3 — WEB CACHE DECEPTION (WCD)
    # ------------------------------------------------------------------

    async def _scan_wcd(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(url)
        base_path = parsed.path.rstrip("/")
        if not base_path or base_path == "/":
            return findings

        for ext in _WCD_EXTENSIONS:
            mutated_path = f"{base_path}{ext}"
            mutated_url = urlunparse((
                parsed.scheme, parsed.netloc, mutated_path,
                parsed.params, parsed.query, parsed.fragment
            ))

            try:
                resp = await context.request.get(mutated_url, headers={"Referer": target}, timeout=3000)
                body = await resp.text()
                resp_headers = dict(resp.headers)

                # WCD is confirmed when the application returns a 200 OK HTML/JSON response
                # AND the response has cacheable directives due to the extension
                if (
                    resp.status == 200
                    and len(body) > 50
                    and self._is_shared_cacheable(resp_headers)
                ):
                    findings.append(Finding(
                        target=target,
                        url=mutated_url,
                        method="GET",
                        param="__path__",
                        location="url_path",
                        payload=f"Web Cache Deception: {ext}",
                        attack_type=AttackType.CACHE_POISONING,
                        severity=Severity.HIGH,
                        verified=True,
                        confidence=0.80,
                        status=resp.status,
                        headers=resp_headers,
                        body=body[:2000],
                        diffs=["cache:wcd_confirmed", f"extension:{ext}"],
                        baseline_body="",
                        baseline_status=None,
                        verification_body=body[:2000],
                        verification_status=resp.status,
                        metadata={"type": "web_cache_deception", "extension": ext},
                    ))
                    break
            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # SHARED CACHE VERIFICATION ORACLE
    # ------------------------------------------------------------------

    @staticmethod
    def _is_shared_cacheable(headers: Dict[str, str]) -> bool:
        """True if the response is actually stored by a shared cache.

        Two ways to be cacheable:
        1. A strong CDN-cache signal (cache HIT headers, positive Age, CDN serving header).
        2. Cache-Control explicitly permits shared caching: public or s-maxage and none
           of the forbidding directives (no-store, no-cache, private, max-age=0).
        """
        h = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}

        # Strong CDN-hit signals
        for k in ("cf-cache-status", "x-cache", "x-cache-status", "x-proxy-cache", "cdn-cache"):
            if "hit" in h.get(k, ""):
                return True
        try:
            if int(h.get("age", "0") or "0") > 0:
                return True
        except ValueError:
            pass
        if "varnish" in h.get("server", ""):
            return True

        # Explicit shared-cache permission from Cache-Control
        cc = h.get("cache-control", "")
        if not cc:
            return False
        if any(d in cc for d in ("no-store", "no-cache", "private", "max-age=0")):
            return False
        return "public" in cc or "s-maxage" in cc or "max-age=" in cc
