"""Cache poisoning detection module for Titan Scanner."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer


class CacheDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        cacheable_params = [p for p in params if any(k in p.lower() for k in ["id", "page", "limit", "offset", "sort", "filter", "search", "q", "category", "type", "status"])]
        if not cacheable_params:
            return findings

        for param_name in cacheable_params[:2]:
            finding = await self._test_cache_poisoning(context, target, method, url, param_name, params)
            if finding:
                findings.append(finding)
                break

        return findings

    async def _test_cache_poisoning(self, context, target, method, url, param_name, all_params) -> Optional[Finding]:
        try:
            poison_marker = "TITANCACHEPOISON"
            test_params = dict(all_params)
            test_params[param_name] = poison_marker

            cache_headers = {
                "Referer": target,
                "X-Original-URL": "/test",
                "X-Rewrite-URL": "/test",
                "X-Forwarded-Host": "evil.com",
            }

            if method == "GET":
                resp = await context.request.get(url, params=test_params, headers=cache_headers, timeout=3000)
            else:
                resp = await context.request.post(url, data=test_params, headers=cache_headers, timeout=3000)
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

            # Cache poisoning needs BOTH halves: (1) the poisoned value is
            # reflected AND (2) the response is demonstrably stored by a
            # SHARED cache. Header presence alone is not enough — GitHub sends
            # Cache-Control/ETag/Age on every response, yet its
            # ``max-age=0, private, must-revalidate`` pages are NOT cacheable;
            # the pre-fix detector verified a HIGH cache-poisoning finding on
            # github.com's dead /upload route off those standard headers.
            if (
                matches
                and resp.status == 200
                and poison_marker in body
                and self._is_shared_cacheable(resp_headers)
            ):
                return Finding(
                    target=target,
                    url=str(resp.url or url),
                    method=method.upper(),
                    param=param_name,
                    location="query" if method == "GET" else "body",
                    payload=f"Cache poisoning probe reflected: {poison_marker}",
                    attack_type=AttackType.CACHE_POISONING,
                    severity=Severity.HIGH,
                    verified=True,
                    confidence=0.7,
                    status=resp.status,
                    headers=resp_headers,
                    body=body[:2000],
                    diffs=["cache:reflection_confirmed"] + [f"cache_indicator:{m}" for m in matches],
                    verification_body=body[:2000],
                    verification_status=resp.status,
                )
        except Exception:
            pass
        return None

    @staticmethod
    def _is_shared_cacheable(headers: Dict[str, str]) -> bool:
        """True if the response is actually stored by a shared cache.

        Two ways to be cacheable:

        1. A strong CDN-cache signal (cache HIT headers, a positive Age, a
           CDN serving header) — the response demonstrably passed through /
           was served from a shared cache.
        2. ``Cache-Control`` explicitly permits shared caching: ``public`` or
           ``s-maxage`` and none of the forbidding directives
           (``no-store``, ``no-cache``, ``private``, ``max-age=0``).

        The mere presence of ``cache-control``/``etag``/``age`` headers means
        nothing — every GitHub page sends them while being explicitly
        non-cacheable (``private``).
        """
        h = {k.lower(): v.lower() for k, v in (headers or {}).items()}

        # Strong CDN-hit signals.
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

        # Explicit shared-cache permission from Cache-Control.
        cc = h.get("cache-control", "")
        if not cc:
            return False
        if any(d in cc for d in ("no-store", "no-cache", "private", "max-age=0")):
            return False
        return "public" in cc or "s-maxage" in cc or "max-age=" in cc
