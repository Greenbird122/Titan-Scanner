"""Endpoint Discovery Engine — crawl site to find ALL business logic endpoints.

A real attacker doesn't need to be told where the endpoints are.
They crawl. They discover. They map.

This module:
1. Crawls the site to find all forms, links, buttons
2. Extracts API endpoints from JS bundles
3. Probes common business logic paths
4. Identifies parameters in each endpoint
5. Maps the full attack surface for business logic testing
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs


@dataclass
class DiscoveredEndpoint:
    """A discovered business logic endpoint."""
    url: str
    method: str
    params: Dict[str, Any]
    source: str  # "crawl", "js", "probe", "form", "api"
    biz_type: str  # "payment", "auth", "cart", "order", "user", "admin", "unknown"
    confidence: float


class EndpointDiscovery:
    """Discover ALL business logic endpoints on a target."""

    # ── Common Business Logic Paths ────────────────────────────────────

    COMMON_BIZ_PATHS = [
        # Payment
        "/api/payment", "/api/pay", "/api/checkout", "/api/billing",
        "/api/invoice", "/api/subscribe", "/api/plan", "/api/pricing",
        "/payment/process", "/checkout/process", "/subscribe",
        # Cart/Order
        "/api/cart", "/api/basket", "/api/order", "/api/orders",
        "/api/item", "/api/items", "/api/product", "/api/products",
        "/cart/add", "/cart/update", "/cart/remove", "/checkout",
        # User/Auth
        "/api/user", "/api/users", "/api/profile", "/api/account",
        "/api/auth", "/api/login", "/api/register", "/api/signup",
        "/api/session", "/api/token", "/api/refresh",
        # Admin
        "/api/admin", "/api/admin/users", "/api/admin/settings",
        "/api/admin/billing", "/api/dashboard", "/api/manage",
        # Credits/Subscription
        "/api/credits", "/api/balance", "/api/subscription",
        "/api/plan/upgrade", "/api/plan/downgrade", "/api/trial",
        # File
        "/api/upload", "/api/file", "/api/files", "/api/document",
        "/api/export", "/api/import", "/api/backup",
        # Webhook
        "/api/webhook", "/webhook", "/api/callback",
        # Settings
        "/api/settings", "/api/config", "/api/preferences",
        "/api/notification", "/api/notifications",
    ]

    # ── Common Parameter Names ─────────────────────────────────────────

    BIZ_PARAM_NAMES = [
        # Price/Money
        "price", "amount", "total", "cost", "fee", "discount", "coupon",
        "promo", "voucher", "credit", "balance", "refund", "payment",
        "currency", "quantity", "qty", "count", "subtotal", "tax",
        # User/Role
        "user_id", "user", "account", "role", "admin", "permission",
        "level", "tier", "plan", "subscription", "workspace", "org",
        "team", "tenant", "customer",
        # Order/Status
        "order_id", "order", "status", "state", "step", "phase",
        "stage", "completed", "paid", "shipped", "delivered",
        # Action
        "action", "command", "method", "operation", "type",
        # IDOR
        "id", "item_id", "product_id", "cart_id", "invoice_id",
    ]

    # ── JS API Pattern Extraction ──────────────────────────────────────

    JS_API_PATTERNS = [
        # fetch() calls
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'fetch\s*\(\s*`([^`]+)`',
        # axios calls
        r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.\w+\s*\(\s*`([^`]+)`',
        # XMLHttpRequest
        r'\.open\s*\(\s*["\'](\w+)["\']\s*,\s*["\']([^"\']+)["\']',
        # API base URLs
        r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
        r'API_URL\s*[:=]\s*["\']([^"\']+)["\']',
        r'apiUrl\s*[:=]\s*["\']([^"\']+)["\']',
        # Next.js API routes
        r'/api/[\w/]+',
        # Supabase/Firebase
        r'supabase\.from\s*\(\s*["\']([^"\']+)["\']',
        r'firebase\.firestore\s*\(\s*\)\s*\.collection\s*\(\s*["\']([^"\']+)["\']',
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._discovered: List[DiscoveredEndpoint] = []
        self._visited: Set[str] = set()
        self._base_url: str = ""

    async def discover(self, target_url: str, max_depth: int = 3) -> List[DiscoveredEndpoint]:
        """Full endpoint discovery pipeline."""
        self._base_url = target_url
        self._visited.clear()
        self._discovered.clear()

        # Phase 1: Crawl the page
        await self._crawl_page(target_url)

        # Phase 2: Extract from JS bundles
        await self._extract_from_js(target_url)

        # Phase 3: Probe common paths
        await self._probe_common_paths(target_url)

        # Phase 4: Discover from forms
        await self._discover_forms(target_url)

        # Phase 5: Parameter discovery for each endpoint
        await self._discover_parameters()

        return self._discovered

    async def _crawl_page(self, url: str, depth: int = 0):
        """Crawl a page to find links, forms, and API calls."""
        if depth > 3 or url in self._visited:
            return
        self._visited.add(url)

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    body = await resp.text()
                    content_type = resp.headers.get("content-type", "")

                    if "html" not in content_type:
                        return

                    # Extract links
                    links = re.findall(r'href=["\']([^"\']+)["\']', body)
                    for link in links:
                        full_url = urljoin(url, link)
                        parsed = urlparse(full_url)
                        if parsed.netloc == urlparse(url).netloc:
                            # Check if it looks like a business logic endpoint
                            if self._is_biz_endpoint(full_url):
                                self._discovered.append(DiscoveredEndpoint(
                                    url=full_url,
                                    method="GET",
                                    params={},
                                    source="crawl",
                                    biz_type=self._classify_endpoint(full_url),
                                    confidence=0.6,
                                ))

                    # Extract forms
                    forms = re.findall(
                        r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\'](\w+)["\']',
                        body, re.IGNORECASE
                    )
                    for action, method in forms:
                        form_url = urljoin(url, action) if action else url
                        self._discovered.append(DiscoveredEndpoint(
                            url=form_url,
                            method=method.upper(),
                            params={},
                            source="form",
                            biz_type=self._classify_endpoint(form_url),
                            confidence=0.8,
                        ))

                    # Extract JS fetch/API calls inline
                    api_calls = re.findall(
                        r'(?:fetch|axios\.\w+|\.post|\.get|\.put|\.patch)\s*\(\s*["`\']([^"`\']+)["`\']',
                        body
                    )
                    for api_call in api_calls:
                        if api_call.startswith("/"):
                            api_call = urljoin(url, api_call)
                        if urlparse(api_call).netloc in ("", urlparse(url).netloc):
                            self._discovered.append(DiscoveredEndpoint(
                                url=api_call,
                                method="POST",
                                params={},
                                source="js",
                                biz_type=self._classify_endpoint(api_call),
                                confidence=0.7,
                            ))

        except Exception:
            pass

    async def _extract_from_js(self, target_url: str):
        """Extract API endpoints from JavaScript bundles."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                # Get main page
                async with session.get(target_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    body = await resp.text()

                # Find all JS bundle URLs
                js_urls = re.findall(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', body)

                for js_url in js_urls[:10]:  # Limit to 10 bundles
                    full_js_url = urljoin(target_url, js_url)
                    try:
                        async with session.get(full_js_url, timeout=aiohttp.ClientTimeout(total=10)) as js_resp:
                            js_body = await js_resp.text()

                            # Extract API patterns
                            for pattern in self.JS_API_PATTERNS:
                                matches = re.findall(pattern, js_body)
                                for match in matches:
                                    if isinstance(match, tuple):
                                        endpoint = match[-1] if len(match) > 1 else match[0]
                                    else:
                                        endpoint = match

                                    if endpoint.startswith("/"):
                                        endpoint = urljoin(target_url, endpoint)
                                    elif not endpoint.startswith("http"):
                                        continue

                                    parsed = urlparse(endpoint)
                                    if parsed.netloc and parsed.netloc != urlparse(target_url).netloc:
                                        continue

                                    if self._is_biz_endpoint(endpoint):
                                        self._discovered.append(DiscoveredEndpoint(
                                            url=endpoint,
                                            method="POST",
                                            params={},
                                            source="js",
                                            biz_type=self._classify_endpoint(endpoint),
                                            confidence=0.75,
                                        ))

                    except Exception:
                        continue

        except Exception:
            pass

    async def _probe_common_paths(self, target_url: str):
        """Probe common business logic paths."""
        try:
            import aiohttp
            parsed = urlparse(target_url)
            base = f"{parsed.scheme}://{parsed.netloc}"

            # Probe in batches of 10
            for i in range(0, len(self.COMMON_BIZ_PATHS), 10):
                batch = self.COMMON_BIZ_PATHS[i:i+10]
                tasks = []
                async with aiohttp.ClientSession() as session:
                    for path in batch:
                        probe_url = base + path
                        tasks.append(self._probe_endpoint(session, probe_url))

                    results = await asyncio.gather(*tasks, return_exceptions=True)

                    for result in results:
                        if not isinstance(result, Exception) and result:
                            self._discovered.append(result)

        except Exception:
            pass

    async def _probe_endpoint(self, session, url: str) -> Optional[DiscoveredEndpoint]:
        """Probe a single endpoint to check if it exists."""
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                status = resp.status
                body = await resp.text()

                # If not 404/405/500, it's likely real
                if status not in (404, 405, 500, 502, 503):
                    return DiscoveredEndpoint(
                        url=url,
                        method="POST" if status in (200, 201) else "GET",
                        params={},
                        source="probe",
                        biz_type=self._classify_endpoint(url),
                        confidence=0.65,
                    )
        except Exception:
            pass
        return None

    async def _discover_forms(self, target_url: str):
        """Discover forms on the page."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    body = await resp.text()

                    # Find all input fields
                    inputs = re.findall(
                        r'<input[^>]*name=["\']([^"\']+)["\']',
                        body, re.IGNORECASE
                    )

                    # Group by likely form
                    if inputs:
                        # Check if any inputs are business-logic related
                        biz_inputs = [i for i in inputs if any(
                            kw in i.lower() for kw in self.BIZ_PARAM_NAMES
                        )]
                        if biz_inputs:
                            self._discovered.append(DiscoveredEndpoint(
                                url=target_url,
                                method="POST",
                                params={i: "test" for i in biz_inputs},
                                source="form",
                                biz_type="unknown",
                                confidence=0.85,
                            ))

        except Exception:
            pass

    async def _discover_parameters(self):
        """Discover parameters for each discovered endpoint."""
        enhanced = []
        for ep in self._discovered:
            if not ep.params:
                # Try to discover params by sending requests
                params = await self._fuzz_params(ep.url, ep.method)
                ep.params = params
            enhanced.append(ep)
        self._discovered = enhanced

    async def _fuzz_params(self, url: str, method: str) -> Dict[str, Any]:
        """Fuzz common parameter names."""
        found_params = {}
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                # Test with common param names
                for param in self.BIZ_PARAM_NAMES[:20]:
                    try:
                        test_data = {param: "test_value"}
                        if method == "GET":
                            async with session.get(url, params=test_data, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                                if resp.status not in (400, 404, 405, 500):
                                    found_params[param] = "test_value"
                        else:
                            async with session.post(url, json=test_data, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                                if resp.status not in (400, 404, 405, 500):
                                    found_params[param] = "test_value"
                    except Exception:
                        continue
        except Exception:
            pass
        return found_params

    def _is_biz_endpoint(self, url: str) -> bool:
        """Check if URL looks like a business logic endpoint."""
        url_lower = url.lower()
        biz_keywords = [
            "payment", "pay", "checkout", "cart", "order", "billing",
            "subscribe", "plan", "credit", "balance", "refund",
            "user", "admin", "account", "profile", "auth", "login",
            "upload", "file", "document", "export",
            "setting", "config", "notification",
            "api/", "/api", "webhook", "callback",
        ]
        return any(kw in url_lower for kw in biz_keywords)

    def _classify_endpoint(self, url: str) -> str:
        """Classify endpoint by business logic type."""
        url_lower = url.lower()
        if any(kw in url_lower for kw in ["payment", "pay", "checkout", "billing", "invoice", "subscribe"]):
            return "payment"
        elif any(kw in url_lower for kw in ["cart", "basket", "order", "item"]):
            return "cart"
        elif any(kw in url_lower for kw in ["user", "profile", "account", "auth", "login"]):
            return "user"
        elif any(kw in url_lower for kw in ["admin", "manage", "dashboard"]):
            return "admin"
        elif any(kw in url_lower for kw in ["credit", "balance", "plan", "subscription"]):
            return "subscription"
        elif any(kw in url_lower for kw in ["upload", "file", "document"]):
            return "file"
        return "unknown"

    def get_endpoints(self) -> List[DiscoveredEndpoint]:
        """Get all discovered endpoints."""
        return self._discovered

    def get_biz_endpoints(self) -> List[DiscoveredEndpoint]:
        """Get only business logic endpoints (exclude unknown)."""
        return [ep for ep in self._discovered if ep.biz_type != "unknown"]
