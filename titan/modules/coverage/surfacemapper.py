"""Attack Surface Mapper — feed endpoints into coverage.

A real attacker maps the entire attack surface first.
Then they measure coverage against that surface.

This module:
1. Crawls target to discover all endpoints
2. Classifies endpoints by type (API, page, admin, etc.)
3. Maps endpoints to relevant attack types
4. Feeds into coverage tracker
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from titan.core.logger import get_logger
from titan.modules.coverage.tracker import CoverageTracker

logger = get_logger("surfacemapper")


@dataclass
class SurfaceEndpoint:
    """A discovered endpoint on the attack surface."""

    url: str
    method: str
    category: str  # "api", "page", "admin", "auth", "static"
    parameters: list[str]
    auth_required: bool
    risk_level: str  # "high", "medium", "low"
    relevant_attacks: list[str]


class AttackSurfaceMapper:
    """Map the attack surface and feed into coverage."""

    # Endpoint categories and their relevant attack types
    CATEGORY_ATTACKS = {
        "api": ["sqli", "idor", "auth_bypass", "business_logic", "rate_limit"],
        "page": ["xss", "csrf", "open_redirect", "info_leak"],
        "admin": ["auth_bypass", "privilege_escalation", "info_leak", "business_logic"],
        "auth": ["auth_bypass", "session", "jwt", "brute_force"],
        "upload": ["file_upload", "path_traversal", "rce"],
        "search": ["sqli", "xss", "ssrf"],
        "payment": ["business_logic", "idor", "auth_bypass"],
        "user": ["idor", "privilege_escalation", "info_leak"],
        "static": ["info_leak", "path_traversal"],
    }

    # Common endpoint patterns
    ENDPOINT_PATTERNS = [
        (r"/api/", "api"),
        (r"/admin", "admin"),
        (r"/auth", "auth"),
        (r"/login", "auth"),
        (r"/signup", "auth"),
        (r"/upload", "upload"),
        (r"/file", "upload"),
        (r"/search", "search"),
        (r"/payment", "payment"),
        (r"/checkout", "payment"),
        (r"/user", "user"),
        (r"/profile", "user"),
        (r"/account", "user"),
    ]

    def __init__(self, tracker: CoverageTracker):
        self.tracker = tracker
        self._surface: list[SurfaceEndpoint] = []

    async def map_surface(self, target_url: str, page_source: str = "") -> list[SurfaceEndpoint]:
        """Map the attack surface of a target."""
        self._surface = []

        # Discover endpoints from page source
        if page_source:
            self._discover_from_source(page_source, target_url)

        # Discover common endpoints
        await self._probe_common_endpoints(target_url)

        # Classify and map attack types
        for endpoint in self._surface:
            endpoint.relevant_attacks = self._get_relevant_attacks(endpoint)

        return self._surface

    def _discover_from_source(self, source: str, base_url: str):
        """Discover endpoints from page source."""
        # Find all links
        links = re.findall(r'href=["\']([^"\']+)["\']', source)
        for link in links:
            if link.startswith("/"):
                url = f"{base_url.rstrip('/')}{link}"
            elif link.startswith("http"):
                url = link
            else:
                continue

            category = self._categorize_endpoint(url)
            self._surface.append(
                SurfaceEndpoint(
                    url=url,
                    method="GET",
                    category=category,
                    parameters=[],
                    auth_required=category in ("admin", "auth", "payment", "user"),
                    risk_level=self._assess_risk(category),
                    relevant_attacks=[],
                )
            )

        # Find all API calls
        api_calls = re.findall(r'["\'](/api/[^"\']+)["\']', source)
        for api in api_calls:
            url = f"{base_url.rstrip('/')}{api}"
            self._surface.append(
                SurfaceEndpoint(
                    url=url,
                    method="POST",
                    category="api",
                    parameters=self._extract_params(api),
                    auth_required=True,
                    risk_level="high",
                    relevant_attacks=[],
                )
            )

        # Find forms
        forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', source)
        for form in forms:
            if form.startswith("/"):
                url = f"{base_url.rstrip('/')}{form}"
            elif form.startswith("http"):
                url = form
            else:
                continue

            category = self._categorize_endpoint(url)
            self._surface.append(
                SurfaceEndpoint(
                    url=url,
                    method="POST",
                    category=category,
                    parameters=[],
                    auth_required=category in ("auth", "payment", "user"),
                    risk_level=self._assess_risk(category),
                    relevant_attacks=[],
                )
            )

    async def _probe_common_endpoints(self, target_url: str):
        """Probe common endpoints."""
        common_paths = [
            "/api/users",
            "/api/products",
            "/api/orders",
            "/api/payment",
            "/api/auth/login",
            "/api/auth/signup",
            "/api/admin",
            "/api/settings",
            "/api/upload",
            "/api/search",
            "/admin",
            "/login",
            "/signup",
            "/dashboard",
            "/profile",
            "/account",
            "/settings",
        ]

        try:
            import aiohttp

            parsed = urlparse(target_url)
            base = f"{parsed.scheme}://{parsed.netloc}"

            async with aiohttp.ClientSession() as session:
                for path in common_paths:
                    try:
                        url = f"{base}{path}"
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                            if resp.status not in (404, 405, 500, 502, 503):
                                category = self._categorize_endpoint(url)
                                self._surface.append(
                                    SurfaceEndpoint(
                                        url=url,
                                        method="GET",
                                        category=category,
                                        parameters=[],
                                        auth_required=category in ("admin", "auth", "payment", "user"),
                                        risk_level=self._assess_risk(category),
                                        relevant_attacks=[],
                                    )
                                )
                    except Exception as exc:
                        logger.debug(f"variant failed, continuing: {exc}")
                        continue
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

    def _categorize_endpoint(self, url: str) -> str:
        """Categorize an endpoint by its URL."""
        url_lower = url.lower()
        for pattern, category in self.ENDPOINT_PATTERNS:
            if re.search(pattern, url_lower):
                return category
        return "page"

    def _assess_risk(self, category: str) -> str:
        """Assess risk level of an endpoint category."""
        high_risk = ["admin", "auth", "payment", "upload"]
        medium_risk = ["api", "user", "search"]
        if category in high_risk:
            return "high"
        elif category in medium_risk:
            return "medium"
        return "low"

    def _get_relevant_attacks(self, endpoint: SurfaceEndpoint) -> list[str]:
        """Get relevant attack types for an endpoint."""
        base_attacks = self.CATEGORY_ATTACKS.get(endpoint.category, [])

        # Add parameter-specific attacks
        for param in endpoint.parameters:
            param_lower = param.lower()
            if any(kw in param_lower for kw in ["id", "user", "account"]):
                if "idor" not in base_attacks:
                    base_attacks.append("idor")
            if any(kw in param_lower for kw in ["url", "link", "redirect"]):
                if "ssrf" not in base_attacks:
                    base_attacks.append("ssrf")
                if "open_redirect" not in base_attacks:
                    base_attacks.append("open_redirect")
            if any(kw in param_lower for kw in ["file", "upload", "document"]):
                if "file_upload" not in base_attacks:
                    base_attacks.append("file_upload")

        return list(set(base_attacks))

    def _extract_params(self, url: str) -> list[str]:
        """Extract parameters from URL."""
        params = []
        if "?" in url:
            query = url.split("?", 1)[1]
            for param in query.split("&"):
                if "=" in param:
                    params.append(param.split("=")[0])
        return params

    def feed_into_tracker(self) -> None:
        """Feed discovered surface into coverage tracker."""
        for endpoint in self._surface:
            for attack_type in endpoint.relevant_attacks:
                # Record as a discovered endpoint (not yet tested)
                self.tracker.record_test(
                    endpoint=endpoint.url,
                    attack_type=attack_type,
                    payload="",
                    status="discovered",
                    response_code=0,
                    notes=f"Discovered: {endpoint.category} endpoint",
                )

    def get_surface(self) -> list[SurfaceEndpoint]:
        return self._surface

    def get_surface_summary(self) -> dict[str, Any]:
        """Get summary of attack surface."""
        categories = {}
        risk_counts = {"high": 0, "medium": 0, "low": 0}
        all_attacks = set()

        for endpoint in self._surface:
            categories[endpoint.category] = categories.get(endpoint.category, 0) + 1
            risk_counts[endpoint.risk_level] += 1
            all_attacks.update(endpoint.relevant_attacks)

        return {
            "total_endpoints": len(self._surface),
            "by_category": categories,
            "by_risk": risk_counts,
            "unique_attack_types": len(all_attacks),
            "relevant_attacks": sorted(all_attacks),
        }
