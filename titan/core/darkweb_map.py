"""Dark Web Mapper — Catalog and map .onion hidden services.

Discovers .onion services via search engine APIs and catalogues
their attack surfaces for Titan scanning.

Usage:
    from titan.core.darkweb_map import DarkWebMapper

    mapper = DarkWebMapper()
    services = await mapper.discover_services("marketplace")
    surface = await mapper.map_surface("http://xyz.onion")
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class OnionService:
    """A discovered .onion hidden service."""
    url: str
    title: str = ""
    description: str = ""
    source: str = ""  # Which catalog found this
    categories: list[str] = field(default_factory=list)
    last_seen: str = ""


@dataclass
class SurfaceMap:
    """Attack surface of a .onion service."""
    url: str
    endpoints: list[dict] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    status_code: int = 0
    title: str = ""


@dataclass
class Delta:
    """Change detected between scans."""
    field: str
    old_value: Any
    new_value: Any
    severity: str = "info"


class DarkWebMapper:
    """Catalog .onion services and map their attack surfaces.

    Features:
      - Search dark web catalogs (Ahmia, etc.)
      - Map .onion service surfaces (same as HTTP mapping)
      - Track changes between scans
      - Categorize services by type
    """

    # Dark web search engine APIs (where available)
    CATALOG_SOURCES = {
        "ahmia": "https://ahmia.fi/api/v1/search?q={query}",
    }

    # Known .onion directories (for fallback discovery)
    KNOWN_DIRECTORIES = [
        "http://juhanurmihplp2nmdknwiakwzmxcyayw7ffb6e77sfkgteve7tid232yd.onion",  # Ahmia
    ]

    async def discover_services(self, keyword: str) -> list[OnionService]:
        """Search dark web catalogs for services matching a keyword."""
        services = []

        # Search via Ahmia API
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = self.CATALOG_SOURCES["ahmia"].format(query=keyword)
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        import json
                        data = json.loads(await resp.text())
                        for item in data.get("results", []):
                            services.append(OnionService(
                                url=item.get("url", ""),
                                title=item.get("title", ""),
                                description=item.get("description", ""),
                                source="ahmia",
                                categories=item.get("categories", []),
                            ))
        except Exception as e:
            logger.debug(f"Ahmia search failed: {e}")

        logger.info(f"Discovered {len(services)} .onion services for '{keyword}'")
        return services

    async def map_surface(self, onion_url: str) -> SurfaceMap:
        """Map the attack surface of a .onion service.

        Uses the Tor transport to crawl the site and discover:
          - Endpoints (links, forms, API routes)
          - Technology stack (headers, meta tags, JS libraries)
          - Forms (input fields for injection testing)
        """
        surface = SurfaceMap(url=onion_url)

        try:
            # Use Tor transport for .onion
            from titan.transport.tor import TorTransport
            from titan.transport.base import AttackRequest, RequestMethod

            transport = TorTransport()

            # Fetch the main page
            response = await transport.send(AttackRequest(
                url=onion_url,
                method=RequestMethod.GET,
                timeout=30.0,
            ))

            if response.is_error:
                logger.warning(f"Could not reach .onion service: {response.error}")
                return surface

            surface.status_code = response.status
            html = response.text

            # Extract title
            title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
            if title_match:
                surface.title = title_match.group(1).strip()

            # Extract links
            links = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
            for link in links:
                if link.startswith("/") or ".onion" in link:
                    surface.links.append(link)

            # Extract forms
            form_pattern = re.compile(
                r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
                re.IGNORECASE | re.DOTALL,
            )
            for match in form_pattern.finditer(html):
                action = match.group(1)
                form_html = match.group(2)
                inputs = re.findall(
                    r'<input[^>]*(?:name|id)=["\']([^"\']+)["\'][^>]*>',
                    form_html,
                    re.IGNORECASE,
                )
                surface.forms.append({
                    "action": action,
                    "inputs": inputs,
                    "method": "POST" if "method" in form_html.lower() and "get" not in form_html.lower() else "GET",
                })

            # Detect tech stack from headers and content
            surface.tech_stack = self._detect_tech(html, response.headers)

            logger.info(
                f"Surface map for {onion_url}: "
                f"{len(surface.links)} links, "
                f"{len(surface.forms)} forms, "
                f"{len(surface.tech_stack)} technologies"
            )

        except Exception as e:
            logger.warning(f"Surface mapping failed: {e}")

        return surface

    async def track_changes(self, onion_url: str, baseline: SurfaceMap) -> list[Delta]:
        """Detect changes since last scan."""
        current = await self.map_surface(onion_url)
        deltas = []

        # Check status code change
        if current.status_code != baseline.status_code:
            deltas.append(Delta(
                field="status_code",
                old_value=baseline.status_code,
                new_value=current.status_code,
                severity="high" if current.status_code != baseline.status_code else "info",
            ))

        # Check new endpoints
        baseline_links = set(baseline.links)
        current_links = set(current.links)
        new_links = current_links - baseline_links
        if new_links:
            deltas.append(Delta(
                field="new_endpoints",
                old_value=len(baseline_links),
                new_value=len(current_links),
                severity="medium",
            ))

        # Check new forms
        if len(current.forms) > len(baseline.forms):
            deltas.append(Delta(
                field="new_forms",
                old_value=len(baseline.forms),
                new_value=len(current.forms),
                severity="medium",
            ))

        # Check tech stack changes
        baseline_tech = set(baseline.tech_stack)
        current_tech = set(current.tech_stack)
        new_tech = current_tech - baseline_tech
        if new_tech:
            deltas.append(Delta(
                field="new_technology",
                old_value=list(baseline_tech),
                new_value=list(new_tech),
                severity="low",
            ))

        return deltas

    def _detect_tech(self, html: str, headers: dict[str, str]) -> list[str]:
        """Detect technology stack from HTML content and headers."""
        tech = []

        # From headers
        server = headers.get("Server", "")
        if server:
            tech.append(f"Server: {server}")

        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            tech.append(f"X-Powered-By: {powered_by}")

        # From HTML
        html_lower = html.lower()
        tech_signatures = {
            "WordPress": ["wp-content", "wp-includes"],
            "Drupal": ["drupal", "sites/default/files"],
            "Joomla": ["joomla", "/components/"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "Flask": ["werkzeug", "flask"],
            "Express": ["express", "x-powered-by: express"],
            "Laravel": ["laravel", "csrf-token"],
            "Ruby on Rails": ["csrf-token", "authenticity_token"],
            "Spring": ["spring", "whitelabel error"],
            "Angular": ["ng-app", "ng-controller", "angular"],
            "React": ["react", "_reactroot", "reactdom"],
            "Vue.js": ["vue", "v-cloak", "vue.js"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
            "Firebase": ["firebase", "firebaseapp"],
            "MongoDB": ["mongodb", "mongo"],
            "MySQL": ["mysql"],
            "PostgreSQL": ["postgresql", "postgres"],
            "Redis": ["redis"],
            "Nginx": ["nginx"],
            "Apache": ["apache"],
            "IIS": ["microsoft-iis"],
            "Cloudflare": ["cloudflare", "cf-ray"],
        }

        for name, signatures in tech_signatures.items():
            for sig in signatures:
                if sig.lower() in html_lower or sig.lower() in str(headers).lower():
                    tech.append(name)
                    break

        return list(set(tech))
