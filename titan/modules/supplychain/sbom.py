"""SBOM Analyzer — Software Bill of Materials analysis from served content.

Extracts dependency information from HTML/JS bundles and checks for:
  1. SRI (Subresource Integrity) — scripts loaded without integrity hashes
  2. Cleartext loading — HTTP (not HTTPS) script/stylesheet loads
  3. Third-party origin profiling — categorize and risk-score external deps
  4. Known vulnerability matching — cross-reference against known CVEs
  5. SBOM extraction — parse package.json, CDN imports from served bundles

The analyzer works on SERVED content (what the browser actually loads),
not source code — so it catches runtime dependencies that static analysis
would miss.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Known vulnerable packages (curated list — expandable)
# ---------------------------------------------------------------------------

KNOWN_VULNERABLE: dict[str, list[dict]] = {
    # package_name -> [{version_range, cve, severity, description}]
    "lodash": [
        {"cve": "CVE-2021-23337", "versions": "<4.17.21", "severity": "high",
         "description": "Command injection via template"},
    ],
    "minimist": [
        {"cve": "CVE-2021-44906", "versions": "<1.2.6", "severity": "critical",
         "description": "Prototype pollution"},
    ],
    "node-fetch": [
        {"cve": "CVE-2022-0235", "versions": "<2.6.7", "severity": "high",
         "description": "Exposure of sensitive information"},
    ],
    "axios": [
        {"cve": "CVE-2023-45857", "versions": "<1.6.0", "severity": "medium",
         "description": "CSRF token exposure"},
    ],
    "express": [
        {"cve": "CVE-2024-29041", "versions": "<4.19.2", "severity": "medium",
         "description": "Open redirect"},
    ],
    "webpack": [
        {"cve": "CVE-2023-28154", "versions": "<5.76.0", "severity": "medium",
         "description": "Cross-realm object access"},
    ],
    "moment": [
        {"cve": "CVE-2022-31129", "versions": "<2.29.4", "severity": "high",
         "description": "ReDoS via crafted date string"},
    ],
    "shell-quote": [
        {"cve": "CVE-2021-42740", "versions": "<1.7.3", "severity": "critical",
         "description": "Command injection"},
    ],
    "tar": [
        {"cve": "CVE-2021-37701", "versions": "<6.1.9", "severity": "high",
         "description": "Arbitrary file creation/overwrite"},
    ],
    "json5": [
        {"cve": "CVE-2022-46175", "versions": "<2.2.2", "severity": "high",
         "description": "Prototype pollution"},
    ],
    "semver": [
        {"cve": "CVE-2022-25883", "versions": "<7.5.2", "severity": "medium",
         "description": "ReDoS via crafted version string"},
    ],
    "xml2js": [
        {"cve": "CVE-2023-0842", "versions": "<0.5.0", "severity": "medium",
         "description": "Prototype pollution"},
    ],
    "glob-parent": [
        {"cve": "CVE-2021-35065", "versions": "<5.1.2", "severity": "high",
         "description": "ReDoS"},
    ],
    "qs": [
        {"cve": "CVE-2022-24999", "versions": "<6.10.3", "severity": "high",
         "description": "Prototype pollution"},
    ],
    "django": [
        {"cve": "CVE-2024-24680", "versions": "<4.2.10", "severity": "medium",
         "description": "DoS via intl.format_html"},
    ],
    "flask": [
        {"cve": "CVE-2023-30861", "versions": "<2.3.2", "severity": "medium",
         "description": "Cookie handling vulnerability"},
    ],
    "werkzeug": [
        {"cve": "CVE-2023-46136", "versions": "<3.0.1", "severity": "high",
         "description": "DoS via multipart parsing"},
    ],
    "pillow": [
        {"cve": "CVE-2023-44271", "versions": "<10.0.0", "severity": "medium",
         "description": "DoS via crafted image"},
    ],
    "requests": [
        {"cve": "CVE-2023-32681", "versions": "<2.31.0", "severity": "medium",
         "description": "Unintended leak of Proxy-Authorization header"},
    ],
    "urllib3": [
        {"cve": "CVE-2023-43804", "versions": "<2.0.6", "severity": "medium",
         "description": "Cookie header not stripped on cross-origin redirects"},
    ],
}


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class ScriptTag:
    """A script or link tag extracted from HTML."""
    src: str
    tag: str = "script"          # script, link, img, iframe
    integrity: str = ""          # SRI hash
    crossorigin: str = ""        # crossorigin attribute
    is_async: bool = False
    is_external: bool = False    # Different origin than page
    origin: str = ""             # Extracted origin
    protocol: str = ""           # http, https, protocol-relative


@dataclass
class DependencyInfo:
    """A dependency extracted from JS/HTML."""
    name: str
    version: str = ""
    source: str = ""             # Where it was found (CDN URL, inline, etc.)
    registry: str = ""           # npm, pypi, cdn
    has_sri: bool = False
    is_cleartext: bool = False
    origin: str = ""


@dataclass
class SBOMReport:
    """Full SBOM analysis report."""
    scripts: list[ScriptTag] = field(default_factory=list)
    dependencies: list[DependencyInfo] = field(default_factory=list)
    sri_missing: list[ScriptTag] = field(default_factory=list)
    cleartext_loads: list[ScriptTag] = field(default_factory=list)
    known_vulns: list[dict] = field(default_factory=list)
    origins: dict[str, dict] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# SBOM Analyzer
# ---------------------------------------------------------------------------

class SBOMAnalyzer:
    """Analyze served content for supply chain risks.

    Usage:
        analyzer = SBOMAnalyzer()
        report = analyzer.analyze(html_content, page_url="https://example.com")
        for finding in report.findings:
            print(f"{finding['severity']}: {finding['title']}")
    """

    # CDN origins we recognize
    KNOWN_CDNS = {
        "cdnjs.cloudflare.com": "cloudflare",
        "cdn.jsdelivr.net": "jsdelivr",
        "unpkg.com": "unpkg",
        "ajax.googleapis.com": "google",
        "code.jquery.com": "jquery",
        "cdn.jsdelivr.net/npm": "jsdelivr-npm",
        "fonts.googleapis.com": "google-fonts",
        "stackpath.bootstrapcdn.com": "bootstrapcdn",
    }

    def analyze(
        self,
        html: str,
        page_url: str = "",
        js_bundles: list[str] | None = None,
    ) -> SBOMReport:
        """Analyze HTML content and optional JS bundles.

        Args:
            html: The page's HTML content.
            page_url: The page URL (for origin comparison).
            js_bundles: Optional list of JS bundle contents to scan.

        Returns:
            SBOMReport with all findings.
        """
        report = SBOMReport()

        # Extract script/link/img tags
        report.scripts = self._extract_tags(html, page_url)

        # Extract dependencies from CDN URLs
        report.dependencies = self._extract_dependencies(report.scripts)

        # Extract dependencies from inline JS
        inline_deps = self._extract_inline_dependencies(html)
        report.dependencies.extend(inline_deps)

        # Extract from JS bundles
        if js_bundles:
            for bundle in js_bundles:
                bundle_deps = self._extract_inline_dependencies(bundle)
                report.dependencies.extend(bundle_deps)

        # SRI analysis
        report.sri_missing = [s for s in report.scripts if s.is_external and not s.integrity]

        # Cleartext analysis
        report.cleartext_loads = [s for s in report.scripts if s.protocol == "http"]

        # Origin profiling
        report.origins = self._profile_origins(report.scripts)

        # Known vulnerability matching
        report.known_vulns = self._match_vulnerabilities(report.dependencies)

        # Generate findings
        report.findings = self._generate_findings(report)

        return report

    def _extract_tags(self, html: str, page_url: str) -> list[ScriptTag]:
        """Extract script, link, and img tags from HTML."""
        tags = []
        page_origin = urlparse(page_url).netloc if page_url else ""

        # Script tags with src
        for match in re.finditer(
            r'<script\s[^>]*src=["\']([^"\']+)["\'][^>]*>',
            html, re.IGNORECASE
        ):
            tag_html = match.group(0)
            src = match.group(1)
            integrity = self._extract_attr(tag_html, "integrity")
            crossorigin = self._extract_attr(tag_html, "crossorigin")
            is_async = "async" in tag_html.lower()

            script = ScriptTag(
                src=src,
                tag="script",
                integrity=integrity,
                crossorigin=crossorigin,
                is_async=is_async,
                is_external=self._is_external(src, page_origin),
                origin=urlparse(src).netloc if src.startswith("http") else "",
                protocol=urlparse(src).scheme if src.startswith("http") else "",
            )
            tags.append(script)

        # Link tags (stylesheets)
        for match in re.finditer(
            r'<link\s[^>]*href=["\']([^"\']+)["\'][^>]*>',
            html, re.IGNORECASE
        ):
            tag_html = match.group(0)
            href = match.group(1)
            if not any(ext in href.lower() for ext in [".css", ".js", ".woff", ".ttf"]):
                continue
            integrity = self._extract_attr(tag_html, "integrity")
            crossorigin = self._extract_attr(tag_html, "crossorigin")

            tag = ScriptTag(
                src=href,
                tag="link",
                integrity=integrity,
                crossorigin=crossorigin,
                is_external=self._is_external(href, page_origin),
                origin=urlparse(href).netloc if href.startswith("http") else "",
                protocol=urlparse(href).scheme if href.startswith("http") else "",
            )
            tags.append(tag)

        # Iframe tags
        for match in re.finditer(
            r'<iframe\s[^>]*src=["\']([^"\']+)["\'][^>]*>',
            html, re.IGNORECASE
        ):
            src = match.group(1)
            tag = ScriptTag(
                src=src,
                tag="iframe",
                is_external=self._is_external(src, page_origin),
                origin=urlparse(src).netloc if src.startswith("http") else "",
                protocol=urlparse(src).scheme if src.startswith("http") else "",
            )
            tags.append(tag)

        return tags

    def _extract_attr(self, tag_html: str, attr: str) -> str:
        """Extract an attribute value from an HTML tag string."""
        match = re.search(rf'{attr}=["\']([^"\']+)["\']', tag_html, re.IGNORECASE)
        return match.group(1) if match else ""

    def _is_external(self, url: str, page_origin: str) -> bool:
        """Check if a URL is external to the page.

        An HTTP script on an HTTPS page is external (mixed content).
        """
        if not page_origin:
            return True
        if url.startswith("//"):
            return True
        parsed = urlparse(url) if url.startswith("http") else None
        if parsed:
            # Different netloc = external
            if parsed.netloc != page_origin:
                return True
            # Same netloc but different scheme (http vs https) = mixed content = external
            page_scheme = "https" if page_origin else "http"
            if parsed.scheme != page_scheme:
                return True
            return False
        # Relative URL = same origin
        return False

    def _extract_dependencies(self, scripts: list[ScriptTag]) -> list[DependencyInfo]:
        """Extract dependency info from CDN URLs."""
        deps = []

        for script in scripts:
            if not script.is_external:
                continue

            # Parse CDN URLs for package info
            dep = self._parse_cdn_url(script.src)
            if dep:
                dep.has_sri = bool(script.integrity)
                dep.is_cleartext = script.protocol == "http"
                dep.origin = script.origin
                deps.append(dep)

        return deps

    def _parse_cdn_url(self, url: str) -> DependencyInfo | None:
        """Parse a CDN URL to extract package name and version."""
        # jsdelivr: https://cdn.jsdelivr.net/npm/package@version/file
        match = re.match(
            r'https?://cdn\.jsdelivr\.net/npm/([^@/]+)@?([^/]*)',
            url
        )
        if match:
            return DependencyInfo(
                name=match.group(1),
                version=match.group(2) or "latest",
                source=url,
                registry="npm",
            )

        # unpkg: https://unpkg.com/package@version/file
        match = re.match(
            r'https?://unpkg\.com/([^@/]+)@?([^/]*)',
            url
        )
        if match:
            return DependencyInfo(
                name=match.group(1),
                version=match.group(2) or "latest",
                source=url,
                registry="npm",
            )

        # Google CDN: https://ajax.googleapis.com/ajax/libs/package/version/file
        match = re.match(
            r'https?://ajax\.googleapis\.com/ajax/libs/([^/]+)/([^/]+)/',
            url
        )
        if match:
            return DependencyInfo(
                name=match.group(1),
                version=match.group(2),
                source=url,
                registry="cdn",
            )

        # Cloudflare CDN
        match = re.match(
            r'https?://cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([^/]+)/',
            url
        )
        if match:
            return DependencyInfo(
                name=match.group(1),
                version=match.group(2),
                source=url,
                registry="cdn",
            )

        return None

    def _extract_inline_dependencies(self, content: str) -> list[DependencyInfo]:
        """Extract dependency info from inline JavaScript."""
        deps = []

        # require('package') patterns
        for match in re.finditer(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""", content):
            name = match.group(1)
            if not name.startswith(".") and "/" not in name:
                deps.append(DependencyInfo(name=name, source="inline-js", registry="npm"))

        # import ... from 'package' patterns
        for match in re.finditer(r"""from\s+['"]([^'"]+)['"]""", content):
            name = match.group(1)
            if not name.startswith(".") and "/" not in name:
                deps.append(DependencyInfo(name=name, source="inline-js", registry="npm"))

        # CDN URL patterns in JS strings
        for match in re.finditer(
            r"""['"]https?://[^'"]*(?:cdn\.jsdelivr\.net|unpkg\.com|ajax\.googleapis\.com)[^'"]*['"]""",
            content
        ):
            url = match.group(0).strip("'\"")
            dep = self._parse_cdn_url(url)
            if dep:
                dep.source = "inline-js"
                deps.append(dep)

        return deps

    def _profile_origins(self, scripts: list[ScriptTag]) -> dict[str, dict]:
        """Profile external origins by category and risk."""
        origins: dict[str, dict] = {}

        for script in scripts:
            if not script.is_external or not script.origin:
                continue

            origin = script.origin
            if origin not in origins:
                origins[origin] = {
                    "count": 0,
                    "tags": set(),
                    "has_sri": False,
                    "cleartext": False,
                    "category": self._categorize_origin(origin),
                }

            origins[origin]["count"] += 1
            origins[origin]["tags"].add(script.tag)
            if script.integrity:
                origins[origin]["has_sri"] = True
            if script.protocol == "http:":
                origins[origin]["cleartext"] = True

        # Convert sets to lists for serialization
        for origin in origins:
            origins[origin]["tags"] = list(origins[origin]["tags"])

        return origins

    def _categorize_origin(self, origin: str) -> str:
        """Categorize an external origin."""
        for cdn, category in self.KNOWN_CDNS.items():
            if cdn in origin:
                return f"cdn:{category}"

        if "google" in origin:
            return "google"
        if "cloudflare" in origin:
            return "cloudflare"
        if "github" in origin:
            return "github"
        if "facebook" in origin or "fb" in origin:
            return "social"
        if any(ad in origin for ad in ["doubleclick", "googlesyndication", "ads.", "analytics"]):
            return "advertising"

        return "third-party"

    def _match_vulnerabilities(self, dependencies: list[DependencyInfo]) -> list[dict]:
        """Match dependencies against known vulnerabilities."""
        vulns = []

        for dep in dependencies:
            if dep.name.lower() in KNOWN_VULNERABLE:
                for vuln in KNOWN_VULNERABLE[dep.name.lower()]:
                    vulns.append({
                        "package": dep.name,
                        "version": dep.version,
                        "cve": vuln["cve"],
                        "severity": vuln["severity"],
                        "description": vuln["description"],
                        "version_range": vuln["versions"],
                        "source": dep.source,
                    })

        return vulns

    def _generate_findings(self, report: SBOMReport) -> list[dict]:
        """Generate Titan findings from the SBOM report."""
        findings = []

        # SRI missing — external scripts without integrity hashes
        if report.sri_missing:
            origins = set(s.origin for s in report.sri_missing if s.origin)
            findings.append({
                "type": "supply_chain_sri_missing",
                "severity": "medium",
                "title": f"Subresource Integrity (SRI) Missing on {len(report.sri_missing)} External Resource(s)",
                "evidence": (
                    f"External scripts/stylesheets without SRI hashes from: "
                    f"{', '.join(sorted(origins)[:5])}"
                ),
                "oracle": "sri_missing",
                "tier": "confirmed",
                "flow_types": ["code_exec"],
                "cvss_score": 6.5,
                "metadata": {
                    "count": len(report.sri_missing),
                    "origins": sorted(origins),
                },
            })

        # Cleartext loading — HTTP scripts on HTTPS pages
        if report.cleartext_loads:
            findings.append({
                "type": "supply_chain_cleartext_load",
                "severity": "high",
                "title": f"Cleartext (HTTP) Resource Loading on {len(report.cleartext_loads)} Resource(s)",
                "evidence": (
                    f"Resources loaded over HTTP (not HTTPS) — susceptible to MITM injection: "
                    f"{[s.src[:80] for s in report.cleartext_loads[:3]]}"
                ),
                "oracle": "cleartext_load",
                "tier": "confirmed",
                "flow_types": ["code_exec", "data_leak"],
                "cvss_score": 7.5,
                "metadata": {
                    "count": len(report.cleartext_loads),
                    "urls": [s.src for s in report.cleartext_loads],
                },
            })

        # Known vulnerabilities
        for vuln in report.known_vulns:
            findings.append({
                "type": "supply_chain_known_vuln",
                "severity": vuln["severity"],
                "title": f"Known Vulnerability: {vuln['package']} {vuln['cve']}",
                "evidence": (
                    f"Package '{vuln['package']}' version '{vuln['version']}' — "
                    f"{vuln['description']} ({vuln['cve']})"
                ),
                "oracle": "known_cve_match",
                "tier": "confirmed",
                "flow_types": ["code_exec"],
                "cvss_score": {"critical": 10.0, "high": 8.0, "medium": 5.0, "low": 2.0}.get(vuln["severity"], 5.0),
                "metadata": {
                    "package": vuln["package"],
                    "version": vuln["version"],
                    "cve": vuln["cve"],
                },
            })

        # Risky origins (advertising, unknown third-party)
        risky_origins = {
            name: info for name, info in report.origins.items()
            if info["category"].startswith("advertising") or info["category"] == "third-party"
        }
        if risky_origins:
            findings.append({
                "type": "supply_chain_risky_origins",
                "severity": "low",
                "title": f"{len(risky_origins)} Risky Third-Party Origin(s) Detected",
                "evidence": (
                    f"External origins with no CDN trust: "
                    f"{list(risky_origins.keys())[:5]}"
                ),
                "oracle": "risky_origin_detected",
                "tier": "confirmed",
                "flow_types": ["code_exec"],
                "cvss_score": 3.0,
                "metadata": {
                    "origins": {k: v["category"] for k, v in risky_origins.items()},
                },
            })

        return findings
