"""Subdomain takeover detection module.

Discovers subdomains of the target via certificate transparency + DNS
brute-force, resolves each for CNAME records, and checks whether the
CNAME points to an unclaimed service (dangling CNAME = takeover opportunity).

Sources:
  - crt.sh certificate transparency logs
  - DNS brute-force of common subdomain prefixes
  - HTML/JS subdomain reference extraction (passed from engine crawl)

Known-vulnerable services database covers 30+ hosting / SaaS platforms
with specific fingerprint strings that indicate an unclaimed deployment.
"""

from __future__ import annotations

import asyncio
import re
import socket
from typing import Any
from urllib.parse import urlparse

from titan.core.logger import get_logger

try:
    import aiohttp
except ImportError:
    aiohttp = None  # graceful degrade — module can still do DNS-only checks

from titan.core.models import AttackType, Finding, Severity

logger = get_logger("detector")


# ─── Known-vulnerable CNAME targets ─────────────────────────────────
# Each entry maps a CNAME suffix (or exact match) to the service name
# and the HTTP body / DNS status that proves the subdomain is unclaimed.
#
# "dns_fingerprint": the subdomain is unclaimed if DNS returns NXDOMAIN
#   on the CNAME target itself (e.g. heroku apps that were deleted).
# "http_fingerprint": list of strings — if ANY appears in the HTTP body
#   of the CNAME target, the subdomain is likely claimable.

VULNERABLE_SERVICES: list[dict[str, Any]] = [
    # ── Vercel ───────────────────────────────────────────────────────
    {
        "service": "Vercel",
        "cnames": [".vercel.app", ".now.sh"],
        "http_fingerprint": [
            "The deployment could not be found",
            "404: NOT_FOUND",
            "DEPLOYMENT_NOT_FOUND",
            "has been removed",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary HTML/JS from the victim's subdomain.",
    },
    # ── GitHub Pages ─────────────────────────────────────────────────
    {
        "service": "GitHub Pages",
        "cnames": [".github.io"],
        "http_fingerprint": [
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an",
            "https://pages.github.com/",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary content from the victim's subdomain.",
    },
    # ── AWS S3 ───────────────────────────────────────────────────────
    {
        "service": "AWS S3",
        "cnames": [".s3.amazonaws.com", ".s3-website", ".s3-us-east-1.amazonaws.com"],
        "http_fingerprint": [
            "NoSuchBucket",
            "The specified bucket does not exist",
            "AccessDenied",
        ],
        "dns_fingerprint": "NXDOMAIN",
        "severity": "critical",
        "takeover_impact": "Host arbitrary content; potential credential harvesting via S3 bucket claim.",
    },
    # ── Heroku ───────────────────────────────────────────────────────
    {
        "service": "Heroku",
        "cnames": [".herokudns.com", ".herokuapp.com", ".herokuspace.com"],
        "http_fingerprint": [
            "No such app",
            "no-hierarchical-app",
            "herokucdn.com/error-pages/no-such-app.html",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary content from the victim's subdomain.",
    },
    # ── Netlify ──────────────────────────────────────────────────────
    {
        "service": "Netlify",
        "cnames": [".netlify.app", ".netlify.com"],
        "http_fingerprint": [
            "Not Found - Request ID:",
            "netlify/pages",
            "You haven't deployed a site yet",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary content from the victim's subdomain.",
    },
    # ── Shopify ──────────────────────────────────────────────────────
    {
        "service": "Shopify",
        "cnames": [".myshopify.com"],
        "http_fingerprint": [
            "Sorry, this shop is currently unavailable.",
            "Only one step left!",
            "Site Unavailable",
        ],
        "severity": "high",
        "takeover_impact": "E-commerce takeover — phish payment credentials via fake storefront.",
    },
    # ── Fastly ───────────────────────────────────────────────────────
    {
        "service": "Fastly",
        "cnames": [".global.ssl.fastly.net", ".fastly.net"],
        "http_fingerprint": [
            "Fastly error: unknown domain",
            "Request failed",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary content via Fastly CDN.",
    },
    # ── Surge ────────────────────────────────────────────────────────
    {
        "service": "Surge",
        "cnames": [".surge.sh"],
        "http_fingerprint": [
            "project not found",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary content.",
    },
    # ── Azure ────────────────────────────────────────────────────────
    {
        "service": "Azure (Traffic Manager)",
        "cnames": [".trafficmanager.net", ".azurewebsites.net", ".cloudapp.net"],
        "http_fingerprint": [
            "404 Web Site not found",
            "Azure Web App - Your web app is running and waiting for your content",
            "doesn't exist in this subscription",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary content from the victim's subdomain.",
    },
    # ── Pantheon ─────────────────────────────────────────────────────
    {
        "service": "Pantheon",
        "cnames": [".pantheonsite.io"],
        "http_fingerprint": [
            "404 error unknown site!",
            "The gods are wise",
            "Pantheon",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary content from the victim's subdomain.",
    },
    # ── Tumblr ───────────────────────────────────────────────────────
    {
        "service": "Tumblr",
        "cnames": [".domains.tumblr.com"],
        "http_fingerprint": [
            "Whatever you were looking for doesn't currently exist at this address",
            "There's nothing here.",
        ],
        "severity": "high",
        "takeover_impact": "Blog takeover — post content under the victim's domain.",
    },
    # ── Zendesk ──────────────────────────────────────────────────────
    {
        "service": "Zendesk",
        "cnames": [".zendesk.com"],
        "http_fingerprint": [
            "Help Center Closed",
            "This help center no longer exists",
        ],
        "severity": "high",
        "takeover_impact": "Support portal takeover — phish customer credentials and data.",
    },
    # ── Intercom ─────────────────────────────────────────────────────
    {
        "service": "Intercom",
        "cnames": [".custom.intercom.help"],
        "http_fingerprint": [
            "This page is reserved for artistic dogs",
            "Uh oh. That page doesn't exist.",
        ],
        "severity": "high",
        "takeover_impact": "Chat widget takeover — intercept customer conversations.",
    },
    # ── WordPress.com ────────────────────────────────────────────────
    {
        "service": "WordPress.com",
        "cnames": [".wordpress.com"],
        "http_fingerprint": [
            "Do you want to register",
        ],
        "severity": "medium",
        "takeover_impact": "Blog takeover — publish content under the victim's domain.",
    },
    # ── Ghost ────────────────────────────────────────────────────────
    {
        "service": "Ghost (Pro)",
        "cnames": [".ghost.io"],
        "http_fingerprint": [
            "The thing you were looking for is no longer here",
        ],
        "severity": "high",
        "takeover_impact": "CMS takeover — full control of the victim's blog/platform.",
    },
    # ── StatusPage ───────────────────────────────────────────────────
    {
        "service": "StatusPage",
        "cnames": [".statuspage.io"],
        "http_fingerprint": [
            "Better StatusPage",
            "Micro Status Page",
        ],
        "severity": "medium",
        "takeover_impact": "Fake status page — mislead users about service health.",
    },
    # ── Helpjuice ────────────────────────────────────────────────────
    {
        "service": "Helpjuice",
        "cnames": [".helpjuice.com"],
        "http_fingerprint": [
            "We could not find what you're looking for",
        ],
        "severity": "high",
        "takeover_impact": "Knowledge base takeover — serve phishing content.",
    },
    # ── Helpscout ────────────────────────────────────────────────────
    {
        "service": "Helpscout",
        "cnames": [".helpscoutdocs.com"],
        "http_fingerprint": [
            "No settings were found for this company",
        ],
        "severity": "high",
        "takeover_impact": "Documentation takeover — phish users via trusted domain.",
    },
    # ── Campaignmonitor ──────────────────────────────────────────────
    {
        "service": "Campaignmonitor",
        "cnames": [".createsend.com", ".campaignmonitor.com"],
        "http_fingerprint": [
            "Double check the URL",
            "Trying to access your account?",
        ],
        "severity": "medium",
        "takeover_impact": "Email campaign takeover — send phishing emails from victim's domain.",
    },
    # ── Cargocollective ──────────────────────────────────────────────
    {
        "service": "Cargocollective",
        "cnames": [".cargocollective.com"],
        "http_fingerprint": [
            "If you're moving your domain away from Cargo you must make this configuration change",
        ],
        "severity": "high",
        "takeover_impact": "Portfolio takeover — serve arbitrary content.",
    },
    # ── Feedpress ────────────────────────────────────────────────────
    {
        "service": "Feedpress",
        "cnames": [".feedpress.me"],
        "http_fingerprint": [
            "The feed has not been found",
        ],
        "severity": "medium",
        "takeover_impact": "RSS feed takeover — serve malicious content to subscribers.",
    },
    # ── Google Cloud ─────────────────────────────────────────────────
    {
        "service": "Google Cloud Storage",
        "cnames": [".c.storage.googleapis.com"],
        "http_fingerprint": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "severity": "critical",
        "takeover_impact": "Storage takeover — serve arbitrary files from victim's subdomain.",
    },
    # ── Instapage ────────────────────────────────────────────────────
    {
        "service": "Instapage",
        "cnames": [".instapage.com"],
        "http_fingerprint": [
            "The page you are looking for can't be found",
        ],
        "severity": "medium",
        "takeover_impact": "Landing page takeover — phish via fake campaign page.",
    },
    # ── LaunchRock ───────────────────────────────────────────────────
    {
        "service": "LaunchRock",
        "cnames": [".launchrock.com"],
        "http_fingerprint": [
            "It looks like you may have taken a wrong turn somewhere",
        ],
        "severity": "medium",
        "takeover_impact": "Coming soon page takeover — serve phishing content.",
    },
    # ── Mindbox ──────────────────────────────────────────────────────
    {
        "service": "Mindbox",
        "cnames": [".mindbox.io"],
        "http_fingerprint": [
            "Unexpected end-of-file",
        ],
        "severity": "low",
        "takeover_impact": "Limited — marketing automation platform.",
    },
    # ── Pingdom ──────────────────────────────────────────────────────
    {
        "service": "Pingdom",
        "cnames": [".stats.pingdom.com"],
        "http_fingerprint": [
            "Sorry, couldn't find the status page",
        ],
        "severity": "low",
        "takeover_impact": "Status page takeover — fake uptime reports.",
    },
    # ── Proposify ────────────────────────────────────────────────────
    {
        "service": "Proposify",
        "cnames": [".proposify.biz"],
        "http_fingerprint": [
            "If you need immediate assistance, please contact",
        ],
        "severity": "medium",
        "takeover_impact": "Proposal tool takeover — phish business contacts.",
    },
    # ── Readme.io ────────────────────────────────────────────────────
    {
        "service": "Readme.io",
        "cnames": [".readme.io"],
        "http_fingerprint": [
            "Project doesn't exist",
        ],
        "severity": "medium",
        "takeover_impact": "API documentation takeover — serve malicious docs.",
    },
    # ── Squarespace ──────────────────────────────────────────────────
    {
        "service": "Squarespace",
        "cnames": [".squarespace.com"],
        "http_fingerprint": [
            "No Such Account",
        ],
        "severity": "high",
        "takeover_impact": "Website takeover — serve arbitrary content.",
    },
    # ── Thinkific ────────────────────────────────────────────────────
    {
        "service": "Thinkific",
        "cnames": [".thinkific.com"],
        "http_fingerprint": [
            "You may have typed the address incorrectly or you may have used an outdated link",
        ],
        "severity": "medium",
        "takeover_impact": "Course platform takeover — phish learners.",
    },
    # ── Tilda ────────────────────────────────────────────────────────
    {
        "service": "Tilda",
        "cnames": [".tilda.ws"],
        "http_fingerprint": [
            "Please go to the site settings and put the domain name in the Domain field",
        ],
        "severity": "medium",
        "takeover_impact": "Website takeover — serve arbitrary content.",
    },
    # ── Unbounce ─────────────────────────────────────────────────────
    {
        "service": "Unbounce",
        "cnames": [".unbounce.com"],
        "http_fingerprint": [
            "The requested URL was not found on this server",
            "If you're an Unbounce customer",
        ],
        "severity": "medium",
        "takeover_impact": "Landing page takeover — phish via fake campaign page.",
    },
    # ── UserVoice ────────────────────────────────────────────────────
    {
        "service": "UserVoice",
        "cnames": [".uservoice.com"],
        "http_fingerprint": [
            "This UserVoice site is currently available to authors only",
        ],
        "severity": "low",
        "takeover_impact": "Feedback portal takeover — harvest user data.",
    },
    # ── Webflow ──────────────────────────────────────────────────────
    {
        "service": "Webflow",
        "cnames": [".proxy.webflow.com", ".proxy-ssl.webflow.com"],
        "http_fingerprint": [
            "The page you are looking for doesn't exist",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary content from the victim's subdomain.",
    },
    # ── Wishpond ─────────────────────────────────────────────────────
    {
        "service": "Wishpond",
        "cnames": [".wishpond.com"],
        "http_fingerprint": [
            "https://www.wishpond.com/404?campaign=true",
        ],
        "severity": "medium",
        "takeover_impact": "Campaign page takeover — phish via fake promotion.",
    },
    # ── WordPress (VIP / Pressable) ──────────────────────────────────
    {
        "service": "WordPress (Pressable)",
        "cnames": [".wpenginepowered.com", ".pressable.com"],
        "http_fingerprint": [
            "Do you want to register",
        ],
        "severity": "medium",
        "takeover_impact": "Blog takeover — publish content under victim's domain.",
    },
]


class SubdomainTakeoverDetector:
    """Detect dangling CNAME records that enable subdomain takeover."""

    name = "subdomain_takeover"
    timeout = 120  # can be slow due to DNS + HTTP probes

    def __init__(self):
        # Build a fast lookup: cname_suffix → service entry
        self._cnameservice: dict[str, dict[str, Any]] = {}
        for svc in VULNERABLE_SERVICES:
            for cname in svc["cnames"]:
                self._cnameservice[cname.lower()] = svc

    # ── Public entry point ───────────────────────────────────────────

    async def scan(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: dict[str, str],
        fingerprint: dict[str, Any],
    ) -> list[Finding]:
        """Run subdomain takeover detection.

        This module is URL-agnostic — it discovers subdomains of the
        target's root domain and probes each for dangling CNAMEs.
        The ``url`` / ``params`` args are unused (module signature
        compatibility with the engine's module matrix).
        """
        findings: list[Finding] = []

        root_domain = self._extract_root_domain(target)
        if not root_domain:
            return findings

        print(f"      [subdomain-takeover] Enumerating subdomains of {root_domain}...")

        # Step 1: Enumerate subdomains
        subdomains = await self._enumerate_subdomains(root_domain)
        if not subdomains:
            print(f"      [subdomain-takeover] No subdomains found for {root_domain}")
            return findings

        print(f"      [subdomain-takeover] Found {len(subdomains)} subdomains, checking CNAMEs...")

        # Step 2: Resolve CNAMEs and check for vulnerable services
        for subdomain in subdomains:
            try:
                cname_target = await self._resolve_cname(subdomain)
                if not cname_target:
                    continue

                # Check if this CNAME points to a known-vulnerable service
                service_info = self._match_service(cname_target)
                if not service_info:
                    continue

                print(f"      [subdomain-takeover] {subdomain} → CNAME {cname_target} ({service_info['service']})")

                # Step 3: Verify claimability
                is_claimable = await self._verify_claimability(subdomain, cname_target, service_info)

                if is_claimable:
                    findings.append(
                        Finding(
                            target=target,
                            url=f"https://{subdomain}",
                            method="DNS",
                            param="CNAME",
                            location="dns",
                            payload=f"CNAME {subdomain} → {cname_target} ({service_info['service']})",
                            attack_type=AttackType.INFO_LEAK,
                            severity=Severity.CRITICAL
                            if service_info["severity"] == "critical"
                            else Severity.HIGH
                            if service_info["severity"] == "high"
                            else Severity.MEDIUM,
                            confidence=0.90,
                            status=200,
                            evidence=(
                                f"Dangling CNAME: {subdomain} points to {cname_target} "
                                f"({service_info['service']}), which is currently unclaimed. "
                                f"{service_info['takeover_impact']}"
                            ),
                            diffs=[
                                "subdomain_takeover:dangling_cname",
                                f"service:{service_info['service']}",
                                f"cname_target:{cname_target}",
                            ],
                            metadata={
                                "subdomain": subdomain,
                                "cname_target": cname_target,
                                "service": service_info["service"],
                                "takeover_impact": service_info["takeover_impact"],
                                "claimable": True,
                            },
                            tags=["subdomain-takeover", "dns", service_info["service"].lower()],
                        )
                    )
                    print(
                        f"      [subdomain-takeover] ⚠️  VULNERABLE: {subdomain} → {cname_target} ({service_info['service']})"
                    )
                else:
                    # CNAME exists and points to a known service, but it's claimed
                    print(f"      [subdomain-takeover] {subdomain} → {cname_target} (claimed)")

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        if not findings:
            print(f"      [subdomain-takeover] No dangling CNAMEs found across {len(subdomains)} subdomains")

        return findings

    # ── Subdomain enumeration ────────────────────────────────────────

    async def _enumerate_subdomains(self, root_domain: str) -> list[str]:
        """Discover subdomains via crt.sh + DNS brute-force."""
        subdomains: set[str] = set()

        # Method 1: crt.sh certificate transparency
        crt_subs = await self._crtsh_enum(root_domain)
        subdomains.update(crt_subs)

        # Method 2: DNS brute-force common prefixes
        bruteforce_subs = await self._dns_bruteforce(root_domain)
        subdomains.update(bruteforce_subs)

        # Remove the root domain itself (not a subdomain)
        subdomains.discard(root_domain)
        subdomains.discard(f"www.{root_domain}")

        return sorted(subdomains)

    async def _crtsh_enum(self, root_domain: str) -> set[str]:
        """Query crt.sh for certificate transparency subdomains."""
        subdomains: set[str] = set()
        if aiohttp is None:
            return subdomains
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%.{root_domain}&output=json"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        import json

                        data = json.loads(await resp.text())
                        for entry in data:
                            name = entry.get("name_value", "").strip()
                            for sub in name.split("\n"):
                                sub = sub.strip().lower()
                                # Skip wildcards
                                if sub.startswith("*"):
                                    sub = sub[1:]
                                if sub and sub.endswith(root_domain) and sub != root_domain:
                                    subdomains.add(sub)
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass
        return subdomains

    async def _dns_bruteforce(self, root_domain: str) -> set[str]:
        """DNS brute-force common subdomain prefixes."""
        COMMON_PREFIXES = [
            "www",
            "api",
            "admin",
            "app",
            "auth",
            "blog",
            "cdn",
            "cms",
            "dashboard",
            "db",
            "dev",
            "docs",
            "email",
            "ftp",
            "git",
            "grafana",
            "internal",
            "jenkins",
            "jira",
            "kibana",
            "mail",
            "monitor",
            "ns1",
            "ns2",
            "portal",
            "proxy",
            "raw",
            "s3",
            "staging",
            "status",
            "test",
            "vpn",
            "wiki",
            "ws",
            "login",
            "signup",
            "register",
            "portal",
            "shop",
            "store",
            "pay",
            "billing",
            "support",
            "help",
            "forum",
            "community",
            "chat",
            "media",
            "static",
            "assets",
            "img",
            "images",
            "files",
            "download",
            "upload",
            "backup",
            "old",
            "new",
            "beta",
            "alpha",
            "demo",
            "sandbox",
            "preview",
            "stg",
            "prod",
            "production",
            "uat",
            "qa",
            "ci",
            "cd",
            "build",
            "deploy",
        ]
        subdomains: set[str] = set()
        try:
            for prefix in COMMON_PREFIXES:
                candidate = f"{prefix}.{root_domain}"
                try:
                    # Non-blocking DNS check
                    loop = asyncio.get_event_loop()
                    ip = await loop.run_in_executor(None, socket.gethostbyname, candidate)
                    if ip:
                        subdomains.add(candidate)
                except (socket.gaierror, OSError) as exc:
                    logger.debug(f"suppressed exception: {exc}")
                    pass
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass
        return subdomains

    # ── CNAME resolution ─────────────────────────────────────────────

    async def _resolve_cname(self, hostname: str) -> str | None:
        """Resolve a hostname's CNAME record. Returns the canonical name or None."""
        try:
            # Try dnspython first
            import dns.resolver

            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: dns.resolver.resolve(hostname, "CNAME"),
            )
            for rdata in answers:
                return str(rdata.target).rstrip(".")
        except ImportError as exc:
            logger.debug(f"suppressed exception: {exc}")
            # Fallback: use socket + nslookup pattern
            pass
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        # Fallback: check if it's a known CNAME pattern via HTTP
        # (some services use ALIAS/ANAME which flatten CNAME at the edge)
        return None

    # ── Service matching ─────────────────────────────────────────────

    def _match_service(self, cname_target: str) -> dict[str, Any] | None:
        """Match a CNAME target against the known-vulnerable services database."""
        cname_lower = cname_target.lower()
        for suffix, service_info in self._cnameservice.items():
            if cname_lower.endswith(suffix) or suffix in cname_lower:
                return service_info
        return None

    # ── Claimability verification ────────────────────────────────────

    async def _verify_claimability(
        self,
        subdomain: str,
        cname_target: str,
        service_info: dict[str, Any],
    ) -> bool:
        """Verify that the CNAME target is actually unclaimed.

        Probes the subdomain itself via HTTP — if it returns a service-specific
        "not found" page matching the fingerprint, the subdomain is claimable.
        """
        http_fingerprints = service_info.get("http_fingerprint", [])
        if not http_fingerprints:
            return False

        if aiohttp is None:
            return False
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://{subdomain}"
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=True,
                    ssl=False,
                ) as resp:
                    body = await resp.text()
                    body_lower = body.lower()

                    for fp in http_fingerprints:
                        if fp.lower() in body_lower:
                            return True

                    # Also check status codes that indicate unclaimed
                    # Some services return 404 or specific error pages
                    if resp.status in (404, 410):
                        # 404 on a subdomain with a CNAME to a known service
                        # is a strong signal — verify it's the service's 404
                        # (not a generic nginx/Apache 404)
                        service_404_indicators = [
                            "not found",
                            "doesn't exist",
                            "unavailable",
                            "no such",
                            "error",
                            "sorry",
                        ]
                        if any(ind in body_lower for ind in service_404_indicators):
                            return True

        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            # If the subdomain is completely unreachable (connection refused,
            # timeout, SSL error) but has a CNAME to a known service, it's
            # still potentially claimable — the CNAME is dangling even if
            # the HTTP probe fails.
            pass

        # DNS-based fallback: if the CNAME target itself returns NXDOMAIN,
        # the subdomain is definitely claimable (service was deleted)
        if service_info.get("dns_fingerprint") == "NXDOMAIN":
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, socket.gethostbyname, cname_target)
                # If we get here, the target resolves — not NXDOMAIN
                return False
            except socket.gaierror:
                # NXDOMAIN — the service was deleted
                return True
            except Exception as exc:
                logger.debug(f"suppressed exception: {exc}")
                pass

        return False

    # ── Helpers ──────────────────────────────────────────────────────

    def _extract_root_domain(self, target: str) -> str | None:
        """Extract the root domain from a target URL or hostname."""
        # Strip protocol
        if "://" in target:
            parsed = urlparse(target)
            hostname = parsed.hostname or ""
        else:
            hostname = target.split("/")[0].split(":")[0]

        # Remove www. prefix
        hostname = hostname.lower().strip()
        if hostname.startswith("www."):
            hostname = hostname[4:]

        # Skip localhost / IP addresses
        if hostname in ("localhost", "127.0.0.1", "::1", ""):
            return None
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
            return None

        # Extract root domain (last two parts, or last three if ccTLD)
        parts = hostname.split(".")
        if len(parts) < 2:
            return None

        # Handle multi-part TLDs (e.g., .co.ke, .com.au)
        TWO_PART_TLDS = {
            "co.uk",
            "co.ke",
            "co.za",
            "com.au",
            "com.br",
            "co.in",
            "co.jp",
            "co.kr",
            "com.cn",
            "com.mx",
            "com.sg",
            "com.tw",
            "net.au",
            "org.uk",
            "or.jp",
            "ne.jp",
            "co.nz",
        }
        tld = ".".join(parts[-2:])
        if tld in TWO_PART_TLDS and len(parts) >= 3:
            return ".".join(parts[-3:])

        return ".".join(parts[-2:])
