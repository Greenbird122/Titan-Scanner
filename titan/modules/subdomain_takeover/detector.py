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
from titan.modules.subdomain_takeover.services import VULNERABLE_SERVICES

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
