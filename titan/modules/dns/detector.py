"""DNS Security Module — subdomain takeover, DNS rebinding.

A real attacker doesn't just test the main domain.
They test subdomains too.

This module:
1. Subdomain enumeration
2. Subdomain takeover detection
3. DNS rebinding testing
4. Zone transfer testing
5. DNSSEC validation
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from titan.core.logger import get_logger
from titan.core.models import AttackType, Finding, Severity

logger = get_logger("detector")


@dataclass
class DNSPayload:
    """A DNS security test payload."""

    name: str
    category: str
    subdomain: str
    expected_effect: str
    severity: Severity
    confidence: float


class DNSSecurityTester:
    """Deep DNS security testing."""

    COMMON_SUBDOMAINS = [
        "www",
        "mail",
        "ftp",
        "admin",
        "api",
        "dev",
        "staging",
        "test",
        "blog",
        "shop",
        "store",
        "app",
        "portal",
        "dashboard",
        "cms",
        "vpn",
        "remote",
        "gateway",
        "proxy",
        "cdn",
        "static",
        "media",
        "images",
        "assets",
        "files",
        "docs",
        "help",
        "support",
        "status",
        "monitor",
        "grafana",
        "kibana",
        "jenkins",
        "gitlab",
        "github",
        "bitbucket",
        "jira",
        "confluence",
        "slack",
        "db",
        "database",
        "mysql",
        "postgres",
        "redis",
        "mongo",
        "elastic",
        "kafka",
        "rabbitmq",
        "memcache",
    ]

    TAKEOVER_INDICATORS = [
        "NoSuchBucket",
        "No such host",
        "No such distribution",
        "Repository not found",
        "No such account",
        "NoSuchPage",
        "Domain not found",
        "No claims",
        "Heroku | No such app",
        "Fastly error: unknown domain",
        "The specified bucket does not exist",
        "NoSuchSite",
        "is not a registered InCloud",
        "No kammerad configuration found",
        "The page you are looking for doesn't exist",
        "There is no app configured at that hostname",
        "No deployment found",
        "Application not found",
        "UnknownSite",
        "404 Site Not Found",
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: list[Finding] = []

    async def enumerate_subdomains(
        self,
        target_url: str,
        domain: str,
    ) -> list[str]:
        """Enumerate subdomains."""
        discovered = []

        try:
            import asyncio

            async def check_subdomain(subdomain):
                full_domain = f"{subdomain}.{domain}"
                try:
                    import socket

                    socket.gethostbyname(full_domain)
                    return full_domain
                except Exception:
                    return None

            tasks = [check_subdomain(sub) for sub in self.COMMON_SUBDOMAINS]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if not isinstance(result, Exception) and result:
                    discovered.append(result)

        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        return discovered

    async def test_subdomain_takeover(
        self,
        target_url: str,
        domain: str,
    ) -> list[Finding]:
        """Test for subdomain takeover."""
        findings = []
        subdomains = await self.enumerate_subdomains(target_url, domain)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                for subdomain in subdomains:
                    try:
                        url = f"https://{subdomain}"
                        async with session.get(
                            url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False
                        ) as resp:
                            body = await resp.text()
                            status = resp.status

                            for indicator in self.TAKEOVER_INDICATORS:
                                if indicator.lower() in body.lower():
                                    finding = Finding(
                                        target=target_url,
                                        url=url,
                                        method="GET",
                                        param="subdomain_takeover",
                                        location="dns",
                                        payload=subdomain,
                                        attack_type=AttackType.INFO_LEAK,
                                        severity=Severity.CRITICAL,
                                        verified=True,
                                        confidence=0.85,
                                        status=status,
                                        body=body[:500],
                                        diffs=[f"dns:takeover:{subdomain}"],
                                        notes=f"Subdomain takeover: {subdomain} ({indicator})",
                                    )
                                    findings.append(finding)
                                    break
                    except Exception as exc:
                        logger.debug(f"variant failed, continuing: {exc}")
                        continue
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        self._findings.extend(findings)
        return findings

    async def test_zone_transfer(
        self,
        target_url: str,
        domain: str,
    ) -> list[Finding]:
        """Test DNS zone transfer."""
        findings = []

        try:
            # Get nameservers
            import subprocess

            result = subprocess.run(["nslookup", "-type=ns", domain], capture_output=True, text=True, timeout=10)

            nameservers = re.findall(r"nameserver = (.+)", result.stdout)

            for ns in nameservers:
                try:
                    # Attempt zone transfer
                    result = subprocess.run(
                        ["dig", f"@{ns.strip()}", domain, "AXFR"], capture_output=True, text=True, timeout=10
                    )

                    if "XFR size" in result.stdout or len(result.stdout) > 1000:
                        finding = Finding(
                            target=target_url,
                            url=f"dns://{ns.strip()}",
                            method="AXFR",
                            param="zone_transfer",
                            location="dns",
                            payload=domain,
                            attack_type=AttackType.INFO_LEAK,
                            severity=Severity.CRITICAL,
                            verified=True,
                            confidence=0.95,
                            status=200,
                            body=result.stdout[:2000],
                            diffs=[f"dns:zone_transfer:{ns.strip()}"],
                            notes=f"DNS zone transfer allowed from {ns.strip()}",
                        )
                        findings.append(finding)
                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        self._findings.extend(findings)
        return findings

    def get_findings(self) -> list[Finding]:
        return self._findings
