"""OSINT Engine — Pre-scan intelligence gathering.

Collects subdomains, DNS records, certificate transparency logs,
tech hints, port scans, and leaked credentials before the main scan.

Usage:
    from titan.core.osint import OSINTEngine

    engine = OSINTEngine()
    report = await engine.enumerate("example.com")
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class SubdomainInfo:
    host: str
    ip_addresses: list[str] = field(default_factory=list)
    source: str = ""


@dataclass
class DNSRecord:
    type: str
    name: str
    value: str
    ttl: int = 0


@dataclass
class PortInfo:
    port: int
    state: str = "open"
    service: str = ""
    version: str = ""


@dataclass
class JSSecret:
    """A secret found in JavaScript bundles."""
    file_url: str
    secret_type: str  # api_key, token, endpoint, password
    value: str
    line: int = 0


@dataclass
class IntelligenceReport:
    """Complete intelligence report for a target."""
    target: str
    subdomains: list[SubdomainInfo] = field(default_factory=list)
    dns_records: list[DNSRecord] = field(default_factory=list)
    tech_hints: list[str] = field(default_factory=list)
    ports: list[PortInfo] = field(default_factory=list)
    js_secrets: list[JSSecret] = field(default_factory=list)
    leaked_creds: list[dict] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class OSINTEngine:
    """Pre-scan intelligence gathering engine.

    Collects information about the target before the main scan begins.
    This intelligence feeds into route scoring, payload generation,
    and attack surface mapping.
    """

    # JS secret patterns
    JS_SECRET_PATTERNS = [
        (r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([^'\"]+)['\"]", "api_key"),
        (r"(?:token|auth[_-]?token|access[_-]?token)\s*[:=]\s*['\"]([^'\"]+)['\"]", "token"),
        (r"(?:secret|client[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"]([^'\"]+)['\"]", "secret"),
        (r"(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]+)['\"]", "password"),
        (r"(?:firebase|firestore)[^'\"]*['\"]([^'\"]*\.app[^'\"]*)['\"]", "firebase_url"),
        (r"(?:mongodb|postgres|mysql|redis)://[^'\"]+['\"]", "database_url"),
        (r"(?:AWS|aws)[^'\"]*(?:key|secret|bucket)[^'\"]*['\"]([^'\"]+)['\"]", "aws_secret"),
        (r"AIza[0-9A-Za-z_-]{35}", "google_api_key"),
        (r"sk-[0-9A-Za-z]{48}", "openai_key"),
        (r"ghp_[0-9A-Za-z]{36}", "github_token"),
    ]

    # Common subdomain prefixes
    COMMON_SUBDOMAINS = [
        "www", "api", "admin", "app", "auth", "blog", "cdn", "cms",
        "dashboard", "db", "dev", "docs", "email", "ftp", "git",
        "grafana", "internal", "jenkins", "jira", "kibana", "mail",
        "monitor", "ns1", "ns2", "portal", "proxy", "raw", "s3",
        " staging", "status", "test", "vpn", "wiki", "ws",
    ]

    async def enumerate(self, target: str) -> IntelligenceReport:
        """Run full enumeration on a target domain."""
        report = IntelligenceReport(target=target)

        # Run all enumeration tasks concurrently
        tasks = [
            self._subdomain_enum(target),
            self._dns_lookup(target),
            self._cert_transparency(target),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.debug(f"Enumeration task failed: {result}")
                continue
            if isinstance(result, list):
                if result and isinstance(result[0], SubdomainInfo):
                    report.subdomains.extend(result)
                elif result and isinstance(result[0], DNSRecord):
                    report.dns_records.extend(result)

        # JS secret scanning (if we have a web URL)
        report.js_secrets = await self._js_secret_scan(target)

        logger.info(
            f"OSINT complete for {target}: "
            f"{len(report.subdomains)} subdomains, "
            f"{len(report.dns_records)} DNS records, "
            f"{len(report.js_secrets)} JS secrets"
        )
        return report

    async def _subdomain_enum(self, target: str) -> list[SubdomainInfo]:
        """Enumerate subdomains via DNS brute-force and certificate transparency."""
        subdomains = []

        # Method 1: Certificate transparency (crt.sh)
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%.{target}&output=json"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        import json
                        data = json.loads(await resp.text())
                        seen = set()
                        for entry in data:
                            name = entry.get("name_value", "").strip()
                            for sub in name.split("\n"):
                                sub = sub.strip().lower()
                                if sub and sub not in seen and sub.endswith(target):
                                    seen.add(sub)
                                    subdomains.append(SubdomainInfo(
                                        host=sub,
                                        source="crt.sh",
                                    ))
        except Exception as e:
            logger.debug(f"Certificate transparency lookup failed: {e}")

        # Method 2: DNS brute-force common subdomains
        for prefix in self.COMMON_SUBDOMAINS:
            subdomain = f"{prefix}.{target}"
            if subdomain not in [s.host for s in subdomains]:
                try:
                    import socket
                    ip = socket.gethostbyname(subdomain)
                    subdomains.append(SubdomainInfo(
                        host=subdomain,
                        ip_addresses=[ip],
                        source="dns_bruteforce",
                    ))
                except socket.gaierror:
                    pass

        return subdomains

    async def _dns_lookup(self, target: str) -> list[DNSRecord]:
        """Perform DNS lookups for common record types."""
        records = []

        # Use dnspython if available, fallback to socket
        try:
            import dns.resolver
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
                try:
                    answers = dns.resolver.resolve(target, rtype)
                    for answer in answers:
                        records.append(DNSRecord(
                            type=rtype,
                            name=target,
                            value=str(answer),
                            ttl=answer.ttl if hasattr(answer, "ttl") else 0,
                        ))
                except Exception:
                    pass
        except ImportError:
            # Fallback: basic A record lookup
            try:
                import socket
                ips = socket.gethostbyname_ex(target)
                for ip in ips[2]:
                    records.append(DNSRecord(type="A", name=target, value=ip))
            except Exception:
                pass

        return records

    async def _cert_transparency(self, target: str) -> list[DNSRecord]:
        """Check certificate transparency logs for additional domains."""
        # Already handled in _subdomain_enum via crt.sh
        return []

    async def _js_secret_scan(self, target: str) -> list[JSSecret]:
        """Scan JavaScript files for hardcoded secrets."""
        secrets = []

        try:
            import aiohttp
            from urllib.parse import urljoin

            base_url = target if target.startswith("http") else f"https://{target}"

            async with aiohttp.ClientSession() as session:
                # Fetch the main page
                async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        return secrets
                    html = await resp.text()

                # Find JS file URLs
                js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', html)
                js_urls = [urljoin(base_url, url) for url in js_urls[:5]]  # Limit to first 5

                # Also check inline scripts
                inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)
                for i, script in enumerate(inline_scripts):
                    for pattern, secret_type in self.JS_SECRET_PATTERNS:
                        for match in re.finditer(pattern, script, re.IGNORECASE):
                            secrets.append(JSSecret(
                                file_url=f"{base_url}#inline-{i}",
                                secret_type=secret_type,
                                value=match.group(1) if match.lastindex else match.group(0),
                            ))

                # Check external JS files
                for js_url in js_urls:
                    try:
                        async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                            if resp.status == 200:
                                js_content = await resp.text()
                                for pattern, secret_type in self.JS_SECRET_PATTERNS:
                                    for match in re.finditer(pattern, js_content, re.IGNORECASE):
                                        secrets.append(JSSecret(
                                            file_url=js_url,
                                            secret_type=secret_type,
                                            value=match.group(1) if match.lastindex else match.group(0),
                                        ))
                    except Exception:
                        continue

        except Exception as e:
            logger.debug(f"JS secret scan failed: {e}")

        return secrets
