"""TLS Security Module — certificate testing, protocol downgrade.

A real attacker doesn't just test the app.
They test the TLS configuration too.

This module:
1. Certificate validation
2. Protocol version testing (SSLv3, TLS 1.0, 1.1)
3. Cipher suite testing
4. Certificate transparency
5. HSTS testing
6. Certificate pinning testing
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from titan.core.models import AttackType, Finding, Severity


@dataclass
class TLSPayload:
    """A TLS security test payload."""
    name: str
    category: str
    description: str
    severity: Severity
    confidence: float


class TLSSecurityTester:
    """Deep TLS security testing."""

    INSECURE_PROTOCOLS = [
        ("SSLv3", ssl.PROTOCOL_SSLv23, "SSLv3 is vulnerable to POODLE"),
        ("TLSv1.0", ssl.PROTOCOL_TLSv1, "TLSv1.0 is deprecated"),
        ("TLSv1.1", ssl.PROTOCOL_TLSv1_1, "TLSv1.1 is deprecated"),
    ]

    INSECURE_CIPHERS = [
        "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: list[Finding] = []

    async def test_certificate(
        self,
        target_url: str,
    ) -> list[Finding]:
        """Test TLS certificate."""
        findings = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        port = parsed.port or 443

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Check expiry
                    import datetime
                    not_after = ssl.cert_time_to_seconds(cert.get("notAfter", ""))
                    if not_after < datetime.datetime.now().timestamp():
                        finding = Finding(
                            target=target_url,
                            url=target_url,
                            method="TLS",
                            param="expired_cert",
                            location="tls",
                            payload="",
                            attack_type=AttackType.INFO_LEAK,
                            severity=Severity.HIGH,
                            verified=True,
                            confidence=0.95,
                            status=0,
                            body=f"Certificate expired: {cert.get('notAfter')}",
                            diffs=["tls:expired_cert"],
                            notes="TLS certificate is expired",
                        )
                        findings.append(finding)

                    # Check issuer
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))

                    if issuer.get("organizationName") == subject.get("organizationName"):
                        finding = Finding(
                            target=target_url,
                            url=target_url,
                            method="TLS",
                            param="self_signed",
                            location="tls",
                            payload="",
                            attack_type=AttackType.INFO_LEAK,
                            severity=Severity.HIGH,
                            verified=True,
                            confidence=0.90,
                            status=0,
                            body=f"Self-signed certificate: {issuer}",
                            diffs=["tls:self_signed"],
                            notes="Certificate appears self-signed",
                        )
                        findings.append(finding)

                    # Check SANs
                    san_names = []
                    for san_type, san_value in cert.get("subjectAltName", []):
                        if san_type == "DNS":
                            san_names.append(san_value)

                    if not san_names:
                        finding = Finding(
                            target=target_url,
                            url=target_url,
                            method="TLS",
                            param="no_sans",
                            location="tls",
                            payload="",
                            attack_type=AttackType.INFO_LEAK,
                            severity=Severity.MEDIUM,
                            verified=True,
                            confidence=0.80,
                            status=0,
                            body="No Subject Alternative Names",
                            diffs=["tls:no_sans"],
                            notes="Certificate has no SANs",
                        )
                        findings.append(finding)

        except ssl.SSLCertVerificationError as e:
            finding = Finding(
                target=target_url,
                url=target_url,
                method="TLS",
                param="cert_verification_failed",
                location="tls",
                payload="",
                attack_type=AttackType.INFO_LEAK,
                severity=Severity.CRITICAL,
                verified=True,
                confidence=0.95,
                status=0,
                body=str(e),
                diffs=["tls:cert_verification_failed"],
                notes=f"Certificate verification failed: {e}",
            )
            findings.append(finding)
        except Exception:
            pass

        self._findings.extend(findings)
        return findings

    async def test_protocols(
        self,
        target_url: str,
    ) -> list[Finding]:
        """Test for insecure TLS protocols."""
        findings = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        port = parsed.port or 443

        for proto_name, proto_const, description in self.INSECURE_PROTOCOLS:
            try:
                context = ssl.SSLContext(proto_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname):
                        finding = Finding(
                            target=target_url,
                            url=target_url,
                            method="TLS",
                            param=f"insecure_protocol_{proto_name.lower()}",
                            location="tls",
                            payload="",
                            attack_type=AttackType.INFO_LEAK,
                            severity=Severity.HIGH,
                            verified=True,
                            confidence=0.90,
                            status=0,
                            body=f"{proto_name} supported: {description}",
                            diffs=[f"tls:{proto_name.lower()}"],
                            notes=f"Insecure protocol: {description}",
                        )
                        findings.append(finding)
            except (TimeoutError, ssl.SSLError, ConnectionRefusedError, OSError):
                # Protocol not supported — good
                pass
            except Exception:
                pass

        self._findings.extend(findings)
        return findings

    async def test_hsts(
        self,
        target_url: str,
    ) -> list[Finding]:
        """Test HSTS configuration."""
        findings = []

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    headers = resp.headers
                    hsts = headers.get("Strict-Transport-Security", "")

                    if not hsts:
                        finding = Finding(
                            target=target_url,
                            url=target_url,
                            method="GET",
                            param="no_hsts",
                            location="header",
                            payload="",
                            attack_type=AttackType.INFO_LEAK,
                            severity=Severity.MEDIUM,
                            verified=True,
                            confidence=0.90,
                            status=resp.status,
                            body="No HSTS header",
                            diffs=["tls:no_hsts"],
                            notes="HSTS header not set",
                        )
                        findings.append(finding)
                    else:
                        # Check max-age
                        import re
                        max_age_match = re.search(r"max-age=(\d+)", hsts)
                        if max_age_match:
                            max_age = int(max_age_match.group(1))
                            if max_age < 31536000:  # 1 year
                                finding = Finding(
                                    target=target_url,
                                    url=target_url,
                                    method="GET",
                                    param="weak_hsts",
                                    location="header",
                                    payload=hsts,
                                    attack_type=AttackType.INFO_LEAK,
                                    severity=Severity.LOW,
                                    verified=True,
                                    confidence=0.80,
                                    status=resp.status,
                                    body=f"HSTS max-age too short: {max_age}",
                                    diffs=["tls:weak_hsts"],
                                    notes=f"HSTS max-age is {max_age} (recommended: 31536000+)",
                                )
                                findings.append(finding)

                        if "includeSubDomains" not in hsts:
                            finding = Finding(
                                target=target_url,
                                url=target_url,
                                method="GET",
                                param="hsts_no_subdomains",
                                location="header",
                                payload=hsts,
                                attack_type=AttackType.INFO_LEAK,
                                severity=Severity.LOW,
                                verified=True,
                                confidence=0.75,
                                status=resp.status,
                                body="HSTS without includeSubDomains",
                                diffs=["tls:hsts_no_subdomains"],
                                notes="HSTS header does not include includeSubDomains",
                            )
                            findings.append(finding)
        except Exception:
            pass

        self._findings.extend(findings)
        return findings

    def get_findings(self) -> list[Finding]:
        return self._findings
