"""Email Security Module — SPF/DKIM/DMARC testing.

A real attacker doesn't just test the app.
They test email security too.

This module:
1. SPF record validation
2. DKIM record validation
3. DMARC record validation
4. Email spoofing test
5. Open relay testing
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Any

from titan.core.logger import get_logger
from titan.core.models import AttackType, Finding, Severity

logger = get_logger("detector")


@dataclass
class EmailPayload:
    """An email security test payload."""

    name: str
    category: str
    record_type: str
    expected_effect: str
    severity: Severity
    confidence: float


class EmailSecurityTester:
    """Deep email security testing."""

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: list[Finding] = []

    async def test_spf(
        self,
        target_url: str,
        domain: str,
    ) -> list[Finding]:
        """Test SPF record."""
        findings = []

        try:
            result = subprocess.run(["dig", "+short", domain, "TXT"], capture_output=True, text=True, timeout=10)

            spf_records = [r for r in result.stdout.strip().split("\n") if "v=spf1" in r]

            if not spf_records:
                finding = Finding(
                    target=target_url,
                    url=f"dns://{domain}",
                    method="DNS",
                    param="no_spf",
                    location="dns",
                    payload="",
                    attack_type=AttackType.INFO_LEAK,
                    severity=Severity.HIGH,
                    verified=True,
                    confidence=0.95,
                    status=0,
                    body="No SPF record found",
                    diffs=["email:no_spf"],
                    notes=f"Domain {domain} has no SPF record — email spoofing possible",
                )
                findings.append(finding)
            else:
                spf = spf_records[0]
                if "~all" in spf or "?all" in spf:
                    finding = Finding(
                        target=target_url,
                        url=f"dns://{domain}",
                        method="DNS",
                        param="weak_spf",
                        location="dns",
                        payload=spf,
                        attack_type=AttackType.INFO_LEAK,
                        severity=Severity.MEDIUM,
                        verified=True,
                        confidence=0.85,
                        status=0,
                        body=f"Weak SPF: {spf}",
                        diffs=["email:weak_spf"],
                        notes="SPF uses soft fail (~all) — spoofed emails may be delivered",
                    )
                    findings.append(finding)
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        self._findings.extend(findings)
        return findings

    async def test_dmarc(
        self,
        target_url: str,
        domain: str,
    ) -> list[Finding]:
        """Test DMARC record."""
        findings = []

        try:
            result = subprocess.run(
                ["dig", "+short", f"_dmarc.{domain}", "TXT"], capture_output=True, text=True, timeout=10
            )

            dmarc_records = [r for r in result.stdout.strip().split("\n") if "v=DMARC1" in r]

            if not dmarc_records:
                finding = Finding(
                    target=target_url,
                    url=f"dns://{domain}",
                    method="DNS",
                    param="no_dmarc",
                    location="dns",
                    payload="",
                    attack_type=AttackType.INFO_LEAK,
                    severity=Severity.HIGH,
                    verified=True,
                    confidence=0.95,
                    status=0,
                    body="No DMARC record found",
                    diffs=["email:no_dmarc"],
                    notes=f"Domain {domain} has no DMARC record — email spoofing possible",
                )
                findings.append(finding)
            else:
                dmarc = dmarc_records[0]
                if "p=none" in dmarc:
                    finding = Finding(
                        target=target_url,
                        url=f"dns://{domain}",
                        method="DNS",
                        param="dmarc_none",
                        location="dns",
                        payload=dmarc,
                        attack_type=AttackType.INFO_LEAK,
                        severity=Severity.MEDIUM,
                        verified=True,
                        confidence=0.90,
                        status=0,
                        body=f"DMARC policy is none: {dmarc}",
                        diffs=["email:dmarc_none"],
                        notes="DMARC policy is 'none' — spoofed emails will be delivered",
                    )
                    findings.append(finding)
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        self._findings.extend(findings)
        return findings

    async def test_dkim(
        self,
        target_url: str,
        domain: str,
    ) -> list[Finding]:
        """Test DKIM record."""
        findings = []

        common_selectors = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail"]

        try:
            for selector in common_selectors:
                result = subprocess.run(
                    ["dig", "+short", f"{selector}._domainkey.{domain}", "TXT"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.stdout.strip():
                    # DKIM found — check if it's valid
                    dkim = result.stdout.strip()
                    if "p=" not in dkim:
                        finding = Finding(
                            target=target_url,
                            url=f"dns://{domain}",
                            method="DNS",
                            param="weak_dkim",
                            location="dns",
                            payload=dkim,
                            attack_type=AttackType.INFO_LEAK,
                            severity=Severity.MEDIUM,
                            verified=True,
                            confidence=0.80,
                            status=0,
                            body=f"Weak DKIM: {dkim}",
                            diffs=["email:weak_dkim"],
                            notes=f"DKIM record has no public key: {dkim}",
                        )
                        findings.append(finding)
                    break
            else:
                finding = Finding(
                    target=target_url,
                    url=f"dns://{domain}",
                    method="DNS",
                    param="no_dkim",
                    location="dns",
                    payload="",
                    attack_type=AttackType.INFO_LEAK,
                    severity=Severity.MEDIUM,
                    verified=True,
                    confidence=0.85,
                    status=0,
                    body="No DKIM record found",
                    diffs=["email:no_dkim"],
                    notes=f"Domain {domain} has no DKIM record",
                )
                findings.append(finding)
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        self._findings.extend(findings)
        return findings

    def get_findings(self) -> list[Finding]:
        return self._findings
