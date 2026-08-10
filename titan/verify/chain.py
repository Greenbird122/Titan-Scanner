"""Vulnerability chain detection for Titan Scanner."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from titan.core.models import Finding


class VulnerabilityChain:
    def __init__(self, name: str, description: str, impact: str):
        self.name = name
        self.description = description
        self.impact = impact
        self.findings: List[Finding] = []

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "impact": self.impact,
            "findings": [f.to_dict() for f in self.findings],
        }


class ChainDetector:
    def detect(self, findings: List[Finding]) -> List[VulnerabilityChain]:
        chains: List[VulnerabilityChain] = []

        xss_findings = [f for f in findings if f.attack_type.name == "XSS"]
        csrf_findings = [f for f in findings if f.attack_type.name == "AUTH_BYPASS" or "csrf" in f.payload.lower()]
        if xss_findings and csrf_findings:
            chain = VulnerabilityChain(
                "XSS + CSRF = Account Takeover",
                "XSS vulnerability combined with missing CSRF protection allows account takeover",
                "Critical - Attacker can steal sessions, change passwords, exfiltrate data",
            )
            for f in xss_findings + csrf_findings:
                chain.add_finding(f)
            chains.append(chain)

        sqli_findings = [f for f in findings if f.attack_type.name == "SQLI"]
        if len(sqli_findings) >= 2:
            chain = VulnerabilityChain(
                "SQL Injection Chain",
                "Multiple SQL injection points allow for complex exploitation",
                "High - Attacker can chain injections for data exfiltration, privilege escalation",
            )
            for f in sqli_findings:
                chain.add_finding(f)
            chains.append(chain)

        ssrf_findings = [f for f in findings if f.attack_type.name == "SSRF"]
        if ssrf_findings:
            chain = VulnerabilityChain(
                "SSRF Internal Pivot",
                "SSRF vulnerability allows internal network scanning and service enumeration",
                "Critical - Attacker can access internal services, cloud metadata, and pivot",
            )
            for f in ssrf_findings:
                chain.add_finding(f)
            chains.append(chain)

        lfi_findings = [f for f in findings if f.attack_type.name == "LFI"]
        if lfi_findings:
            chain = VulnerabilityChain(
                "LFI to RCE Chain",
                "Local file inclusion can be chained with log poisoning or /proc/self/environ for RCE",
                "Critical - LFI can lead to full server compromise",
            )
            for f in lfi_findings:
                chain.add_finding(f)
            chains.append(chain)

        deser_findings = [f for f in findings if f.attack_type.name == "DESERIALIZATION"]
        if deser_findings:
            chain = VulnerabilityChain(
                "Deserialization Chain",
                "Deserialization vulnerabilities can be chained for RCE",
                "Critical - Deserialization often leads to immediate RCE",
            )
            for f in deser_findings:
                chain.add_finding(f)
            chains.append(chain)

        return chains
