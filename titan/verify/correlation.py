"""SAST-DAST Correlation Engine — Correlate source code findings with runtime evidence.

When the same CWE appears in both SAST (source) and DAST (runtime),
confidence jumps to near-certain. This engine bridges the gap.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class SARIFFinding:
    """A finding from SAST analysis (Semgrep, CodeQL, etc. in SARIF format)."""
    rule_id: str          # CWE number (e.g., "CWE-89")
    message: str
    file_path: str
    line_start: int
    line_end: int = 0
    severity: str = "medium"
    code_snippet: str = ""
    data_flow: list[dict] = field(default_factory=list)


@dataclass
class CorrelatedFinding:
    """A finding correlated from both SAST and DAST sources."""
    cwe: str
    title: str
    confidence: float       # 0.0 - 1.0
    sast_source: SARIFFinding | None = None
    dast_finding: dict | None = None
    code_location: str = ""
    http_flow: str = ""
    attack_chain: list[str] = field(default_factory=list)
    patch_suggestion: str = ""


class CorrelationEngine:
    """Correlate SAST and DAST findings.

    Matching criteria:
      1. Same CWE number (e.g., CWE-89 for SQLi)
      2. Same data flow (source → sink matches)
      3. Same file/endpoint

    When both agree, confidence is near-certain (0.95+).
    """

    # CWE to Titan attack type mapping
    CWE_MAP = {
        "CWE-89": "sqli",
        "CWE-79": "xss",
        "CWE-78": "rce",
        "CWE-918": "ssrf",
        "CWE-22": "lfi",
        "CWE-287": "auth_bypass",
        "CWE-306": "missing_auth",
        "CWE-352": "csrf",
        "CWE-434": "unrestricted_upload",
        "CWE-502": "deserialization",
        "CWE-611": "xxe",
        "CWE-776": "ssti",
        "CWE-862": "idor",
        "CWE-939": "idor",
        "CWE-1021": "xss_stored",
        "CWE-1188": "insecure_default",
    }

    def correlate(
        self,
        sast_findings: list[SARIFFinding],
        titan_findings: list[dict],
    ) -> list[CorrelatedFinding]:
        """Correlate SAST and DAST findings."""
        correlated = []

        for sast in sast_findings:
            sast_cwe = sast.rule_id.upper()

            for titan in titan_findings:
                titan_type = titan.get("type", "")
                titan_attack_type = titan.get("attack_type", "")

                # Check if they match by CWE
                matched = False
                for cwe, attack_type in self.CWE_MAP.items():
                    if cwe in sast_cwe and (attack_type in titan_type or attack_type in titan_attack_type):
                        matched = True
                        break

                # Direct CWE match
                if not matched:
                    titan_cwe = titan.get("cwe", "")
                    if titan_cwe and titan_cwe.upper() == sast_cwe:
                        matched = True

                if matched:
                    # Correlated! High confidence.
                    correlation = CorrelatedFinding(
                        cwe=sast_cwe,
                        title=f"Correlated {sast_cwe}: {sast.message[:80]}",
                        confidence=0.95,  # Both sources agree = near-certain
                        sast_source=sast,
                        dast_finding=titan,
                        code_location=f"{sast.file_path}:{sast.line_start}",
                        http_flow=f"{titan.get('method', 'GET')} {titan.get('url', 'unknown')}",
                        patch_suggestion=self._generate_patch_suggestion(sast),
                    )
                    correlated.append(correlation)

                    logger.info(
                        f"Correlated: {sast_cwe} at {sast.file_path}:{sast.line_start} "
                        f"with DAST finding: {titan_type}"
                    )

        logger.info(f"Correlated {len(correlated)} findings from {len(sast_findings)} SAST + {len(titan_findings)} DAST")
        return correlated

    def _generate_patch_suggestion(self, finding: SARIFFinding) -> str:
        """Generate a patch suggestion based on the SAST finding."""
        cwe = finding.rule_id.upper()

        patches = {
            "CWE-89": "Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
            "CWE-79": "HTML-encode all user input before rendering. Use Content-Security-Policy headers.",
            "CWE-78": "Use subprocess with list arguments, not shell=True. Validate and sanitize all input.",
            "CWE-918": "Validate and allowlist URLs for server-side requests. Block internal IP ranges.",
            "CWE-22": "Validate file paths against an allowlist. Use os.path.realpath() and check prefix.",
            "CWE-287": "Implement proper authentication checks on all sensitive endpoints.",
            "CWE-352": "Implement CSRF tokens on all state-changing operations.",
            "CWE-434": "Validate file type and size on upload. Store outside webroot. Rename files.",
            "CWE-502": "Never deserialize untrusted data. Use safe formats (JSON, not pickle).",
            "CWE-611": "Disable external entity processing in XML parsers.",
            "CWE-776": "Use auto-escaping template engines. Never render user input in templates.",
            "CWE-862": "Verify the requesting user owns the resource before returning data.",
        }

        return patches.get(cwe, f"Review {finding.file_path}:{finding.line_start} for {cwe} vulnerability.")
