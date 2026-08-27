"""Cross-data inference engine.

Combines findings from different modules / tracks into higher-confidence
inferences.  A single module finding is evidence; two independent findings
that share a data path or capability are a *chain* with a specific impact.

This is the layer that turns:
  finding A: SSRF on /proxy?url=...
  finding B: AWS IMDS endpoint 169.254.169.254 reachable through A
into:
  inference: Cloud credential exposure via SSRF-to-IMDS

The inference engine does NOT run new probes.  It reasons over the
existing finding graph and produces inference records that the report
renders as chained attack paths.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class Inference:
    """A cross-finding inference."""

    inference_type: str
    severity: str
    confidence: float
    source_findings: List[str] = field(default_factory=list)
    description: str = ""
    remediation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class CrossDataInferenceEngine:
    """Reasons over findings to produce chained inferences."""

    def __init__(self) -> None:
        self._rules = self._build_rules()

    def _build_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": "ssrf_to_cloud_imds",
                "name": "SSRF to Cloud IMDS",
                "severity": "critical",
                "confidence": 0.85,
                "require": {"attack_types": {"SSRF"}},
                "co_require": {"attack_types": {"Cloud IMDS Exposure", "OOB"}},
                "description": "SSRF sink can reach cloud instance metadata service. An attacker can steal IAM credentials.",
                "remediation": "Block 169.254.169.254 and metadata endpoints at the proxy/load balancer. Use IMDSv2 with hop-limit.",
            },
            {
                "id": "sqli_to_file_read",
                "name": "SQLi to File Read",
                "severity": "critical",
                "confidence": 0.75,
                "require": {"attack_types": {"SQLi"}},
                "co_require": {"attack_types": {"LFI", "Path Traversal"}},
                "description": "SQL injection can be chained with file-read to extract database credentials or source code.",
                "remediation": "Use parameterized queries. Restrict DB user permissions. Move secrets out of the web root.",
            },
            {
                "id": "xss_to_account_takeover",
                "name": "XSS to Account Takeover",
                "severity": "critical",
                "confidence": 0.7,
                "require": {"attack_types": {"XSS"}},
                "co_require": {"capabilities": {"auth_bypass", "session_fixation"}},
                "description": "Stored XSS in a high-traffic page can capture admin sessions and lead to full account takeover.",
                "remediation": "Implement CSP with script-src 'self'. Sanitize all user-generated content. Use HttpOnly + Secure cookies.",
            },
            {
                "id": "idor_to_data_exposure",
                "name": "IDOR to Mass Data Exposure",
                "severity": "high",
                "confidence": 0.8,
                "require": {"attack_types": {"IDOR", "BOLA"}},
                "co_require": {"attack_types": {"SQLi", "NoSQLi"}},
                "description": "Broken object-level authorization combined with injection can expose entire datasets.",
                "remediation": "Implement per-object authorization checks. Use UUIDs instead of sequential IDs.",
            },
            {
                "id": "deser_to_rce",
                "name": "Deserialization to RCE",
                "severity": "critical",
                "confidence": 0.8,
                "require": {"attack_types": {"Deserialization"}},
                "co_require": {"attack_types": {"RCE"}},
                "description": "Unsafe deserialization can lead to remote code execution when combined with RCE-capable gadget chains.",
                "remediation": "Avoid native deserialization of untrusted data. Use JSON or signed tokens.",
            },
            {
                "id": "ssrf_to_port_scan",
                "name": "SSRF to Internal Port Scan",
                "severity": "high",
                "confidence": 0.7,
                "require": {"attack_types": {"SSRF"}},
                "co_require": {"attack_types": {"Open Redirect", "Redirect"}},
                "description": "SSRF combined with open redirect can be used to scan internal ports and services.",
                "remediation": "Validate and sanitize all URLs in SSRF-prone parameters. Block private IP ranges.",
            },
            {
                "id": "auth_bypass_to_admin",
                "name": "Auth Bypass to Admin Compromise",
                "severity": "critical",
                "confidence": 0.75,
                "require": {"attack_types": {"Auth Bypass", "JWT"}},
                "co_require": {"capabilities": {"admin_access", "role_escalation"}},
                "description": "Authentication bypass can be chained with privilege escalation to gain admin access.",
                "remediation": "Use short-lived JWT with proper signature verification. Enforce MFA for admin accounts.",
            },
            {
                "id": "file_upload_to_rce",
                "name": "File Upload to RCE",
                "severity": "critical",
                "confidence": 0.8,
                "require": {"attack_types": {"Upload"}},
                "co_require": {"attack_types": {"RCE", "Path Traversal"}},
                "description": "Unrestricted file upload can lead to remote code execution when combined with path traversal.",
                "remediation": "Validate file types server-side. Store uploads outside web root. Use random filenames.",
            },
        ]

    def infer(self, findings: List[Any]) -> List[Inference]:
        inferences: List[Inference] = []
        finding_map = {str(getattr(f, "id", "")): f for f in findings}
        finding_types = {str(getattr(f, "id", "")): (getattr(getattr(f, "attack_type", None), "value", "") or "") for f in findings}
        finding_caps = {str(getattr(f, "id", "")): (getattr(f, "capabilities", []) or []) for f in findings}

        for rule in self._rules:
            primary = self._find_matching(findings, rule.get("require", {}), finding_map, finding_types, finding_caps)
            if not primary:
                continue
            secondary = self._find_matching(findings, rule.get("co_require", {}), finding_map, finding_types, finding_caps)
            if not secondary:
                continue
            # Ensure primary and secondary are different findings
            secondary = [s for s in secondary if str(getattr(s, "id", "")) not in {str(getattr(p, "id", "")) for p in primary}]
            if not secondary:
                continue

            source_ids = [str(getattr(f, "id", "")) for f in primary + secondary]
            inferences.append(Inference(
                inference_type=rule["id"],
                severity=rule["severity"],
                confidence=rule["confidence"],
                source_findings=source_ids,
                description=rule["description"],
                remediation=rule["remediation"],
                metadata={
                    "rule": rule["name"],
                    "primary_count": len(primary),
                    "secondary_count": len(secondary),
                },
            ))

        return inferences

    def _find_matching(
        self,
        findings: List[Any],
        criteria: Dict[str, Any],
        finding_map: Dict[str, Any],
        finding_types: Dict[str, str],
        finding_caps: Dict[str, List[str]],
    ) -> List[Any]:
        matched: List[Any] = []
        for f in findings:
            fid = str(getattr(f, "id", ""))
            ftype = finding_types.get(fid, "")
            fcaps = set(finding_caps.get(fid, []) or [])

            if "attack_types" in criteria:
                if not any(t.lower() in ftype.lower() for t in criteria["attack_types"]):
                    continue
            if "capabilities" in criteria:
                if not criteria["capabilities"] & fcaps:
                    continue
            if "min_confidence" in criteria:
                if getattr(f, "confidence", 0) < criteria["min_confidence"]:
                    continue
            if "verified_only" in criteria and criteria["verified_only"]:
                if not getattr(f, "verified", False):
                    continue
            matched.append(f)
        return matched
