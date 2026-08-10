"""AI-powered payload mutation using DeepSeek."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from titan.ai.payloadforge import PayloadForge


class PayloadSmith:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._client = None
        self.forge = PayloadForge()
        self._init_client()

    def _init_client(self):
        if not self.config.get("enabled", True):
            return
        try:
            parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if parent not in sys.path:
                sys.path.insert(0, parent)
            from dsk.api import create_api
            model = self.config.get("model", "deepseek-chat")
            fallback = self.config.get("fallback", "ollama")
            self._client = create_api(default_model=f"deepseek/{model}", fallback_model=f"ollama/{fallback}" if fallback else "")
        except Exception:
            try:
                from provider import DeepSeekProvider
                self._client = DeepSeekProvider()
            except Exception:
                self._client = None

    async def _provider_available(self) -> bool:
        """Fail-fast probe so an unreachable LLM can't stall the scan.

        Every detector awaits mutate() before sending a single request; when no
        provider is configured and Ollama is down, each call burns the full
        15s wait_for timeout — multiplying into minutes of dead time across
        modules and endpoints. Probe the actual endpoint (1s) and bail out
        immediately if it's not reachable.
        """
        client = self._client
        if client is None:
            return False
        # DeepSeekProvider: direct API when a key exists, otherwise Ollama.
        api_key = getattr(client, "api_key", None)
        if api_key:
            return True
        ollama_host = getattr(client, "ollama_host", None)
        if ollama_host:
            parsed = urlparse(ollama_host)
            host = parsed.hostname or "localhost"
            port = parsed.port or 11434
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=1.0
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return True
            except Exception:
                return False
        # Unknown client shape (e.g. dsk create_api): assume it works; the
        # per-call timeout still bounds it.
        return True

    async def _call_chat(self, session, prompt: str) -> List[Dict[str, Any]]:
        # chat_completion is synchronous/streaming — run it in a thread so
        # asyncio.wait_for can actually interrupt a slow provider.
        return await asyncio.to_thread(
            lambda: list(self._client.chat_completion(session, prompt))
        )

    async def mutate(self, base_payloads: List[str], context: Dict[str, Any]) -> List[str]:
        if not self._client:
            return base_payloads
        if not await self._provider_available():
            return base_payloads

        fingerprint = context.get("fingerprint", {})
        attack_type = context.get("attack_type", "generic")
        param_type = context.get("param_type", "text")
        location = context.get("location", "query")
        previous_responses = context.get("previous_responses", [])

        prompt = self._build_mutation_prompt(
            base_payloads, fingerprint, attack_type, param_type, location, previous_responses
        )

        try:
            if hasattr(self._client, "chat_completion"):
                session = self._client.create_chat_session()
                chunks = await asyncio.wait_for(self._call_chat(session, prompt), timeout=15)
                text = "".join(c.get("content", "") for c in chunks if c.get("type") == "text")
            elif hasattr(self._client, "generate"):
                text = await asyncio.wait_for(self._client.generate(prompt), timeout=15)
            else:
                return base_payloads

            mutated = []
            for line in text.split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("```"):
                    mutated.append(line)
            return mutated[: self.config.get("max_payloads_per_param", 20)]
        except Exception:
            return base_payloads

    def get_base_payloads(self, attack_type: str, context: Dict[str, Any]) -> List[str]:
        return self.forge.get_context_payloads(attack_type, context)

    def get_waf_bypass_payloads(self, base_payloads: List[str], waf: str = "unknown") -> List[str]:
        return self.forge.get_waf_bypass_payloads(base_payloads, waf)

    def get_encoded_payloads(self, payload: str, encoding: str = "all") -> List[str]:
        return self.forge.get_encoded_payloads(payload, encoding)

    def detect_waf(self, headers: Dict[str, str], body: str, status: int) -> Optional[str]:
        return self.forge.detect_waf(headers, body, status)

    def get_polyglot_uploads(self, file_type: str = "all") -> List[Dict[str, Any]]:
        return self.forge.get_polyglot_uploads(file_type)

    def get_oob_callbacks(self, count: int = 5) -> List[str]:
        return self.forge.get_oob_callbacks(count)

    def _build_mutation_prompt(
        self,
        base_payloads: List[str],
        fingerprint: Dict[str, Any],
        attack_type: str,
        param_type: str,
        location: str,
        previous_responses: List[str],
    ) -> str:
        tech_stack = ", ".join(fingerprint.get("technologies", [])[:10]) or "unknown"
        frameworks = ", ".join(fingerprint.get("frameworks", [])[:10]) or "unknown"
        waf = fingerprint.get("waf", "unknown")

        previous_context = ""
        if previous_responses:
            previous_context = "\nPrevious response patterns:\n" + "\n".join(
                f"- {r[:200]}" for r in previous_responses[-3:]
            )

        return f"""You are a payload mutation engine for a penetration testing tool. Your job is to take base payloads and mutate them to bypass WAFs and exploit vulnerabilities with maximum precision.

TARGET CONTEXT:
- Tech stack: {tech_stack}
- Frameworks: {frameworks}
- WAF: {waf}
- Attack type: {attack_type}
- Parameter type: {param_type}
- Injection location: {location}

BASE PAYLOADS:
{chr(10).join(f"- {p}" for p in base_payloads[:10])}
{previous_context}

RULES:
1. Mutate each payload to bypass common WAF rules (case changes, encoding, comments, whitespace, null bytes)
2. Maintain exploit effectiveness - the mutated payload must still work
3. Use framework-specific techniques (e.g., Laravel Blade, Twig, Jinja2 for SSTI)
4. Adapt to detected tech stack (e.g., PHP-specific tricks for PHP targets)
5. Include both simple and complex mutations
6. Return ONLY the mutated payloads, one per line
7. NO explanations, NO numbering, NO markdown
8. Maximum 20 payloads

MUTATED PAYLOADS:"""

    async def generate_exploit_chain(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not self._client or not findings:
            return []

        findings_summary = "\n".join(
            f"- {f.get('attack_type', 'unknown')} at {f.get('url', 'unknown')} param={f.get('param', 'unknown')}"
            for f in findings[:10]
        )

        prompt = f"""You are an exploit chain analyst. Given these findings, identify potential exploit chains that combine multiple vulnerabilities for greater impact.

FINDINGS:
{findings_summary}

RULES:
1. Identify chains where one vulnerability enables another (e.g., XSS + CSRF = account takeover)
2. Consider privilege escalation paths
3. Consider data exfiltration chains
4. Consider authentication bypass chains
5. Return JSON array of chains, each with: "name", "description", "findings" (array of param/url), "impact"
6. NO explanations outside JSON

CHAINS:"""

        try:
            if hasattr(self._client, "chat_completion"):
                session = self._client.create_chat_session()
                chunks = await asyncio.to_thread(
                    lambda: list(self._client.chat_completion(session, prompt))
                )
                text = "".join(c.get("content", "") for c in chunks if c.get("type") == "text")
            elif hasattr(self._client, "generate"):
                text = await asyncio.wait_for(self._client.generate(prompt), timeout=15)
            else:
                return []

            import json
            start = text.find("[")
            end = text.rfind("]") + 1
            if start >= 0 and end > start:
                chains = json.loads(text[start:end])
                return chains if isinstance(chains, list) else []
        except Exception:
            pass
        return []
