"""Conversational channel for LLM/AI endpoints (Track C).

Pure aiohttp — deliberately independent of the Playwright driver so a dead
browser driver can never block AI probing. Talks to the target's chat /
completion endpoints with the message shapes those endpoints expect
(OpenAI-style chat.completions, plain messages, or raw prompt), extracts the
model's text from the common response envelopes, and degrades to "" on any
error (a broken endpoint is a non-finding, never a scan failure).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

DEFAULT_TIMEOUT = 15


class LLMChannel:
    def __init__(self, timeout: float = DEFAULT_TIMEOUT, model: str = "gpt-4o-mini", headers: Optional[Dict[str, str]] = None):
        self.timeout = timeout
        self.model = model
        self.headers = {"Content-Type": "application/json"}
        if headers:
            self.headers.update(headers)
        self.requests: List[Dict[str, Any]] = []  # recorded probes (test hook)

    async def converse(self, endpoint: str, user_text: str, system_text: str = "") -> str:
        """Send one user message (plus optional system context) and return the
        model's raw text reply, or "" on any failure. ``system_text`` lets the
        exfil/indirect-injection probes plant a poisoned context the same way
        a RAG pipeline would receive it."""
        messages: List[Dict[str, str]] = []
        if system_text:
            messages.append({"role": "system", "content": system_text})
        messages.append({"role": "user", "content": user_text})

        self.requests.append({"endpoint": endpoint, "messages": messages})
        text = await self._post_json(endpoint, {"messages": messages}, prefer=endpoint)
        if text:
            return text

        # Fallback shapes: some endpoints want a bare prompt or a system/user
        # split instead of the OpenAI envelope. Only a NON-EMPTY reply stops
        # the fallback ladder — an endpoint that 200s with an empty body on
        # the first shape must get the next shape tried.
        text = await self._post_json(endpoint, {"prompt": user_text}, prefer=endpoint)
        if text:
            return text
        text = await self._post_json(endpoint, {"input": user_text}, prefer=endpoint)
        if text:
            return text
        return ""

    async def _post_json(self, endpoint: str, payload: Dict[str, Any], prefer: str = "") -> Optional[str]:
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(endpoint, json=payload, headers=self.headers, timeout=self.timeout) as resp:
                    if resp.status >= 400:
                        return None
                    raw = await resp.text()
            return self._extract_text(raw)
        except Exception:
            return None

    @staticmethod
    def _extract_text(raw: str) -> str:
        """Pull the model's text out of the common response envelopes."""
        if not raw:
            return ""
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            return (raw or "").strip()
        if not isinstance(data, dict):
            return (raw or "").strip()

        # OpenAI chat.completions: choices[0].message.content / .text
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                msg = first.get("message") or {}
                if isinstance(msg, dict) and msg.get("content"):
                    return str(msg["content"]).strip()
                if first.get("text"):
                    return str(first["text"]).strip()

        # Common flat envelopes.
        for key in ("response", "output", "output_text", "reply", "answer", "completion", "content", "result", "text"):
            val = data.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
            if isinstance(val, list) and val and isinstance(val[0], str):
                return "\n".join(str(v) for v in val).strip()
            if isinstance(val, dict):
                for sub in ("content", "text", "message", "reply"):
                    sv = val.get(sub)
                    if isinstance(sv, str) and sv.strip():
                        return sv.strip()

        # A raw string response.
        for key in ("message", "data"):
            val = data.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        return (raw or "").strip()
