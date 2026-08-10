"""DeepSeek integration for Titan Scanner."""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, Optional


class DeepSeekClient:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._client = None
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

    async def generate(self, prompt: str) -> str:
        if not self._client:
            return ""
        try:
            if hasattr(self._client, "chat_completion"):
                session = self._client.create_chat_session()
                chunks = list(self._client.chat_completion(session, prompt))
                return "".join(c.get("content", "") for c in chunks if c.get("type") == "text")
            elif hasattr(self._client, "generate"):
                return await self._client.generate(prompt)
        except Exception:
            pass
        return ""

    def generate_sync(self, prompt: str) -> str:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                return ""
            return loop.run_until_complete(self.generate(prompt))
        except RuntimeError:
            return ""
