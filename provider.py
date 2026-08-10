import os
import json
import asyncio
from typing import Optional
import requests


class ConfigurationError(Exception):
    pass


class DeepSeekProvider:
    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        self.base_url = (base_url or os.getenv("DEEPSEEK_BASE_URL") or "https://api.deepseek.com").rstrip("/")
        self.model = model or os.getenv("DEEPSEEK_MODEL") or "deepseek-chat"
        self.ollama_host = os.getenv("OLLAMA_HOST") or "http://localhost:11434"
        self.ollama_model = os.getenv("OLLAMA_MODEL") or "deepseek-coder:1.3b"

    async def generate(self, prompt: str) -> str:
        if self.api_key:
            return await self._call_deepseek(prompt)
        try:
            return await self._call_ollama(prompt)
        except Exception:
            raise ConfigurationError(
                "No LLM provider configured. Set DEEPSEEK_API_KEY for the official API, "
                "or ensure Ollama is running at OLLAMA_HOST with OLLAMA_MODEL."
            )

    async def _call_deepseek(self, prompt: str) -> str:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1024,
        }
        loop = asyncio.get_event_loop()
        resp = await loop.run_in_executor(None, lambda: requests.post(url, json=payload, headers=headers, timeout=60))
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    async def _call_ollama(self, prompt: str) -> str:
        url = f"{self.ollama_host}/api/chat"
        payload = {
            "model": self.ollama_model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
        loop = asyncio.get_event_loop()
        resp = await loop.run_in_executor(None, lambda: requests.post(url, json=payload, timeout=120))
        resp.raise_for_status()
        data = resp.json()
        return data["message"]["content"]
