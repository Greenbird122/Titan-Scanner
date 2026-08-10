"""Interactsh OOB integration for Titan Scanner."""

from __future__ import annotations

import asyncio
import random
import string
from typing import Any, Dict, List, Optional


class InteractshClient:
    def __init__(self, server: str = "https://interactsh.com"):
        self.server = server.rstrip("/")
        self.correlation_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        self._registered = False

    async def register(self) -> bool:
        try:
            import aiohttp
            url = f"{self.server}/register"
            payload = {"correlation-id": self.correlation_id, "format": "json"}
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=10) as resp:
                    if resp.status == 200:
                        self._registered = True
                        return True
        except Exception:
            pass
        return False

    async def poll(self, timeout: int = 30) -> List[Dict[str, Any]]:
        if not self._registered:
            await self.register()
        results: List[Dict[str, Any]] = []
        try:
            import aiohttp
            url = f"{self.server}/poll?id={self.correlation_id}&format=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=timeout) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        results = data.get("data", {}).get("interactions", [])
        except Exception:
            pass
        return results

    def generate_oob_url(self, suffix: str = "test") -> str:
        return f"http://{self.correlation_id}.{suffix}.{self.server.replace('https://', '').replace('http://', '')}"

    async def deregister(self) -> bool:
        try:
            import aiohttp
            url = f"{self.server}/deregister"
            payload = {"correlation-id": self.correlation_id}
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=10) as resp:
                    return resp.status == 200
        except Exception:
            return False
