"""Interactsh OOB integration for Titan Scanner."""


from __future__ import annotations

import random
import string
from typing import Any

from titan.core.logger import get_logger

logger = get_logger("interactsh")



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
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass
        return False

    async def poll(self, timeout: int = 30) -> list[dict[str, Any]]:
        if not self._registered:
            await self.register()
        results: list[dict[str, Any]] = []
        try:
            import aiohttp
            url = f"{self.server}/poll?id={self.correlation_id}&format=json"
            async with aiohttp.ClientSession() as session, session.get(url, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results = data.get("data", {}).get("interactions", [])
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
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
