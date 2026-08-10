"""Stealth module for Titan Scanner."""

from __future__ import annotations

import asyncio
import random
import time
from typing import List, Optional


class StealthEngine:
    def __init__(
        self,
        jitter: float = 0.3,
        min_delay: float = 0.5,
        max_delay: float = 2.0,
        user_agents: Optional[List[str]] = None,
    ):
        self.jitter = jitter
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.user_agents = user_agents or [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        ]
        self._last_request_time = 0.0

    def get_user_agent(self) -> str:
        return random.choice(self.user_agents)

    def get_headers(self) -> dict:
        headers = {
            "User-Agent": self.get_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "no-cache",
        }
        if random.random() < 0.3:
            headers["DNT"] = "1"
        if random.random() < 0.2:
            headers["X-Forwarded-For"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        return headers

    async def delay(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request_time
        jitter_range = self.max_delay * self.jitter
        target_delay = random.uniform(self.min_delay, self.max_delay)
        jittered_delay = target_delay + random.uniform(-jitter_range, jitter_range)
        jittered_delay = max(0.05, jittered_delay)

        if elapsed < jittered_delay:
            wait_time = jittered_delay - elapsed
            await asyncio.sleep(wait_time)

        self._last_request_time = time.monotonic()
