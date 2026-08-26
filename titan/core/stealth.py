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
        # SHARPEN-S1: adaptive mode — when the target's measured latency is
        # low (local lab, fast CDN) the per-module delay is the dominant scan
        # cost (~475 module invocations × 0.15–0.6s = 70–280s of pure sleep).
        # Once we know the target responds fast, delays collapse toward a
        # minimal floor; slow/hostile targets keep the configured stealth.
        self.adaptive = True
        self._base_rtt: Optional[float] = None
        self.user_agents = user_agents or [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        ]
        self._last_request_time = 0.0
        # WARMUP: skip delay for the first N requests so the RTT sampler
        # can measure the target's baseline latency without paying 0.5-2s
        # stealth sleep per module invocation.  Once observe_latency() has
        # enough samples, the adaptive floor kicks in anyway — the warmup
        # just gets us there ~20-40s faster.
        self._warmup_remaining: int = 5
        # WARMUP: skip delay for the first N requests so the RTT sampler
        # can measure the target's baseline latency without paying 0.5-2s
        # stealth sleep per module invocation.  Once observe_latency() has
        # enough samples, the adaptive floor kicks in anyway — the warmup
        # just gets us there ~20-40s faster.
        self._warmup_remaining: int = 5

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

    def observe_latency(self, rtt: float) -> None:
        """Feed a measured request round-trip so adaptive mode can scale
        delays. Fast targets (lab, API-heavy apps) get near-floor delays;
        slow or throttled targets keep the configured stealth range."""
        if rtt is None or rtt < 0:
            return
        self._base_rtt = rtt
        if not self.adaptive:
            return
        # A 100ms-responding target does not need 600ms gaps; a 3s-responding
        # one genuinely needs the stealth range to avoid tripping rate limits.
        if rtt < 0.35:
            self.min_delay = min(self.min_delay, 0.05)
            self.max_delay = min(self.max_delay, 0.18)
        elif rtt < 1.0:
            self.min_delay = min(self.min_delay, 0.10)
            self.max_delay = min(self.max_delay, 0.30)
        # else: keep configured range unchanged.

    async def delay(self) -> None:
        # WARMUP: the first few requests skip the delay entirely so the
        # RTT sampler (observe_latency) collects baseline data fast.
        if self._warmup_remaining > 0:
            self._warmup_remaining -= 1
            self._last_request_time = time.monotonic()
            return

        now = time.monotonic()
        elapsed = now - self._last_request_time
        jitter_range = self.max_delay * self.jitter
        target_delay = random.uniform(self.min_delay, self.max_delay)
        jittered_delay = target_delay + random.uniform(-jitter_range, jitter_range)
        jittered_delay = max(0.02, jittered_delay)

        if elapsed < jittered_delay:
            wait_time = jittered_delay - elapsed
            await asyncio.sleep(wait_time)

        self._last_request_time = time.monotonic()
