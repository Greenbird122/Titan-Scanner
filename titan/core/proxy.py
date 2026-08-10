"""Proxy rotation middleware for Titan Scanner."""

from __future__ import annotations

import random
from typing import Any, Dict, List, Optional


class ProxyRotator:
    def __init__(self, proxies: Optional[List[str]] = None, strategy: str = "round-robin"):
        self.proxies = proxies or []
        self.strategy = strategy
        self._current = 0
        self._sticky_map: Dict[str, str] = {}

    def get_proxy(self, target: str = "") -> Optional[str]:
        if not self.proxies:
            return None

        if self.strategy == "random":
            return random.choice(self.proxies)
        elif self.strategy == "sticky":
            if target and target in self._sticky_map:
                return self._sticky_map[target]
            proxy = self.proxies[self._current % len(self.proxies)]
            if target:
                self._sticky_map[target] = proxy
            self._current += 1
            return proxy
        else:
            proxy = self.proxies[self._current % len(self.proxies)]
            self._current += 1
            return proxy

    def rotate(self) -> Optional[str]:
        if not self.proxies:
            return None
        proxy = self.proxies[self._current % len(self.proxies)]
        self._current += 1
        return proxy

    @property
    def count(self) -> int:
        return len(self.proxies)
