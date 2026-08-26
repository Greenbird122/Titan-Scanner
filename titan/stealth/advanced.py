"""Anti-Forensics — Evasion and noise injection for stealth scanning.

Provides:
  1. Traffic shaping — normalize timing patterns to blend with normal traffic
  2. Polymorphic payloads — unique variants each time, avoid signature detection
  3. Decoy traffic — inject noise to confuse IDS/IPS
  4. Timing normalization — distribute requests to avoid burst detection
  5. Header fingerprint randomization — rotate TLS fingerprints, UA chains

This is the difference between "scanner" and "operator-grade tool."

Usage:
    from titan.stealth.advanced import AntiForensics

    af = AntiForensics()

    # Shape a request timeline
    timeline = af.shape_timeline(requests, baseline="browser")

    # Generate polymorphic payload
    payload = af.polymorphic("alert(1)", variant="xss")

    # Generate decoy requests
    decoys = af.generate_decoys(target_url, count=5)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse, urlencode, parse_qs

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Traffic shaping — normalize timing patterns
# ---------------------------------------------------------------------------

@dataclass
class TimingProfile:
    """A timing profile that mimics real browser behavior."""
    name: str
    base_delay: float        # Base delay between requests (seconds)
    jitter: float            # Jitter fraction (0-1)
    burst_prob: float        # Probability of burst (rapid requests)
    burst_size: int          # Number of requests in a burst
    burst_delay: float       # Delay within burst
    idle_prob: float         # Probability of idle period
    idle_duration: tuple[float, float] = (2.0, 10.0)  # Min/max idle


# Pre-defined timing profiles
BROWSER_PROFILE = TimingProfile(
    name="browser",
    base_delay=1.5,
    jitter=0.4,
    burst_prob=0.2,
    burst_size=3,
    burst_delay=0.3,
    idle_prob=0.1,
    idle_duration=(3.0, 15.0),
)

STEALTH_PROFILE = TimingProfile(
    name="stealth",
    base_delay=3.0,
    jitter=0.6,
    burst_prob=0.05,
    burst_size=2,
    burst_delay=1.0,
    idle_prob=0.2,
    idle_duration=(5.0, 30.0),
)

AGGRESSIVE_PROFILE = TimingProfile(
    name="aggressive",
    base_delay=0.5,
    jitter=0.2,
    burst_prob=0.3,
    burst_size=5,
    burst_delay=0.1,
    idle_prob=0.05,
    idle_duration=(1.0, 5.0),
)


class TrafficShaper:
    """Normalize timing patterns to blend with real traffic."""

    PROFILES = {
        "browser": BROWSER_PROFILE,
        "stealth": STEALTH_PROFILE,
        "aggressive": AGGRESSIVE_PROFILE,
    }

    def __init__(self, profile: str = "browser"):
        self.profile = self.PROFILES.get(profile, BROWSER_PROFILE)

    def shape_timeline(
        self,
        request_count: int,
        start_time: float | None = None,
    ) -> list[float]:
        """Generate a shaped timeline of request timestamps.

        Returns a list of timestamps (seconds from start) when each
        request should be sent to blend with real browser traffic.
        """
        if start_time is None:
            start_time = time.time()

        timeline = []
        current_time = 0.0
        p = self.profile

        for i in range(request_count):
            # Check for idle period
            if random.random() < p.idle_prob:
                idle = random.uniform(*p.idle_duration)
                current_time += idle

            # Check for burst
            if random.random() < p.burst_prob:
                burst_count = min(p.burst_size, request_count - i)
                for j in range(burst_count):
                    current_time += p.burst_delay * (1 + random.gauss(0, 0.1))
                    timeline.append(current_time)
                    i += 1
                    if i >= request_count:
                        break
                continue

            # Normal request with jitter
            delay = p.base_delay * (1 + random.gauss(0, p.jitter))
            delay = max(0.1, delay)  # Floor at 100ms
            current_time += delay
            timeline.append(current_time)

        return sorted(timeline[:request_count])

    def calculate_delays(
        self,
        request_count: int,
        budget: float = 300.0,
    ) -> list[float]:
        """Calculate delays between requests to fit within a budget.

        Returns a list of delays (seconds) between consecutive requests.
        """
        timeline = self.shape_timeline(request_count)

        if not timeline:
            return []

        # Scale to fit budget
        total = timeline[-1]
        if total > budget:
            scale = budget / total
            timeline = [t * scale for t in timeline]

        delays = [timeline[0]]
        for i in range(1, len(timeline)):
            delays.append(timeline[i] - timeline[i - 1])

        return delays


# ---------------------------------------------------------------------------
# Polymorphic payloads — unique variants each time
# ---------------------------------------------------------------------------

class PolymorphicEngine:
    """Generate unique payload variants to avoid signature detection.

    Each call produces a different encoding/variation of the same payload,
    making it harder for WAFs and IDS to signature-match.
    """

    # Encoding strategies
    ENCODINGS = [
        "url_encode",
        "double_url_encode",
        "html_entity",
        "hex_encode",
        "octal_encode",
        "unicode_escape",
        "base64",
        "mixed_case",
        "whitespace_injection",
        "comment_injection",
    ]

    def generate(
        self,
        base_payload: str,
        variant: str = "auto",
        count: int = 1,
        encoding: str | None = None,
    ) -> list[str]:
        """Generate polymorphic variants of a base payload.

        Args:
            base_payload: The original payload string.
            variant: "xss", "sqli", "ssrf", or "auto" (detect from payload).
            count: Number of variants to generate.
            encoding: Force a specific encoding (None = random).

        Returns:
            List of unique encoded variants.
        """
        if variant == "auto":
            variant = self._detect_variant(base_payload)

        variants = []
        seen = set()

        for _ in range(count * 3):  # Generate extra to ensure uniqueness
            if len(variants) >= count:
                break

            # Choose encoding
            enc = encoding or random.choice(self.ENCODINGS)

            # Apply encoding
            encoded = self._encode(base_payload, enc, variant)

            # Apply variant-specific transformations
            if variant == "xss":
                encoded = self._xss_transform(encoded)
            elif variant == "sqli":
                encoded = self._sqli_transform(encoded)
            elif variant == "ssrf":
                encoded = self._ssrf_transform(encoded)

            # Ensure uniqueness
            if encoded not in seen:
                seen.add(encoded)
                variants.append(encoded)

        return variants

    def _detect_variant(self, payload: str) -> str:
        """Auto-detect payload type."""
        lower = payload.lower()
        if any(x in lower for x in ["<script", "alert(", "onerror", "onload", "javascript:"]):
            return "xss"
        if any(x in lower for x in ["select ", "union ", "or 1=1", "'", "drop ", "insert "]):
            return "sqli"
        if any(x in lower for x in ["http://", "https://", "file://", "gopher://", "169.254"]):
            return "ssrf"
        return "generic"

    def _encode(self, payload: str, encoding: str, variant: str) -> str:
        """Apply encoding to payload."""
        if encoding == "url_encode":
            return "".join(f"%{ord(c):02x}" for c in payload)
        elif encoding == "double_url_encode":
            return "".join(f"%25{ord(c):02x}" for c in payload)
        elif encoding == "html_entity":
            return "".join(f"&#{ord(c)};" for c in payload)
        elif encoding == "hex_encode":
            return "".join(f"\\x{ord(c):02x}" for c in payload)
        elif encoding == "octal_encode":
            return "".join(f"\\{ord(c):03o}" for c in payload)
        elif encoding == "unicode_escape":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        elif encoding == "base64":
            import base64
            return base64.b64encode(payload.encode()).decode()
        elif encoding == "mixed_case":
            return "".join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in payload
            )
        elif encoding == "whitespace_injection":
            words = payload.split(" ")
            return " ".join(
                w + (" " * random.randint(1, 3))
                for w in words
            ).strip()
        elif encoding == "comment_injection":
            if variant == "sqli":
                # SQL comment injection
                parts = payload.split(" ")
                if len(parts) > 1:
                    mid = len(parts) // 2
                    return " ".join(parts[:mid]) + "/**/" + " ".join(parts[mid:])
            return payload
        return payload

    def _xss_transform(self, payload: str) -> str:
        """XSS-specific transformations."""
        transforms = [
            lambda p: p.replace("<", "<"),
            lambda p: p.replace(">", ">"),
            lambda p: p.replace("alert", "al" + chr(101) + "rt"),
            lambda p: p.replace("script", "scr" + chr(105) + "pt"),
            lambda p: p.replace('"', "&quot;"),
            lambda p: p.replace("'", "&#x27;"),
        ]
        return random.choice(transforms)(payload)

    def _sqli_transform(self, payload: str) -> str:
        """SQLi-specific transformations."""
        transforms = [
            lambda p: p.replace(" ", "/**/"),
            lambda p: p.replace("OR", "oR"),
            lambda p: p.replace("=", " LIKE "),
            lambda p: p.replace("'", "''"),
            lambda p: p.replace("--", "#"),
        ]
        return random.choice(transforms)(payload)

    def _ssrf_transform(self, payload: str) -> str:
        """SSRF-specific transformations."""
        transforms = [
            lambda p: p.replace("http://", "HtTp://"),
            lambda p: p.replace(".", "."),
            lambda p: p.replace("127.0.0.1", "127.1"),
            lambda p: p.replace("169.254.169.254", "169.254.169.254.nip.io"),
            lambda p: p.replace("@", "%40"),
        ]
        return random.choice(transforms)(payload)


# ---------------------------------------------------------------------------
# Decoy traffic — inject noise to confuse IDS
# ---------------------------------------------------------------------------

class DecoyGenerator:
    """Generate decoy HTTP requests to inject noise.

    Decoys look like real traffic but carry no attack payloads.
    They increase the signal-to-noise ratio for any IDS monitoring
    the scanner's traffic.
    """

    # Common paths that look like normal browsing
    DECOY_PATHS = [
        "/", "/index.html", "/favicon.ico", "/robots.txt",
        "/sitemap.xml", "/manifest.json", "/.well-known/",
        "/assets/", "/static/", "/images/", "/css/", "/js/",
        "/api/health", "/api/status", "/api/version",
        "/login", "/register", "/about", "/contact", "/help",
        "/privacy", "/terms", "/sitemap", "/feed",
    ]

    # Realistic User-Agents
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    ]

    def generate(
        self,
        target_url: str,
        count: int = 5,
        session: Any = None,
    ) -> list[dict]:
        """Generate decoy request specs.

        Returns a list of dicts with url, method, headers — ready to send.
        """
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        decoys = []
        paths = random.sample(self.DECOY_PATHS, min(count, len(self.DECOY_PATHS)))

        for path in paths:
            url = base + path
            ua = random.choice(self.USER_AGENTS)
            decoys.append({
                "url": url,
                "method": "GET",
                "headers": {
                    "User-Agent": ua,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                    "Cache-Control": "no-cache",
                },
                "description": f"Decoy: {path}",
            })

        return decoys

    async def inject(
        self,
        target_url: str,
        transport: Any,
        count: int = 3,
        delay_range: tuple[float, float] = (0.5, 3.0),
    ) -> int:
        """Inject decoy traffic through a transport.

        Returns the number of successful decoy requests.
        """
        from titan.transport import AttackRequest, RequestMethod

        decoys = self.generate(target_url, count=count)
        sent = 0

        for decoy in decoys:
            try:
                delay = random.uniform(*delay_range)
                await asyncio.sleep(delay)

                await transport.send(AttackRequest(
                    url=decoy["url"],
                    method=RequestMethod.GET,
                    headers=decoy["headers"],
                    timeout=10.0,
                ))
                sent += 1
            except Exception:
                continue

        return sent


# ---------------------------------------------------------------------------
# Header fingerprint randomization
# ---------------------------------------------------------------------------

class FingerprintRandomizer:
    """Randomize TLS and HTTP fingerprints to avoid detection."""

    # Common TLS fingerprints (JA3 hashes)
    JA3_FINGERPRINTS = [
        "771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
        "771,4865-4866-4867-49195-49199-49196-49200,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
        "771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13-51-45-43-27-21,29-23-24,0",
    ]

    # HTTP/2 fingerprint orders
    H2_ORDERS = [
        ["method", "authority", "scheme", "path"],
        [":method", ":authority", ":scheme", ":path"],
    ]

    def randomize_headers(self, base_headers: dict | None = None) -> dict[str, str]:
        """Generate randomized HTTP headers that look like a real browser."""
        headers = dict(base_headers or {})

        # User-Agent rotation
        headers["User-Agent"] = random.choice(DecoyGenerator.USER_AGENTS)

        # Accept header variation
        accepts = [
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ]
        headers["Accept"] = random.choice(accepts)

        # Accept-Language variation
        languages = [
            "en-US,en;q=0.9",
            "en-US,en;q=0.9,es;q=0.8",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.9,fr;q=0.8",
        ]
        headers["Accept-Language"] = random.choice(languages)

        # Add random but realistic headers
        optional_headers = {
            "Sec-Fetch-Dest": ["document", "empty", "script"],
            "Sec-Fetch-Mode": ["navigate", "cors", "no-cors"],
            "Sec-Fetch-Site": ["none", "cross-site", "same-origin"],
            "Sec-Fetch-User": ["?1"],
            "Upgrade-Insecure-Requests": ["1"],
            "DNT": ["1"],
            "Sec-CH-UA": ['"Chromium";v="125", "Google Chrome";v="125"'],
            "Sec-CH-UA-Mobile": ["?0"],
            "Sec-CH-UA-Platform": ['"Windows"', '"macOS"', '"Linux"'],
        }

        # Randomly include optional headers (50% chance each)
        for header, values in optional_headers.items():
            if random.random() > 0.5:
                headers[header] = random.choice(values)

        return headers


# ---------------------------------------------------------------------------
# Main anti-forensics coordinator
# ---------------------------------------------------------------------------

class AntiForensics:
    """Unified anti-forensics interface.

    Coordinates traffic shaping, polymorphic payloads, decoy traffic,
    and fingerprint randomization into a cohesive evasion strategy.
    """

    def __init__(
        self,
        profile: str = "browser",
        decoy_count: int = 3,
        polymorphic_count: int = 3,
    ):
        self.shaper = TrafficShaper(profile)
        self.polymorphic = PolymorphicEngine()
        self.decoys = DecoyGenerator()
        self.fingerprint = FingerprintRandomizer()
        self.decoy_count = decoy_count
        self.polymorphic_count = polymorphic_count

    def prepare_attack(
        self,
        payload: str,
        target_url: str,
        variant: str = "auto",
    ) -> dict:
        """Prepare a full attack with anti-forensics.

        Returns a dict with:
          - polymorphic_payloads: list of unique encoded variants
          - decoy_requests: list of decoy request specs
          - timing: shaped delay timeline
          - headers: randomized headers
        """
        # Generate polymorphic payloads
        payloads = self.polymorphic.generate(
            payload, variant=variant, count=self.polymorphic_count,
        )

        # Generate decoys
        decoy_specs = self.decoys.generate(target_url, count=self.decoy_count)

        # Generate timing
        total_requests = len(payloads) + len(decoy_specs)
        timeline = self.shaper.shape_timeline(total_requests)

        # Generate randomized headers
        headers = self.fingerprint.randomize_headers()

        return {
            "polymorphic_payloads": payloads,
            "decoy_requests": decoy_specs,
            "timing": timeline,
            "headers": headers,
            "stats": {
                "payload_variants": len(payloads),
                "decoy_count": len(decoy_specs),
                "total_requests": total_requests,
                "estimated_duration": timeline[-1] if timeline else 0,
            },
        }
