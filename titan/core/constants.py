"""Shared constants for Titan Scanner engine.

Centralizes checkpoint indicators, soft-404 markers, driver death markers,
and other sentinel values used across the scan pipeline.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Challenge-wall fingerprints: strong enough to abort a scan on their own,
# regardless of HTTP status — some WAFs serve the wall with 200/202 to
# confuse naive status-based filters.
# ---------------------------------------------------------------------------
STRONG_CHECKPOINT_INDICATORS: list[str] = [
    "just a moment",  # Cloudflare interstitial
    "checking your browser",  # Cloudflare interstitial
    "ray id:",  # Cloudflare error/challenge pages
    "cf-ray",  # Cloudflare body marker
    "cf-mitigated",  # Cloudflare managed challenge
    "cf-chl",  # Cloudflare challenge cookie
    "challenge-platform",  # Cloudflare challenge JS bundle
    "vercel security checkpoint",
]

# Generic wall words: only treated as a checkpoint when paired with a blocking
# status. A 200 page full of "challenge" is a CTF/training site, not a wall.
GENERIC_CHECKPOINT_INDICATORS: list[str] = [
    "cloudflare",
    "captcha",
    "access denied",
    "security check",
    "ddos protection",
    "please verify",
    "challenge",
    "blocked",
    "403 forbidden",
]

# Statuses that indicate the request was intercepted rather than served
# normally. 202 is the anti-bot "accepted for processing" wall.
CHECKPOINT_STATUSES: frozenset[int] = frozenset({401, 403, 405, 429, 503, 202})

# ---------------------------------------------------------------------------
# Body markers that identify a soft-404 page: an HTML "not found" response
# served with HTTP 200. A real API endpoint returns structured data on a
# benign request; an HTML error page with not-found copy is a dead route.
# ---------------------------------------------------------------------------
SOFT_404_MARKERS: tuple[str, ...] = (
    "page not found",
    "was not found",
    "not found on this server",
    "requested url was not found",
    "couldn't find",
    "does not exist",
    "no longer exists",
    "no such file",
    "can't find what you're looking for",  # WordPress default 404 copy
    "error 404",
)

# ---------------------------------------------------------------------------
# Error-message markers that mean the Playwright Node driver itself is dead
# or its connection to Python broke. A driver that dies mid-scan is
# dangerous: pending protocol futures may NEVER resolve AND never raise,
# so a module run wedges instead of failing.
# ---------------------------------------------------------------------------
DRIVER_DEATH_MARKERS: tuple[str, ...] = (
    "connection closed while reading from the driver",
    "connection is closed",
    "target page, context or browser has been closed",
    "browser has been closed",
    "broken pipe",
    "epipe",
    "connection reset by peer",
    "the driver process",
)

# ---------------------------------------------------------------------------
# Attack classes whose identical (attack, payload, verified) findings on
# DIFFERENT endpoints are one root cause — a catch-all route that echoes
# the query string reproduces the same bug on every fuzzed path.
# ---------------------------------------------------------------------------
ROOT_CAUSE_ATTACK_TYPES: frozenset[str] = frozenset(
    {
        "LFI",
        "SQLi",
        "NoSQLi",
        "SSRF",
        "XSS",
        "RCE",
        "SSTI",
        "XXE",
        "Request Smuggling",
        "Open Redirect",
        "OOB",
        "Deserialization",
    }
)
