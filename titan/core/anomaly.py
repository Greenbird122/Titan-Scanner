"""Anomaly detection for the crawl loop.

Detects mid-scan anomalies (500 errors, response drift, new cookies,
redirect changes) and signals the engine to promote the route to the
front of the queue with a boosted score.

Anomalies are NOT findings — they are signals that a route deserves
deeper investigation by the module matrix.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse


# ── Anomaly types ──────────────────────────────────────────────────────

@dataclass
class Anomaly:
    """A detected anomaly on a crawled route."""
    url: str
    kind: str          # "status_500", "body_drift", "new_cookie", "new_header", "redirect_shift"
    detail: str        # human-readable description
    boost: int = 10    # score boost when promoting to front of queue


@dataclass
class AnomalyTracker:
    """Stateful tracker that detects anomalies across pages in a single scan.

    Maintains a baseline of "normal" behaviour (status codes, body hashes,
    cookies, headers) and flags deviations as anomalies.
    """
    # Baseline: status code per hostname (most routes return 200)
    _baseline_status: Dict[str, int] = field(default_factory=dict)
    # All status codes seen per hostname
    _status_history: Dict[str, List[int]] = field(default_factory=dict)
    # Body hashes seen (to detect drift — different body on same path pattern)
    _body_hashes: Set[str] = field(default_factory=set)
    # Cookies seen across all pages
    _known_cookies: Set[str] = field(default_factory=set)
    # Headers seen across all pages
    _known_headers: Set[str] = field(default_factory=set)
    # Redirect targets seen
    _redirect_targets: Set[str] = field(default_factory=set)
    # Detected anomalies for this scan
    anomalies: List[Anomaly] = field(default_factory=list)

    def check(
        self,
        url: str,
        status: int,
        body: str,
        headers: Dict[str, str],
        cookies: Optional[List[str]] = None,
        redirect_target: Optional[str] = None,
    ) -> List[Anomaly]:
        """Check a page response for anomalies. Returns newly detected anomalies.

        Call this ONCE per crawled page, after the response is received.
        """
        detected: List[Anomaly] = []
        hostname = urlparse(url).hostname or ""

        # ── 1. Status 500 / 5xx (server error on this route) ────────
        if status >= 500:
            # Check if other routes on this host return 200
            other_statuses = self._status_history.get(hostname, [])
            has_healthy = any(s < 400 for s in other_statuses)
            if has_healthy or not other_statuses:
                # Either other routes are healthy (this route is broken)
                # or it's the first route (500 is always interesting)
                a = Anomaly(
                    url=url,
                    kind="status_500",
                    detail=f"Server error {status} — other routes on {hostname} return healthy",
                    boost=10,
                )
                detected.append(a)

        # Track status history
        if hostname not in self._status_history:
            self._status_history[hostname] = []
        self._status_history[hostname].append(status)

        # ── 2. Body drift (same host, different content fingerprint) ─
        if body and status == 200:
            # Normalize body: strip timestamps, dynamic tokens, nonces
            normalized = _normalize_body(body)
            body_hash = hashlib.md5(normalized.encode("utf-8", errors="replace")).hexdigest()
            if self._body_hashes and body_hash not in self._body_hashes:
                # First body on this host was seen — this body is DIFFERENT
                # Could be an error page, admin panel, or hidden content
                body_len = len(body)
                if body_len > 500:  # skip trivial redirects/short pages
                    a = Anomaly(
                        url=url,
                        kind="body_drift",
                        detail=f"Response body differs from baseline ({body_len} bytes, hash {body_hash[:8]})",
                        boost=5,
                    )
                    detected.append(a)
            self._body_hashes.add(body_hash)

        # ── 3. New cookies (never seen before in this scan) ──────────
        if cookies:
            new_cookies = [c for c in cookies if c not in self._known_cookies]
            if new_cookies and self._known_cookies:
                a = Anomaly(
                    url=url,
                    kind="new_cookie",
                    detail=f"New cookie(s) set: {', '.join(new_cookies[:5])}",
                    boost=8,
                )
                detected.append(a)
            self._known_cookies.update(new_cookies)

        # ── 4. New interesting headers ───────────────────────────────
        interesting_headers = {
            "x-debug", "x-debug-token", "x-debug-path",
            "x-backend", "x-upstream", "x-real-ip",
            "x-powered-by", "x-aspnet-version", "x-runtime",
            "server", "x-frame-options",
        }
        if headers:
            for h in headers:
                h_lower = h.lower()
                if any(ih in h_lower for ih in interesting_headers):
                    if h_lower not in self._known_headers:
                        a = Anomaly(
                            url=url,
                            kind="new_header",
                            detail=f"New header: {h}: {headers[h][:100]}",
                            boost=4,
                        )
                        detected.append(a)
                        self._known_headers.add(h_lower)

        # ── 5. Redirect chain changes ────────────────────────────────
        if redirect_target and redirect_target not in self._redirect_targets:
            if self._redirect_targets:
                a = Anomaly(
                    url=url,
                    kind="redirect_shift",
                    detail=f"Redirects to {redirect_target} (new target not seen before)",
                    boost=6,
                )
                detected.append(a)
            self._redirect_targets.add(redirect_target)

        # Record all anomalies
        self.anomalies.extend(detected)
        return detected


def _normalize_body(body: str) -> str:
    """Strip dynamic content from a response body to enable comparison.

    Removes: timestamps, CSRF tokens, nonces, session IDs, random strings.
    """
    import re
    # Remove common dynamic tokens
    normalized = re.sub(r'csrf[_-]?token["\s:=]+["\']?[a-zA-Z0-9+/=]{16,}', '', body, flags=re.IGNORECASE)
    normalized = re.sub(r'nonce["\s:=]+["\']?[a-f0-9]{16,}', '', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'session["\s:=]+["\']?[a-zA-Z0-9]{20,}', '', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'__\w+__\s*=\s*["\']?[a-f0-9]{16,}', '', normalized, flags=re.IGNORECASE)
    # Remove timestamps (epoch and ISO)
    normalized = re.sub(r'\b1[67]\d{8,10}\b', 'TIMESTAMP', normalized)
    normalized = re.sub(r'20\d{2}-\d{2}-\d{2}[T ]\d{2}:\d{2}', 'TIMESTAMP', normalized)
    # Remove Vue/React hydration data (large JSON blobs)
    normalized = re.sub(r'__NUXT__\s*=\s*\{[^}]{200,}', '__NUXT__={}', normalized)
    normalized = re.sub(r'__NEXT_DATA__\s*=\s*\{[^}]{200,}', '__NEXT_DATA__={}', normalized)
    return normalized
