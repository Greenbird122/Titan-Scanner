"""Route scorer: rank URLs by attack value for priority scanning.

High-value routes (auth, upload, API, IDOR-prone) get scanned first.
Low-value routes (static assets, favicon, robots.txt) get deprioritized
or skip expensive modules entirely.

Score scale: 0 (skip) → 10 (critical priority)
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


# ── Pattern banks ──────────────────────────────────────────────────────

# Paths that almost always contain vulnerabilities (score boost)
_HIGH_VALUE_PATHS = re.compile(
    r"/(login|signin|signup|register|auth|oauth|callback|"
    r"upload|import|export|download|file|attachment|"
    r"admin|dashboard|panel|manage|settings|config|"
    r"api|graphql|rest|webhook|callback|"
    r"search|query|filter|sort|"
    r"password|reset|forgot|otp|verify|"
    r"token|session|jwt|cookie|"
    r"profile|user|account|member|"
    r"payment|checkout|cart|order|subscribe|"
    r"comment|review|post|message|chat|"
    r"redirect|url|link|goto|forward|"
    r"preview|render|embed|iframe|"
    r"exec|run|eval|system|command|shell|"
    r"db|database|sql|query|mongo|redis|"
    r"internal|meta|debug|trace|status|health|"
    r"swagger|openapi|docs|spec)",
    re.IGNORECASE,
)

# Paths that are almost never interesting (score penalty)
_LOW_VALUE_PATHS = re.compile(
    r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$|"
    r"/(favicon|robots|sitemap|humans|security|well-known|"
    r"manifest|service-worker|sw\.js|workbox|"
    r"assets|static|media|images|fonts|vendor|node_modules)/|"
    r"^/(apple-touch|browserconfig|tile)",
    re.IGNORECASE,
)

# Parameters that indicate attack surface
_HIGH_VALUE_PARAMS = re.compile(
    r"(id|user|token|key|secret|password|email|phone|"
    r"file|path|url|redirect|callback|next|return|"
    r"admin|role|type|action|method|query|search|"
    r"page|limit|offset|sort|order|format|type)",
    re.IGNORECASE,
)

# HTTP methods that change state
_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def score_url(
    url: str,
    forms: Optional[List[Dict[str, Any]]] = None,
    params: Optional[List[str]] = None,
    method: str = "GET",
    depth: int = 0,
    technologies: Optional[List[str]] = None,
) -> int:
    """Score a URL by its attack value (0-10).

    Higher scores mean the route is more likely to contain vulnerabilities
    and should be scanned with the full module matrix. Lower scores mean
    expensive modules (sqli, ssti, prototype) can be skipped.

    Scoring factors:
    - Path patterns (auth, upload, API endpoints = high value)
    - HTTP method (POST/PUT/DELETE = state-changing = higher value)
    - Form presence (forms = user input = attack surface)
    - Parameter names (id, token, file = high-value params)
    - Technology stack (React/Next.js = more client-side risk)
    - Crawl depth (deeper = less likely to be primary attack surface)
    """
    score = 5  # baseline: every route deserves a look

    parsed = urlparse(url)
    path = parsed.path.lower()
    query = parsed.query.lower()

    # ── Path pattern matching ──────────────────────────────────────
    if _HIGH_VALUE_PATHS.search(path):
        score += 3
    if _LOW_VALUE_PATHS.search(path):
        score -= 4

    # ── HTTP method ────────────────────────────────────────────────
    if method.upper() in _STATE_CHANGING_METHODS:
        score += 2

    # ── Forms present ──────────────────────────────────────────────
    if forms:
        score += min(len(forms), 3)  # +1 per form, cap at +3
        # Forms with file inputs are extra interesting (upload = RCE path)
        for form in forms:
            inputs = form.get("inputs", [])
            for inp in inputs:
                if inp.get("type", "").lower() == "file":
                    score += 2
                    break

    # ── Query parameters ──────────────────────────────────────────
    if query:
        param_names = [p.split("=")[0] for p in query.split("&") if "=" in p]
        high_params = sum(1 for p in param_names if _HIGH_VALUE_PARAMS.search(p))
        score += min(high_params, 3)

    # ── Explicit param list ────────────────────────────────────────
    if params:
        high_params = sum(1 for p in params if _HIGH_VALUE_PARAMS.search(p))
        score += min(high_params, 2)

    # ── Technology signals ─────────────────────────────────────────
    if technologies:
        tech_lower = {t.lower() for t in technologies}
        # SPA frameworks = more client-side attack surface
        if tech_lower & {"react", "vue", "angular", "next.js", "nuxt"}:
            score += 1
        # Firebase/Supabase = direct DB access risk
        if tech_lower & {"firebase", "supabase", "firestore"}:
            score += 2
        # GraphQL = injection surface
        if "graphql" in tech_lower:
            score += 1

    # ── Depth penalty ──────────────────────────────────────────────
    # Deeper pages are less likely to be primary attack surface
    if depth > 2:
        score -= 1
    if depth > 4:
        score -= 1

    # ── API URL bonus ──────────────────────────────────────────────
    api_indicators = ["/api/", "/v1/", "/v2/", "/rest/", "/graphql", "api."]
    if any(ind in path for ind in api_indicators):
        score += 2

    # ── Clamp to 0-10 ─────────────────────────────────────────────
    return max(0, min(10, score))


def should_run_expensive_modules(score: int) -> bool:
    """True if the route's score justifies running expensive modules.

    Expensive modules: sqli, ssti, prototype pollution, mass-assignment,
    path traversal, command injection. These add 5-15s per invocation.

    Routes scoring < 3 get only the cheap modules (headers, info-leak,
    CSP, redirect). Routes scoring >= 3 get the full matrix.
    """
    return score >= 3


def sort_queue(queue: List[tuple], technologies: Optional[List[str]] = None) -> List[tuple]:
    """Sort a crawl queue by attack-value score (highest first).

    Args:
        queue: List of (url, depth) tuples
        technologies: Optional technology list from fingerprint

    Returns:
        New list sorted by score (highest first), preserving original tuples.
    """
    scored = []
    for url, depth in queue:
        s = score_url(url, depth=depth, technologies=technologies)
        scored.append((s, url, depth))
    # Sort by score descending, then by depth ascending (shallower first on tie)
    scored.sort(key=lambda x: (-x[0], x[2]))
    return [(url, depth) for _, url, depth in scored]
