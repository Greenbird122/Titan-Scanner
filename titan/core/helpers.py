"""Utility helpers extracted from the core engine.

Pure functions and small helpers that have no engine state dependencies.
Keeps the engine focused on orchestration.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import urlparse, urlunparse

from titan.core.constants import SOFT_404_MARKERS


# ---------------------------------------------------------------------------
# Async task helpers
# ---------------------------------------------------------------------------

def consume_task_exception(task: asyncio.Task) -> None:
    """Done-callback that swallows a task's exception so an abandoned task
    never logs an orphaned "Future exception was never retrieved" warning.

    NOTE: must catch BaseException, not Exception. Since Python 3.8
    asyncio.CancelledError is a BaseException, and ``task.exception()``
    on a cancelled task re-raises the CancelledError itself.
    """
    try:
        task.exception()
    except BaseException:
        pass


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """Strip query string and fragment for deduplication purposes.

    The same endpoint reached via a crawled link (?id=1) and via API
    discovery (?id=1&q=test&search=test...) would otherwise dedupe
    into two identical findings.
    """
    parsed = urlparse(url)
    normalized = urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", "")
    )
    return normalized.split("#")[0]


def is_soft_404(body: str) -> bool:
    """Detect an HTML not-found page served with a 200 status.

    Structured responses (JSON/XML/plain text) are real API answers,
    not HTML 404 pages.
    """
    if not body:
        return False
    head = body[:4000].lower()
    if "<html" not in head and not head.startswith("<!doctype"):
        return False
    if len(body) < 100_000 and any(m in head for m in SOFT_404_MARKERS):
        return True
    # Branded 404 pages (GitHub, large SaaS) exceed the size cap while
    # still being pure not-found shells — but their <title> says so.
    m = re.search(r"<title[^>]*>(.*?)</title>", head, re.DOTALL)
    if m:
        title = m.group(1).lower()
        if "404" in title or any(mk in title for mk in SOFT_404_MARKERS):
            return True
    return False


# ---------------------------------------------------------------------------
# Finding deduplication
# ---------------------------------------------------------------------------

def dedupe_findings(findings: list, root_cause_types: frozenset[str]) -> list:
    """Deduplicate findings by (normalized_url, param, attack_type).

    A second pass collapses root-cause findings: identical
    (attack_type, payload, verified) across DIFFERENT endpoints
    collapse to ONE representative finding. Other URLs are preserved
    in metadata["affected_urls"].
    """
    from titan.core.models import Finding  # local to avoid circular

    seen: set[tuple] = set()
    deduped: list[Finding] = []

    # Content-scan collapse: site-wide identical payloads
    site_wide: set[tuple] = set()
    for f in findings:
        norm_url = normalize_url(f.url)
        key = (norm_url, f.param, f.attack_type.value)
        if f.param == "body" or f.location == "header":
            sig = (f.attack_type.value, f.payload, f.severity.value)
            if sig in site_wide:
                continue
            site_wide.add(sig)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Root-cause pass
    root: dict[tuple, Finding] = {}
    out: list[Finding] = []
    for f in deduped:
        if (
            f.attack_type is not None
            and f.attack_type.value in root_cause_types
            and f.payload
        ):
            key = (f.attack_type.value, f.payload, f.verified)
            if key in root:
                rep = root[key]
                urls = rep.metadata.setdefault("affected_urls", [rep.url])
                if f.url not in urls:
                    urls.append(f.url)
                rep.metadata["merged_count"] = len(urls)
                if f.confidence > rep.confidence:
                    rep.confidence = f.confidence
                    rep.url = f.url
                    rep.param = f.param
                continue
            root[key] = f
        out.append(f)
    return out


def dedupe_apis(apis: list[str]) -> list[str]:
    """Deduplicate API URLs by path (ignoring query strings)."""
    seen: set[str] = set()
    deduped: list[str] = []
    for api in apis:
        key = api.split("?")[0]
        if key not in seen:
            seen.add(key)
            deduped.append(api)
    return deduped


# ---------------------------------------------------------------------------
# JSON URL extraction
# ---------------------------------------------------------------------------

def extract_urls_from_json(json_text: str, is_in_scope: Any) -> list[str]:
    """Parse a JSON response body and extract in-scope URLs."""
    urls: list[str] = []
    try:
        data = json.loads(json_text)
        urls.extend(_scan_json_for_urls(data, is_in_scope))
    except Exception:
        pass
    return urls


def _scan_json_for_urls(obj: Any, is_in_scope: Any) -> list[str]:
    """Recursively scan a JSON object for URL-like values."""
    urls: list[str] = []
    if isinstance(obj, dict):
        for key in ("url", "href", "link", "path", "endpoint", "api",
                     "next", "previous"):
            val = obj.get(key)
            if isinstance(val, str) and val.startswith("http") and is_in_scope(val):
                urls.append(val)
            elif isinstance(val, dict) and "url" in val:
                urls.extend(_scan_json_for_urls(val, is_in_scope))
        for val in obj.values():
            urls.extend(_scan_json_for_urls(val, is_in_scope))
    elif isinstance(obj, list):
        for item in obj:
            urls.extend(_scan_json_for_urls(item, is_in_scope))
    return urls
