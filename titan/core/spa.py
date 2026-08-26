"""PUSH-TO-100 B1 — SPA/JS-rendered harness (pure helpers).

A JS-rendered app (Angular/React/Vue) loads most of its API surface only at
runtime: XHR/fetch calls fired after boot, route click-throughs, WebSocket
handshakes. The old crawl never saw that surface — it discovered hash routes
and then SKIPPED them (`#` = SPA shell), so a real SPA like Juice Shop came
back with zero findings.

These helpers are the pure, testable core of the fix; the engine wraps them
with Playwright orchestration:

  * ``ws_to_http`` — a WebSocket handshake URL is a probeable HTTP surface.
  * ``select_runtime_apis`` — dedupe + scope captured URLs (http + ws) into
    the API queue the module matrix consumes.
  * ``route_table_candidates`` — extract candidate SPA routes from the route
    table shapes apps actually expose (Angular router, React Router, Vue
    router, framework globals) plus hash/href links. Pure so the engine's
    page.evaluate only needs to ship back a JSON-safe blob.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse


def ws_to_http(url: str) -> str:
    """Convert a WebSocket handshake URL to its HTTP probe form.

    ``ws://host/path`` -> ``http://host/path``; ``wss://`` -> ``https://``.
    Non-ws URLs pass through unchanged; unparseable input passes through.
    """
    if not url:
        return url
    if url.startswith("ws://"):
        return "http://" + url[len("ws://"):]
    if url.startswith("wss://"):
        return "https://" + url[len("wss://"):]
    return url


def select_runtime_apis(
    captured: List[str],
    ws_urls: Optional[List[str]] = None,
    base_url: str = "",
    scope_host: str = "",
) -> List[str]:
    """Turn raw runtime captures (http + ws) into the deduped, in-scope API
    queue for the module matrix.

    * WebSocket URLs are converted to their HTTP probe form.
    * Relative URLs are resolved against ``base_url``.
    * URLs outside ``scope_host`` (or a subdomain of it) are dropped.
    * Order is stable (sorted) so the module matrix sees a deterministic
      queue run-to-run.
    """
    raw: List[str] = list(captured or [])
    raw.extend(ws_urls or [])
    out: List[str] = []
    seen: set = set()
    for u in raw:
        if not u:
            continue
        u = ws_to_http(u)
        if u.startswith("/"):
            u = urljoin(base_url, u)
        if not u.startswith("http"):
            continue
        if scope_host:
            host = (urlparse(u).hostname or "").lower()
            if not (host == scope_host or host.endswith("." + scope_host)):
                continue
        if u not in seen:
            seen.add(u)
            out.append(u)
    return sorted(out)


def route_table_candidates(
    blob: Dict[str, Any],
    base_url: str = "",
    max_routes: int = 50,
) -> List[str]:
    """Extract candidate SPA routes from a JSON-safe blob the page shipped
    back (the engine's page.evaluate serializes the browser-side route table).

    Recognized shapes (any may be absent):
      * ``routes`` / ``__ROUTES__`` / ``router.routes`` — a list of strings
        or dicts with ``path`` / ``pathname``.
      * ``hash_links`` — ``a[href^=\"#\"]`` hrefs already resolved to
        absolute URLs by the browser.
      * ``path_links`` — same-origin ``a[href^=\"/\"]`` hrefs.
      * ``data_routes`` — ``[data-route]/[data-path]/[data-link]`` values.
      * ``nested`` — a list of child blobs each with ``path`` (route tables
        are often nested per Angular module / React lazy chunk).

    Returns absolute, deduped routes sorted for determinism. Empty when the
    blob carries no route shape.
    """
    candidates: List[str] = []

    def _add(value: Any) -> None:
        if isinstance(value, str):
            candidates.append(value)
        elif isinstance(value, dict):
            for key in ("path", "pathname", "url", "href"):
                v = value.get(key)
                if isinstance(v, str) and v:
                    candidates.append(v)
                    break
            # Nested route tables (Angular modules / React lazy chunks): a
            # route dict often carries ``children`` with their own paths.
            children = value.get("children")
            if isinstance(children, list):
                for child in children:
                    _add(child)

    for key in ("routes", "__ROUTES__", "spa_routes"):
        val = blob.get(key)
        if isinstance(val, list):
            for item in val:
                _add(item)
    router = blob.get("router")
    if isinstance(router, dict):
        for key in ("routes", "routeTable", "config"):
            rv = router.get(key)
            if isinstance(rv, list):
                for item in rv:
                    _add(item)
        if isinstance(router.get("path"), str):
            candidates.append(router["path"])
    for key in ("hash_links", "path_links", "data_routes"):
        val = blob.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item:
                    candidates.append(item)
    nested = blob.get("nested")
    if isinstance(nested, list):
        for child in nested:
            if isinstance(child, dict):
                for key in ("path", "pathname", "url", "href"):
                    v = child.get(key)
                    if isinstance(v, str) and v:
                        candidates.append(v)
                        break

    out: List[str] = []
    seen: set = set()
    for c in candidates:
        if not c:
            continue
        if c.startswith("/"):
            c = urljoin(base_url, c)
        if not c.startswith("http"):
            continue
        if c not in seen:
            seen.add(c)
            out.append(c)
    return sorted(out)[:max_routes]


def strip_fragment(url: str) -> str:
    """Drop the ``#...`` fragment so a hash route's probeable URL is its
    base (the SPA server serves the same shell for every route)."""
    if not url:
        return url
    return url.split("#", 1)[0]
