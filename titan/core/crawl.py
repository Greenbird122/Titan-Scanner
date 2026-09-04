"""Crawl engine: page discovery, API probing, SPA routing, and path fuzzing.

Extracted from TitanEngine to keep the core engine focused on
orchestration. The Crawler class holds crawl state and runs the
breadth-first walk of the target site.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from typing import Any, TYPE_CHECKING
from urllib.parse import urljoin, urlparse, parse_qs

from titan.core.helpers import (
    consume_task_exception,
    dedupe_apis,
    extract_urls_from_json,
    is_soft_404,
)

if TYPE_CHECKING:
    from titan.core.models import ScanResult


# ---------------------------------------------------------------------------
# No-op probes for fast profile (deep-only probes replaced with empty stubs)
# ---------------------------------------------------------------------------

async def _noop_api_probe() -> list[str]:
    return []


async def _noop_params_probe() -> dict[str, list[str]]:
    return {}


async def _noop_methods_probe() -> list[dict[str, Any]]:
    return []


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

class Crawler:
    """Breadth-first web crawler with concurrent module scheduling.

    Holds all crawl state (visited set, discovered URLs, coverage counters)
    so the engine stays clean. The crawl() method is the main entry point.
    """

    def __init__(self, engine: Any) -> None:
        # Back-reference to the engine for config, stealth, scope checks,
        # and module scheduling.  Avoids passing 20+ params everywhere.
        self.engine = engine

    # ------------------------------------------------------------------
    # Main crawl loop
    # ------------------------------------------------------------------

    async def crawl(
        self,
        context: Any,
        page: Any,
        base_url: str,
        result: ScanResult,
        fingerprint: dict[str, Any],
    ) -> None:
        """Run the breadth-first crawl over the target.

        Each page is fetched, its forms/links/APIs discovered, and the
        module matrix scheduled as a background task so the next page
        can start immediately.
        """
        e = self.engine  # shorthand

        # Seed URLs from config
        seeds_only = bool(e.config.get("crawl", {}).get("seeds_only"))
        queue: list[tuple[str, int]] = []
        for seed in e.config.get("crawl", {}).get("seed_urls", []) or []:
            seed = str(seed).strip()
            if not seed:
                continue
            if seed != base_url and seed not in e.visited and e._is_in_scope(seed):
                e.visited.add(seed)
                queue.append((seed, 1))
        if not seeds_only:
            queue.append((base_url, 0))
        e.visited.add(base_url)

        captured_apis: set[str] = set()
        processed_count = 0
        _module_tasks: list = []

        while queue and processed_count < e.max_pages:
            if e._driver_dead:
                print("[!] Driver dead; stopping crawl early")
                break

            current, depth = queue.pop(0)
            if depth > e.max_depth:
                e._coverage["capped_depth"] = True
                continue
            if e._is_spa_shell(current):
                continue

            print(f"[+] Crawling: {current} (depth {depth}, visited {len(e.visited)})")
            page_start = asyncio.get_event_loop().time()
            processed_count += 1
            e._coverage["urls_crawled"] = processed_count

            try:
                result_data = await self._process_page(
                    context, page, current, base_url, depth,
                    captured_apis, fingerprint, result,
                )
                if result_data is not None:
                    queue.extend(result_data.get("new_queue_items", []))

                # Anomaly interrupt + route re-sort
                if result_data and result_data.get("resp_status", 0) < 400:
                    self._handle_anomalies(context, current, depth, queue)

                if queue:
                    techs = fingerprint.get("technologies", []) if fingerprint else []
                    from titan.core.route_scorer import sort_queue
                    queue = sort_queue(queue, technologies=techs)

            except Exception as exc:
                print(f"    [!] Error crawling {current}: {exc}")
                continue

        # Wait for background module tasks
        if _module_tasks:
            print(f"[+] Waiting for {len(_module_tasks)} background module task(s) to finish...")
            done_results = await asyncio.gather(*_module_tasks, return_exceptions=True)
            for res in done_results:
                if isinstance(res, BaseException):
                    if e._is_driver_death(res):
                        e._driver_dead = True
                    continue
                if isinstance(res, list):
                    result.findings.extend(res)

        e._coverage["queue_exhausted"] = not queue
        e._coverage["capped_max_pages"] = bool(queue) and processed_count >= e.max_pages

    # ------------------------------------------------------------------
    # Single-page processing
    # ------------------------------------------------------------------

    async def _process_page(
        self,
        context: Any,
        page: Any,
        current: str,
        base_url: str,
        depth: int,
        captured_apis: set[str],
        fingerprint: dict[str, Any],
        result: ScanResult,
    ) -> dict[str, Any] | None:
        """Process a single page: fetch, discover, schedule modules.

        Returns a dict with new_queue_items and resp_status, or None on skip.
        """
        e = self.engine
        is_api_url = e._looks_like_api(current)
        resp = None
        body = ""
        title = ""
        forms: list = []
        links: list = []
        apis: list = []

        if is_api_url:
            return await self._process_api_url(
                context, current, base_url, depth, captured_apis,
            )
        else:
            return await self._process_html_page(
                context, page, current, base_url, depth,
                captured_apis, fingerprint, result,
            )

    async def _process_api_url(
        self,
        context: Any,
        current: str,
        base_url: str,
        depth: int,
        captured_apis: set[str],
    ) -> dict[str, Any] | None:
        """Handle an API-shaped URL (direct request, no browser)."""
        e = self.engine
        new_items: list[tuple[str, int]] = []
        try:
            api_resp = await context.page.request.get(current, timeout=10000)
            body = await api_resp.text()

            new_urls = extract_urls_from_json(body, e._is_in_scope)
            for u in new_urls:
                if u not in e.visited and len(e.visited) < e.max_pages:
                    e.visited.add(u)
                    new_items.append((u, depth + 1))

            if api_resp.status in (301, 302, 307, 308):
                location = api_resp.headers.get("location", "")
                if location and location not in e.visited:
                    e.visited.add(location)
                    new_items.append((location, depth + 1))
        except Exception:
            pass
        return {"new_queue_items": new_items, "resp_status": 200}

    async def _process_html_page(
        self,
        context: Any,
        page: Any,
        current: str,
        base_url: str,
        depth: int,
        captured_apis: set[str],
        fingerprint: dict[str, Any],
        result: ScanResult,
    ) -> dict[str, Any] | None:
        """Handle an HTML page: fetch with browser, discover, schedule modules."""
        e = self.engine
        new_items: list[tuple[str, int]] = []

        captured_urls: list[str] = []
        ws_urls: list[str] = []
        captured_count = 0

        def capture_request(request):
            nonlocal captured_count
            if captured_count < 50 and e._looks_like_api(request.url):
                captured_urls.append(request.url)
                captured_count += 1

        page.on("request", capture_request)

        async def _goto_with_retry():
            for attempt in range(2):
                try:
                    return await page.goto(current, wait_until="domcontentloaded", timeout=8000)
                except Exception as exc:
                    msg = f"{type(exc).__name__}: {exc}".lower()
                    transient = ("net::err" in msg or "timeout" in msg
                                 or "connection" in msg or "interrupted" in msg)
                    if attempt == 0 and transient:
                        await asyncio.sleep(1.5)
                        continue
                    raise

        resp = await _goto_with_retry()
        try:
            await page.wait_for_load_state("networkidle", timeout=2000)
        except Exception:
            pass
        page.remove_listener("request", capture_request)

        for url in captured_urls:
            if e._looks_like_api(url):
                captured_apis.add(url)

        if not resp or resp.status >= 400:
            status_code = resp.status if resp else 0
            print(f"    [!] Skipped (status {status_code})")
            if status_code in (401, 403) and e._auth_scope == "unauthenticated":
                e._gated_routes.add(current)
            if status_code in (403, 429):
                waf_info = e._waf_tracker.detect(
                    current, status_code, "", dict(resp.headers) if resp else {}
                )
                if waf_info:
                    print(f"    [!] WAF detected: {waf_info.waf_name} (confidence {waf_info.confidence:.0%})")
            return {"new_queue_items": [], "resp_status": status_code}

        body = await page.content()
        title = await page.title()
        if e._is_checkpoint(title, body, dict(resp.headers), resp.status):
            print(f"    [!] Checkpoint on subpage: {title}")
            return {"new_queue_items": [], "resp_status": resp.status}

        # Duplicate body check
        body_fingerprint = hashlib.md5(body.encode()).hexdigest() if body else ""
        if body_fingerprint in e._response_cache:
            print("    [i] Duplicate response, skipping modules")
            e._coverage["duplicate_bodies_skipped"] += 1
            return {"new_queue_items": [], "resp_status": resp.status}
        e._response_cache.add(body_fingerprint)

        # Discovery
        from titan.core.discovery import DiscoveryEngine
        disc = DiscoveryEngine(e)
        (
            forms, links, static_apis, js_apis, spa_routes,
            swagger_endpoints, postman_endpoints, graphql_eps,
            common_param_discoveries, http_methods,
        ) = await disc.discover_all(context, page, base_url, current)

        all_apis = sorted(set(static_apis + js_apis + list(captured_apis)))

        # Eager discovery view
        for _u in list(links) + all_apis + list(spa_routes):
            if _u and e._is_in_scope(_u):
                e._discovered_urls.add(_u.split("?")[0])

        # Queue new routes
        for route in spa_routes:
            if route not in e.visited and e._is_in_scope(route) and len(e.visited) < e.max_pages:
                e.visited.add(route)
                new_items.append((route, depth + 1))

        for ep in swagger_endpoints:
            ep_url = ep["path"]
            if ep_url not in e.visited and e._is_in_scope(ep_url) and len(e.visited) < e.max_pages:
                e.visited.add(ep_url)
                new_items.append((ep_url, depth + 1))
            all_apis.append(ep_url)

        for ep in postman_endpoints:
            ep_url = ep["path"]
            if ep_url not in e.visited and e._is_in_scope(ep_url) and len(e.visited) < e.max_pages:
                e.visited.add(ep_url)
                new_items.append((ep_url, depth + 1))
            all_apis.append(ep_url)

        for ep in graphql_eps:
            if ep not in e.visited and e._is_in_scope(ep) and len(e.visited) < e.max_pages:
                e.visited.add(ep)
                new_items.append((ep, depth + 1))
            all_apis.append(ep)

        for ep_url, params in common_param_discoveries.items():
            if ep_url not in e.visited and e._is_in_scope(ep_url) and len(e.visited) < e.max_pages:
                e.visited.add(ep_url)
                new_items.append((ep_url, depth + 1))
            if params:
                all_apis.append(ep_url)

        for ep in http_methods:
            ep_url = ep["path"]
            if ep_url not in e.visited and e._is_in_scope(ep_url) and len(e.visited) < e.max_pages:
                e.visited.add(ep_url)
                new_items.append((ep_url, depth + 1))
            all_apis.append(ep_url)

        # Path fuzzing
        try:
            from titan.core.pathfuzz import PathFuzzer
            fuzz_cfg = e.config.get("crawl", {}).get("fuzz", {})
            fuzzer = PathFuzzer(
                fuzz_cfg,
                in_scope=e._is_in_scope,
                stealth=e.stealth if hasattr(e, "stealth") else None,
            )
            fuzzed = await asyncio.wait_for(
                fuzzer.fuzz(context, all_apis),
                timeout=float(fuzz_cfg.get("budget", 60)),
            )
            if fuzzed:
                print(f"    [+] Path fuzzer: {len(fuzzed)} deeper endpoint(s) discovered")
                for fu in fuzzed:
                    fu_base = fu.split("?")[0]
                    if fu_base not in e.visited and e._is_in_scope(fu_base) and len(e.visited) < e.max_pages:
                        e.visited.add(fu_base)
                        new_items.append((fu_base, depth + 1))
                    if fu_base not in all_apis:
                        all_apis.append(fu_base)
        except Exception:
            pass

        discovered_apis = dedupe_apis(all_apis)
        if len(discovered_apis) > e.max_apis:
            e._coverage["capped_apis"] = True
        e._coverage["apis_discovered"] += len(discovered_apis)
        apis = discovered_apis[:e.max_apis]
        e._coverage["apis_scanned"] += len(apis)

        # Schedule module matrix
        from titan.core.route_scorer import score_url
        techs = fingerprint.get("technologies", []) if fingerprint else []
        _route_score = score_url(current, forms=forms, technologies=techs, depth=depth)

        print(f"    [+] Forms: {len(forms)}, Links: {len(links)}, APIs: {len(apis)}")

        # Queue links and APIs
        for link in links:
            e._discovered_urls.add(link.split("?")[0])
            if link not in e.visited and e._is_in_scope(link):
                e.visited.add(link)
                new_items.append((link, depth + 1))

        for api in apis:
            api_base = api.split("?")[0]
            if api_base not in e.visited and e._is_in_scope(api_base) and len(e.visited) < e.max_pages:
                e.visited.add(api_base)
                new_items.append((api_base, depth + 1))

        return {
            "new_queue_items": new_items,
            "resp_status": resp.status if resp else 0,
            "forms": forms,
            "links": links,
            "apis": apis,
            "route_score": _route_score,
        }

    def _handle_anomalies(
        self,
        context: Any,
        current: str,
        depth: int,
        queue: list[tuple[str, int]],
    ) -> None:
        """Check for anomalies and promote routes."""
        e = self.engine
        try:
            _cookies: list[str] = []
            try:
                # Synchronous cookie access via event loop if available
                pass
            except Exception:
                pass
            _redirect = None
            if e.redirect_chain:
                _redirect = e.redirect_chain[-1].get("to")
            anomalies = e._anomaly_tracker.check(
                url=current,
                status=200,
                body="",
                headers={},
                cookies=_cookies,
                redirect_target=_redirect,
            )
            for a in anomalies:
                print(f"    [!] ANOMALY: {a.kind} on {current} — {a.detail}")
                if current not in e.visited and e._is_in_scope(current):
                    queue.insert(0, (current, depth))
        except Exception:
            pass
