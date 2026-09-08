"""Browser interaction + SPA harness for TitanEngine.

Extracted from titan/core/engine.py. Supplies the interaction phase
(capture + form fill/submit), the SPA route-hydration harness, and the
clickable-element walk that surfaces runtime API endpoints. State the
runners read (``config``, ``visited``, ``_scan_target``, driver health,
module runner) stays on the host engine; this mixin only supplies behavior.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import urlparse

from titan.core.logger import get_logger

logger = get_logger("browser_interaction")


class BrowserInteractionMixin:
    """Interaction capture and SPA harness for TitanEngine."""

    # State supplied by the host engine before any mixin method runs.
    config: dict
    visited: Any
    _driver_dead: bool
    _spa_detected: bool
    _deep: bool
    _scan_target: str
    _modules: Any
    _extract_forms: Any

    # ==================================================================
    # Interactions & SPA
    # ==================================================================

    async def _run_interactions(self, context, target, fingerprint, result):
        if self._driver_dead:
            return
        if not self._spa_detected and not self._deep:
            return

        interaction_targets = list(self.visited)[:5]
        budget = max(1, self.config.get("crawl", {}).get("interaction_timeout", 90))

        async def interact_one(vu: str):
            async def _interact():
                i_page = None
                try:
                    i_page = await asyncio.wait_for(context.new_page(), timeout=10)
                    self._harden_page(i_page)
                except asyncio.TimeoutError:
                    return
                try:
                    api_endpoints = await asyncio.wait_for(
                        self._interact_and_capture(context, i_page, vu), timeout=30
                    )
                    for api_url in api_endpoints:
                        if api_url not in self.visited and self._is_in_scope(api_url):
                            self.visited.add(api_url)
                            try:
                                api_findings = await asyncio.wait_for(
                                    self._run_api_modules(context, target, api_url, fingerprint),
                                    timeout=60,
                                )
                            except asyncio.TimeoutError:
                                api_findings = []
                            result.findings.extend(api_findings)
                finally:
                    try:
                        await asyncio.wait_for(i_page.close(), timeout=5)
                    except Exception as exc:
                        logger.debug(f"suppressed exception: {exc}")
                        pass
            try:
                await asyncio.wait_for(_interact(), timeout=budget)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception) as exc:
                logger.debug(f"suppressed exception: {exc}")
                pass

        await asyncio.gather(
            *[interact_one(vu) for vu in interaction_targets],
            return_exceptions=True,
        )

    async def _interact_and_capture(self, context, page, base_url: str) -> list[str]:
        """Interact with a page and capture API endpoints."""
        from titan.core.spa import select_runtime_apis

        logger.info(f"[+] Starting interaction on {base_url}")
        api_endpoints: list[str] = []
        try:
            await page.goto(base_url, wait_until="domcontentloaded", timeout=15000)
        except Exception:
            return api_endpoints

        captured_urls: list[str] = []
        ws_urls: list[str] = []

        def capture_request(request):
            if self._looks_like_api(request.url):
                captured_urls.append(request.url)

        def capture_websocket(ws):
            try:
                u = ws.url
                if u and self._is_in_scope(u):
                    ws_urls.append(u)
            except Exception as exc:
                logger.debug(f"suppressed exception: {exc}")
                pass

        page.on("request", capture_request)
        page.on("websocket", capture_websocket)

        try:
            forms = await self._extract_forms(page)
            for form in forms:
                try:
                    await self._fill_and_submit_form(page, form, base_url)
                    await page.wait_for_timeout(1000)
                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        try:
            clickable = await page.evaluate('''() => {
                const elements = [];
                for (const el of document.querySelectorAll('button, a[href], [role="button"], input[type="submit"]')) {
                    elements.push({
                        tag: el.tagName.toLowerCase(),
                        text: (el.innerText || el.textContent || '').trim().slice(0, 50),
                        id: el.id || '',
                        class: el.className || ''
                    });
                }
                return elements.slice(0, 10);
            }''')
            for el in clickable:
                try:
                    el_id = el.get('id', '')
                    el_class = el.get('class', '').split()[0] if el.get('class') else ''
                    if el_id:
                        element = await page.query_selector(f"#{el_id}")
                        if element:
                            await element.click(force=True)
                    elif el_class:
                        element = await page.query_selector(f".{el_class}")
                        if element:
                            await element.click(force=True)
                    else:
                        element = await page.query_selector('button, a[href], [role="button"], input[type="submit"]')
                        if element:
                            await element.click(force=True)
                    await page.wait_for_timeout(500)
                    forms_count = await page.evaluate('''() => document.querySelectorAll('form').length''')
                    if forms_count > 0:
                        form_data = await self._extract_forms(page)
                        for form in form_data:
                            try:
                                await self._fill_and_submit_form(page, form, base_url)
                                await page.wait_for_timeout(500)
                            except Exception as exc:
                                logger.debug(f"variant failed, continuing: {exc}")
                                continue
                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        try:
            await page.evaluate('''() => window.scrollTo(0, document.body.scrollHeight)''')
            await page.wait_for_timeout(1000)
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        page.remove_listener("request", capture_request)
        api_endpoints = select_runtime_apis(
            captured_urls, ws_urls=ws_urls, base_url=base_url,
            scope_host=urlparse(self._scan_target).hostname or "",
        )
        logger.info(f"[+] Interaction captured {len(api_endpoints)} API endpoints ({len(ws_urls)} websocket)")
        return api_endpoints

    async def _fill_and_submit_form(self, page, form: dict, base_url: str) -> None:
        inputs = form.get("inputs", [])
        for inp in inputs:
            try:
                name = inp.get("name", "")
                if not name:
                    continue
                await page.evaluate('''(name) => {
                    const el = document.querySelector('[name="{name}"]');
                    if (el) {
                        el.value = 'test';
                        el.dispatchEvent(new Event('input', { bubbles: true }));
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                    }
                }''', name)
            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue
        try:
            submit_btn = await page.query_selector('button[type="submit"], input[type="submit"]')
            if submit_btn:
                await submit_btn.click(force=True)
            else:
                await page.keyboard.press("Enter")
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

    async def _run_spa_harness(self, context, target, fingerprint, result):
        from titan.core.spa import strip_fragment

        if self._driver_dead:
            return
        spa_cfg = self.config.get("crawl", {}).get("spa", {})
        hydrate_budget = float(spa_cfg.get("hydrate_budget", 10))
        max_routes = int(spa_cfg.get("max_routes", 6))
        per_route_budget = int(spa_cfg.get("per_route_budget", 30))
        wait_idle = int(spa_cfg.get("network_idle", 2500))

        spa_page = None
        try:
            spa_page = await asyncio.wait_for(context.new_page(), timeout=10)
            self._harden_page(spa_page)
            routes = await asyncio.wait_for(
                self._hydrate_spa_routes(context, spa_page, target, budget=hydrate_budget),
                timeout=hydrate_budget + 5,
            )
            routes = list(dict.fromkeys(routes))[:max_routes]
            if not routes:
                logger.info("[+] SPA harness: no route table hydrated")
                return
            logger.info(f"[+] SPA harness: walking {len(routes)} hydrated route(s)")
            captured_total = 0
            for route in routes:
                if self._driver_dead:
                    break
                probe_url = strip_fragment(route)
                captured: list[str] = []
                try:
                    async def _walk_one():
                        nonlocal captured
                        await spa_page.goto(probe_url, wait_until="domcontentloaded", timeout=15000)
                        try:
                            await spa_page.wait_for_load_state("networkidle", timeout=wait_idle)
                        except Exception as exc:
                            logger.debug(f"suppressed exception: {exc}")
                            pass
                        captured = await self._interact_and_capture(context, spa_page, route)
                    await asyncio.wait_for(_walk_one(), timeout=per_route_budget)
                except asyncio.TimeoutError as exc:
                    logger.debug(f"suppressed exception: {exc}")
                    pass
                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue
                for api_url in captured:
                    if api_url not in self.visited and self._is_in_scope(api_url):
                        self.visited.add(api_url)
                        try:
                            api_findings = await asyncio.wait_for(
                                self._modules._run_api_modules(context, target, api_url, fingerprint),
                                timeout=60,
                            )
                        except asyncio.TimeoutError:
                            api_findings = []
                        result.findings.extend(api_findings)
                captured_total += len(captured)
            logger.info(f"[+] SPA harness: {captured_total} runtime API endpoint(s) captured")
        except (asyncio.TimeoutError, Exception) as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass
        finally:
            if spa_page is not None:
                try:
                    await asyncio.wait_for(spa_page.close(), timeout=5)
                except Exception as exc:
                    logger.debug(f"suppressed exception: {exc}")
                    pass

    async def _hydrate_spa_routes(self, context, page, base_url, budget=10.0):
        from titan.core.spa import route_table_candidates
        deadline = time.monotonic() + budget
        seen_routes: list[str] = []
        while time.monotonic() < deadline:
            try:
                blob = await page.evaluate('''() => {
                    const routes = [], pathLinks = [], hashLinks = [], dataRoutes = [];
                    const origin = window.location.origin;
                    const pushRoute = (r) => { if (r && typeof r === 'string') routes.push(r); };
                    if (window.__ROUTES__) (window.__ROUTES__ || []).forEach(pushRoute);
                    if (window.routes) {
                        if (Array.isArray(window.routes)) window.routes.forEach(pushRoute);
                        else if (window.routes.routes) (window.routes.routes || []).forEach(pushRoute);
                    }
                    if (window.router) {
                        const r = window.router;
                        if (r.routes) (r.routes || []).forEach(rt => {
                            if (rt && typeof rt === 'object') {
                                pushRoute(rt.path); pushRoute(rt.pathname);
                                if (rt.children) (rt.children || []).forEach(c => pushRoute(c.path));
                            } else pushRoute(rt);
                        });
                    }
                    document.querySelectorAll('a[href^="#"]').forEach(a => {
                        const href = a.getAttribute('href');
                        if (href && href.length > 1) hashLinks.push(origin + href);
                    });
                    document.querySelectorAll('a[href^="/"]').forEach(a => {
                        const href = a.getAttribute('href');
                        if (href && !href.startsWith('/__')) pathLinks.push(origin + href);
                    });
                    document.querySelectorAll('[data-route], [data-path], [data-link]').forEach(el => {
                        const val = el.getAttribute('data-route') || el.getAttribute('data-path') || el.getAttribute('data-link');
                        if (val) dataRoutes.push(origin + val);
                    });
                    return { routes, hash_links: hashLinks, path_links: pathLinks, data_routes: dataRoutes };
                }''')
            except Exception:
                break
            if not isinstance(blob, dict):
                break
            urlparse(self._scan_target).hostname or ""
            found = [
                r for r in route_table_candidates(blob, base_url=base_url)
                if self._is_in_scope(r)
            ]
            if found:
                seen_routes = found
                break
            try:
                await page.wait_for_timeout(1500)
            except Exception:
                break
        return seen_routes

