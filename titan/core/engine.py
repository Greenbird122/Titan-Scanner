"""Core scan engine for Titan Scanner.

Orchestrates the full scan pipeline: authorization, crawl, module matrix,
verification, reporting, and post-scan analysis phases. Heavy lifting is
delegated to:
  - titan.core.constants  — marker/sentinel values
  - titan.core.helpers    — pure utility functions
  - titan.core.crawl      — breadth-first crawl loop
  - titan.core.discovery  — page/probe discovery
  - titan.core.modules_runner — attack module dispatch
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import time
from typing import Any

from titan.ai.payloadsmith import PayloadSmith
from titan.core.anomaly import AnomalyTracker
from titan.core.auth import AuthEngine
from titan.core.browser_interaction import BrowserInteractionMixin
from titan.core.browser_lifecycle import BrowserLifecycleMixin
from titan.core.campaign_phases import CampaignPhasesMixin
from titan.core.constants import (
    ROOT_CAUSE_ATTACK_TYPES,
)
from titan.core.crawl import Crawler
from titan.core.dispatch import DispatchMixin
from titan.core.engine_helpers import EngineHelpersMixin
from titan.core.fingerprint import TechFingerprinter
from titan.core.helpers import (
    consume_task_exception,
    dedupe_findings,
)
from titan.core.logger import get_logger
from titan.core.models import Finding, ScanResult
from titan.core.modules_runner import ModuleRunner
from titan.core.post_scan_phases import PostScanPhasesMixin
from titan.core.proxy import ProxyRotator
from titan.core.sessions import Identity, SessionPool
from titan.core.stealth import StealthEngine
from titan.core.transport_mixin import TransportMixin
from titan.integrations.interactsh import InteractshClient
from titan.verify.role_aware import RoleAwareScanner

logger = get_logger("engine")


class TitanEngine(TransportMixin, BrowserInteractionMixin, BrowserLifecycleMixin, CampaignPhasesMixin, DispatchMixin, EngineHelpersMixin, PostScanPhasesMixin):
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.fingerprinter = TechFingerprinter()
        self.payload_smith = PayloadSmith(config.get("ai", {}))
        self.auth_engine = AuthEngine(config)
        self.session_pool = SessionPool()
        self._role_scanner = RoleAwareScanner()
        self._platform_brain = None
        self._platform_extra_params: list[str] = []
        self.interactsh = InteractshClient()
        self.findings: list[Finding] = []
        self.visited: set = set()
        self._discovered_urls: set = set()

        # Crawl profiles
        crawl_cfg = config.get("crawl", {})
        _profile = str(crawl_cfg.get("profile", "fast")).lower()
        self._deep = _profile in ("deep", "hostile")
        self._hostile = _profile == "hostile"
        self.redirect_chain: list[dict[str, Any]] = []
        self._spa_detected = False
        self.max_pages = crawl_cfg.get("max_pages", 5 if not self._deep else 20)
        self.max_apis = crawl_cfg.get("max_apis", 15)
        self.max_depth = crawl_cfg.get("max_depth", 1 if not self._deep else 2)

        self._mutation_cache: dict[str, list[str]] = {}
        self._response_cache: set = set()
        self._coverage: dict[str, Any] = {
            "urls_crawled": 0, "duplicate_bodies_skipped": 0,
            "endpoint_groups_run": 0, "apis_discovered": 0,
            "apis_scanned": 0, "params_discovered": 0,
            "fuzz_budget_spent": 0.0, "queue_exhausted": False,
            "capped_max_pages": False, "capped_depth": False,
            "capped_apis": False, "crawl_timed_out": False,
            "checkpoint_blocked": False,
        }

        self._module_semaphore = asyncio.Semaphore(
            config.get("crawl", {}).get("module_concurrency", 8)
        )
        self._module_timeouts: dict[str, int] = {}
        self._module_line_counts: dict[str, int] = {}
        self._scan_target: str = ""
        self._driver_dead: bool = False

        self.proxy_rotator = ProxyRotator(
            proxies=config.get("proxy", {}).get("list", []),
            strategy=config.get("proxy", {}).get("rotation", "round-robin"),
        )
        stealth_cfg = config.get("stealth", {})
        self.stealth = StealthEngine(
            jitter=stealth_cfg.get("jitter", 0.3),
            min_delay=stealth_cfg.get("min_delay", 0.15),
            max_delay=stealth_cfg.get("max_delay", 0.6),
        )
        self.stealth.adaptive = bool(stealth_cfg.get("adaptive", True))
        self._anomaly_tracker = AnomalyTracker()
        self._gated_routes: set = set()
        self._auth_scope: str = "unauthenticated"

        from titan.core.waf import WAFTracker
        self._waf_tracker = WAFTracker()

        # Transport abstraction
        self._transport_registry: Any = None
        self._transport_http: Any = None
        self._transport_ready: bool = False

        # Sub-engines (delegates)
        self._crawler = Crawler(self)
        self._modules = ModuleRunner(self)

    # ==================================================================
    # Main scan entry point
    # ==================================================================

    async def scan(self, target: str) -> ScanResult:
        t0 = time.time()
        self._scan_target = target
        random.seed(hashlib.sha256(target.encode("utf-8")).hexdigest())
        result = ScanResult(target=target, started_at=t0, config_snapshot=self.config)

        # S5 authorization gate
        denial = self._authorization_status(target)
        if denial:
            result.errors.append(denial)
            result.finished_at = time.time()
            logger.warning(f"[!] {denial}")
            return result

        if self.config.get("governance", {}).get("enabled", True):
            try:
                from titan.integrations.titan_gov import request_scan_approval
                approved = await request_scan_approval(
                    target, self.config.get("aggression", "passive")
                )
                if not approved:
                    result.errors.append("Scan not approved by governance")
                    result.finished_at = time.time()
                    return result
            except Exception as exc:
                result.errors.append(f"Governance check failed: {exc}")
                result.finished_at = time.time()
                logger.warning(f"[!] Governance check failed, denying scan: {exc}")
                return result

        try:
            result = await self._run_scan_pipeline(target, result)
        except asyncio.TimeoutError:
            result.errors.append("Scan timed out after 240s")
            logger.warning("[!] Scan timed out")
        except Exception as exc:
            logger.exception("Scan pipeline failed")
            result.errors.append(str(exc))

        # Post-scan phases
        await self._run_post_scan_phases(target, result)

        result.findings = dedupe_findings(result.findings, ROOT_CAUSE_ATTACK_TYPES)
        result.findings = [f for f in result.findings if self._is_in_scope(f.url)]

        # Evidence gates & verification
        await self._run_verification(result)

        # Coverage & reporting
        result.coverage = self._finalize_coverage(result)
        result.finished_at = time.time()

        if self.config.get("reporting", {}).get("enabled", True):
            try:
                from titan.reporting import SiteReportWriter
                site_dir = SiteReportWriter(self.config.get("output_dir", "findings")).write(result)
                logger.info(f"[+] Site report written to {site_dir}")
            except Exception as exc:
                logger.warning(f"[!] Failed to write site report: {exc}")

        # Transport cleanup
        await self._close_transport()

        return result

    async def _run_scan_pipeline(self, target: str, result: ScanResult) -> ScanResult:
        """Core scan: Playwright browser, crawl, interactions, modules."""
        from playwright.async_api import async_playwright

        p = await async_playwright().start()
        try:
            browser, context = await self._launch_crawler(p, target)
            # Hide the loudest automation signal on every page in this context.
            try:
                await context.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
                )
            except Exception:
                pass
            self._crawl_context = context
            page = await context.new_page()
            self._harden_page(page)

            logger.info(f"[+] Loading target: {target}")
            _goto_start = time.monotonic()
            response = await page.goto(target, wait_until="domcontentloaded", timeout=30000)
            _goto_elapsed = time.monotonic() - _goto_start
            try:
                self.stealth.observe_latency(_goto_elapsed)
            except Exception:
                pass

            headers = dict(response.headers) if response else {}
            body = await page.content()
            title = await page.title()
            logger.info(f"[+] Page title: {title}")
            logger.info(f"[+] Response status: {response.status if response else 'N/A'}")

            if self._is_checkpoint(title, body, headers, response.status if response else 200):
                result.errors.append(f"Security checkpoint blocked access: {title}")
                self._coverage["checkpoint_blocked"] = True
                logger.warning(f"[!] Checkpoint detected: {title}")
                result.finished_at = time.time()
                await self._close_crawler(browser, context)
                return result

            fingerprint = await self.fingerprinter.analyze(headers, body, target)
            fingerprint["interactsh"] = self.interactsh
            result.fingerprint = fingerprint
            logger.info(f"[+] Technologies detected: {fingerprint.get('technologies', [])[:10]}")

            # Platform brain
            self._platform_brain = self._select_platform_brain(fingerprint, body, headers)
            if self._platform_brain is not None:
                logger.info(f"[+] Platform brain: {self._platform_brain.name}")
                for seed in self._platform_brain.extra_seed_urls(target):
                    if seed not in self.visited and self._is_in_scope(seed):
                        self.visited.add(seed)
                        self._discovered_urls.add(seed)
                self._platform_extra_params = list(self._platform_brain.extra_parameters())
            else:
                self._platform_extra_params = []

            # Authentication
            if self.config.get("auth"):
                logger.info("[+] Attempting authentication...")
                logged_in = await self.auth_engine.login(context, page, target)
                if logged_in:
                    role_name = self.auth_engine.get_current_role() or "user"
                    logger.info(f"[+] Authenticated as {role_name}")
                    self._role_scanner.record_role(role_name)
                    auth_headers = self.auth_engine.get_auth_headers()
                    if auth_headers:
                        await context.set_extra_http_headers(auth_headers)
                    self.session_pool.add(Identity(
                        name=role_name, headers=dict(auth_headers),
                        cookies=self.auth_engine.get_cookies(),
                    ))
                else:
                    logger.warning("[!] Authentication failed, continuing unauthenticated")

            # Crawl
            crawl_timeout = self.config.get("crawl", {}).get(
                "timeout", 90 if not self._deep else 300
            )
            crawl_task = asyncio.ensure_future(
                self._crawler.crawl(context, page, target, result, fingerprint)
            )
            crawl_task.add_done_callback(consume_task_exception)
            done, pending = await asyncio.wait({crawl_task}, timeout=crawl_timeout)
            if crawl_task in pending:
                result.errors.append(f"Crawl timed out after {crawl_timeout}s")
                self._coverage["crawl_timed_out"] = True
                logger.warning("[!] Crawl timed out, proceeding with interaction")
                crawl_task.cancel()
                try:
                    await asyncio.wait({crawl_task}, timeout=5)
                except Exception:
                    pass
            else:
                try:
                    crawl_task.result()
                except asyncio.CancelledError:
                    pass
                except Exception as exc:
                    result.errors.append(f"Crawl failed: {exc}")

            # Interactions, SPA, roles, replay, identity, browser, LLM, etc.
            if not self._driver_dead:
                await self._run_interactions(context, target, fingerprint, result)
                if self.config.get("crawl", {}).get("spa", {}).get("enabled", True):
                    has_hash_routes = any("#" in u for u in self.visited)
                    spa_frameworks = {"react", "vue", "angular", "svelte",
                                      "ember", "backbone", "next.js", "nuxt",
                                      "gatsby", "remix", "astro"}
                    detected_techs = {t.lower() for t in fingerprint.get("technologies", [])}
                    if has_hash_routes or bool(detected_techs & spa_frameworks):
                        try:
                            await self._run_spa_harness(context, target, fingerprint, result)
                        except Exception:
                            pass
                    else:
                        logger.info("[+] SPA harness: skipped (no hash routes or SPA framework detected)")

            # Multi-role testing
            await self._run_multi_role(context, page, target, fingerprint, result)

            # Session replay
            await self._run_session_replay(context, target, result)

            # Identity matrix
            if len(self.session_pool) >= 2 and not self._driver_dead:
                logger.info(f"[+] Identity matrix: {len(self.session_pool)} identities")
                for visited_url in list(self.visited)[:10]:
                    try:
                        identity_findings = await asyncio.wait_for(
                            self._modules.run_identity_modules(context, target, visited_url, {}),
                            timeout=20,
                        )
                        result.findings.extend(identity_findings)
                    except Exception:
                        continue

            # Browser modules
            if self.config.get("clientside", {}).get("enabled", True) and not self._driver_dead:
                await self._modules.run_browser_modules(context, page, target, fingerprint, result)

            # LLM, storage, subdomain, IMDS, SBOM, deep audit
            await self._run_optional_phases(target, result, page)

            await self._close_crawler(browser, context)
        finally:
            try:
                await asyncio.wait_for(p.stop(), timeout=5)
            except Exception:
                pass

        return result

    # ==================================================================
    # Forwarding methods (for tests / external callers)
    # ==================================================================

    async def _run_browser_modules(self, context, page, target, fingerprint, result):
        """Forward to ModuleRunner. Kept for test compatibility."""
        return await self._modules.run_browser_modules(context, page, target, fingerprint, result)

    async def _run_modules(
        self, context, target, forms, links, apis, fingerprint, result=None, route_score=5,
    ):
        """Run attack modules against all endpoint groups.

        Kept inline on the engine for test monkey-patching compatibility:
        tests replace engine._run_attack_modules and expect it to be called.
        """
        findings: list[Finding] = []

        form_tasks = []
        for form in forms:
            from urllib.parse import urljoin
            action = form.get("action") or target
            action = urljoin(target, action)
            if not self._is_in_scope(action):
                continue
            method = form.get("method", "GET").upper()
            data = {i["name"]: i["value"] for i in form.get("inputs", []) if i.get("name")}
            if not data:
                continue
            self._coverage["params_discovered"] += len(data)
            form_tasks.append(self._run_attack_modules(context, target, method, action, data, fingerprint, route_score=route_score))

        link_tasks = []
        for link in links:
            if "?" not in link:
                continue
            if not self._is_in_scope(link):
                continue
            from urllib.parse import parse_qs, urlparse
            parsed = urlparse(link)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}
            if not params:
                continue
            self._coverage["params_discovered"] += len(params)
            link_tasks.append(self._run_attack_modules(context, target, "GET", link, params, fingerprint, route_score=route_score))

        api_tasks = []
        for api in apis:
            if self._is_in_scope(api):
                api_tasks.append(self._run_api_modules(context, target, api, fingerprint))

        if self._driver_dead:
            return []

        all_task_groups = form_tasks + link_tasks + api_tasks
        self._coverage["endpoint_groups_run"] += len(all_task_groups)
        if all_task_groups:
            pending = [asyncio.ensure_future(c) for c in all_task_groups]
            try:
                for fut in asyncio.as_completed(pending):
                    try:
                        res = await fut
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        if self._is_driver_death(exc):
                            self._driver_dead = True
                            logger.warning("[!] Playwright driver died mid-matrix; aborting remaining groups")
                            for f in pending:
                                if not f.done():
                                    f.cancel()
                            break
                        continue
                    if isinstance(res, list) and res:
                        findings.extend(res)
                        if result is not None:
                            result.findings.extend(res)
            except asyncio.CancelledError:
                for fut in pending:
                    if not fut.done():
                        fut.cancel()
                raise

        return findings

    async def _run_attack_modules(self, context, target, method, url, params, fingerprint, route_score=5):
        """Forward to ModuleRunner. Kept for test compatibility."""
        return await self._modules.run_attack_modules(context, target, method, url, params, fingerprint, route_score)

    async def _run_single_module(self, name, runner, context, target, method, url, params, fingerprint):
        """Forward to ModuleRunner. Kept for test compatibility."""
        return await self._modules._run_single_module(name, runner, context, target, method, url, params, fingerprint)

    async def _run_identity_modules(self, context, target, api_url, fingerprint):
        """Forward to ModuleRunner. Kept for test compatibility."""
        return await self._modules.run_identity_modules(context, target, api_url, fingerprint)

    async def _run_api_modules(self, context, target, api_url, fingerprint):
        """Forward to ModuleRunner. Kept for test compatibility."""
        return await self._modules._run_api_modules(context, target, api_url, fingerprint)

    async def _test_rest_api(self, context, target, api_url, fingerprint):
        """Forward to ModuleRunner. Kept for test compatibility."""
        return await self._modules._test_rest_api(context, target, api_url, fingerprint)

    async def _fuzz_paths(self, context, seeds: list[str], base_url: str = "") -> list[str]:
        """Path-fuzz seeds, delegating to PathFuzzer. Kept for test
        compatibility and used by the crawl wiring (crawl.py)."""
        from titan.core.pathfuzz import PathFuzzer

        fuzz_cfg = self.config.get("crawl", {}).get("fuzz", {})
        # M3 gate: the wordlist fuzzer is deep/hostile-only — a fast profile
        # must skip it even when fuzz.enabled is explicitly true.
        if not getattr(self, "_deep", False):
            return []
        if not fuzz_cfg.get("enabled", False):
            return []
        fuzzer = PathFuzzer(
            fuzz_cfg,
            in_scope=self._is_in_scope,
            stealth=self.stealth if hasattr(self, "stealth") else None,
        )
        try:
            return await asyncio.wait_for(
                fuzzer.fuzz(context, seeds),
                timeout=float(fuzz_cfg.get("budget", 60)),
            )
        except Exception:
            return []

    async def _discover_all(self, context, page, base_url, current):
        """Forward to DiscoveryEngine. Kept for test compatibility."""
        from titan.core.discovery import DiscoveryEngine
        return await DiscoveryEngine(self).discover_all(context, page, base_url, current)

    # Discovery probe forwards (for test monkey-patching)
    async def _extract_forms(self, page):
        from titan.core.discovery import DiscoveryEngine
        return await DiscoveryEngine(self)._extract_forms(page)

    async def _extract_links(self, page, base_url):
        from titan.core.discovery import DiscoveryEngine
        return await DiscoveryEngine(self)._extract_links(page, base_url)

    async def _discover_apis(self, page, base_url):
        from titan.core.discovery import DiscoveryEngine
        return await DiscoveryEngine(self)._discover_apis(page, base_url)

    async def _extract_apis_from_js(self, page, base_url):
        from titan.core.discovery import DiscoveryEngine
        return await DiscoveryEngine(self)._extract_apis_from_js(page, base_url)

    async def _crawl_spa_routes(self, context, page, base_url):
        from titan.core.discovery import DiscoveryEngine
        return await DiscoveryEngine(self)._crawl_spa_routes(context, page, base_url)

    async def _parse_swagger_spec(self, context, base_url):
        from titan.core.discovery import DiscoveryEngine
        return await DiscoveryEngine(self)._parse_swagger_spec(context, base_url)

    async def _parse_postman_collection(self, context, base_url):
        from titan.core.discovery import DiscoveryEngine
        return await DiscoveryEngine(self)._parse_postman_collection(context, base_url)

    async def _discover_graphql_endpoints(self, context, base_url):
        from titan.core.discovery import DiscoveryEngine
        return await DiscoveryEngine(self)._discover_graphql_endpoints(context, base_url)

    async def _brute_force_common_params(self, context, base_url, max_endpoints=3):
        from titan.core.discovery import DiscoveryEngine
        return await DiscoveryEngine(self)._brute_force_common_params(context, base_url, max_endpoints)

    async def _brute_force_http_methods(self, context, base_url, max_endpoints=3):
        from titan.core.discovery import DiscoveryEngine
        return await DiscoveryEngine(self)._brute_force_http_methods(context, base_url, max_endpoints)

    # ==================================================================
    # Browserless scan (benchmark mode)
    # ==================================================================

    async def scan_browserless(self, target: str) -> ScanResult:
        """Browserless benchmark scan: module matrix without a browser."""
        t0 = time.time()
        self._scan_target = target
        result = ScanResult(target=target, started_at=t0, config_snapshot=self.config)

        denial = self._authorization_status(target)
        if denial:
            result.errors.append(denial)
            result.finished_at = time.time()
            logger.warning(f"[!] {denial}")
            return result

        try:
            from playwright.async_api import async_playwright
            p = await async_playwright().start()
        except Exception as exc:
            result.errors.append(f"playwright start failed: {exc}")
            result.finished_at = time.time()
            return result
        try:
            _api_context = await p.request.new_context(ignore_https_errors=True)
        except Exception as exc:
            result.errors.append(f"request context failed: {exc}")
            result.finished_at = time.time()
            try:
                await p.stop()
            except Exception:
                pass
            return result

        class _RequestShim:
            request = _api_context
        context = _RequestShim()

        auth_cfg = self.config.get("auth", {})
        if auth_cfg.get("cookies"):
            try:
                cookies = auth_cfg["cookies"]
                if isinstance(cookies, dict):
                    for name, value in cookies.items():
                        # add_cookies is part of the Playwright API; mypy
                        # resolves p.request to a stub without it.
                        await _api_context.add_cookies([  # type: ignore[attr-defined]
                            {"name": str(name), "value": str(value), "url": target}
                        ])
            except Exception:
                pass

        fingerprint: dict[str, Any] = {}
        try:
            resp = await _api_context.get(target, timeout=15000)
            headers = dict(resp.headers)
            body = await resp.text()
            fingerprint = await self.fingerprinter.analyze(headers, body, target)
            import re as _re
            from urllib.parse import urljoin
            from urllib.parse import urlparse as _up
            _host = (_up(target).hostname or "").lower()
            for _m in _re.finditer(r'''(?:href|src|action)=["']([^"'#]+)''', body):
                _u = urljoin(target, _m.group(1))
                if _u.startswith("http") and (_up(_u).hostname or "").lower() == _host:
                    self._discovered_urls.add(_u)
        except Exception as exc:
            result.errors.append(f"baseline fetch failed: {exc}")
        fingerprint["interactsh"] = self.interactsh

        seeds = self.config.get("crawl", {}).get("seed_urls", []) or []
        if not seeds:
            result.errors.append("scan_browserless requires crawl.seed_urls")
            result.finished_at = time.time()
            try:
                await p.stop()
            except Exception:
                pass
            return result

        for seed in seeds:
            seed = str(seed).strip()
            if not seed or not seed.startswith("http") or not self._is_in_scope(seed):
                continue
            try:
                seed_findings = await self._test_rest_api(context, target, seed, fingerprint)
                result.findings.extend(seed_findings)
                logger.info(f"    [+] Seed {seed}: {len(seed_findings)} finding(s)")
            except Exception as exc:
                result.errors.append(f"seed scan failed {seed}: {exc}")

        self._coverage["urls_crawled"] = len(seeds)
        self._coverage["apis_discovered"] = len(seeds)
        self._coverage["apis_scanned"] = len(seeds)
        self._coverage["queue_exhausted"] = True
        result.coverage = self._finalize_coverage(result)
        result.fingerprint = fingerprint
        result.finished_at = time.time()

        try:
            await _api_context.dispose()
        except Exception:
            pass
        try:
            await p.stop()
        except Exception:
            pass
        return result

    # NOTE: _test_rest_api / _endpoint_is_alive / _post_probe live in
    # ModuleRunner (the canonical implementations). engine.py forwards via
    # the _test_rest_api shim above; a shadowing duplicate was removed here
    # because it called _modules.run_attack_modules directly, bypassing the
    # engine._run_attack_modules hook (breaking test patching + parity).
