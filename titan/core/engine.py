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
from urllib.parse import urlparse

from titan.core.models import Finding, ScanResult
from titan.core.fingerprint import TechFingerprinter
from titan.core.constants import (
    CHECKPOINT_STATUSES,
    DRIVER_DEATH_MARKERS,
    GENERIC_CHECKPOINT_INDICATORS,
    ROOT_CAUSE_ATTACK_TYPES,
    STRONG_CHECKPOINT_INDICATORS,
)
from titan.core.helpers import (
    consume_task_exception,
    dedupe_findings,
    normalize_url,
)
from titan.core.crawl import Crawler
from titan.core.modules_runner import ModuleRunner
from titan.core.transport_mixin import TransportMixin
from titan.ai.payloadsmith import PayloadSmith
from titan.integrations.interactsh import InteractshClient
from titan.core.auth import AuthEngine
from titan.core.sessions import Identity, SessionPool
from titan.core.proxy import ProxyRotator
from titan.core.stealth import StealthEngine
from titan.core.anomaly import AnomalyTracker
from titan.verify.flows import apply_flows
from titan.verify.role_aware import RoleAwareScanner


class TitanEngine(TransportMixin):
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
    # Scope & authorization
    # ==================================================================

    def _is_in_scope(self, url: str) -> bool:
        """Fail-closed scope check: no target means nothing is in scope."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            target_hostname = urlparse(
                self._scan_target or self.config.get("target", "")
            ).hostname or ""
            if not target_hostname:
                return False
            if not hostname:
                return False
            return hostname == target_hostname or hostname.endswith("." + target_hostname)
        except Exception:
            return False

    def _is_spa_shell(self, url: str) -> bool:
        return "#" in url

    @staticmethod
    def _is_state_changing_path(url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(k in path for k in (
            "update", "create", "delete", "remove", "edit", "register",
            "signup", "add", "save", "set", "change", "reset",
            "upload", "transfer", "send", "approve", "role",
        ))

    def _authorization_status(self, target: str) -> str | None:
        from titan.core.authorization import authorize_target
        return authorize_target(
            target,
            consent_dir=self.config.get("exploit", {}).get("consent_dir", "consent"),
            practice_manifest=self.config.get("authorization", {}).get("practice_manifest"),
            key_path=self.config.get("exploit", {}).get("key_path"),
        )

    def _has_consent(self, target: str) -> bool:
        try:
            from titan.exploit.consent import verify_consent
            verify_consent(
                target,
                consent_dir=self.config.get("exploit", {}).get("consent_dir", "consent"),
            )
            return True
        except Exception:
            return False

    # ==================================================================
    # Driver health
    # ==================================================================

    def _is_driver_death(self, exc: BaseException) -> bool:
        msg = f"{type(exc).__name__}: {exc}".lower()
        return any(marker in msg for marker in DRIVER_DEATH_MARKERS)

    # ==================================================================
    # Page hardening (popups, dialogs, downloads, redirects)
    # ==================================================================

    async def _launch_crawler(self, p: Any, target: str):
        """Launch hardened Playwright browser; returns (browser, context).

        - ``browser: auto|system|bundled`` — ``system``/``auto`` uses the real
          installed Chrome via ``channel=chrome`` (genuine TLS fingerprint,
          defeats naive bot-gates); ``bundled`` forces Playwright's Chromium.
          Falls back to bundled if system Chrome is unavailable.
        - ``browser_profile: <path>`` — when set, uses a persistent context so
          cookies/sessions survive between runs (credentialed rounds); the
          returned ``browser`` is None and teardown closes the context.
        """
        browser_args = {"headless": self.config.get("headless", True)}
        proxy_config = self.config.get("proxy", {})
        if proxy_config.get("enabled") and proxy_config.get("list"):
            proxy_url = self.proxy_rotator.get_proxy(target)
            if proxy_url:
                browser_args["proxy"] = {"server": proxy_url}

        mode = str(self.config.get("browser", "auto")).lower()
        if mode in ("system", "auto"):
            browser_args["channel"] = "chrome"

        profile_dir = self.config.get("browser_profile") or None
        context_kwargs = dict(
            user_agent=self.stealth.get_user_agent(),
            extra_http_headers=self.stealth.get_headers(),
            ignore_https_errors=True,
        )

        def _persistent() -> Any:
            return p.chromium.launch_persistent_context(
                user_data_dir=profile_dir, **browser_args, **context_kwargs
            )

        try:
            if profile_dir:
                return None, await _persistent()
            browser = await p.chromium.launch(**browser_args)
            return browser, await browser.new_context(**context_kwargs)
        except Exception:
            if not browser_args.get("channel"):
                raise
            # System Chrome unavailable (e.g. CI runner) — fall back to bundled.
            browser_args.pop("channel")
            if profile_dir:
                return None, await _persistent()
            browser = await p.chromium.launch(**browser_args)
            return browser, await browser.new_context(**context_kwargs)

    async def _close_crawler(self, browser: Any, context: Any) -> None:
        """Close the crawler handle — browser for ephemeral launches, the
        persistent context itself when a profile dir is in use."""
        try:
            handle = browser or context
            await asyncio.wait_for(handle.close(), timeout=10)
        except Exception:
            pass

    def _harden_page(self, page: Any) -> None:
        try:
            page.on("popup", lambda p: asyncio.create_task(self._close_popup(p)))
            page.on("dialog", lambda d: asyncio.create_task(self._dismiss_dialog(d)))
            page.on("download", lambda dl: asyncio.create_task(self._suppress_download(dl)))
            page.on("response", self._record_redirect)
        except Exception:
            pass

    async def _close_popup(self, popup: Any) -> None:
        try:
            await asyncio.wait_for(popup.close(), timeout=3)
        except Exception:
            pass

    async def _dismiss_dialog(self, dialog: Any) -> None:
        try:
            await asyncio.wait_for(dialog.dismiss(), timeout=3)
        except Exception:
            pass

    async def _suppress_download(self, download: Any) -> None:
        try:
            await asyncio.wait_for(download.cancel(), timeout=3)
        except Exception:
            pass

    def _record_redirect(self, response: Any) -> None:
        try:
            if response.status in (301, 302, 303, 307, 308):
                req = getattr(response, "request", None)
                src = req.url if req is not None else ""
                self.redirect_chain.append({
                    "from": src,
                    "status": response.status,
                    "to": (response.headers or {}).get("location", ""),
                })
                if len(self.redirect_chain) > 200:
                    self.redirect_chain.pop(0)
        except Exception:
            pass

    # ==================================================================
    # Checkpoint detection
    # ==================================================================

    def _is_checkpoint(self, title: str, body: str, headers: dict, status: int = 200) -> bool:
        text = f"{title} {body[:5000]}".lower()
        for indicator in STRONG_CHECKPOINT_INDICATORS:
            if indicator in text:
                return True
        if status in CHECKPOINT_STATUSES:
            if "cloudflare" in headers.get("server", "").lower():
                return True
            for indicator in GENERIC_CHECKPOINT_INDICATORS:
                if indicator in text:
                    return True
        return False

    # ==================================================================
    # Coverage & platform
    # ==================================================================

    def _finalize_coverage(self, result: ScanResult) -> dict[str, Any]:
        from titan.verify.coverage import finalize_coverage
        return finalize_coverage(
            self._coverage, driver_dead=self._driver_dead,
            max_pages=self.max_pages, max_depth=self.max_depth,
        )

    def _select_platform_brain(self, fingerprint: dict, html: str, headers: dict) -> Any | None:
        try:
            from titan.brains import BrainRegistry, MoodleBrain
        except ImportError:
            return None
        registry = BrainRegistry()
        registry.register(MoodleBrain())
        return registry.select(fingerprint, html, headers)

    def _prior_observed(self, target: str) -> dict[str, Any] | None:
        try:
            from pathlib import Path
            import json as _json
            from titan.reporting import site_slug as _slug
            out_dir = Path(self.config.get("output_dir", "findings"))
            p = out_dir / _slug(target) / "intel.json"
            if p.exists():
                return _json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
        return None

    def _looks_like_api(self, url: str) -> bool:
        if not self._is_in_scope(url):
            return False
        api_indicators = ["/api/", "/sales/", "/v1/", "/v2/", "/rest/", "/graphql", "api.", ".json"]
        path = urlparse(url.lower()).path
        return any(ind in path for ind in api_indicators)

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
            print(f"[!] {denial}")
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
            except Exception:
                pass

        try:
            result = await self._run_scan_pipeline(target, result)
        except asyncio.TimeoutError:
            result.errors.append("Scan timed out after 240s")
            print("[!] Scan timed out")
        except Exception as exc:
            import traceback
            traceback.print_exc()
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
                print(f"[+] Site report written to {site_dir}")
            except Exception as exc:
                print(f"[!] Failed to write site report: {exc}")

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

            print(f"[+] Loading target: {target}")
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
            print(f"[+] Page title: {title}")
            print(f"[+] Response status: {response.status if response else 'N/A'}")

            if self._is_checkpoint(title, body, headers, response.status if response else 200):
                result.errors.append(f"Security checkpoint blocked access: {title}")
                self._coverage["checkpoint_blocked"] = True
                print(f"[!] Checkpoint detected: {title}")
                result.finished_at = time.time()
                await self._close_crawler(browser, context)
                return result

            fingerprint = await self.fingerprinter.analyze(headers, body, target)
            fingerprint["interactsh"] = self.interactsh
            result.fingerprint = fingerprint
            print(f"[+] Technologies detected: {fingerprint.get('technologies', [])[:10]}")

            # Platform brain
            self._platform_brain = self._select_platform_brain(fingerprint, body, headers)
            if self._platform_brain is not None:
                print(f"[+] Platform brain: {self._platform_brain.name}")
                for seed in self._platform_brain.extra_seed_urls(target):
                    if seed not in self.visited and self._is_in_scope(seed):
                        self.visited.add(seed)
                        self._discovered_urls.add(seed)
                self._platform_extra_params = list(self._platform_brain.extra_parameters())
            else:
                self._platform_extra_params = []

            # Authentication
            if self.config.get("auth"):
                print("[+] Attempting authentication...")
                logged_in = await self.auth_engine.login(context, page, target)
                if logged_in:
                    role_name = self.auth_engine.get_current_role() or "user"
                    print(f"[+] Authenticated as {role_name}")
                    self._role_scanner.record_role(role_name)
                    auth_headers = self.auth_engine.get_auth_headers()
                    if auth_headers:
                        await context.set_extra_http_headers(auth_headers)
                    self.session_pool.add(Identity(
                        name=role_name, headers=dict(auth_headers),
                        cookies=self.auth_engine.get_cookies(),
                    ))
                else:
                    print("[!] Authentication failed, continuing unauthenticated")

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
                print("[!] Crawl timed out, proceeding with interaction")
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
                        print("[+] SPA harness: skipped (no hash routes or SPA framework detected)")

            # Multi-role testing
            await self._run_multi_role(context, page, target, fingerprint, result)

            # Session replay
            await self._run_session_replay(context, target, result)

            # Identity matrix
            if len(self.session_pool) >= 2 and not self._driver_dead:
                print(f"[+] Identity matrix: {len(self.session_pool)} identities")
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
                    except Exception:
                        pass
            try:
                await asyncio.wait_for(_interact(), timeout=budget)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                pass

        await asyncio.gather(
            *[interact_one(vu) for vu in interaction_targets],
            return_exceptions=True,
        )

    async def _interact_and_capture(self, context, page, base_url: str) -> list[str]:
        """Interact with a page and capture API endpoints."""
        from urllib.parse import urlparse
        from titan.core.spa import select_runtime_apis

        print(f"[+] Starting interaction on {base_url}")
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
            except Exception:
                pass

        page.on("request", capture_request)
        page.on("websocket", capture_websocket)

        try:
            forms = await self._extract_forms(page)
            for form in forms:
                try:
                    await self._fill_and_submit_form(page, form, base_url)
                    await page.wait_for_timeout(1000)
                except Exception:
                    continue
        except Exception:
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
                            except Exception:
                                continue
                except Exception:
                    continue
        except Exception:
            pass

        try:
            await page.evaluate('''() => window.scrollTo(0, document.body.scrollHeight)''')
            await page.wait_for_timeout(1000)
        except Exception:
            pass

        page.remove_listener("request", capture_request)
        api_endpoints = select_runtime_apis(
            captured_urls, ws_urls=ws_urls, base_url=base_url,
            scope_host=urlparse(self._scan_target).hostname or "",
        )
        print(f"[+] Interaction captured {len(api_endpoints)} API endpoints ({len(ws_urls)} websocket)")
        return api_endpoints

    async def _extract_forms(self, page):
        return await page.evaluate('''() => {
            const forms = [];
            for (const f of document.querySelectorAll('form')) {
                const inputs = [];
                for (const inp of f.querySelectorAll('input, textarea, select, [contenteditable="true"]')) {
                    const isEditable = inp.getAttribute && inp.getAttribute('contenteditable') === 'true';
                    inputs.push({
                        name: inp.name || inp.id || inp.getAttribute('data-param') || '',
                        type: inp.type || (isEditable ? 'richtext' : 'text'),
                        value: inp.value || inp.innerText || '',
                        tag: inp.tagName.toLowerCase()
                    });
                }
                forms.push({
                    action: f.action || window.location.href,
                    method: (f.method || 'GET').toUpperCase(),
                    inputs
                });
            }
            return forms;
        }''')

    async def _fill_and_submit_form(self, page, form: dict, base_url: str) -> None:
        inputs = form.get("inputs", [])
        for inp in inputs:
            try:
                name = inp.get("name", "")
                if not name:
                    continue
                await page.evaluate(f'''(name) => {{
                    const el = document.querySelector('[name="{{name}}"]');
                    if (el) {{
                        el.value = 'test';
                        el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                        el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                    }}
                }}''', name)
            except Exception:
                continue
        try:
            submit_btn = await page.query_selector('button[type="submit"], input[type="submit"]')
            if submit_btn:
                await submit_btn.click(force=True)
            else:
                await page.keyboard.press("Enter")
        except Exception:
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
                print("[+] SPA harness: no route table hydrated")
                return
            print(f"[+] SPA harness: walking {len(routes)} hydrated route(s)")
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
                        except Exception:
                            pass
                        captured = await self._interact_and_capture(context, spa_page, route)
                    await asyncio.wait_for(_walk_one(), timeout=per_route_budget)
                except asyncio.TimeoutError:
                    pass
                except Exception:
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
            print(f"[+] SPA harness: {captured_total} runtime API endpoint(s) captured")
        except (asyncio.TimeoutError, Exception):
            pass
        finally:
            if spa_page is not None:
                try:
                    await asyncio.wait_for(spa_page.close(), timeout=5)
                except Exception:
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
            scope_host = urlparse(self._scan_target).hostname or ""
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

    # ==================================================================
    # Multi-role, session replay, optional phases
    # ==================================================================

    async def _run_multi_role(self, context, page, target, fingerprint, result):
        roles = self.config.get("auth", {}).get("roles", [])
        if not roles or self._driver_dead:
            return
        print(f"[+] Testing {len(roles)} additional roles...")
        for role_creds in roles:
            try:
                await self.auth_engine.logout(context, page, target)
                logged_in = await self.auth_engine.login_as_role(context, page, target, role_creds)
                if logged_in:
                    role_name = role_creds.get("role", "unknown")
                    print(f"[+] Scanning as role: {role_name}")
                    self._role_scanner.record_role(role_name)
                    auth_headers = self.auth_engine.get_auth_headers()
                    if auth_headers:
                        await context.set_extra_http_headers(auth_headers)
                    self.session_pool.add(Identity(
                        name=role_name, headers=dict(auth_headers),
                        cookies=self.auth_engine.get_cookies(),
                    ))
                    for visited_url in list(self.visited)[:10]:
                        try:
                            api_findings = await asyncio.wait_for(
                                self._modules._run_api_modules(context, target, visited_url, {}),
                                timeout=15,
                            )
                            for f in api_findings:
                                f.tags = f.tags + [f"role:{role_name}"]
                            result.findings.extend(api_findings)
                        except Exception:
                            continue
            except Exception:
                continue

    async def _run_session_replay(self, context, target, result):
        if not self._gated_routes or self._driver_dead:
            return
        replay_count = 0
        replay_limit = min(len(self._gated_routes), 10)
        print(f"[+] Session replay: re-scanning {replay_limit} gated routes with auth...")
        for gated_url in list(self._gated_routes)[:replay_limit]:
            try:
                _auth_hdrs = dict(self.auth_engine.get_auth_headers() or {})
                t_resp = await self._transport_send(gated_url, headers=_auth_hdrs, timeout=10.0)
                gated_status = 0
                if t_resp and not t_resp.is_error:
                    gated_status = t_resp.status
                else:
                    gated_resp = await asyncio.wait_for(
                        context.request.get(gated_url, timeout=10000), timeout=15,
                    )
                    if gated_resp:
                        gated_status = gated_resp.status
                if gated_status == 200:
                    print(f"    [+] REPLAY {gated_url} → {gated_status} (was 401/403, now open)")
                    replay_findings = await asyncio.wait_for(
                        self._modules._run_api_modules(context, target, gated_url, {}),
                        timeout=15,
                    )
                    for f in replay_findings:
                        f.tags = f.tags + ["scope:auth", "replay:true"]
                    result.findings.extend(replay_findings)
                    replay_count += 1
            except Exception:
                continue
        if replay_count:
            print(f"    [i] Session replay: {replay_count} routes re-opened with auth")
        self._coverage["replayed_gated"] = replay_count

    async def _run_optional_phases(self, target, result, page):
        """Run LLM, storage, subdomain, IMDS, SBOM, and deep audit phases."""
        if self.config.get("llm", {}).get("enabled", True):
            await self._run_llm_channel(target, result)
        if self.config.get("cloud", {}).get("storage", {}).get("enabled", True):
            await self._run_storage_probe(target, result)
        if self.config.get("subdomain_takeover", {}).get("enabled", True):
            await self._run_subdomain_takeover(target, result)
        if self.config.get("cloud", {}).get("imds", {}).get("enabled", True):
            await self._probe_cloud_imds(target, result)
        if self.config.get("crawl", {}).get("supplychain", {}).get("enabled", True):
            await self._run_sbom_analysis(target, result, page)
        if self.config.get("deep_audit", {}).get("enabled", True):
            await self._run_deep_audit(target, result)

    # ==================================================================
    # Optional phase implementations (LLM, storage, subdomain, etc.)
    # ==================================================================

    @staticmethod
    def _is_llm_endpoint(url: str) -> bool:
        path = urlparse(url).path.lower()
        markers = (
            "/api/chat", "/chat/completions", "/v1/chat", "/v1/completions",
            "/api/assistant", "/api/generate", "/api/completion",
            "/api/message", "/api/ai", "/api/ask", "/api/answer",
            "/api/query", "/api/inference", "/api/prompt", "/api/completions",
        )
        return any(m in path for m in markers)

    async def _run_llm_channel(self, target, result):
        llm_cfg = self.config.get("llm", {})
        if not llm_cfg.get("enabled", True):
            return
        endpoints: list[str] = [e for e in (llm_cfg.get("endpoints") or []) if e]
        discovered = [u for u in list(self.visited) if self._is_llm_endpoint(u)]
        for u in discovered:
            if u not in endpoints:
                endpoints.append(u)
        if not endpoints:
            return
        endpoints = endpoints[:2]
        try:
            from titan.modules.llm.channel import LLMChannel
            from titan.modules.llm.detector import LLMDetector
            channel = getattr(self, "_llm_channel", None)
            if channel is None:
                channel = LLMChannel(
                    timeout=float(llm_cfg.get("timeout", 15)),
                    model=llm_cfg.get("model", "gpt-4o-mini"),
                )
            interactsh = getattr(self, "_llm_interactsh", None) or self.interactsh
            detector = LLMDetector(channel, interactsh, llm_cfg)
            per_endpoint = float(llm_cfg.get("per_endpoint_timeout", 40))
            for ep in endpoints:
                print(f"[+] LLM channel: probing {ep}")
                try:
                    findings = await asyncio.wait_for(detector.scan(target, ep), timeout=per_endpoint)
                    result.findings.extend(findings)
                    if findings:
                        print(f"    [+] Track C: {len(findings)} LLM findings on {ep}")
                except (asyncio.TimeoutError, Exception):
                    continue
        except Exception:
            return

    async def _run_storage_probe(self, target, result):
        if not self.config.get("cloud", {}).get("storage", {}).get("enabled", True):
            return
        try:
            from titan.modules.cloud.storage import StorageProbe
            probe = StorageProbe(fetcher=getattr(self, "_storage_fetcher", None))
            storage_findings = await probe.scan(target, result.findings)
            result.findings.extend(storage_findings)
            if storage_findings:
                print(f"[+] Track D: {len(storage_findings)} publicly listable bucket(s) found")
        except Exception:
            return

    async def _run_subdomain_takeover(self, target, result):
        if not self.config.get("subdomain_takeover", {}).get("enabled", True):
            return
        try:
            from titan.modules.subdomain_takeover.detector import SubdomainTakeoverDetector
            detector = SubdomainTakeoverDetector()
            takeover_findings = await detector.scan(
                context=None, target=target, method="GET",
                url=target, params={}, fingerprint={},
            )
            result.findings.extend(takeover_findings)
            if takeover_findings:
                print(f"[+] Subdomain takeover: {len(takeover_findings)} vulnerable subdomain(s) found")
        except Exception as exc:
            print(f"[!] Subdomain takeover detection failed: {exc}")

    async def _probe_cloud_imds(self, target, result):
        ssrf_findings = [
            f for f in result.findings
            if str(getattr(f, "type", "")) in ("ssrf", "AttackType.SSRF", "cloud_imds_exposure")
            and f.url
        ]
        if not ssrf_findings:
            return
        try:
            from titan.modules.cloud_control.imds import IMDSProber
        except ImportError:
            return
        prober = IMDSProber(timeout=5.0)
        ssrf_url = ssrf_findings[0].url
        ssrf_param = ssrf_findings[0].param or "url"

        async def _ssrf_sink(imds_url, method="GET", headers=None, timeout=5.0):
            import aiohttp
            from urllib.parse import urlparse as _up, parse_qs, urlencode
            parsed = _up(ssrf_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[ssrf_param] = [imds_url]
            new_query = urlencode(params, doseq=True)
            sink_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.request(
                        method=method, url=sink_url, headers=headers or {},
                        timeout=aiohttp.ClientTimeout(total=timeout), ssl=False,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        return (resp.status, dict(resp.headers), body)
            except Exception:
                return (0, {}, "")

        print("[+] Cloud IMDS probing through SSRF sink...")
        imds_findings = await prober.probe(_ssrf_sink)
        if imds_findings:
            result.findings.extend(imds_findings)
            critical = sum(1 for f in imds_findings if f.get("severity") == "critical")
            print(f"[+] Cloud IMDS: {len(imds_findings)} finding(s) ({critical} critical)")

    async def _run_sbom_analysis(self, target, result, page=None):
        try:
            from titan.modules.supplychain.sbom import SBOMAnalyzer
        except ImportError:
            return
        analyzer = SBOMAnalyzer()
        html = ""
        if page:
            try:
                html = await page.content()
            except Exception:
                pass
        if not html:
            return
        report = analyzer.analyze(html, page_url=target)
        if report.findings:
            for f_dict in report.findings:
                try:
                    from titan.core.models import Severity, AttackType
                    severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                                    "medium": Severity.MEDIUM, "low": Severity.LOW}
                    finding = Finding(
                        type=AttackType.SUPPLY_CHAIN if hasattr(AttackType, 'SUPPLY_CHAIN') else AttackType.OTHER,
                        severity=severity_map.get(f_dict.get("severity", "medium"), Severity.MEDIUM),
                        title=f_dict.get("title", "Supply Chain Finding"),
                        url=target, param=f_dict.get("type", ""),
                        evidence=f_dict.get("evidence", ""), confidence=0.8,
                        cvss_score=f_dict.get("cvss_score", 5.0),
                        tags=["supplychain", "sbom"],
                        metadata=f_dict.get("metadata", {}),
                    )
                    result.findings.append(finding)
                except Exception:
                    pass
            print(f"[+] SBOM: {len(report.findings)} finding(s)")

    async def _run_deep_audit(self, target, result):
        try:
            from titan.modules.deep_audit.prober import DeepAuditor
            auditor = DeepAuditor()
            audit_result = await auditor.audit(
                target, budget=float(self.config.get("deep_audit", {}).get("budget", 60)),
            )
            from titan.core.models import Severity, AttackType
            for af in audit_result.findings:
                if af.severity in ("critical", "high", "medium"):
                    try:
                        sev = Severity(af.severity)
                    except ValueError:
                        sev = Severity.MEDIUM
                    try:
                        atype = AttackType(af.category.replace("_", "-").replace("misconfiguration", "info-leak"))
                    except ValueError:
                        atype = AttackType.INFO_LEAK
                    finding = Finding(
                        target=target, url=target, method="GET", param="deep-audit",
                        location="cloud", payload=af.description[:200],
                        attack_type=atype, severity=sev,
                        confidence=0.95 if af.verified else 0.7,
                        status=200, evidence=af.proof,
                        tier="confirmed" if af.verified else "suspicious",
                        tags=["deep-audit", af.category, af.id],
                        notes=f"{af.title}: {af.remediation}",
                    )
                    result.findings.append(finding)
            verified = sum(1 for f in audit_result.findings if f.verified)
            print(f"[+] Deep Audit: {len(audit_result.findings)} finding(s), {verified} verified")
        except Exception as exc:
            result.errors.append(f"Deep audit failed: {exc}")
            print(f"[!] Deep audit: {exc}")

    # ==================================================================
    # Post-scan phases (hostile, brain, evolution, anti-forensics, fleet)
    # ==================================================================

    async def _run_post_scan_phases(self, target, result):
        """Fleet, hostile pass, anti-forensics, brain loop, evolution."""
        if self.config.get("fleet", {}).get("enabled", False):
            await self._run_fleet_scan(target, result)

        supplychain_cfg = self.config.get("crawl", {}).get("supplychain", {})
        if self._hostile or supplychain_cfg.get("enabled", True):
            try:
                await self._run_hostile_pass(target, result)
            except Exception as exc:
                result.errors.append(f"Track G hostile pass failed: {exc}")

        try:
            await self._apply_anti_forensics(target, result)
        except Exception as exc:
            result.errors.append(f"Anti-forensics failed: {exc}")

        try:
            await self._run_brain_loop(target, result)
        except Exception as exc:
            result.errors.append(f"Brain loop failed: {exc}")

        try:
            await self._run_evolution(target, result)
        except Exception as exc:
            result.errors.append(f"Evolution engine failed: {exc}")

        # CVSS & PoC generation
        from titan.core.cvss import CVSSScorer
        from titan.core.poc import PoCGenerator
        for f in result.findings:
            if f.tier != "confirmed":
                f.cvss_score = None
                f.cvss_vector = ""
                f.poc_curl = ""
                f.poc_python = ""
                continue
            if "ai_escalation" in f.metadata or not f.cvss_score:
                cvss_data = CVSSScorer.score(f)
                f.cvss_score = cvss_data["cvss_score"]
                f.cvss_vector = cvss_data["cvss_vector"]
            if not f.poc_curl or not f.poc_python:
                poc = PoCGenerator.generate(f)
                f.poc_curl = poc["curl"]
                f.poc_python = poc["python"]

        # Exploit phase
        try:
            await self._run_exploit_modules(target, result)
        except Exception as exc:
            result.errors.append(f"Track E exploit phase failed: {exc}")

    async def _run_hostile_pass(self, target, result):
        import aiohttp
        from titan.hostile import findings_from_dicts, run_pass
        from titan.reporting import site_slug

        candidates = [target] + [
            u for u in self.visited
            if self._is_in_scope(u) and not self._is_spa_shell(u)
        ]
        candidates = list(dict.fromkeys(candidates))[:3]
        samples: list[dict] = []
        for u in candidates:
            try:
                ua = self.stealth.get_user_agent()
                _hdrs = {"User-Agent": ua} if ua else {}
                transport_resp = await self._transport_send(u, headers=_hdrs, timeout=12.0)
                if transport_resp and not transport_resp.is_error and transport_resp.status == 200:
                    samples.append({"url": u, "html": transport_resp.text[:600000]})
                    continue
                async with aiohttp.ClientSession() as _sess:
                    async with _sess.get(u, timeout=12, ssl=False, headers=_hdrs or None) as resp:
                        if resp.status == 200:
                            text = await resp.text(errors="replace")
                            samples.append({"url": u, "html": text[:600000]})
            except Exception:
                continue
        if not samples:
            return
        consented = self._has_consent(target)
        async with aiohttp.ClientSession() as _hostile_session:
            payload = await run_pass(
                samples, target, target=target, session=_hostile_session,
                consented=consented, prior_observed=self._prior_observed(target),
            )
        payload["redirect_chain"] = self.redirect_chain[-50:]
        result.hostile = payload
        new_findings = findings_from_dicts(payload.get("findings", []))
        result.findings.extend(new_findings)
        print(f"[+] Track G: {len(new_findings)} hostile-surface finding(s)")

    async def _apply_anti_forensics(self, target, result):
        af_cfg = self.config.get("stealth", {}).get("anti_forensics", {})
        if not af_cfg.get("enabled", False):
            return
        try:
            from titan.stealth.advanced import AntiForensics
            af = AntiForensics(
                profile=af_cfg.get("profile", "browser"),
                decoy_count=int(af_cfg.get("decoy_count", 3)),
                polymorphic_count=int(af_cfg.get("polymorphic_count", 3)),
            )
            if self._transport_http:
                try:
                    sent = await af.decoys.inject(target, self._transport_http, count=int(af_cfg.get("decoy_count", 3)))
                    if sent:
                        print(f"[+] Anti-forensics: {sent} decoy request(s) sent")
                except Exception:
                    pass
            high_value = [f for f in result.findings if f.confidence >= 0.7 and f.payload][:5]
            if high_value:
                report_data = []
                for finding in high_value:
                    attack = af.prepare_attack(finding.payload, target, variant="auto")
                    report_data.append({
                        "original": finding.payload,
                        "variants": attack["polymorphic_payloads"],
                    })
                print(f"[+] Anti-forensics: {len(report_data)} payload(s) polymorphized")
        except Exception as exc:
            result.errors.append(f"Anti-forensics failed: {exc}")
            print(f"[!] Anti-forensics: {exc}")

    async def _run_brain_loop(self, target, result):
        brain_cfg = self.config.get("brain", {})
        if not brain_cfg.get("enabled", True):
            return
        high_value = [
            f for f in result.findings
            if f.confidence >= 0.6 and f.attack_type.value in (
                "SQLi", "XSS", "SSRF", "RCE", "LFI", "SSTI", "XXE", "NoSQLi",
            )
        ]
        if not high_value:
            return
        print(f"[+] Brain loop: {len(high_value)} high-value finding(s) to mutate")
        try:
            from titan.brain.loop import BrainLoop
            brain = BrainLoop(target=target)
            budget = float(brain_cfg.get("budget", 90))
            deadline = time.time() + budget
            mutations_found = 0
            bypasses_found = 0
            for finding in high_value:
                if time.time() > deadline:
                    break
                try:
                    from titan.stealth.advanced import PolymorphicEngine
                    poly = PolymorphicEngine()
                    variants = poly.generate(
                        finding.payload, variant="auto",
                        count=int(brain_cfg.get("variants_per_finding", 5)),
                    )
                except Exception:
                    variants = [finding.payload]
                for variant in variants:
                    if time.time() > deadline:
                        break
                    try:
                        test_url = self._build_variant_url(finding, variant)
                        if not test_url:
                            continue
                        resp = await self._transport_send(test_url, method=finding.method, timeout=8.0)
                        if resp is None or resp.is_error:
                            continue
                        is_bypass = self._detect_bypass(finding, resp)
                        mutations_found += 1
                        if is_bypass:
                            bypasses_found += 1
                            bypass_finding = Finding(
                                url=test_url, method=finding.method,
                                param=finding.param, location=finding.location,
                                payload=variant, attack_type=finding.attack_type,
                                severity=finding.severity,
                                confidence=min(finding.confidence + 0.1, 0.99),
                                status=resp.status,
                                evidence="Brain bypass: variant produced different response",
                                tier="suspicious",
                                tags=finding.tags + ["brain:bypass", "mutation:true"],
                                notes=f"Mutated from {finding.attack_type.value} at {finding.url}",
                            )
                            result.findings.append(bypass_finding)
                    except Exception:
                        continue
                try:
                    brain.strategy.record_result(
                        module=f"brain_{finding.attack_type.value.lower()}",
                        success=bypasses_found > 0, value=0.1,
                    )
                except Exception:
                    pass
            if mutations_found:
                print(f"[+] Brain loop: {mutations_found} mutations tested, {bypasses_found} bypass(es) found")
        except Exception as exc:
            result.errors.append(f"Brain loop failed: {exc}")
            print(f"[!] Brain loop: {exc}")

    def _build_variant_url(self, finding, variant: str) -> str | None:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
        try:
            parsed = urlparse(finding.url)
            if finding.location == "query":
                qs = parse_qs(parsed.query, keep_blank_values=True)
                if finding.param in qs:
                    qs[finding.param] = [variant]
                return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            elif finding.location == "path":
                return finding.url.replace(finding.param, quote(variant, safe=""))
            return None
        except Exception:
            return None

    def _detect_bypass(self, original_finding, resp) -> bool:
        try:
            if resp.status != getattr(original_finding, "status", 200):
                if resp.status == 200 and getattr(original_finding, "status", 200) in (403, 405, 503):
                    return True
                if resp.status == 200 and original_finding.attack_type.value in ("SQLi", "XSS", "RCE"):
                    return True
            body = resp.text.lower() if hasattr(resp, "text") else ""
            if original_finding.attack_type.value == "SQLi" and any(m in body for m in ["sql", "syntax", "mysql", "sqlite", "postgres", "ORA-"]):
                return True
            if original_finding.attack_type.value == "XSS" and any(m in body for m in ["<script", "alert(", "onerror", "onload"]):
                return True
            return False
        except Exception:
            return False

    async def _run_evolution(self, target, result):
        evolution_cfg = self.config.get("brain", {}).get("evolution", {})
        if not evolution_cfg.get("enabled", True):
            return
        bypass_findings = [f for f in result.findings if "brain:bypass" in (f.tags or [])]
        if not bypass_findings:
            return
        print(f"[+] Evolution engine: {len(bypass_findings)} bypass finding(s) to analyze")
        try:
            from titan.brain.evolution import EvolutionEngine
            engine = EvolutionEngine()
            generated = 0
            for finding in bypass_findings[:5]:
                try:
                    detector_code = engine.generate(
                        finding_type=finding.attack_type.value,
                        pattern=finding.payload,
                        context=finding.notes or "",
                    )
                    if not detector_code:
                        continue
                    if not engine.validate(detector_code):
                        continue
                    if evolution_cfg.get("persist", True):
                        path = engine.write_detector(
                            detector_code,
                            name=f"auto_{finding.attack_type.value.lower()}_{generated}",
                        )
                        if path:
                            print(f"    [+] Evolution: wrote detector to {path}")
                            generated += 1
                except Exception:
                    continue
            if generated:
                print(f"[+] Evolution engine: {generated} detector(s) generated")
        except Exception as exc:
            result.errors.append(f"Evolution engine failed: {exc}")
            print(f"[!] Evolution engine: {exc}")

    async def _run_exploit_modules(self, target, result):
        cfg = self.config.get("exploit", {})
        if not cfg.get("enabled", False):
            return
        verified = [f for f in result.findings if f.verified]
        if not verified:
            return
        from pathlib import Path
        from titan.exploit.consent import ConsentError
        from titan.exploit.listener import ExploitListener
        from titan.exploit.planner import PlanningError, stage_and_register, usable_findings
        from titan.exploit.sqli_extractor import ExtractionError
        from titan.exploit.sqlidump import sqlidump, usable_sqli_findings
        from titan.exploit.ssrfpivot import PivotError, ssrf_pivot, usable_ssrf_findings
        from titan.exploit.upload_planner import stage_webshell, usable_upload_findings

        consent_dir = Path(cfg.get("consent_dir", "consent"))
        output_dir = Path(cfg.get("output_dir", "findings"))
        key_path = Path(cfg["key_path"]) if cfg.get("key_path") else None
        max_per_type = int(cfg.get("max_per_type", 2))
        budget = float(cfg.get("budget", 120))

        lcfg = cfg.get("listener", {})
        listener = ExploitListener(
            host=lcfg.get("host", "127.0.0.1"),
            port=int(lcfg.get("port", 8770)),
            nonce=lcfg.get("nonce"),
        )
        started = False
        if lcfg.get("start", False):
            try:
                await asyncio.wait_for(listener.start(), timeout=10)
                started = True
                print(f"[+] Track E: listener up at {listener.bound_url}")
            except Exception as exc:
                result.errors.append(f"Track E listener failed to start: {exc}")
                print(f"[!] Track E: listener failed to start ({exc})")

        deadline = time.time() + budget
        sessions: list[dict[str, Any]] = []

        async def guarded(what, coro):
            remaining = deadline - time.time()
            if remaining <= 0:
                coro.close()
                return None
            try:
                return await asyncio.wait_for(coro, timeout=max(1.0, min(remaining, 60)))
            except (ConsentError, PlanningError, ExtractionError, PivotError, asyncio.TimeoutError) as exc:
                result.errors.append(f"Track E {what}: skipped ({exc})")
                print(f"    [!] Track E {what}: {exc}")
            except Exception as exc:
                result.errors.append(f"Track E {what}: failed ({exc})")
                print(f"    [!] Track E {what}: {exc}")
            return None

        def record(channel, store, extra=None):
            try:
                meta = store.read_meta()
            except Exception:
                meta = {}
            entry: dict[str, Any] = {
                "channel": channel, "session_id": store.session_id,
                "target": target, "status": meta.get("status", "active"),
                "dir": str(store.dir),
            }
            if extra:
                entry.update(extra)
            sessions.append(entry)
            print(f"    [+] Track E: {channel} session {entry['session_id']} staged")

        for f in usable_findings(verified, target)[:max_per_type]:
            store = await guarded(
                f"RCE {f.method} {f.url}",
                stage_and_register(f, target, listener, consent_dir=consent_dir, output_dir=output_dir, key_path=key_path),
            )
            if store:
                record("rce-agent", store, {"finding_url": f.url})

        for f in usable_upload_findings(verified, target)[:max_per_type]:
            out = await guarded(
                f"upload {f.method} {f.url}",
                stage_webshell(f, target, listener, consent_dir=consent_dir, output_dir=output_dir, key_path=key_path),
            )
            if out:
                store, ws_url = out
                record("webshell", store, {"finding_url": f.url, "webshell_url": ws_url})

        for f in usable_sqli_findings(verified, target)[:max_per_type]:
            store = await guarded(
                f"sqli {f.method} {f.url}",
                sqlidump(f, target, consent_dir=consent_dir, output_dir=output_dir, key_path=key_path),
            )
            if store:
                record("sqli-extraction", store, {"finding_url": f.url})

        for f in usable_ssrf_findings(verified, target)[:max_per_type]:
            store = await guarded(
                f"ssrf {f.method} {f.url}",
                ssrf_pivot(f, target, consent_dir=consent_dir, output_dir=output_dir, key_path=key_path),
            )
            if store:
                record("ssrf-pivot", store, {"finding_url": f.url})

        if started:
            try:
                await asyncio.wait_for(listener.stop(), timeout=5)
            except Exception:
                pass
        result.exploit_sessions = sessions
        if sessions:
            print(f"[+] Track E: {len(sessions)} exploitation session(s) staged")

    async def _run_fleet_scan(self, target, result):
        fleet_cfg = self.config.get("fleet", {})
        if not fleet_cfg.get("enabled", False):
            return
        try:
            from titan.fleet import FleetCoordinator, AgentType
        except ImportError:
            print("[!] Fleet module not available — skipping")
            return
        discovered = list(self.visited)[:5]
        targets = [target] + [u for u in discovered if u != target and self._is_in_scope(u)]
        targets = list(dict.fromkeys(targets))[:fleet_cfg.get("max_targets", 5)]
        agent_names = fleet_cfg.get("agents", ["recon", "identity", "learning"])
        agent_types = []
        for name in agent_names:
            try:
                agent_types.append(AgentType(name))
            except ValueError:
                pass
        if not agent_types:
            agent_types = [AgentType.RECON, AgentType.IDENTITY, AgentType.LEARNING]
        budget = fleet_cfg.get("budget", 120.0)
        print(f"[+] Fleet scan: {len(targets)} target(s), {len(agent_types)} agent type(s), budget={budget}s")
        coordinator = FleetCoordinator(
            max_concurrent=fleet_cfg.get("max_concurrent", 5),
            consent_dir=self.config.get("exploit", {}).get("consent_dir", "consent"),
        )
        context = {"findings": result.findings, "fingerprint": result.fingerprint, "transport": self._transport_http}
        fleet_result = await coordinator.scan_all(targets=targets, agent_types=agent_types, budget=budget, context=context)
        fleet_count = 0
        for merged in fleet_result.merged_findings:
            exists = any(f.type == merged.type and f.url == merged.url and f.param == merged.param for f in result.findings)
            if not exists:
                try:
                    from titan.core.models import Severity, AttackType
                    severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                                    "medium": Severity.MEDIUM, "low": Severity.LOW}
                    finding = Finding(
                        type=AttackType(merged.type) if merged.type in [e.value for e in AttackType] else AttackType.OTHER,
                        severity=severity_map.get(merged.severity, Severity.MEDIUM),
                        title=f"[Fleet] {merged.type}: {merged.param or 'global'}",
                        url=merged.url, param=merged.param, evidence=merged.evidence,
                        confidence=merged.effective_confidence, cvss_score=merged.cvss_score,
                        tags=["fleet", f"sources:{','.join(merged.sources)}"],
                        metadata={"fleet_sources": merged.sources, "corroborated": merged.is_corroborated},
                    )
                    result.findings.append(finding)
                    fleet_count += 1
                except Exception:
                    pass
        if fleet_result.mutations:
            result.mutations = getattr(result, "mutations", []) + fleet_result.mutations
        if fleet_count:
            print(f"[+] Fleet: {fleet_count} new finding(s) merged")

    # ==================================================================
    # Verification & evidence gates
    # ==================================================================

    async def _run_verification(self, result):
        from titan.verify.oracles import enforce_evidence
        ev_stats = enforce_evidence(result.findings)
        if ev_stats.get("demoted"):
            print(f"[!] Evidence gate: demoted {ev_stats['demoted']} verified finding(s)")

        from titan.verify.auto_verify import AutoVerifier
        av = AutoVerifier()
        if getattr(self, "_crawl_context", None):
            verified_count = 0
            demoted_count = 0
            for f in result.findings:
                if f.verified and f.confidence >= 0.5:
                    original_verified = f.verified
                    await av.verify_finding(self._crawl_context, f)
                    if original_verified and not f.verified:
                        demoted_count += 1
                    elif f.verified:
                        verified_count += 1
            if demoted_count:
                print(f"[!] Auto-verify: demoted {demoted_count} finding(s)")
            if verified_count:
                print(f"[+] Auto-verify: {verified_count} finding(s) passed")

        role_scanner = getattr(self, "_role_scanner", None)
        if isinstance(role_scanner, RoleAwareScanner):
            role_adjusted = 0
            for f in result.findings:
                if getattr(f, "verified", False):
                    role_scanner.adjust_finding(f)
                    if getattr(f, "metadata", {}).get("role_gated"):
                        role_adjusted += 1
            if role_adjusted:
                print(f"[i] Role-aware: adjusted {role_adjusted} finding(s)")

        platform_brain = getattr(self, "_platform_brain", None)
        if platform_brain is not None:
            for f in result.findings:
                try:
                    platform_brain.tag_finding(f)
                except Exception:
                    pass

        apply_flows(result.findings)

        try:
            from titan.verify.chain_analyzer import ChainAnalyzer
            chains = ChainAnalyzer().detect(result.findings)
            result.chains = [c.to_dict() for c in chains]
            for chain in chains:
                for f in chain.hops:
                    others = [h.url for h in chain.hops if h is not f]
                    if others:
                        f.chain = list(dict.fromkeys(others))
            if chains:
                print(f"[+] Track D: {len(chains)} attack chains composed")
        except Exception as exc:
            result.errors.append(f"Chain analysis failed: {exc}")

        try:
            from titan.verify.inference import CrossDataInferenceEngine
            inf_engine = CrossDataInferenceEngine()
            result.inferences = [i.to_dict() for i in inf_engine.infer(result.findings)]
            if result.inferences:
                print(f"[+] Inference: {len(result.inferences)} cross-data inference(s)")
        except Exception as exc:
            result.errors.append(f"Inference failed: {exc}")

        ai_cfg = self.config.get("ai", {})
        if ai_cfg.get("escalate", {}).get("enabled", False):
            try:
                from titan.verify.ai_escalation import AIEscalator
                esc = AIEscalator(ai_cfg)
                result.ai_escalation = await esc.escalate(result.findings)
                print(f"[+] AI escalation: {result.ai_escalation.get('sent', 0)} sent")
            except Exception as exc:
                result.errors.append(f"AI escalation failed: {exc}")

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
            from urllib.parse import urlparse, parse_qs
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
                            print("[!] Playwright driver died mid-matrix; aborting remaining groups")
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
            print(f"[!] {denial}")
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
                        await _api_context.add_cookies([
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
            from urllib.parse import urljoin, urlparse as _up
            import re as _re
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
                print(f"    [+] Seed {seed}: {len(seed_findings)} finding(s)")
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
