"""Core scan engine for Titan Scanner."""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlencode, urlparse

from titan.core.models import Finding, ScanResult
from titan.core.fingerprint import TechFingerprinter
from titan.ai.payloadsmith import PayloadSmith
from titan.integrations.dawn import DawnMemory
from titan.integrations.titan_gov import request_scan_approval
from titan.integrations.interactsh import InteractshClient
from titan.core.auth import AuthEngine
from titan.core.sessions import Identity, SessionPool
from titan.core.proxy import ProxyRotator
from titan.core.stealth import StealthEngine
from titan.core.route_scorer import score_url, should_run_expensive_modules, sort_queue
from titan.core.anomaly import AnomalyTracker
from titan.verify.flows import apply_flows
from titan.verify.role_aware import RoleAwareScanner


# Challenge-wall fingerprints strong enough to abort a scan on their own,
# regardless of HTTP status — some WAFs serve the wall with 200/202 to
# confuse naive status-based filters.
STRONG_CHECKPOINT_INDICATORS = [
    "just a moment",           # Cloudflare interstitial
    "checking your browser",   # Cloudflare interstitial
    "ray id:",                 # Cloudflare error/challenge pages
    "cf-ray",                  # Cloudflare body marker
    "cf-mitigated",            # Cloudflare managed challenge
    "cf-chl",                  # Cloudflare challenge cookie
    "challenge-platform",      # Cloudflare challenge JS bundle
    "vercel security checkpoint",
]

# Generic wall words: only treated as a checkpoint when paired with a blocking
# status. A 200 page full of "challenge" is a CTF/training site (ctflearn,
# hackthissite, google-gruyere), not a wall — aborting on those burned real
# targets.
GENERIC_CHECKPOINT_INDICATORS = [
    "cloudflare",
    "captcha",
    "access denied",
    "security check",
    "ddos protection",          # marketing copy on legit hosting pages
    "please verify",
    "challenge",
    "blocked",
    "403 forbidden",
]

# Statuses that indicate the request was intercepted rather than served
# normally. 202 is the anti-bot "accepted for processing" wall.
CHECKPOINT_STATUSES = {401, 403, 405, 429, 503, 202}

# Body markers that identify a soft-404 page: an HTML "not found" response
# served with HTTP 200 (WordPress, IIS and many frameworks do this for ANY
# unknown path). A real API endpoint returns structured data on a benign
# request; an HTML error page with not-found copy is a dead route, and running
# the module matrix against it produces "verified" storms because every
# payload gets reflected into the error page.
SOFT_404_MARKERS = (
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

# Error-message markers that mean the Playwright Node driver itself is dead or
# its connection to Python broke. A driver that dies mid-scan is dangerous in a
# special way: pending protocol futures may NEVER resolve AND never raise (the
# EPIPE crash observed on github.com), so a module run wedges instead of
# failing. Once detected, all further driver work is skipped and the scan
# reports the findings collected so far.
DRIVER_DEATH_MARKERS = (
    "connection closed while reading from the driver",
    "connection is closed",
    "target page, context or browser has been closed",
    "browser has been closed",
    "broken pipe",
    "epipe",
    "connection reset by peer",
    "the driver process",
)

# M3 fast-profile no-op probes: in-place empty substitutes for the deep-only
# discovery probes. They MUST be awaitables (asyncio.gather rejects plain
# lists), so each is an async function returning the empty default — the
# gather tuple still matches the caller's unpacking exactly.
async def _noop_api_probe() -> List[str]:
    return []


async def _noop_params_probe() -> Dict[str, List[str]]:
    return {}


async def _noop_methods_probe() -> List[Dict[str, Any]]:
    return []


def _consume_task_exception(task: "asyncio.Task") -> None:
    """Done-callback that swallows a task's exception so an abandoned task
    (e.g. a crawl task wedged in a dead-driver await) never logs an orphaned
    "Future exception was never retrieved" warning when the loop tears down.

    NOTE: this must catch BaseException, not Exception. Since Python 3.8
    asyncio.CancelledError is a BaseException, and ``task.exception()`` on a
    cancelled task re-raises the CancelledError itself — ``except Exception``
    lets it escape and prints the noisy
    "Exception in callback _consume_task_exception()" traceback on EVERY
    crawl-timeout cancellation (observed on weather.co.ke / genohealth.co.uk
    scans, where the scan continued fine but the console drowned in asyncio
    teardown noise).
    """
    try:
        task.exception()
    except BaseException:
        pass


class TitanEngine:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.fingerprinter = TechFingerprinter()
        self.payload_smith = PayloadSmith(config.get("ai", {}))
        self.auth_engine = AuthEngine(config)
        # Track B (stateful identity testing): holds every authenticated
        # persona concurrently so BOLA/mass-assignment detectors can do
        # cross-identity differentials.
        self.session_pool = SessionPool()
        self._role_scanner = RoleAwareScanner()
        self._platform_brain = None
        self._platform_extra_params: List[str] = []
        self.interactsh = InteractshClient()
        self.findings: List[Finding] = []
        self.visited: set = set()
        # Eagerly-populated set of every in-scope absolute URL the crawl has
        # DISCOVERED (links, APIs, SPA routes) — populated the moment they are
        # found, BEFORE the page's module matrix runs. self.visited only gains
        # a URL after its own crawl pass, so the SSRF module scanning a link
        # from page A could not see an internal route found on page A until it
        # was too late. This set is the crawl's discovery view.
        self._discovered_urls: set = set()
        # SCAN-QUALITY M3 crawl profiles. ``fast`` (default): content-derived
        # discovery only (forms, links, JS-referenced APIs, captured requests)
        # with zero hardcoded path/param/route guesses — the health-app
        # vocabulary and local-lab endpoints that got probed on EVERY site are
        # gated behind ``deep``. ``deep`` restores the full arsenal: wordlist
        # path fuzzing, common-param/method brute force, swagger/postman/
        # graphql spec probing, SPA hash-route guessing.
        crawl_cfg = config.get("crawl", {})
        # SCAN-QUALITY M3 crawl profiles + Track G. ``hostile`` = the deep
        # arsenal PLUS the hostile & ad-monetized surface pass (monetization
        # profile, cloak/miner/push/clickbait detectors, supply-chain probes).
        _profile = str(crawl_cfg.get("profile", "fast")).lower()
        self._deep = _profile in ("deep", "hostile")
        self._hostile = _profile == "hostile"
        # Track G redirect recorder: 3xx hops observed during the crawl /
        # interaction phases, surfaced in scan_meta + the hostile profile.
        self.redirect_chain: List[Dict[str, Any]] = []
        # Set during the crawl when the page actually looks like a client-side
        # app (hash links, JS route table). Gates the interaction phase so a
        # static weather site never gets its "#/patients" routes replayed.
        self._spa_detected = False
        self.max_pages = crawl_cfg.get("max_pages", 5 if not self._deep else 20)
        # PUSH-TO-100: per-page cap on how many discovered APIs run the module
        # matrix. Configurable so deep-profile / benchmark runs can scan the
        # full discovered surface instead of silently dropping endpoints (the
        # coverage verdict still flags ``capped_apis`` when the cap binds).
        self.max_apis = crawl_cfg.get("max_apis", 15)
        self.max_depth = crawl_cfg.get("max_depth", 1 if not self._deep else 2)
        self._mutation_cache: Dict[str, List[str]] = {}
        self._response_cache: set = set()
        # PUSH-TO-100 A3 — coverage accounting. Counters are incremented as the
        # scan runs; the verdict (complete|partial + reason) is computed once
        # at scan end so the report can claim — and the operator can audit —
        # that the discovered surface was provably covered.
        self._coverage: Dict[str, Any] = {
            "urls_crawled": 0,
            "duplicate_bodies_skipped": 0,
            "endpoint_groups_run": 0,
            "apis_discovered": 0,
            "apis_scanned": 0,
            "params_discovered": 0,
            "fuzz_budget_spent": 0.0,
            "queue_exhausted": False,
            "capped_max_pages": False,
            "capped_depth": False,
            "capped_apis": False,
            "crawl_timed_out": False,
            "checkpoint_blocked": False,
        }
        # Module concurrency is configurable (crawl.module_concurrency). The
        # module matrix is the scan's biggest cost center, and the default of 4
        # serializes ~475 module invocations (19 modules x ~25 endpoint groups)
        # into long wall-clock scans.
        self._module_semaphore = asyncio.Semaphore(self.config.get("crawl", {}).get("module_concurrency", 8))
        self._module_timeouts: Dict[str, int] = {}
        self._module_line_counts: Dict[str, int] = {}
        self._scan_target: str = ""
        # Set when a driver-death error is observed in a module run. Every
        # later phase checks it and skips driver work: a dead driver can wedge
        # instead of raising, so we stop touching it and write the findings we
        # already collected.
        self._driver_dead: bool = False
        self.proxy_rotator = ProxyRotator(
            proxies=self.config.get("proxy", {}).get("list", []),
            strategy=self.config.get("proxy", {}).get("rotation", "round-robin"),
        )
        stealth_cfg = self.config.get("stealth", {})
        self.stealth = StealthEngine(
            jitter=stealth_cfg.get("jitter", 0.3),
            min_delay=stealth_cfg.get("min_delay", 0.15),
            max_delay=stealth_cfg.get("max_delay", 0.6),
        )
        # SHARPEN-S1: adaptive latency-scaling defaults ON; config can disable.
        self.stealth.adaptive = bool(stealth_cfg.get("adaptive", True))
        # ANOMALY INTERRUPT: tracks mid-scan anomalies (500s, body drift,
        # new cookies) and promotes interesting routes to the front of
        # the crawl queue.
        self._anomaly_tracker = AnomalyTracker()
        # SESSION-AWARE REPLAY: routes that returned 401/403 during the
        # unauthenticated crawl. If auth succeeds, these routes are re-queued
        # for a second pass with the authenticated session.
        self._gated_routes: set = set()
        # Track whether the current pass is authenticated
        self._auth_scope: str = "unauthenticated"
        # WAF BYPASS: tracks WAF presence per route and provides payload
        # re-encoding when payloads are blocked by WAF.
        from titan.core.waf import WAFTracker
        self._waf_tracker = WAFTracker()
        # Omega — Transport Abstraction Layer.  The registry gives every
        # module a protocol-agnostic send() — HTTP today, Tor/gRPC/WS
        # tomorrow — without the detectors knowing which wire they're on.
        self._transport_registry: Optional[Any] = None
        self._transport_http: Optional[Any] = None
        # Lazy-init flag: we set up the registry once the scan starts so
        # the async event loop is running.
        self._transport_ready: bool = False

    async def _ensure_transport(self) -> None:
        """Lazily initialise the transport registry on first use.

        Called once per scan; subsequent calls are no-ops.  The registry
        auto-detects which transports are available (HTTP always, Tor if
        the service is reachable, gRPC/WS/MQTT if deps are installed).
        """
        if self._transport_ready:
            return
        try:
            from titan.transport import TransportRegistry
            self._transport_registry = TransportRegistry()
            await self._transport_registry.auto_register()
            self._transport_http = self._transport_registry.get("http")
            self._transport_ready = True
            avail = self._transport_registry.available
            print(f"[+] Transport layer ready: {', '.join(avail)}")
        except Exception as exc:
            # Transport init must never abort a scan — degrade gracefully.
            print(f"[!] Transport layer init failed (continuing without): {exc}")
            self._transport_ready = True  # Prevent retries

    async def _transport_send(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Any = None,
        params: Optional[Dict[str, str]] = None,
        timeout: float = 15.0,
    ) -> Optional[Any]:
        """Send an HTTP request through the transport abstraction.

        Returns the ``AttackResponse`` on success, or ``None`` when the
        transport layer is unavailable (caller should fall back to the
        Playwright context.request).
        """
        await self._ensure_transport()
        if not self._transport_http:
            return None
        try:
            from titan.transport import AttackRequest, RequestMethod
            _method = RequestMethod(method.upper())
            response = await self._transport_http.send(AttackRequest(
                url=url,
                method=_method,
                headers=headers or {},
                body=body,
                params=params,
                timeout=timeout,
            ))
            return response
        except Exception:
            return None

    async def scan(self, target: str) -> ScanResult:
        # Wall-clock (epoch) timestamps: they surface in the per-site reports.
        t0 = time.time()
        self._scan_target = target
        # SCAN-QUALITY M2 determinism: seed the global RNG from the target so
        # every random.choices()/randint() in the pipeline (path-fuzz 404
        # markers, XSS TITANXSS markers, stealth jitter) produces the SAME
        # values on every scan of the same target. Markers leak into findings
        # (payload/diff strings), so an unseeded RNG made two runs of the same
        # site differ in report text even when the verdicts matched.
        random.seed(hashlib.sha256(target.encode("utf-8")).hexdigest())
        result = ScanResult(target=target, started_at=t0, config_snapshot=self.config)

        # S5 — hard authorization gate on the read-only path. Before ANY
        # request is sent, the target must be loopback (operator's own
        # machine), covered by a signed consent file, or listed on the
        # authorized-practice manifest. This closes the hole that let the
        # autonomous arena crawl arbitrary third-party hosts (instagram.com,
        # google.com, ...) with no authorization record.
        denial = self._authorization_status(target)
        if denial:
            result.errors.append(denial)
            result.finished_at = time.time()
            print(f"[!] {denial}")
            return result

        if self.config.get("governance", {}).get("enabled", True):
            try:
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
            from playwright.async_api import async_playwright
            # Explicit start/stop instead of `async with`: a crawl-timeout
            # cancellation can wedge the Node driver, and an un-bounded
            # driver.stop() in __aexit__ would hang the process forever AFTER
            # "Scan complete" (observed: the scan finished but the process
            # lingered for 40+ minutes). Bound the teardown.
            p = await async_playwright().start()
            try:
                browser_args = {"headless": self.config.get("headless", True)}
                proxy_config = self.config.get("proxy", {})
                if proxy_config.get("enabled") and proxy_config.get("list"):
                    proxy_url = self.proxy_rotator.get_proxy(target) if hasattr(self, "proxy_rotator") else proxy_config.get("list", [""])[0]
                    if proxy_url:
                        browser_args["proxy"] = {"server": proxy_url}

                browser = await p.chromium.launch(**browser_args)
                # ignore_https_errors: a certificate without a subject CN (seen
                # on real subdomains, e.g. alumni.kibu.ac.ke) crashes the Node
                # driver mid-scan (captureSecurityDetails TypeError) and kills
                # every later request. Bypassing cert validation also lets
                # scans proceed against self-signed / broken-cert targets.
                context = await browser.new_context(
                    user_agent=self.stealth.get_user_agent() if hasattr(self, "stealth") else None,
                    extra_http_headers=self.stealth.get_headers() if hasattr(self, "stealth") else {},
                    ignore_https_errors=True,
                )
                self._crawl_context = context
                page = await context.new_page()
                self._harden_page(page)

                print(f"[+] Loading target: {target}")
                _goto_start = time.monotonic()
                response = await page.goto(target, wait_until="domcontentloaded", timeout=30000)
                _goto_elapsed = time.monotonic() - _goto_start

                # SHARPEN-S1: adapt stealth delays to the measured target
                # latency — the per-module delay is the scan's biggest cost
                # (~475 invocations × 0.15–0.6s), and a fast target doesn't
                # need the full stealth gap. Observe latency once per scan.
                try:
                    if hasattr(self, "stealth"):
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
                    try:
                        await asyncio.wait_for(browser.close(), timeout=10)
                    except Exception:
                        pass
                    return result

                fingerprint = await self.fingerprinter.analyze(headers, body, target)
                fingerprint["interactsh"] = self.interactsh
                result.fingerprint = fingerprint
                print(f"[+] Technologies detected: {fingerprint.get('technologies', [])[:10]}")

                # PLATFORM BRAIN: select a platform-specific brain and
                # specialize the crawl for it.
                self._platform_brain = self._select_platform_brain(fingerprint, body, headers)
                if self._platform_brain is not None:
                    print(f"[+] Platform brain: {self._platform_brain.name}")
                    for seed in self._platform_brain.extra_seed_urls(target):
                        if seed not in self.visited and self._is_in_scope(seed):
                            self.visited.add(seed)
                            self._discovered_urls.add(seed)
                    # Extra parameters feed the common-param brute forcer.
                    self._platform_extra_params = list(self._platform_brain.extra_parameters())
                else:
                    self._platform_extra_params = []

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
                            name=role_name,
                            headers=dict(auth_headers),
                            cookies=self.auth_engine.get_cookies(),
                        ))
                    else:
                        print("[!] Authentication failed, continuing unauthenticated")

                crawl_timeout = self.config.get("crawl", {}).get(
                    "timeout", 90 if not self._deep else 300
                )
                crawl_task = asyncio.ensure_future(
                    self._crawl(context, page, target, result, fingerprint)
                )
                # Consume any exception the abandoned task eventually raises so
                # it is never logged as an orphaned future warning.
                crawl_task.add_done_callback(_consume_task_exception)
                done, pending = await asyncio.wait({crawl_task}, timeout=crawl_timeout)
                if crawl_task in pending:
                    result.errors.append(f"Crawl timed out after {crawl_timeout}s")
                    self._coverage["crawl_timed_out"] = True
                    print("[!] Crawl timed out, proceeding with interaction")
                    # Bounded-abandon: NEVER await the cancellation of a crawl
                    # task stuck in a dead-driver Playwright call. wait_for()
                    # waits for the cancel to COMPLETE; a task wedged in an
                    # await that neither resolves nor raises makes that wait
                    # run forever (observed: silent hang after a Node driver
                    # EPIPE crash on github.com — no report was ever written).
                    # Cancel, give the loop a short window to unwind, then move
                    # on; the teardown below (p.stop) kills the driver, which
                    # forces the wedged awaits to error out.
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

                if self._driver_dead:
                    print("[!] Playwright driver died mid-scan; skipping interaction phase")
                else:
                    await self._run_interactions(context, target, fingerprint, result)
                    # B1 — SPA/JS-rendered harness: hydrate the route table and
                    # walk each route so runtime XHR/fetch/WebSocket calls reach
                    # the module matrix (closes the 0-finding SPA gap). Bounded
                    # per-route; every failure degrades quietly.
                    if self.config.get("crawl", {}).get("spa", {}).get("enabled", True):
                        # SPA-SKIP: if the crawl found zero hash routes AND no SPA
                        # framework signals in the technology fingerprint, the SPA
                        # harness will waste 10-15s discovering nothing.  Skip it.
                        has_hash_routes = any("#" in u for u in self.visited)
                        spa_frameworks = {"react", "vue", "angular", "svelte",
                                          "ember", "backbone", "next.js", "nuxt",
                                          "gatsby", "remix", "astro"}
                        detected_techs = {t.lower() for t in fingerprint.get("technologies", [])}
                        has_spa_signal = has_hash_routes or bool(detected_techs & spa_frameworks)
                        if has_spa_signal:
                            try:
                                await self._run_spa_harness(context, target, fingerprint, result)
                            except Exception:
                                pass
                        else:
                            print("[+] SPA harness: skipped (no hash routes or SPA framework detected)")

                roles = self.config.get("auth", {}).get("roles", [])
                if roles and not self._driver_dead:
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
                                    name=role_name,
                                    headers=dict(auth_headers),
                                    cookies=self.auth_engine.get_cookies(),
                                ))

                                for visited_url in list(self.visited)[:10]:
                                    try:
                                        api_findings = await asyncio.wait_for(
                                            self._run_api_modules(context, target, visited_url, {}),
                                            timeout=15,
                                        )
                                        for f in api_findings:
                                            f.tags = f.tags + [f"role:{role_name}"]
                                        result.findings.extend(api_findings)
                                    except Exception:
                                        continue
                        except Exception:
                            continue

                # SESSION-AWARE REPLAY: routes that returned 401/403 during
                # the main crawl are re-queued with the authenticated session.
                # This catches findings behind auth gates that the initial
                # crawl skipped.
                if self._gated_routes and not self._driver_dead:
                    replay_count = 0
                    replay_limit = min(len(self._gated_routes), 10)
                    print(f"[+] Session replay: re-scanning {replay_limit} gated routes with auth...")
                    for gated_url in list(self._gated_routes)[:replay_limit]:
                        try:
                            # Omega: try transport first, fall back to Playwright.
                            _auth_hdrs = dict(self.auth_engine.get_auth_headers() or {})
                            t_resp = await self._transport_send(
                                gated_url, headers=_auth_hdrs, timeout=10.0,
                            )
                            gated_status = 0
                            gated_body = ""
                            if t_resp and not t_resp.is_error:
                                gated_status = t_resp.status
                                gated_body = t_resp.text
                            else:
                                # Fallback to Playwright context.request
                                gated_resp = await asyncio.wait_for(
                                    context.request.get(gated_url, timeout=10000),
                                    timeout=15,
                                )
                                if gated_resp:
                                    gated_status = gated_resp.status
                                    gated_body = await gated_resp.text()
                            if gated_status == 200:
                                print(f"    [+] REPLAY {gated_url} → {gated_status} (was 401/403, now open)")
                                replay_findings = await asyncio.wait_for(
                                    self._run_api_modules(context, target, gated_url, {}),
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

                # Track B — identity-level testing. BOLA, mass assignment,
                # JWT and session fixation need >= 2 authenticated identities
                # held concurrently (request A's object with B's session and
                # diff). Runs against the discovered API surface only; every
                # failure degrades quietly.
                if len(self.session_pool) >= 2 and not self._driver_dead:
                    print(f"[+] Identity matrix: {len(self.session_pool)} identities; running BOLA/mass-assignment/JWT/session checks")
                    for visited_url in list(self.visited)[:10]:
                        try:
                            identity_findings = await asyncio.wait_for(
                                self._run_identity_modules(context, target, visited_url, {}),
                                timeout=20,
                            )
                            result.findings.extend(identity_findings)
                        except Exception:
                            continue

                # Track A — client-side browser security. DOM XSS, postMessage,
                # prototype pollution, skimmer heuristic and CSP audit all need
                # a REAL browser context (the oracle is inside the page's JS,
                # not the server response). Bounded: max 2 pages, per-detector
                # timeout, every failure degrades quietly.
                if self.config.get("clientside", {}).get("enabled", True) and not self._driver_dead:
                    await self._run_browser_modules(context, page, target, fingerprint, result)

                # Track C — LLM/AI application probing. Conversational probes
                # against the target's AI endpoints, judged by a deterministic
                # behavioral contract + consensus oracle. Pure aiohttp, so it
                # runs even if the Playwright driver died.
                if self.config.get("llm", {}).get("enabled", True):
                    await self._run_llm_channel(target, fingerprint, result)

                # Track D — cloud storage exposure. Probes buckets referenced
                # by the scan's own evidence for public listing; the findings
                # feed the flow-typed chain analyzer. Pure aiohttp.
                if self.config.get("cloud", {}).get("storage", {}).get("enabled", True):
                    await self._run_storage_probe(target, result)

                # Omega Phase 2 — Cloud IMDS probing. When SSRF findings exist,
                # probe cloud IMDS through the discovered SSRF sinks to extract
                # IAM credentials, service account tokens, and instance metadata.
                if self.config.get("cloud", {}).get("imds", {}).get("enabled", True):
                    await self._probe_cloud_imds(target, result)

                # Omega Phase 4 — SBOM analysis. Scan served HTML/JS for SRI
                # violations, cleartext loads, known CVEs in dependencies, and
                # risky third-party origins.
                if self.config.get("crawl", {}).get("supplychain", {}).get("enabled", True):
                    await self._run_sbom_analysis(target, result, page)

                # Omega — Deep Audit: parse JS for cloud configs, probe Firebase/
                # Supabase directly, enumerate collections, test security rules.
                # Runs AFTER the main scan so it has the full estate map.
                if self.config.get("deep_audit", {}).get("enabled", True):
                    try:
                        from titan.modules.deep_audit.prober import DeepAuditor
                        auditor = DeepAuditor()
                        audit_result = await auditor.audit(
                            target,
                            budget=float(self.config.get("deep_audit", {}).get("budget", 60)),
                        )
                        # Merge deep audit findings into scan results
                        from titan.core.models import Finding, Severity, AttackType
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
                                    target=target,
                                    url=target,
                                    method="GET",
                                    param="deep-audit",
                                    location="cloud",
                                    payload=af.description[:200],
                                    attack_type=atype,
                                    severity=sev,
                                    confidence=0.95 if af.verified else 0.7,
                                    status=200,
                                    evidence=af.proof,
                                    tier="confirmed" if af.verified else "suspicious",
                                    tags=["deep-audit", af.category, af.id],
                                    notes=f"{af.title}: {af.remediation}",
                                )
                                result.findings.append(finding)
                        # Log summary
                        verified = sum(1 for f in audit_result.findings if f.verified)
                        print(
                            f"[+] Deep Audit: {len(audit_result.findings)} finding(s), "
                            f"{verified} verified, "
                            f"{len(audit_result.attack_chain)} attack chain step(s)"
                        )
                    except Exception as exc:
                        result.errors.append(f"Deep audit failed: {exc}")
                        print(f"[!] Deep audit: {exc}")

                try:
                    await asyncio.wait_for(browser.close(), timeout=10)
                except Exception:
                    # A driver crash on close (e.g. a bad TLS cert mid-crawl)
                    # must never surface as a scan error or mask findings.
                    pass
            finally:
                # Driver teardown must be bounded: a wedged driver makes
                # p.stop() hang, which would keep the process alive after the
                # scan completed. 5s cap; the OS kills the browser subprocess
                # if the driver is truly stuck.
                try:
                    await asyncio.wait_for(p.stop(), timeout=5)
                except Exception:
                    pass
        except asyncio.TimeoutError:
            result.errors.append("Scan timed out after 240s")
            print("[!] Scan timed out")
        except Exception as exc:
            import traceback
            traceback.print_exc()
            result.errors.append(str(exc))

        # Omega Phase 7 — Fleet multi-agent scan. After the main scan
        # discovers the surface, fleet agents run specialized deep dives
        # (recon, identity, learning) on the discovered endpoints. Fleet
        # findings are merged with the main scan findings before dedup.
        if self.config.get("fleet", {}).get("enabled", False):
            await self._run_fleet_scan(target, result)

        result.findings = self._dedupe_findings(result.findings)
        result.findings = [f for f in result.findings if self._is_in_scope(f.url)]

        # SCAN-QUALITY M1 evidence gate: attach an evidence grade to every
        # finding and auto-demote injection-family findings marked verified
        # without a named strong oracle marker (the reflection-verifies
        # storms: 21 identical "CRITICAL LFI" on an echoing catch-all). Runs
        # BEFORE apply_flows so flows/chain analysis only sees honest
        # verified evidence.
        from titan.verify.oracles import enforce_evidence
        ev_stats = enforce_evidence(result.findings)
        if ev_stats.get("demoted"):
            print(
                f"[!] Evidence gate: demoted {ev_stats['demoted']} verified "
                f"finding(s) with no strong oracle marker "
                f"({ev_stats['capped']} severity-capped to MEDIUM)"
            )

        # SCAN-QUALITY M1b auto-verification: run negative controls against
        # each finding and demote if the control produces the same response.
        # This catches the remaining false positives that slip through the
        # evidence gate (e.g., smuggling FPs on edge 501s, baseline-echo
        # errors in non-injection modules).
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
                print(
                    f"[!] Auto-verify: demoted {demoted_count} finding(s) "
                    f"that failed negative control tests"
                )
            if verified_count:
                print(
                    f"[+] Auto-verify: {verified_count} finding(s) passed "
                    f"negative control tests"
                )

        # ROLE-AWARE SCANNING: downgrade findings that require capabilities
        # the current authenticated role does not possess.  Runs AFTER
        # auto-verify so the evidence gate sees honest findings first.
        from titan.verify.role_aware import RoleAwareScanner
        role_scanner = getattr(self, "_role_scanner", None)
        if isinstance(role_scanner, RoleAwareScanner):
            role_adjusted = 0
            for f in result.findings:
                if getattr(f, "verified", False):
                    role_scanner.adjust_finding(f)
                    if getattr(f, "metadata", {}).get("role_gated"):
                        role_adjusted += 1
            if role_adjusted:
                print(
                    f"[i] Role-aware: adjusted {role_adjusted} finding(s) for "
                    f"role={role_scanner.role().value}"
                )

        # PLATFORM BRAIN: tag findings with platform context.
        platform_brain = getattr(self, "_platform_brain", None)
        if platform_brain is not None:
            for f in result.findings:
                try:
                    platform_brain.tag_finding(f)
                except Exception:
                    pass

        # Track D prerequisite: tag every verified finding with the
        # capabilities it exposes to an attacker (file_read, creds,
        # url_fetch, auth_bypass, code_exec, data_leak, oob, client_exec,
        # model_control). Runs BEFORE the chain analyzer below — the analyzer
        # joins findings on these flows.
        apply_flows(result.findings)

        # Track D — flow-typed chain analysis. Joins findings whose
        # capabilities combine into attack goals (SSRF to metadata + a
        # hardcoded cloud key = Cloud Credential Exposure). Populates
        # result.chains and the per-finding ``chain`` URL lists the report
        # renders. Never fatal — a failure is recorded, not thrown.
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

        # CROSS-DATA INFERENCE: combine independent findings into higher-
        # confidence chained inferences (e.g. SSRF + cloud IMDS = credential
        # exposure).  Runs AFTER the chain analyzer so the inference engine
        # can reuse chain metadata.
        try:
            from titan.verify.inference import CrossDataInferenceEngine
            inf_engine = CrossDataInferenceEngine()
            result.inferences = [i.to_dict() for i in inf_engine.infer(result.findings)]
            if result.inferences:
                print(f"[+] Inference: {len(result.inferences)} cross-data inference(s)")
        except Exception as exc:
            result.errors.append(f"Inference failed: {exc}")

        # AI escalation: model verdicts for ambiguous high-value findings only.
        # Runs before CVSS/PoC so a verdict can influence scoring. Every failure
        # inside the escalator degrades to "no opinion" and is counted, never
        # thrown, so a broken provider cannot kill the scan.
        ai_cfg = self.config.get("ai", {})
        if ai_cfg.get("escalate", {}).get("enabled", False):
            try:
                from titan.verify.ai_escalation import AIEscalator
                esc = AIEscalator(ai_cfg)
                result.ai_escalation = await esc.escalate(result.findings)
                print(
                    f"[+] AI escalation: {result.ai_escalation.get('sent', 0)} sent, "
                    f"{result.ai_escalation.get('confirmed', 0)} confirmed, "
                    f"{result.ai_escalation.get('rejected', 0)} rejected, "
                    f"{result.ai_escalation.get('failed', 0)} failed"
                )
            except Exception as exc:
                result.errors.append(f"AI escalation failed: {exc}")

        # Track G — hostile & ad-monetized surface (crawl.profile: hostile).
        # Read-only analysis always runs; active probes (redirect chains,
        # referrer gates) only under a signed consent file for the target.
        # Pure aiohttp so it runs even if the Playwright driver died. Runs
        # BEFORE the CVSS/PoC loop below so hostile findings get scored too.
        #
        # B4 — the read-only supply-chain surface (third-party origins, SRI,
        # cleartext loads, redirect-chain observation, headers posture) is
        # part of EVERY scan now, not hostile-profile-only (spec D3). The
        # hostile extras (monetization score, cloak/miner/push detectors) stay
        # hostile-profile; the pass self-gates active probes by consent, so
        # the default scan covers supply-chain read-only.
        supplychain_cfg = self.config.get("crawl", {}).get("supplychain", {})
        if self._hostile or supplychain_cfg.get("enabled", True):
            try:
                await self._run_hostile_pass(target, result)
            except Exception as exc:
                result.errors.append(f"Track G hostile pass failed: {exc}")

        # Omega Phase 8 — Anti-forensics: decoy traffic + polymorphic payloads
        # Runs BEFORE brain/evolution so the brain operates on the full
        # finding set including decoy-blurred traffic analysis.
        try:
            await self._apply_anti_forensics(target, result)
        except Exception as exc:
            result.errors.append(f"Anti-forensics failed: {exc}")

        # Omega Phase 5 — Brain Loop: mutate payloads, find bypasses
        # Runs AFTER main scan + fleet so it has the full finding set to
        # mutate. Produces new bypass findings that feed into evolution.
        try:
            await self._run_brain_loop(target, result)
        except Exception as exc:
            result.errors.append(f"Brain loop failed: {exc}")

        # Omega Phase 6 — Evolution: generate new detectors from brain patterns
        # Runs AFTER brain loop so it can analyze successful mutations.
        try:
            await self._run_evolution(target, result)
        except Exception as exc:
            result.errors.append(f"Evolution engine failed: {exc}")

        from titan.core.cvss import CVSSScorer
        from titan.core.poc import PoCGenerator
        for f in result.findings:
            # PUSH-TO-100 A1 tier contract: ONLY confirmed findings get
            # scored. `suspicious`/no-evidence findings are triaged but never
            # carry a CVSS score or a PoC — they must not read as proven in
            # the report. (The crawl-tail loop above may have scored them
            # pre-tier; this is the authoritative pass and wipes them.)
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

        # Track E — consent-gated exploitation. Self-gating (no-op unless
        # config enables it AND consent exists); pure aiohttp, so it runs even
        # if the Playwright driver died. See _run_exploit_modules.
        try:
            await self._run_exploit_modules(target, result)
        except Exception as exc:
            result.errors.append(f"Track E exploit phase failed: {exc}")

        clean_fingerprint = {}
        for k, v in (result.fingerprint or {}).items():
            try:
                import json
                json.dumps(v)
                clean_fingerprint[k] = v
            except (TypeError, ValueError):
                pass
        result.fingerprint = clean_fingerprint

        # PUSH-TO-100 A3 — coverage verdict. The claim "coverage: complete"
        # only fires when the crawl provably drained its queue and nothing
        # capped/aborted the discovered surface. Every partial verdict names
        # WHY so the operator can extend the budget, fix the cap, or unblock
        # the checkpoint instead of re-scanning blind.
        result.coverage = self._finalize_coverage(result)

        result.finished_at = time.time()

        # Per-site documentation: findings are persisted under
        # <output_dir>/<site-slug>/{report.md, findings.json, scan_meta.json}
        # plus a sites.json index. Never fatal — a docs failure must not kill a
        # completed scan.
        if self.config.get("reporting", {}).get("enabled", True):
            try:
                from titan.reporting import SiteReportWriter
                site_dir = SiteReportWriter(self.config.get("output_dir", "findings")).write(result)
                print(f"[+] Site report written to {site_dir}")
            except Exception as exc:
                print(f"[!] Failed to write site report: {exc}")

        # Omega — clean up the transport layer's connection pool.
        try:
            if self._transport_http and hasattr(self._transport_http, "close"):
                await self._transport_http.close()
        except Exception:
            pass

        return result

    def _is_driver_death(self, exc) -> bool:
        """True if an exception means the Playwright driver connection died.

        These errors surface when the Node driver process crashed or its pipe
        to Python broke. They are catchable (playwright.Error subclasses,
        OSError), but any LATER driver call may wedge rather than raise — so
        once one is seen, the scan stops scheduling driver work entirely.
        """
        msg = f"{type(exc).__name__}: {exc}".lower()
        return any(marker in msg for marker in DRIVER_DEATH_MARKERS)

    def _harden_page(self, page) -> None:
        """Track G (M4) — hostile-chrome handling on every page we drive:
        close popups/popunders, dismiss dialogs, suppress downloads, and
        record 3xx redirect hops. Every handler degrades silently so an
        ad-heavy site can never wedge the crawl.
        """
        try:
            page.on("popup", lambda p: asyncio.create_task(self._close_popup(p)))
            page.on("dialog", lambda d: asyncio.create_task(self._dismiss_dialog(d)))
            page.on("download", lambda dl: asyncio.create_task(self._suppress_download(dl)))
            page.on("response", self._record_redirect)
        except Exception:
            pass

    async def _close_popup(self, popup) -> None:
        try:
            await asyncio.wait_for(popup.close(), timeout=3)
        except Exception:
            pass

    async def _dismiss_dialog(self, dialog) -> None:
        try:
            await asyncio.wait_for(dialog.dismiss(), timeout=3)
        except Exception:
            pass

    async def _suppress_download(self, download) -> None:
        try:
            await asyncio.wait_for(download.cancel(), timeout=3)
        except Exception:
            pass

    def _record_redirect(self, response) -> None:
        """Record a 3xx hop (bounded ring) for the Track G redirect map."""
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

    def _finalize_coverage(self, result: ScanResult) -> Dict[str, Any]:
        """Compute the A3 coverage verdict from the counters accumulated during
        the scan. Pure logic lives in titan.verify.coverage so the tests can
        pin it exactly; the engine only supplies its own counters + flags.
        """
        from titan.verify.coverage import finalize_coverage

        return finalize_coverage(
            self._coverage,
            driver_dead=self._driver_dead,
            max_pages=self.max_pages,
            max_depth=self.max_depth,
        )

    def _authorization_status(self, target: str) -> Optional[str]:
        """S5 gate: return a denial reason if the target may NOT be scanned,
        else None. Enforced at the top of scan() before any request is sent.

        Authorized when the host is loopback (the operator's own machine), a
        signed consent file covers it, or it is on the authorized-practice
        manifest. Read-only profiling is gated exactly like active probes.
        """
        from titan.core.authorization import authorize_target

        return authorize_target(
            target,
            consent_dir=self.config.get("exploit", {}).get("consent_dir", "consent"),
            practice_manifest=self.config.get("authorization", {}).get(
                "practice_manifest"
            ),
            key_path=self.config.get("exploit", {}).get("key_path"),
        )

    def _has_consent(self, target: str) -> bool:
        """True when a signed, unexpired consent file covers the target.

        Post-S5 this is a building block of the read-only gate (see
        _authorization_status) and still gates Track G's ACTIVE probes
        (redirect-chain mapping, referrer-gate detection).
        """
        try:
            from titan.exploit.consent import verify_consent
            verify_consent(
                target,
                consent_dir=self.config.get("exploit", {}).get("consent_dir", "consent"),
            )
            return True
        except Exception:
            return False

    async def _run_hostile_pass(self, target: str, result: ScanResult) -> None:
        """Track G — monetization profile + hostile-content findings.

        Read-only analysis always runs; active probes (redirect chains,
        referrer gates) only under a signed consent file for the target.
        Pure aiohttp, so it runs even if the Playwright driver died.

        B4: this is ALSO the default scan's supply-chain pass — the third-
        party-origin profile with SRI/cleartext checks is read-only and now
        runs under every profile (crawl.supplychain.enabled).
        """
        import aiohttp
        from titan.hostile import findings_from_dicts, run_pass
        from titan.reporting import site_slug

        candidates = [target] + [
            u for u in self.visited
            if self._is_in_scope(u) and not self._is_spa_shell(u)
        ]
        candidates = list(dict.fromkeys(candidates))[:3]
        samples: List[Dict[str, str]] = []
        for u in candidates:
            try:
                ua = self.stealth.get_user_agent() if hasattr(self, "stealth") else None
                _hdrs = {"User-Agent": ua} if ua else {}
                # Omega: prefer the transport layer for HTTP fetching.
                # Falls back to aiohttp when the transport is unavailable.
                transport_resp = await self._transport_send(
                    u, headers=_hdrs, timeout=12.0,
                )
                if transport_resp and not transport_resp.is_error and transport_resp.status == 200:
                    text = transport_resp.text
                    samples.append({"url": u, "html": text[:600000]})
                    continue
                # Fallback: raw aiohttp (used when transport is down)
                async with aiohttp.ClientSession() as _sess:
                    async with _sess.get(
                        u, timeout=12, ssl=False, headers=_hdrs or None,
                    ) as resp:
                        if resp.status == 200:
                            text = await resp.text(errors="replace")
                            samples.append({"url": u, "html": text[:600000]})
            except Exception:
                continue
        if not samples:
            return
        consented = self._has_consent(target)
        # run_pass() requires an aiohttp session for active probes
        # (redirect-chain mapping, referrer-gate detection).
        async with aiohttp.ClientSession() as _hostile_session:
            payload = await run_pass(
                samples, target, target=target, session=_hostile_session,
                consented=consented, prior_observed=self._prior_observed(target),
            )
        payload["redirect_chain"] = self.redirect_chain[-50:]
        result.hostile = payload
        new_findings = findings_from_dicts(payload.get("findings", []))
        result.findings.extend(new_findings)
        print(
            f"[+] Track G: {len(new_findings)} hostile-surface finding(s) · "
            f"{len(payload.get('profile', {}).get('origins', []))} third-party origin(s) · "
            f"monetization score {payload.get('profile', {}).get('monetization_score', 0)} · "
            f"active probes={'on' if payload.get('active_probes') else 'off (no consent)'}"
        )

    def _prior_observed(self, target: str) -> Optional[Dict[str, Any]]:
        """Load the previous scan's observed intel for a target (M6 flux diff)."""
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

    def _is_checkpoint(self, title: str, body: str, headers: Dict[str, str], status: int = 200) -> bool:
        text = f"{title} {body[:5000]}".lower()
        # Strong fingerprints are a wall regardless of status (some WAFs serve
        # the challenge as 200/202 to evade naive filters).
        for indicator in STRONG_CHECKPOINT_INDICATORS:
            if indicator in text:
                return True
        # Generic wall words only count when the server actually returned a
        # blocking status — a 200 page that says "challenge" is a CTF/training
        # site (ctflearn, hackthissite, google-gruyere), not a wall. A
        # cloudflare server header at a blocking status is itself the wall
        # (catches empty-body CF 403s that no body word can match).
        if status in CHECKPOINT_STATUSES:
            if "cloudflare" in headers.get("server", "").lower():
                return True
            for indicator in GENERIC_CHECKPOINT_INDICATORS:
                if indicator in text:
                    return True
        return False

    async def _crawl(self, context, page, base_url: str, result: ScanResult, fingerprint: Dict[str, Any]):
        # PUSH-TO-100 C1: benchmark/manifest seeding — the operator may hand the
        # crawl a set of known-vulnerable endpoints (the benchmark manifest's
        # ground truth) so the module matrix runs on them even when the crawler
        # would not discover them (SPA endpoints that only fire on user
        # interaction, POST-only APIs, etc.). These are TEST targets the
        # benchmark certifies; they ride the normal scope/authorization gates.
        # Seeds are queued FIRST: a real SPA's homepage exposes dozens of APIs
        # whose module-matrix runs can exhaust the crawl budget before the
        # seeded ground truth is ever probed.
        # ``seeds_only`` (benchmark mode): walk ONLY the seeded challenge
        # endpoints and skip the base-page crawl entirely — a heavy SPA's
        # homepage can OOM the target server (Juice Shop's Node heap died
        # mid-scan) before any seed runs. The base URL is still marked
        # visited so downstream phases (interaction, SPA harness) stay scoped.
        seeds_only = bool(self.config.get("crawl", {}).get("seeds_only"))
        queue: List[tuple] = []
        for seed in self.config.get("crawl", {}).get("seed_urls", []) or []:
            seed = str(seed).strip()
            if not seed:
                continue
            if seed != base_url and seed not in self.visited and self._is_in_scope(seed):
                self.visited.add(seed)
                queue.append((seed, 1))
        if not seeds_only:
            queue.append((base_url, 0))
        self.visited.add(base_url)
        captured_apis: set = set()
        processed_count = 0
        # CONCURRENT CRAWL: module runners use context.request (not
        # page.goto), so they're safe to run while the browser fetches the
        # next page.  We schedule module runs as background tasks and
        # overlap them with the next page's fetch+discovery phase.
        _module_tasks: List = []

        while queue and processed_count < self.max_pages:
            if self._driver_dead:
                print("[!] Driver dead; stopping crawl early")
                break
            current, depth = queue.pop(0)

            if depth > self.max_depth:
                self._coverage["capped_depth"] = True
                continue

            if self._is_spa_shell(current):
                continue

            print(f"[+] Crawling: {current} (depth {depth}, visited {len(self.visited)})")
            page_start = time.monotonic()
            processed_count += 1
            self._coverage["urls_crawled"] = processed_count

            try:
                is_api_url = self._looks_like_api(current)
                resp = None
                body = ""
                title = ""
                forms = []
                links = []
                apis = []

                if is_api_url:
                    try:
                        api_resp = await page.request.get(current, timeout=10000)
                        body = await api_resp.text()
                        resp = type('Resp', (), {'status': api_resp.status, 'headers': dict(api_resp.headers)})()
                        
                        new_urls = self._extract_urls_from_json(body, base_url)
                        for u in new_urls:
                            if u not in self.visited and len(self.visited) < self.max_pages:
                                self.visited.add(u)
                                queue.append((u, depth + 1))
                                
                        if api_resp.status in (301, 302, 307, 308):
                            location = api_resp.headers.get("location", "")
                            if location and location not in self.visited:
                                self.visited.add(location)
                                queue.append((location, depth + 1))
                    except Exception:
                        pass
                else:
                    api_urls: List[str] = []
                    captured_count = 0
                    def capture_request(request):
                        nonlocal captured_count
                        if captured_count < 50 and self._looks_like_api(request.url):
                            api_urls.append(request.url)
                            captured_count += 1
                    
                    page.on("request", capture_request)
                    # Retry-with-backoff (M3): a transient network error (the
                    # observed net::ERR_INTERNET_DISCONNECTED / ERR_NETWORK_CHANGED
                    # timeouts on weather.co.ke) gets ONE retry after a short
                    # backoff; a persistent failure still degrades to the skip
                    # below, never an abort.
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
                    
                    for url in api_urls:
                        if self._looks_like_api(url):
                            captured_apis.add(url)

                    if resp and resp.status < 400:
                        body = await page.content()
                        title = await page.title()
                        if self._is_checkpoint(title, body, dict(resp.headers), resp.status):
                            print(f"    [!] Checkpoint on subpage: {title}")
                            continue
                        
                        body_fingerprint = hashlib.md5(body.encode()).hexdigest() if body else ""
                        if hasattr(self, '_response_cache') and body_fingerprint in self._response_cache:
                            print(f"    [i] Duplicate response, skipping modules")
                            self._coverage["duplicate_bodies_skipped"] += 1
                            continue
                        if not hasattr(self, '_response_cache'):
                            self._response_cache = set()
                        self._response_cache.add(body_fingerprint)
                        
                        # Discovery probes are independent — run them
                        # concurrently instead of one-after-another (sequential
                        # discovery is the second-biggest scan cost after the
                        # module matrix). A flaky probe degrades to an empty
                        # result for that probe only — it never aborts the
                        # other nine and skips the whole page's findings.
                        (
                            forms,
                            links,
                            static_apis,
                            js_apis,
                            spa_routes,
                            swagger_endpoints,
                            postman_endpoints,
                            graphql_eps,
                            common_param_discoveries,
                            http_methods,
                        ) = await self._discover_all(context, page, base_url, current)
                        fuzz_cfg = self.config.get("crawl", {}).get("fuzz", {})
                        # Sorted: a set's iteration order is hash-order, which
                        # varies run-to-run on randomized hash seeds — the module
                        # matrix and crawl queue must see a stable order (M2).
                        all_apis = sorted(set(static_apis + js_apis + list(captured_apis)))

                        # Eager discovery view: every URL found on this page is
                        # known NOW, before the module matrix runs — the SSRF
                        # module needs this same-page visibility to probe
                        # same-origin internal routes.
                        for _u in list(links) + all_apis + list(spa_routes):
                            if _u and self._is_in_scope(_u):
                                self._discovered_urls.add(_u.split("?")[0])

                        for route in spa_routes:
                            if route not in self.visited and self._is_in_scope(route) and len(self.visited) < self.max_pages:
                                self.visited.add(route)
                                queue.append((route, depth + 1))

                        for ep in swagger_endpoints:
                            ep_url = ep["path"]
                            if ep_url not in self.visited and self._is_in_scope(ep_url) and len(self.visited) < self.max_pages:
                                self.visited.add(ep_url)
                                queue.append((ep_url, depth + 1))
                            all_apis.append(ep_url)

                        for ep in postman_endpoints:
                            ep_url = ep["path"]
                            if ep_url not in self.visited and self._is_in_scope(ep_url) and len(self.visited) < self.max_pages:
                                self.visited.add(ep_url)
                                queue.append((ep_url, depth + 1))
                            all_apis.append(ep_url)

                        for ep in graphql_eps:
                            if ep not in self.visited and self._is_in_scope(ep) and len(self.visited) < self.max_pages:
                                self.visited.add(ep)
                                queue.append((ep, depth + 1))
                            all_apis.append(ep)

                        for ep_url, params in common_param_discoveries.items():
                            if ep_url not in self.visited and self._is_in_scope(ep_url) and len(self.visited) < self.max_pages:
                                self.visited.add(ep_url)
                                queue.append((ep_url, depth + 1))
                            if params:
                                all_apis.append(ep_url)

                        for ep in http_methods:
                            ep_url = ep["path"]
                            if ep_url not in self.visited and self._is_in_scope(ep_url) and len(self.visited) < self.max_pages:
                                self.visited.add(ep_url)
                                queue.append((ep_url, depth + 1))
                            all_apis.append(ep_url)

                        # Response-driven path fuzzing: brute-force deeper
                        # segments off everything discovered so far. Hits are
                        # fed straight back into all_apis (so the module matrix
                        # scans them this very page) AND the crawl queue (so
                        # they get their own crawl pass). Bounded by
                        # crawl.fuzz; a failure degrades to zero extra
                        # endpoints, never an error.
                        try:
                            fuzzed = await asyncio.wait_for(
                                self._fuzz_paths(context, all_apis, base_url),
                                timeout=float(fuzz_cfg.get("budget", 60)),
                            )
                            if fuzzed:
                                print(f"    [+] Path fuzzer: {len(fuzzed)} deeper endpoint(s) discovered")
                                for fu in fuzzed:
                                    fu_base = fu.split("?")[0]
                                    if fu_base not in self.visited and self._is_in_scope(fu_base) and len(self.visited) < self.max_pages:
                                        self.visited.add(fu_base)
                                        queue.append((fu_base, depth + 1))
                                    if fu_base not in all_apis:
                                        all_apis.append(fu_base)
                        except Exception:
                            pass

                        discovered_apis = self._dedupe_apis(all_apis)
                        if len(discovered_apis) > self.max_apis:
                            self._coverage["capped_apis"] = True
                        self._coverage["apis_discovered"] += len(discovered_apis)
                        apis = discovered_apis[: self.max_apis]
                        self._coverage["apis_scanned"] += len(apis)

                if not resp or resp.status >= 400:
                    status_code = resp.status if resp else 0
                    print(f"    [!] Skipped (status {status_code})")
                    # SESSION-AWARE REPLAY: track 401/403 routes so they can
                    # be re-scanned after auth succeeds.
                    if status_code in (401, 403) and self._auth_scope == "unauthenticated":
                        self._gated_routes.add(current)
                    # WAF BYPASS: detect WAF blocking on 403/429 responses
                    if status_code in (403, 429):
                        waf_info = self._waf_tracker.detect(
                            current, status_code, body if body else "", dict(resp.headers) if resp else {}
                        )
                        if waf_info:
                            print(f"    [!] WAF detected: {waf_info.waf_name} (confidence {waf_info.confidence:.0%})")
                    continue

                # ROLE-AWARE: record this successful access for capability inference
                self._role_scanner.record_access(current, resp.status, body)

                if is_api_url:
                    print(f"    [+] API: {current} (status {resp.status}, len={len(body)})")
                    discovered_apis = self._dedupe_apis([current] + apis)
                    if len(discovered_apis) > self.max_apis:
                        self._coverage["capped_apis"] = True
                    self._coverage["apis_discovered"] += len(discovered_apis)
                    apis = discovered_apis[: self.max_apis]
                    self._coverage["apis_scanned"] += len(apis)
                    # CONCURRENT: schedule module run as background task so
                    # the next page's fetch can start immediately.
                    _module_tasks.append(
                        asyncio.create_task(
                            self._run_api_modules(context, current, current, fingerprint)
                        )
                    )
                else:
                    print(f"    [+] Forms: {len(forms)}, Links: {len(links)}, APIs: {len(apis)}")
                    # CONCURRENT: schedule module run as background task.
                    # Module runners use context.request (not page.goto), so
                    # they're safe to run while the browser navigates to the
                    # next page.  Findings are collected after the crawl loop.
                    # ROUTE-SCORING: compute attack value for this URL so
                    # expensive modules are skipped on low-value routes.
                    techs = fingerprint.get("technologies", []) if fingerprint else []
                    _route_score = score_url(current, forms=forms, technologies=techs, depth=depth)
                    _module_tasks.append(
                        asyncio.create_task(
                            self._run_modules(context, current, forms, links, apis, fingerprint, result, route_score=_route_score)
                        )
                    )

                for link in links:
                    self._discovered_urls.add(link.split("?")[0])
                    if link not in self.visited and self._is_in_scope(link):
                        self.visited.add(link)
                        queue.append((link, depth + 1))

                for api in apis:
                    api_base = api.split("?")[0]
                    if api_base not in self.visited and self._is_in_scope(api_base) and len(self.visited) < self.max_pages:
                        self.visited.add(api_base)
                        queue.append((api_base, depth + 1))

                # ANOMALY INTERRUPT: check this page for anomalies and
                # promote interesting routes to the front of the queue.
                if resp and resp.status < 400:
                    try:
                        # Get cookies from the browser context
                        _cookies = []
                        try:
                            _cookies = [c["name"] for c in await context.cookies()]
                        except Exception:
                            pass
                        # Check for redirect target
                        _redirect = None
                        if self.redirect_chain:
                            _redirect = self.redirect_chain[-1].get("to")
                        anomalies = self._anomaly_tracker.check(
                            url=current,
                            status=resp.status,
                            body=body[:50000],  # cap body for performance
                            headers=dict(resp.headers),
                            cookies=_cookies,
                            redirect_target=_redirect,
                        )
                        for a in anomalies:
                            print(f"    [!] ANOMALY: {a.kind} on {current} — {a.detail}")
                            # Promote: prepend to front of queue with boosted score
                            if current not in self.visited and self._is_in_scope(current):
                                queue.insert(0, (current, depth))
                    except Exception:
                        pass

                # ROUTE-SCORING: re-sort the queue by attack value after
                # discovering new URLs.  High-value routes (auth, upload,
                # API) are scanned first; low-value routes (static assets)
                # are deprioritized or skipped entirely.
                if queue:
                    techs = fingerprint.get("technologies", []) if fingerprint else []
                    queue = sort_queue(queue, technologies=techs)

                elapsed = time.monotonic() - page_start
                print(f"    [i] Page processed in {elapsed:.1f}s")
            except Exception as e:
                print(f"    [!] Error crawling {current}: {e}")
                continue

        # CONCURRENT CRAWL: wait for all background module tasks to finish.
        # Module runners use context.request (not page.goto), so they ran
        # concurrently with the next page's fetch.  Now we collect results.
        if _module_tasks:
            print(f"[+] Waiting for {len(_module_tasks)} background module task(s) to finish...")
            done_results = await asyncio.gather(*_module_tasks, return_exceptions=True)
            for res in done_results:
                if isinstance(res, BaseException):
                    if self._is_driver_death(res):
                        self._driver_dead = True
                    continue
                if isinstance(res, list):
                    result.findings.extend(res)

        # A3 coverage flags from the loop's exit condition: the queue drained
        # (complete) vs the max_pages cap stopped the crawl with URLs still
        # queued (partial — reason: budget).
        self._coverage["queue_exhausted"] = not queue
        self._coverage["capped_max_pages"] = bool(queue) and processed_count >= self.max_pages

        result.findings = self._dedupe_findings(result.findings)
        result.findings = [f for f in result.findings if self._is_in_scope(f.url)]

        from titan.core.cvss import CVSSScorer
        from titan.core.poc import PoCGenerator
        for f in result.findings:
            if not f.cvss_score:
                cvss_data = CVSSScorer.score(f)
                f.cvss_score = cvss_data["cvss_score"]
                f.cvss_vector = cvss_data["cvss_vector"]
            if not f.poc_curl or not f.poc_python:
                poc = PoCGenerator.generate(f)
                f.poc_curl = poc["curl"]
                f.poc_python = poc["python"]

        clean_fingerprint = {}
        for k, v in (result.fingerprint or {}).items():
            try:
                import json
                json.dumps(v)
                clean_fingerprint[k] = v
            except (TypeError, ValueError):
                pass
        result.fingerprint = clean_fingerprint

    def _is_in_scope(self, url: str) -> bool:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            target_hostname = urlparse(self._scan_target or self.config.get("target", "")).hostname or ""
            if not target_hostname:
                return True
            return hostname == target_hostname or hostname.endswith("." + target_hostname)
        except Exception:
            return True

    def _select_platform_brain(self, fingerprint: Dict[str, Any], html: str, headers: Dict[str, str]) -> Optional[Any]:
        try:
            from titan.brains import BrainRegistry, MoodleBrain
        except ImportError:
            return None
        registry = BrainRegistry()
        registry.register(MoodleBrain())
        return registry.select(fingerprint, html, headers)

    async def _run_interactions(self, context, target: str, fingerprint: Dict[str, Any], result: ScanResult) -> None:
        """Bounded SPA/API interaction phase.

        Each interaction gets its OWN page (the shared-page race was real —
        five concurrent ``page.goto`` calls on one page abort each other and
        silently drop captured endpoints) and a HARD per-interaction budget.
        A crawl-timeout cancellation can wedge the Playwright Node driver
        (abandoned in-flight calls); an un-bounded ``new_page``/``close`` on a
        wedged driver hangs the scan for minutes (observed: ~42 min of silence
        after a crawl timeout). Every page op is timeout-wrapped so a wedged
        driver degrades to an empty interaction, never a hang.
        """
        if self._driver_dead:
            return
        # SPA gate (M3): the interaction phase replays SPA-style navigation to
        # capture API calls — it is only meaningful when the crawl saw
        # client-side signals (hash links / JS route table). Deep profile
        # always runs it; a static site with no SPA signals skips it entirely
        # (the observed "#/patients on a weather site" artifact).
        if not self._spa_detected and not self._deep:
            return
        interaction_targets = list(self.visited)[:5]
        # Clamp to >= 1: asyncio.wait_for raises ValueError on a negative
        # timeout, and 0 would silently skip every interaction.
        budget = max(1, self.config.get("crawl", {}).get("interaction_timeout", 90))

        async def interact_one(vu: str):
            async def _interact():
                i_page = None
                try:
                    i_page = await asyncio.wait_for(context.new_page(), timeout=10)
                    self._harden_page(i_page)
                except asyncio.TimeoutError:
                    # Wedged driver: can't even open a page. Give up quietly.
                    return
                try:
                    api_endpoints = await asyncio.wait_for(
                        self._interact_and_capture(context, i_page, vu), timeout=30
                    )
                    for api_url in api_endpoints:
                        if api_url not in self.visited and self._is_in_scope(api_url):
                            self.visited.add(api_url)
                            # Bounded: the module matrix on a captured
                            # API can run minutes on its own; the
                            # interaction phase must never exceed a
                            # fixed tail budget.
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
            except asyncio.TimeoutError:
                pass
            except asyncio.CancelledError:
                pass
            except Exception:
                pass

        # return_exceptions=True: an interaction task that dies to a driver
        # teardown (TargetClosedError on a page.close() racing p.stop()) must
        # never propagate into the scan's main task — the observed
        # "Future exception was never retrieved ... TargetClosedError" spam
        # after every crawl timeout came from exactly this gather.
        await asyncio.gather(
            *[interact_one(vu) for vu in interaction_targets],
            return_exceptions=True,
        )

    async def _interact_and_capture(self, context, page, base_url: str) -> List[str]:
        print(f"[+] Starting interaction on {base_url}")
        api_endpoints: List[str] = []
        
        try:
            await page.goto(base_url, wait_until="domcontentloaded", timeout=15000)
        except Exception:
            return api_endpoints
        
        captured_urls: List[str] = []
        ws_urls: List[str] = []
        def capture_request(request):
            if self._looks_like_api(request.url):
                captured_urls.append(request.url)
        
        # B1 — WebSocket handshake URLs are a probeable HTTP surface (the
        # module matrix probes their http(s) form). Juice Shop's chat, most
        # realtime feeds, and many SPA backends expose endpoints over WS that
        # the request listener never sees.
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
                    
                    forms = await page.evaluate('''() => document.querySelectorAll('form').length''')
                    if forms > 0:
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
        
        # B1 — fold WebSocket captures in as http(s) probes, deduped + scoped
        # by the pure helper (same logic the tests pin).
        from titan.core.spa import select_runtime_apis
        api_endpoints = select_runtime_apis(
            captured_urls,
            ws_urls=ws_urls,
            base_url=base_url,
            scope_host=urlparse(self._scan_target).hostname or "",
        )
        
        print(f"[+] Interaction captured {len(api_endpoints)} API endpoints "
              f"({len(ws_urls)} websocket)")
        return api_endpoints

    async def _fill_and_submit_form(self, page, form: Dict[str, Any], base_url: str) -> None:
        action = form.get("action") or base_url
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        
        for inp in inputs:
            try:
                name = inp.get("name", "")
                if not name:
                    continue
                await page.evaluate(f'''(name) => {{
                    const el = document.querySelector('[name="{name}"]');
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

    def _looks_like_api(self, url: str) -> bool:
        if not self._is_in_scope(url):
            return False
        api_indicators = ["/api/", "/sales/", "/v1/", "/v2/", "/rest/", "/graphql", "api.", ".json"]
        lower = url.lower()
        path = urlparse(lower).path
        return any(ind in path for ind in api_indicators)

    def _is_spa_shell(self, url: str) -> bool:
        return "#" in url

    @staticmethod
    def _is_state_changing_path(url: str) -> bool:
        """True if the URL path names a state-changing endpoint (create /
        update / delete / register / login) — the only places mass-assignment
        fields make sense to POST."""
        path = urlparse(url).path.lower()
        return any(k in path for k in (
            "update", "create", "delete", "remove", "edit", "register",
            "signup", "add", "save", "set", "change", "reset",
            "upload", "transfer", "send", "approve", "role",
        ))

    async def _discover_all(
        self,
        context,
        page,
        base_url: str,
        current: str,
    ):
        """Run all discovery probes concurrently, isolating failures.

        Probes run in parallel to cut discovery from many sequential
        multi-second requests down to one round. ``return_exceptions=True``
        means a failing probe (e.g. a ``page.evaluate`` racing a navigation)
        is returned as an exception and degraded to its empty default — one
        failure can never nullify the other probes or skip the page.

        M3 profile gate: in ``fast`` mode only the content-derived probes run
        (forms, links, JS-referenced APIs, JS route table, SPA hash signals).
        Every hardcoded guess — the API path list, swagger/postman/graphql
        spec probing, common-param brute force, HTTP-method brute force — is
        ``deep``-only, so a static site is never probed with another site's
        vocabulary (the weather.co.ke "#/patients" / local-lab "/hash"
        artifacts).
        """
        # Keep the probe order EXACTLY matching the caller's unpacking
        # (forms, links, static_apis, js_apis, spa_routes, swagger, postman,
        # graphql, common_params, methods); gated probes are replaced in place
        # by empty sentinels in fast mode.
        probes = [
            self._extract_forms(page),
            self._extract_links(page, base_url),
            self._discover_apis(page, base_url) if self._deep else _noop_api_probe(),
            self._extract_apis_from_js(page, base_url),
            self._crawl_spa_routes(context, page, current),
            self._parse_swagger_spec(context, current) if self._deep else _noop_api_probe(),
            self._parse_postman_collection(context, current) if self._deep else _noop_api_probe(),
            self._discover_graphql_endpoints(context, current) if self._deep else _noop_api_probe(),
            self._brute_force_common_params(context, current, max_endpoints=5) if self._deep else _noop_params_probe(),
            self._brute_force_http_methods(context, current, max_endpoints=5) if self._deep else _noop_methods_probe(),
        ]
        (
            forms,
            links,
            static_apis,
            js_apis,
            spa_routes,
            swagger_endpoints,
            postman_endpoints,
            graphql_eps,
            common_param_discoveries,
            http_methods,
        ) = await asyncio.gather(*probes, return_exceptions=True)

        # SPA signal for the interaction gate: hash links or a JS route table
        # mean the app drives navigation client-side — the interaction phase
        # is only worth its time then (a static weather site with zero SPA
        # signals must not get its routes replayed).
        try:
            if isinstance(links, list) and any("#" in l for l in links):
                self._spa_detected = True
            elif isinstance(spa_routes, list) and spa_routes:
                self._spa_detected = True
        except Exception:
            pass
        # Degrade any failed probe to its empty default.
        if isinstance(forms, BaseException):
            forms = []
        if isinstance(links, BaseException):
            links = []
        if isinstance(static_apis, BaseException):
            static_apis = []
        if isinstance(js_apis, BaseException):
            js_apis = []
        if isinstance(spa_routes, BaseException):
            spa_routes = []
        if isinstance(swagger_endpoints, BaseException):
            swagger_endpoints = []
        if isinstance(postman_endpoints, BaseException):
            postman_endpoints = []
        if isinstance(graphql_eps, BaseException):
            graphql_eps = []
        if isinstance(common_param_discoveries, BaseException):
            common_param_discoveries = {}
        if isinstance(http_methods, BaseException):
            http_methods = []
        return (
            forms,
            links,
            static_apis,
            js_apis,
            spa_routes,
            swagger_endpoints,
            postman_endpoints,
            graphql_eps,
            common_param_discoveries,
            http_methods,
        )

    async def _extract_apis_from_js(self, page, base_url: str) -> List[str]:
        apis: List[str] = []
        js_paths = await page.evaluate('''() => {
            const scripts = [];
            for (const s of document.querySelectorAll('script[src]')) {
                scripts.push(s.getAttribute('src'));
            }
            return scripts;
        }''')
        
        for js_path in js_paths:
            try:
                if js_path.startswith("http"):
                    js_url = js_path
                else:
                    js_url = base_url.rstrip("/") + js_path
                resp = await page.request.get(js_url, timeout=10000)
                if resp.status != 200:
                    continue
                text = await resp.text()
                apis.extend([u for u in self._parse_api_patterns(text, base_url) if self._is_in_scope(u)])
            except Exception:
                continue
        return apis

    def _parse_api_patterns(self, js_text: str, base_url: str) -> List[str]:
        apis: List[str] = []
        patterns = [
            r'https?://[^\s"\'<>]+/sales/[^\s"\'<>]+',
            r'https?://[^\s"\'<>]+/api/[^\s"\'<>]+',
            r'https?://[^\s"\'<>]+/v1/[^\s"\'<>]+',
            r'https?://[^\s"\'<>]+/v2/[^\s"\'<>]+',
            r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
            r'axios\.create\([^)]*baseURL[^)]*\)',
            r'https?://[^\s"\'<>]+/auth/[^\s"\'<>]+',
            r'https?://[^\s"\'<>]+/login[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/register[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/patients[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/appointments[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/facilities[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/referrals[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/triage[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/followup[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/voice[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/ussd[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/transcription[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/analytics[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/reports[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/notifications[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/prescriptions[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/lab-results[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/vitals[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/audit[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/settings[^\s"\'<>]*',
            r'https?://[^\s"\'<>]+/config[^\s"\'<>]*',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']',
        ]
        for pat in patterns:
            matches = re.findall(pat, js_text)
            for m in matches:
                if isinstance(m, tuple):
                    m = m[0] if m[0] else m[1]
                apis.append(m)
        return sorted(set(apis))

    async def _crawl_spa_routes(self, context, page, base_url: str) -> List[str]:
        discovered: List[str] = []
        
        try:
            js_routes = await page.evaluate('''() => {
                const routes = new Set();
                const origin = window.location.origin;
                
                if (window.__ROUTES__) {
                    for (const r of window.__ROUTES__) routes.add(origin + r);
                }
                if (window.routes) {
                    for (const r of window.routes) routes.add(origin + r);
                }
                if (window.router) {
                    const r = window.router;
                    if (r.routes) {
                        for (const route of r.routes) {
                            if (route.path) routes.add(origin + route.path);
                            if (route.pathname) routes.add(origin + route.pathname);
                        }
                    }
                }
                
                document.querySelectorAll('a[href^="#"], a[href^="/"]').forEach(a => {
                    const href = a.getAttribute('href');
                    if (href && !href.startsWith('#/__')) {
                        routes.add(origin + href);
                    }
                });
                
                document.querySelectorAll('[data-route], [data-path], [data-link]').forEach(el => {
                    const val = el.getAttribute('data-route') || el.getAttribute('data-path') || el.getAttribute('data-link');
                    if (val) routes.add(origin + val);
                });
                
                return Array.from(routes).slice(0, 50);
            }''')
            
            for route in js_routes:
                if self._is_in_scope(route):
                    discovered.append(route)
        except Exception:
            pass
        
        # The common hash-route list is a hardcoded guess (the health-app
        # vocabulary that got replayed against a static weather site) —
        # deep-profile only. The JS route-table enumeration above is
        # content-derived and always runs.
        if self._deep:
            try:
                hash_routes = await page.evaluate('''() => {
                    const routes = [];
                    const origin = window.location.origin;
                    const common = ['/', '/login', '/register', '/dashboard', '/admin', '/profile', '/settings', '/patients', '/appointments', '/referrals', '/clinical', '/triage', '/analytics', '/notifications', '/followup', '/payments', '/facilities', '/voice', '/ussd', '/transcription'];
                    for (const r of common) routes.push(origin + '#!' + r, origin + '#' + r);
                    return routes;
                }''')

                for route in hash_routes:
                    if self._is_in_scope(route):
                        discovered.append(route)
            except Exception:
                pass

        return sorted(set(discovered))

    async def _hydrate_spa_routes(
        self, context, page, base_url: str, budget: float = 10.0
    ) -> List[str]:
        """B1 — wait for the SPA's route table to hydrate, then return the
        discovered routes.

        A real SPA (Angular/React/Vue) mounts its router lazily: the first
        page.evaluate often sees no route table because the framework hasn't
        booted. We poll up to ``budget`` seconds — route table + hash links
        + data-route attributes — and return the first non-empty, in-scope
        set. The click-through walk (_run_spa_harness) then drives each
        route so its runtime XHR/fetch/WebSocket calls surface into the API
        queue. Pure route extraction lives in titan.core.spa so the
        page.evaluate only ships back a JSON-safe blob.
        """
        from titan.core.spa import route_table_candidates

        deadline = time.monotonic() + budget
        seen_routes: List[str] = []
        while time.monotonic() < deadline:
            try:
                blob = await page.evaluate('''() => {
                    const routes = [];
                    const pathLinks = [];
                    const hashLinks = [];
                    const dataRoutes = [];
                    const origin = window.location.origin;

                    const pushRoute = (r) => { if (r && typeof r === 'string') routes.push(r); };

                    // Framework globals (Angular / React Router / Vue / custom).
                    if (window.__ROUTES__) (window.__ROUTES__ || []).forEach(pushRoute);
                    if (window.routes) {
                        if (Array.isArray(window.routes)) window.routes.forEach(pushRoute);
                        else if (window.routes.routes) (window.routes.routes || []).forEach(pushRoute);
                    }
                    if (window.router) {
                        const r = window.router;
                        if (r.routes) {
                            (r.routes || []).forEach(rt => {
                                if (rt && typeof rt === 'object') {
                                    pushRoute(rt.path); pushRoute(rt.pathname);
                                    if (rt.children) (rt.children || []).forEach(c => pushRoute(c.path));
                                } else pushRoute(rt);
                            });
                        }
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

    async def _run_spa_harness(
        self, context, target: str, fingerprint: Dict[str, Any], result: ScanResult
    ) -> None:
        """B1 — drive a JS-rendered app's routes so its runtime API surface
        reaches the module matrix.

        This is what turns a 0-finding SPA scan (Juice Shop) into a real one:
        hydrate the route table, walk each discovered route with its OWN page
        (same isolation rule as interactions), wait for network idle, and
        feed every captured XHR/fetch/WebSocket URL into the module matrix.

        Every step is budget-bounded and degrades quietly: a wedged driver or
        a flaky route yields an empty capture, never a hang. Hash routes are
        walked with their fragment stripped (the server serves the same shell
        for every route; the fragment only matters client-side).
        """
        from titan.core.spa import strip_fragment

        if self._driver_dead:
            return
        spa_cfg = self.config.get("crawl", {}).get("spa", {})
        hydrate_budget = float(spa_cfg.get("hydrate_budget", 10))
        max_routes = int(spa_cfg.get("max_routes", 6))
        per_route_budget = int(spa_cfg.get("per_route_budget", 30))
        wait_idle = int(spa_cfg.get("network_idle", 2500))

        page = None
        try:
            page = await asyncio.wait_for(context.new_page(), timeout=10)
            self._harden_page(page)
            routes = await asyncio.wait_for(
                self._hydrate_spa_routes(context, page, target, budget=hydrate_budget),
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
                captured: List[str] = []
                try:
                    async def _walk_one():
                        nonlocal captured
                        await page.goto(probe_url, wait_until="domcontentloaded", timeout=15000)
                        try:
                            await page.wait_for_load_state("networkidle", timeout=wait_idle)
                        except Exception:
                            pass
                        captured = await self._interact_and_capture(context, page, route)
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
                                self._run_api_modules(context, target, api_url, fingerprint),
                                timeout=60,
                            )
                        except asyncio.TimeoutError:
                            api_findings = []
                        result.findings.extend(api_findings)
                captured_total += len(captured)
            print(f"[+] SPA harness: {captured_total} runtime API endpoint(s) captured")
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
        finally:
            if page is not None:
                try:
                    await asyncio.wait_for(page.close(), timeout=5)
                except Exception:
                    pass

    async def _fuzz_paths(self, context, seeds: List[str], base_url: str) -> List[str]:
        """Response-driven path fuzzing: brute-force deeper segments off the
        discovered API surface with a wordlist.

        Each seed gets a random-marker 404 control request first; a candidate
        path is kept only when its (status, body-signature) response differs
        from that control, so soft-404 HTML and framework catch-alls are
        filtered by the server's own answer. Bounded by ``crawl.fuzz``
        (max_seeds/max_depth/max_words_per_seed/max_requests/concurrency). A
        failure anywhere degrades to an empty result — fuzzing must never be
        able to break a crawl.
        """
        fuzz_cfg = self.config.get("crawl", {}).get("fuzz", {})
        # M3 profile gate: the wordlist fuzzer is deep-profile only. It probes
        # hundreds of guessed segments per page, which contradicts the
        # fast-default contract; ``fuzz.enabled: false`` still overrides deep.
        if not self._deep:
            return []
        if not fuzz_cfg.get("enabled", True):
            return []
        try:
            from titan.core.pathfuzz import PathFuzzer
            fuzzer = PathFuzzer(
                fuzz_cfg,
                in_scope=self._is_in_scope,
                stealth=self.stealth if hasattr(self, "stealth") else None,
            )
            return await fuzzer.fuzz(context, seeds)
        except Exception:
            return []

    async def _parse_swagger_spec(self, context, base_url: str) -> List[Dict[str, Any]]:
        endpoints: List[Dict[str, Any]] = []
        spec_urls = [
            base_url.rstrip("/") + "/swagger.json",
            base_url.rstrip("/") + "/openapi.json",
            base_url.rstrip("/") + "/api-docs",
            base_url.rstrip("/") + "/swagger.yaml",
            base_url.rstrip("/") + "/openapi.yaml",
        ]
        
        for spec_url in spec_urls:
            try:
                resp = await context.request.get(spec_url, timeout=10000)
                if resp.status != 200:
                    continue
                text = await resp.text()
                
                try:
                    spec = json.loads(text)
                except Exception:
                    continue
                
                paths = spec.get("paths", {})
                for path, methods in paths.items():
                    if not self._is_in_scope(base_url.rstrip("/") + path):
                        continue
                    for method, details in methods.items():
                        if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
                            continue
                        params = []
                        for param in details.get("parameters", []):
                            if param.get("in") == "query":
                                params.append(param.get("name", ""))
                            elif param.get("in") == "body":
                                schema = param.get("schema", {})
                                props = schema.get("properties", {})
                                params.extend(list(props.keys()))
                        endpoints.append({
                            "path": base_url.rstrip("/") + path,
                            "method": method.upper(),
                            "params": params,
                            "summary": details.get("summary", ""),
                            "operation_id": details.get("operationId", ""),
                        })
            except Exception:
                continue
        
        return endpoints

    async def _parse_postman_collection(self, context, base_url: str) -> List[Dict[str, Any]]:
        endpoints: List[Dict[str, Any]] = []
        collection_urls = [
            base_url.rstrip("/") + "/postman_collection.json",
            base_url.rstrip("/") + "/collection.json",
            base_url.rstrip("/") + "/api_collection.json",
        ]
        
        for col_url in collection_urls:
            try:
                resp = await context.request.get(col_url, timeout=10000)
                if resp.status != 200:
                    continue
                text = await resp.text()
                collection = json.loads(text)
                
                items = collection.get("item", [])
                for item in self._flatten_postman_items(items):
                    request = item.get("request", {})
                    url = request.get("url", {})
                    method = request.get("method", "GET").upper()
                    
                    if isinstance(url, dict):
                        raw = url.get("raw", "")
                        path = raw.split("?")[0]
                        if not path.startswith("http"):
                            path = base_url.rstrip("/") + path
                        query = url.get("query", [])
                        params = [q.get("key", "") for q in query if q.get("key")]
                    else:
                        path = str(url).split("?")[0]
                        params = []
                    
                    if self._is_in_scope(path):
                        endpoints.append({
                            "path": path,
                            "method": method,
                            "params": params,
                            "summary": item.get("name", ""),
                        })
            except Exception:
                continue
        
        return endpoints

    def _flatten_postman_items(self, items: List[Any]) -> List[Dict[str, Any]]:
        result = []
        for item in items:
            if "item" in item:
                result.extend(self._flatten_postman_items(item["item"]))
            else:
                result.append(item)
        return result

    async def _discover_graphql_endpoints(self, context, base_url: str) -> List[str]:
        endpoints: List[str] = []
        graphql_paths = ["/graphql", "/api/graphql", "/graphql/api", "/v1/graphql", "/v2/graphql"]
        
        for path in graphql_paths:
            try:
                resp = await context.request.post(
                    base_url.rstrip("/") + path,
                    json={"query": "{ __schema { types { name } } }"},
                    headers={"Content-Type": "application/json"},
                    timeout=10000,
                )
                text = await resp.text()
                if resp.status == 200 and "__schema" in text:
                    endpoints.append(base_url.rstrip("/") + path)
            except Exception:
                continue
        
        return endpoints

    async def _brute_force_common_params(self, context, base_url: str, max_endpoints: int = 3) -> Dict[str, List[str]]:
        common_params = [
            "id", "user_id", "account_id", "profile_id", "patient_id", "client_id", "order_id",
            "file", "file_id", "document", "image", "name", "username",
            "email", "phone", "password", "token", "api_key", "key",
            "url", "path", "page", "search", "query", "q",
            "status", "type", "category", "action", "cmd", "command",
            "country", "city", "location", "address",
            "date", "time", "amount", "price", "quantity", "qty",
            "message", "text", "content", "title",
            "redirect", "callback", "next", "debug", "admin",
            "format", "lang", "uuid", "slug", "csrf", "source",
            "limit", "offset", "sort", "order", "filter",
            "start_date", "end_date", "from", "to",
            "include", "exclude", "fields", "expand",
            "tenant", "org", "organization", "workspace",
            "appointment_id", "referral_id", "facility_id", "visit_id",
            "doctor_id", "nurse_id", "staff_id", "department",
            "diagnosis", "prescription", "medication", "lab_result",
            "vital", "symptom", "allergy", "immunization",
            "payment_id", "invoice_id", "transaction_id", "receipt",
        ]
        # PLATFORM BRAIN: append platform-specific parameters.
        common_params.extend(getattr(self, "_platform_extra_params", []) or [])
        top_params = common_params[:25]
        
        test_endpoints = []
        for visited in list(self.visited)[:max_endpoints]:
            if not self._is_spa_shell(visited):
                test_endpoints.append(visited)
        
        if not test_endpoints:
            test_endpoints = [base_url]
        
        discovered: Dict[str, List[str]] = {}
        for endpoint in test_endpoints[:max_endpoints]:
            accepted_params = []
            
            async def test_param(param):
                try:
                    test_params = {param: "1"}
                    resp = await context.request.get(endpoint, params=test_params, timeout=1500)
                    body = await resp.text()
                    
                    if resp.status == 200:
                        baseline_resp = await context.request.get(endpoint, timeout=1500)
                        baseline_body = await baseline_resp.text()
                        
                        if len(body) != len(baseline_body):
                            return param
                        elif param.lower() in body.lower() and param.lower() not in baseline_body.lower():
                            return param
                except Exception:
                    pass
                return None
            
            results = await asyncio.gather(*[test_param(p) for p in top_params])
            accepted_params = [r for r in results if r]
            
            if accepted_params:
                discovered[endpoint] = accepted_params[:10]
        
        return discovered

    async def _brute_force_http_methods(self, context, base_url: str, max_endpoints: int = 3) -> List[Dict[str, Any]]:
        methods = ["OPTIONS", "PUT", "PATCH", "DELETE", "HEAD"]
        results: List[Dict[str, Any]] = []
        
        test_endpoints = []
        for visited in list(self.visited)[:max_endpoints]:
            if not self._is_spa_shell(visited):
                test_endpoints.append(visited)
        
        if not test_endpoints:
            test_endpoints = [base_url]
        
        for endpoint in test_endpoints[:max_endpoints]:
            async def test_method(method):
                try:
                    resp = await context.request.fetch(endpoint, method=method, timeout=3000)
                    if resp.status not in (404, 405, 501):
                        return {
                            "path": endpoint,
                            "method": method,
                            "params": [],
                            "summary": f"Method {method} accepted (status {resp.status})",
                        }
                except Exception:
                    pass
                return None
            
            method_results = await asyncio.gather(*[test_method(m) for m in methods])
            results.extend([r for r in method_results if r])
        
        return results[:50]

    def _dedupe_apis(self, apis: List[str]) -> List[str]:
        seen = set()
        deduped = []
        for api in apis:
            key = api.split("?")[0]
            if key not in seen:
                seen.add(key)
                deduped.append(api)
        return deduped

    def _normalize_url(self, url: str) -> str:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        # Strip the query string: the same endpoint reached via a crawled link
        # (?id=1) and via API discovery (?id=1&q=test&search=test...) would
        # otherwise dedupe into two identical findings.
        normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", ""))
        return normalized.split("#")[0]

    # Attack classes whose identical (attack, payload, verified) findings on
    # DIFFERENT endpoints are one root cause — a catch-all route that echoes
    # the query string reproduces the same bug on every fuzzed path (the
    # zairaku.rest case: 21 identical CRITICAL LFI on 21 fuzzed endpoints).
    ROOT_CAUSE_ATTACK_TYPES = frozenset({
        "LFI", "SQLi", "NoSQLi", "SSRF", "XSS", "RCE", "SSTI", "XXE",
        "Request Smuggling", "Open Redirect", "OOB", "Deserialization",
    })

    def _dedupe_findings(self, findings: List[Finding]) -> List[Finding]:
        seen = set()
        deduped = []
        # Content-scan collapse: a body/header scan verdict with an IDENTICAL
        # payload across different URLs is one root cause, not one finding per
        # URL. A leaked AWS key in a shared JS bundle (HTB flagged the same
        # bundle on every page) or a missing security header on every endpoint
        # is a single misconfiguration — report it once.
        site_wide = set()
        for f in findings:
            norm_url = self._normalize_url(f.url)
            key = (norm_url, f.param, f.attack_type.value)
            if f.param == "body" or f.location == "header":
                # Severity is part of the signature: never let a CRITICAL
                # body leak be dropped in favor of an earlier HIGH with the
                # same payload.
                sig = (f.attack_type.value, f.payload, f.severity.value)
                if sig in site_wide:
                    continue
                site_wide.add(sig)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        # Root-cause pass: identical (attack_type, payload, verified) across
        # DIFFERENT endpoints collapse to ONE representative finding. The
        # other URLs are preserved in metadata["affected_urls"] so evidence
        # and remediation scope are not lost. Verification state is part of
        # the signature (a confirmed copy and a weak copy stay separate); the
        # highest-confidence copy wins and carries the merged URL list.
        root: Dict[tuple, Finding] = {}
        out: List[Finding] = []
        for f in deduped:
            if (
                f.attack_type is not None
                and f.attack_type.value in self.ROOT_CAUSE_ATTACK_TYPES
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

    async def _extract_forms(self, page) -> List[Dict[str, Any]]:
        return await page.evaluate('''() => {
            const forms = [];
            const all = document.querySelectorAll('form');
            for (const f of all) {
                const inputs = [];
                const fields = f.querySelectorAll('input, textarea, select, [contenteditable="true"]');
                for (const inp of fields) {
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

    async def _extract_links(self, page, base_url: str) -> List[str]:
        return await page.evaluate('''(base) => {
            const links = new Set();
            for (const a of document.querySelectorAll('a[href]')) {
                try {
                    const raw = a.href || a.getAttribute('href') || '';
                    let h;
                    if (raw.startsWith('#')) {
                        const url = new URL(base);
                        h = url.origin + url.pathname + raw;
                    } else {
                        h = new URL(raw, base).href;
                    }
                    if (h && !h.startsWith('javascript:') && !h.startsWith('mailto:') && !h.startsWith('tel:')) {
                        links.add(h);
                    }
                } catch(e) {}
            }
            for (const a of document.querySelectorAll('a[onclick]')) {
                try {
                    const href = a.getAttribute('onclick') || '';
                    const match = href.match(/['"]([^'"]+)['"]/);
                    if (match) {
                        const h = new URL(match[1], base).href;
                        if (h && !h.startsWith('javascript:')) links.add(h);
                    }
                } catch(e) {}
            }
            return Array.from(links);
        }''', base_url)

    async def _discover_apis(self, page, base_url: str) -> List[str]:
        apis = []
        paths = [
            "/swagger.json", "/openapi.json", "/api-docs", "/api/docs",
            "/graphql", "/api/graphql", "/graphiql", "/v1/graphql", "/v2/graphql",
            "/.well-known/raml", "/api.raml", "/api/swagger.json",
            "/api/v1/swagger.json", "/api/v2/swagger.json",
            "/api/v1/docs", "/api/v2/docs",
            "/products", "/categories", "/users", "/orders", "/payments",
            "/conversations", "/messages", "/notifications", "/dashboard",
            "/api/v1/products", "/api/v1/categories", "/api/v1/users",
            "/api/v2/products", "/api/v2/categories", "/api/v2/users",
            "/sales/products", "/sales/categories", "/sales/orders",
            "/sales/users", "/sales/conversations", "/sales/messages",
            "/health", "/healthz", "/ready", "/live", "/status", "/metrics",
            "/api/health", "/api/status", "/api/metrics", "/api/version",
            "/actuator", "/actuator/health", "/actuator/info",
            "/debug", "/debug/vars", "/console", "/admin", "/administrator",
            "/phpinfo", "/info", "/server-info", "/server-status",
            "/.env", "/.git/config", "/.DS_Store", "/backup", "/bak",
            "/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/token",
            "/api/v1/patients", "/api/v1/appointments", "/api/v1/facilities",
            "/api/v1/referrals", "/api/v1/triage", "/api/v1/followup",
            "/api/v1/voice", "/api/v1/ussd", "/api/v1/transcription",
            "/api/v1/analytics", "/api/v1/reports", "/api/v1/audit",
            "/api/v1/settings", "/api/v1/config", "/api/v1/notifications",
            "/api/v1/prescriptions", "/api/v1/lab-results", "/api/v1/vitals",
            "/sqli", "/xss", "/lfi", "/cmd", "/rce", "/ssrf", "/xxe", "/ssti",
            "/api/user", "/api/login", "/api/data", "/hash", "/config",
            "/search", "/login", "/register", "/upload", "/download", "/export",
            "/admin", "/administrator", "/manager", "/dashboard", "/panel",
            "/console", "/debug", "/test", "/dev", "/development",
            "/api/search", "/api/login", "/api/register", "/api/upload",
            "/api/download", "/api/export", "/api/admin", "/api/config",
        ]
        async def probe_get(path: str):
            found: List[str] = []
            try:
                resp = await page.request.get(base_url.rstrip("/") + path, timeout=5000)
                if resp.status == 200:
                    body = await resp.text()
                    if body and not body.startswith("<!doctype"):
                        found.append(base_url.rstrip("/") + path)
                        found.extend(self._extract_urls_from_json(body, base_url))
                elif resp.status in (301, 302, 307, 308):
                    location = resp.headers.get("location", "")
                    if location:
                        found.append(location)
            except Exception:
                pass
            return found

        # Concurrent probes: ~100 sequential requests each with a 5s timeout
        # would add up to minutes of pure waiting on slow targets.
        for found in await asyncio.gather(*[probe_get(p) for p in paths]):
            apis.extend(found)

        # POST-only endpoints (login, hash, register, token...) answer 404/405
        # to a GET probe, so a GET-only discovery pass can never find them — yet
        # they are exactly where authn bypasses and weak-crypto live. Probe the
        # common set with a benign POST body and keep anything that responds.
        post_paths = [
            "/api/login", "/login", "/signin", "/api/signin",
            "/api/register", "/register", "/api/signup", "/signup",
            "/api/token", "/token", "/api/refresh", "/refresh",
            "/api/auth/login", "/api/auth/register", "/api/auth/token",
            "/hash", "/api/hash", "/upload", "/api/upload",
            "/api/logout", "/api/session", "/session", "/api/verify",
            "/api/forgot", "/api/reset", "/api/2fa", "/api/otp",
        ]

        async def probe_post(path: str):
            try:
                resp = await page.request.post(
                    base_url.rstrip("/") + path,
                    data={"test": "1"},
                    timeout=4000,
                )
                if resp.status not in (404, 405, 501):
                    return base_url.rstrip("/") + path
            except Exception:
                pass
            return None

        # Probe concurrently — sequential 4s-timeout POSTs would add up to
        # minutes per page against slow targets.
        post_results = await asyncio.gather(*[probe_post(p) for p in post_paths])
        apis.extend([r for r in post_results if r])
        return apis

    def _extract_urls_from_json(self, json_text: str, base_url: str) -> List[str]:
        urls: List[str] = []
        try:
            import json
            data = json.loads(json_text)
            urls.extend(self._scan_json_for_urls(data, base_url))
        except Exception:
            pass
        return urls

    def _scan_json_for_urls(self, obj: Any, base_url: str) -> List[str]:
        urls: List[str] = []
        if isinstance(obj, dict):
            for key in ["url", "href", "link", "path", "endpoint", "api", "next", "previous"]:
                val = obj.get(key)
                if isinstance(val, str) and val.startswith("http") and self._is_in_scope(val):
                    urls.append(val)
                elif isinstance(val, dict) and "url" in val:
                    urls.extend(self._scan_json_for_urls(val, base_url))
            for val in obj.values():
                urls.extend(self._scan_json_for_urls(val, base_url))
        elif isinstance(obj, list):
            for item in obj:
                urls.extend(self._scan_json_for_urls(item, base_url))
        return urls

    async def _run_modules(
        self,
        context,
        target: str,
        forms: List[Dict[str, Any]],
        links: List[str],
        apis: List[str],
        fingerprint: Dict[str, Any],
        result: Optional[ScanResult] = None,
        route_score: int = 5,
    ) -> List[Finding]:
        findings: List[Finding] = []

        form_tasks = []
        for form in forms:
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
            # Stream results as groups finish instead of gathering everything:
            # the crawl runs under a wall-clock budget, and a mid-phase timeout
            # cancellation used to discard every in-flight finding. Extending
            # result.findings eagerly keeps already-verified evidence even when
            # the crawl is cut short.
            pending = [asyncio.ensure_future(c) for c in all_task_groups]
            try:
                for fut in asyncio.as_completed(pending):
                    try:
                        res = await fut
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        if self._is_driver_death(exc):
                            # Driver died mid-matrix: every remaining group
                            # would wedge, not fail. Cancel them all and keep
                            # the findings already collected.
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
                # A crawl-timeout cancellation only cancels the await we are
                # currently blocked on — every OTHER endpoint group in `pending`
                # would keep running orphaned, holding the module semaphore and
                # hammering the target for minutes after the timeout (and spam
                # "Future exception was never retrieved" as their Playwright
                # calls die). Cancel them all so the budget actually stops work.
                for fut in pending:
                    if not fut.done():
                        fut.cancel()
                raise

        return findings

    async def _run_attack_modules(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
        fingerprint: Dict[str, Any],
        route_score: int = 5,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # The params dict already carries the query values. If the URL still
        # contains a query string, re-sending url?x=1&x=<payload> makes servers
        # read the FIRST value — silently nullifying every injection. Strip it.
        url = url.split("?")[0]

        modules = [
            ("sqli", self._run_sqli),
            ("xss", self._run_xss),
            ("ssrf", self._run_ssrf),
            ("auth", self._run_auth),
            ("idor", self._run_idor),
            ("lfi", self._run_lfi),
            ("rce", self._run_rce),
            ("nosqli", self._run_nosqli),
            ("ssti", self._run_ssti),
            ("xxe", self._run_xxe),
            ("upload", self._run_upload),
            ("logic", self._run_logic),
            ("cors", self._run_cors),
            ("headers", self._run_headers),
            ("crypto", self._run_crypto),
            ("deser", self._run_deser),
            ("race", self._run_race),
            ("cache", self._run_cache),
            ("smuggling", self._run_smuggling),
            # PUSH-TO-100 B3 — novel-class detectors: dictionary input
            # fuzzing + parser-differential (same bytes, two parsers).
            ("fuzzer", self._run_fuzzer),
            ("parserdiff", self._run_parserdiff),
            # Source/bundle floor + API-fed DOM-sink static analysis.
            ("sourcesecret", self._run_sourcesecret),
            ("apixss", self._run_apixss),
            ("baas", self._run_baas),
        ]

        is_spa_shell = "#" in url
        config_only_modules = {"cors", "headers", "crypto", "deser", "race", "cache", "smuggling"}
        # ROUTE-SCORING: expensive modules that add 5-15s per invocation.
        # Skip these on low-score routes (< 3) to save time on static pages.
        expensive_modules = {"sqli", "ssti", "nosqli", "xxe", "rce", "lfi",
                             "upload", "deser", "race", "smuggling", "parserdiff"}

        if self._driver_dead:
            return []

        async def run_with_limit(name, runner):
            async with self._module_semaphore:
                return await self._run_single_module(name, runner, context, target, method, url, params, fingerprint)

        # PHASE 7 — EARLY EXIT: split modules into cheap and expensive.
        # Run cheap modules first. If zero findings after 5 cheap modules,
        # skip the expensive ones entirely. High-value routes (score > 5)
        # always run everything.
        cheap_modules = ["headers", "cors", "crypto", "auth", "idor", "logic"]
        skip_early = route_score <= 5  # only apply early-exit on non-critical routes

        # Batch 1: cheap modules
        cheap_tasks = []
        cheap_names = []
        for name, runner in modules:
            if not self.config.get("modules", {}).get(name, {}).get("enabled", True):
                continue
            if is_spa_shell and name not in config_only_modules:
                continue
            # ROUTE-SCORING: skip expensive modules on low-value routes
            if route_score < 3 and name in expensive_modules:
                continue
            if name in cheap_modules:
                cheap_tasks.append(run_with_limit(name, runner))
                cheap_names.append(name)

        cheap_results = await asyncio.gather(*cheap_tasks, return_exceptions=True) if cheap_tasks else []
        for res in cheap_results:
            if isinstance(res, BaseException):
                if self._is_driver_death(res):
                    self._driver_dead = True
                continue
            if isinstance(res, list):
                findings.extend(res)

        # PHASE 7 — early-exit decision: if cheap modules found nothing on a
        # low-value route, skip the expensive batch entirely.
        cheap_had_findings = len(findings) > 0
        if skip_early and not cheap_had_findings and cheap_tasks:
            skipped_count = sum(1 for n, _ in modules if n in expensive_modules)
            # Don't skip config-only modules — they're cheap and always useful
            skipped_count -= sum(1 for n in expensive_modules if n in config_only_modules)
            if skipped_count > 0:
                print(f"    [i] Early exit: 0 findings from {len(cheap_tasks)} cheap modules, skipping {skipped_count} expensive modules")
                return findings

        # Batch 2: expensive modules (or all if skip_early didn't trigger)
        expensive_tasks = []
        for name, runner in modules:
            if not self.config.get("modules", {}).get(name, {}).get("enabled", True):
                continue
            if is_spa_shell and name not in config_only_modules:
                continue
            if route_score < 3 and name in expensive_modules:
                continue
            if name not in cheap_modules:
                expensive_tasks.append(run_with_limit(name, runner))

        results = await asyncio.gather(*expensive_tasks, return_exceptions=True) if expensive_tasks else []
        for res in results:
            if isinstance(res, BaseException):
                if self._is_driver_death(res):
                    self._driver_dead = True
                continue
            if isinstance(res, list):
                findings.extend(res)

        # EVIDENCE-GATE OVERRIDE: modules self-declare verified=True without
        # external proof.  Force ALL module output to verified=False so the
        # evidence gate (verify/flows.py) is the SOLE path to verified=True.
        # This kills hallucination-class criticals at the source.
        for f in findings:
            f.verified = False

        return findings

    async def _run_single_module(self, name, runner, context, target, method, url, params, fingerprint):
        timeout_count = self._module_timeouts.get(name, 0)
        if timeout_count >= 2:
            return []
        await self.stealth.delay()
        # rce/sqli run statistical timing oracles (3 samples per delay-capable
        # payload) — a 15s budget cuts them off mid-confirmation. Everything
        # else keeps the tight 15s cap so slow endpoints don't stall the scan.
        # Per-module override: modules.<name>.timeout (seconds).
        # TIMEOUT-ESCALATION: after the first timeout on a module, halve the
        # budget for subsequent runs — it's clearly not going to finish.
        # After 2 timeouts, skip entirely (the check above).
        module_cfg = self.config.get("modules", {}).get(name, {})
        if "timeout" in module_cfg:
            base_budget = module_cfg["timeout"]
        else:
            module_lines = self._module_line_counts.get(name)
            if module_lines is None:
                try:
                    module_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules", name, "detector.py")
                    if os.path.exists(module_path):
                        with open(module_path, "r", encoding="utf-8") as f:
                            module_lines = sum(1 for _ in f)
                            self._module_line_counts[name] = module_lines
                except Exception:
                    module_lines = 0
            if module_lines > 600:
                base_budget = 90
            elif module_lines > 400:
                base_budget = 60
            elif module_lines > 300:
                base_budget = 45
            elif module_lines > 200:
                base_budget = 30
            elif module_lines > 100:
                base_budget = 20
            else:
                base_budget = 15
        budget = base_budget if timeout_count == 0 else max(3, base_budget // 2)
        try:
            module_findings = await asyncio.wait_for(
                runner(context, target, method, url, params, fingerprint),
                timeout=budget,
            )
            if module_findings:
                # EVIDENCE-GATE OVERRIDE: force verified=False on all module
                # output.  The evidence gate (verify/flows.py) is the SOLE
                # path to verified=True.  This kills hallucination-class
                # criticals at the source.
                for f in module_findings:
                    f.verified = False
                print(f"      [+] {name}: {len(module_findings)} findings")
            return module_findings or []
        except asyncio.TimeoutError:
            self._module_timeouts[name] = timeout_count + 1
            # WAF BYPASS: if this module timed out and WAF is detected on
            # this route, log it so the operator knows retries may be needed.
            if self._waf_tracker.is_waf_blocked(url):
                waf = self._waf_tracker.get_waf(url)
                if waf:
                    print(f"      [!] {name} timeout + WAF ({waf.waf_name}) — may need bypass variants")
            else:
                print(f"      [!] {name} timed out (budget was {budget}s)")
            return []
        except Exception as exc:
            if self._is_driver_death(exc):
                # The driver died under this module. Marking it dead makes
                # every other scheduled module skip immediately instead of
                # wedging on a broken connection (the github.com EPIPE case).
                self._driver_dead = True
                print(f"      [!] {name}: driver connection lost")
            return []

    async def _run_api_modules(
        self,
        context,
        target: str,
        api_url: str,
        fingerprint: Dict[str, Any],
    ) -> List[Finding]:
        # NOTE: do NOT hold self._module_semaphore here. _test_rest_api / the
        # graphql scanner dispatch into _run_attack_modules, whose per-module
        # tasks acquire the same semaphore. With >= semaphore-limit API URLs on
        # one page, the API tasks would hold every slot while waiting for inner
        # module tasks that can never acquire one — a full scan deadlock (the
        # page burn every crawl-timout second without a single request). The
        # semaphore still bounds global concurrency because the module runners
        # gate on it themselves.
        findings: List[Finding] = []
        if self._driver_dead:
            return findings
        if "graphql" in api_url.lower():
            findings.extend(await self._run_graphql(context, target, api_url, fingerprint))
        else:
            findings.extend(await self._test_rest_api(context, target, api_url, fingerprint))
        # EVIDENCE-GATE OVERRIDE: force verified=False on API module output.
        for f in findings:
            f.verified = False
        return findings

    async def _run_browser_modules(self, context, page, target: str, fingerprint: Dict[str, Any], result: ScanResult) -> None:
        """Track A — client-side browser security module matrix.

        Runs inside the real Playwright browser: each detector installs JS
        hooks / navigates with a marker and treats the page's JS behaviour
        as the oracle. Bounded like every other phase — max 2 pages, a
        hard per-detector timeout, and every failure degrades to an empty
        result so a broken page can never stall the scan.
        """
        if self._driver_dead:
            return
        # One marker per scan run: the DOM XSS probe uses it so the same
        # marker is injected regardless of how many pages are probed, and
        # tests can pin it for deterministic fake-page scripting.
        if not getattr(self, "_client_marker", None):
            # M2 determinism: derive from the target-seeded RNG (scan() seeds
            # it), NOT secrets — the marker leaks into DOM-XSS finding payloads,
            # so a nondeterministic marker would break bit-identical re-runs.
            self._client_marker = "titanmx" + "".join(
                random.choices("0123456789abcdef", k=12)
            )
        targets = [u for u in list(self.visited)[:2] if not self._is_spa_shell(u)]
        if not targets:
            targets = [target]
        modules_cfg = self.config.get("clientside", {})

        for page_url in targets:
            b_page = None
            # Bounded-abandon for new_page too: a driver that died mid-scan
            # can leave this await wedged (neither resolving nor raising),
            # and wait_for awaits the cancellation — which would hang the
            # whole scan from inside scan(). Same pattern as the crawl task.
            np_task = asyncio.ensure_future(context.new_page())
            np_task.add_done_callback(_consume_task_exception)
            np_done, _ = await asyncio.wait({np_task}, timeout=10)
            if np_task not in np_done:
                np_task.cancel()
                continue
            try:
                b_page = np_task.result()
            except Exception:
                continue
            try:
                params = {}
                from urllib.parse import parse_qs
                qs = parse_qs(urlparse(page_url).query)
                params = {k: v[0] for k, v in qs.items() if v}

                checks = [
                    ("domxss", self._run_domxss),
                    ("postmessage", self._run_postmessage),
                    ("prototype", self._run_proto_pollution),
                    ("third_party", self._run_third_party),
                    ("csp", self._run_csp),
                    ("redirect", self._run_redirect),
                ]
                for name, runner in checks:
                    if not modules_cfg.get(name, {}).get("enabled", True):
                        continue
                    # Bounded-abandon per detector: a detector wedged in a
                    # dead-driver page.evaluate must time out and be left
                    # abandoned, NEVER awaited to cancellation (wait_for
                    # would hang on the wedge).
                    det_task = asyncio.ensure_future(runner(b_page, target, page_url, params))
                    det_task.add_done_callback(_consume_task_exception)
                    det_done, _ = await asyncio.wait({det_task}, timeout=15)
                    if det_task not in det_done:
                        det_task.cancel()
                        continue
                    try:
                        findings = det_task.result()
                    except Exception:
                        findings = []
                    result.findings.extend(findings)
            finally:
                try:
                    close_task = asyncio.ensure_future(b_page.close())
                    close_task.add_done_callback(_consume_task_exception)
                    close_done, _ = await asyncio.wait({close_task}, timeout=5)
                    if close_task not in close_done:
                        close_task.cancel()
                except Exception:
                    pass

    async def _run_domxss(self, b_page, target: str, page_url: str, params: Dict[str, str]):
        from titan.modules.clientside.domxss.detector import DomXSSDetector
        det = DomXSSDetector(self.payload_smith, {})
        return await det.scan(b_page, target, page_url, params, marker=getattr(self, "_client_marker", None))

    async def _run_postmessage(self, b_page, target: str, page_url: str, params: Dict[str, str]):
        from titan.modules.clientside.postmessage.detector import PostMessageDetector
        det = PostMessageDetector(self.payload_smith, {})
        return await det.scan(b_page, target, page_url, params)

    async def _run_proto_pollution(self, b_page, target: str, page_url: str, params: Dict[str, str]):
        from titan.modules.clientside.prototype.detector import PrototypePollutionDetector
        det = PrototypePollutionDetector(self.payload_smith, {})
        return await det.scan(b_page, target, page_url, params)

    async def _run_third_party(self, b_page, target: str, page_url: str, params: Dict[str, str]):
        from titan.modules.clientside.thirdparty.detector import ThirdPartyDetector
        det = ThirdPartyDetector(self.payload_smith, {})
        return await det.scan(b_page, target, page_url, params)

    async def _run_csp(self, b_page, target: str, page_url: str, params: Dict[str, str]):
        from titan.modules.clientside.csp.detector import CSPDetector
        det = CSPDetector(self.payload_smith, {})
        return await det.scan(b_page, target, page_url, params)

    async def _run_redirect(self, b_page, target: str, page_url: str, params: Dict[str, str]):
        """Track F — client-side redirect hijack detection. Loads the page
        with a navigation recorder installed BEFORE any page JS, so even a
        bundle that fires on load (zairaku.rest shape: clean HTTP 200, the
        hijack lives in JS) is caught. Heuristic: findings are unverified by
        design; the consent-gated interception PoC turns one into a PASS/FAIL
        remediation proof."""
        from titan.modules.redirect.detector import RedirectDetector
        det = RedirectDetector(self.payload_smith, {})
        return await det.scan(b_page, target, page_url, params)

    @staticmethod
    def _is_llm_endpoint(url: str) -> bool:
        """True if a discovered URL looks like an AI/chat/completion endpoint
        (the surface Track C converses with). Conservative: requires an
        /api/ or /v1/ prefix or an explicit AI path word so plain pages like
        "/chat" or "/ai" never get probed."""
        path = urlparse(url).path.lower()
        markers = (
            "/api/chat", "/chat/completions", "/v1/chat", "/v1/completions",
            "/api/assistant", "/api/generate", "/api/completion",
            "/api/message", "/api/ai", "/api/ask", "/api/answer",
            "/api/query", "/api/inference", "/api/prompt", "/api/completions",
        )
        return any(m in path for m in markers)

    async def _run_llm_channel(self, target: str, fingerprint: Dict[str, Any], result: ScanResult) -> None:
        """Track C — LLM/AI application probing.

        Converses with the target's AI endpoints (explicit ``llm.endpoints``
        config first, then discovered /api/chat-style paths) using a
        deterministic behavioral contract + consensus oracle. Pure aiohttp
        (driver-independent); max 2 endpoints; per-endpoint hard budget;
        every failure degrades to nothing. A target without any AI endpoint
        costs the scan one no-op call.
        """
        llm_cfg = self.config.get("llm", {})
        if not llm_cfg.get("enabled", True):
            return

        endpoints: List[str] = [e for e in (llm_cfg.get("endpoints") or []) if e]
        discovered = [u for u in list(self.visited) if self._is_llm_endpoint(u)]
        for u in discovered:
            if u not in endpoints:
                endpoints.append(u)
        if not endpoints:
            print("[i] No LLM/AI endpoints found; skipping Track C")
            return

        endpoints = endpoints[:2]
        try:
            from titan.modules.llm.channel import LLMChannel
            from titan.modules.llm.detector import LLMDetector
            # Injectable for tests (same pattern as _client_marker): a scripted
            # channel / interactsh keep the seam deterministic.
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
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue
        except Exception:
            return

    async def _run_storage_probe(self, target: str, result: ScanResult) -> None:
        """Track D — cloud storage public-listing probe.

        Extracts bucket references from the scan's OWN findings (leaked URLs,
        hardcoded-key contexts, echoed bodies) and probes each for public
        listing. Findings feed the flow-typed chain analyzer. Bounded (max 3
        buckets, short aiohttp timeouts), every failure degrades to nothing.
        The config gate lives HERE too so the seam is independently safe to
        call (and independently testable).
        """
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

    async def _probe_cloud_imds(self, target: str, result: ScanResult) -> None:
        """Omega Phase 2 — Cloud IMDS probing through SSRF sinks.

        When the scan finds SSRF-capable endpoints, probe cloud IMDS through
        them to extract IAM credentials, service account tokens, and instance
        metadata. Supports AWS (IMDSv1/v2), GCP, and Azure.
        """
        # Find SSRF findings that we can use as sinks
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

        # Build an SSRF sink from the first confirmed SSRF finding.
        # The sink sends requests through the SSRF-vulnerable parameter.
        ssrf_url = ssrf_findings[0].url
        ssrf_param = ssrf_findings[0].param or "url"

        async def _ssrf_sink(
            imds_url: str,
            method: str = "GET",
            headers: dict | None = None,
            timeout: float = 5.0,
        ) -> tuple:
            """Send a request through the SSRF sink."""
            import aiohttp
            from urllib.parse import quote, urlparse, parse_qs, urlencode

            # Inject the IMDS URL into the SSRF parameter
            parsed = urlparse(ssrf_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[ssrf_param] = [imds_url]
            new_query = urlencode(params, doseq=True)
            sink_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.request(
                        method=method,
                        url=sink_url,
                        headers=headers or {},
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=False,
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

    async def _run_fleet_scan(self, target: str, result: ScanResult) -> None:
        """Omega Phase 7 — Fleet multi-agent deep dive.

        After the main scan discovers the surface, fleet agents run
        specialized deep dives on the discovered endpoints:
          - ReconAgent: OSINT, fingerprinting, surface mapping
          - IdentityAgent: Auth flows, session analysis
          - LearningAgent: Mutation harvesting, pattern analysis

        Fleet findings are merged with the main scan findings. The
        consent gate is enforced per-agent (exploit/post-exploit agents
        require signed consent; recon/identity/learning are read-only).
        """
        fleet_cfg = self.config.get("fleet", {})
        if not fleet_cfg.get("enabled", False):
            return

        try:
            from titan.fleet import FleetCoordinator, AgentType
        except ImportError:
            print("[!] Fleet module not available — skipping")
            return

        # Build target list: the main target + up to 5 discovered endpoints
        discovered = list(self.visited)[:5]
        targets = [target] + [u for u in discovered if u != target and self._is_in_scope(u)]
        targets = list(dict.fromkeys(targets))[:fleet_cfg.get("max_targets", 5)]

        # Select agent types from config
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
        max_concurrent = fleet_cfg.get("max_concurrent", 5)

        print(f"[+] Fleet scan: {len(targets)} target(s), {len(agent_types)} agent type(s), budget={budget}s")

        coordinator = FleetCoordinator(
            max_concurrent=max_concurrent,
            consent_dir=self.config.get("exploit", {}).get("consent_dir", "consent"),
        )

        # Pass existing findings as context so agents can build on them
        context = {
            "findings": result.findings,
            "fingerprint": result.fingerprint,
            "transport": self._transport_http,
        }

        fleet_result = await coordinator.scan_all(
            targets=targets,
            agent_types=agent_types,
            budget=budget,
            context=context,
        )

        # Merge fleet findings into the scan result
        fleet_count = 0
        for merged in fleet_result.merged_findings:
            # Convert MergedFinding to a Finding-compatible dict
            finding_dict = {
                "type": merged.type,
                "url": merged.url,
                "param": merged.param,
                "severity": merged.severity,
                "evidence": merged.evidence,
                "confidence": merged.effective_confidence,
                "cvss_score": merged.cvss_score,
                "metadata": {
                    **merged.metadata,
                    "fleet_sources": merged.sources,
                    "corroborated": merged.is_corroborated,
                },
            }
            # Check if this finding already exists (dedup by type+url+param)
            exists = any(
                f.type == merged.type and f.url == merged.url and f.param == merged.param
                for f in result.findings
            )
            if not exists:
                # Create a Finding object and append
                try:
                    from titan.core.models import Finding, Severity, AttackType
                    severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                                    "medium": Severity.MEDIUM, "low": Severity.LOW}
                    finding = Finding(
                        type=AttackType(merged.type) if merged.type in [e.value for e in AttackType] else AttackType.OTHER,
                        severity=severity_map.get(merged.severity, Severity.MEDIUM),
                        title=f"[Fleet] {merged.type}: {merged.param or 'global'}",
                        url=merged.url,
                        param=merged.param,
                        evidence=merged.evidence,
                        confidence=merged.effective_confidence,
                        cvss_score=merged.cvss_score,
                        tags=["fleet", f"sources:{','.join(merged.sources)}"],
                        metadata=finding_dict["metadata"],
                    )
                    result.findings.append(finding)
                    fleet_count += 1
                except Exception:
                    # If Finding creation fails, skip silently
                    pass

        # Collect mutations from learning agent
        if fleet_result.mutations:
            result.mutations = getattr(result, "mutations", []) + fleet_result.mutations

        if fleet_count:
            print(f"[+] Fleet: {fleet_count} new finding(s) merged ({len(fleet_result.merged_findings)} total, "
                  f"{fleet_result.stats.get('findings', {}).get('corroborated', 0)} corroborated)")
        if fleet_result.errors:
            for err in fleet_result.errors[:3]:
                print(f"    [!] Fleet: {err}")

    async def _run_sbom_analysis(self, target: str, result: ScanResult, page: Any = None) -> None:
        """Omega Phase 4 — SBOM analysis of served content.

        Scans the page's HTML for SRI violations, cleartext loads,
        known CVEs in detected dependencies, and risky third-party origins.
        """
        try:
            from titan.modules.supplychain.sbom import SBOMAnalyzer
        except ImportError:
            return

        analyzer = SBOMAnalyzer()

        # Get HTML content from the page
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
            # Convert to Finding objects and append
            for f_dict in report.findings:
                try:
                    from titan.core.models import Finding, Severity, AttackType
                    severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                                    "medium": Severity.MEDIUM, "low": Severity.LOW}
                    finding = Finding(
                        type=AttackType.SUPPLY_CHAIN if hasattr(AttackType, 'SUPPLY_CHAIN') else AttackType.OTHER,
                        severity=severity_map.get(f_dict.get("severity", "medium"), Severity.MEDIUM),
                        title=f_dict.get("title", "Supply Chain Finding"),
                        url=target,
                        param=f_dict.get("type", ""),
                        evidence=f_dict.get("evidence", ""),
                        confidence=0.8,
                        cvss_score=f_dict.get("cvss_score", 5.0),
                        tags=["supplychain", "sbom"],
                        metadata=f_dict.get("metadata", {}),
                    )
                    result.findings.append(finding)
                except Exception:
                    pass

            sri = len(report.sri_missing)
            ctext = len(report.cleartext_loads)
            vulns = len(report.known_vulns)
            print(f"[+] SBOM: {len(report.findings)} finding(s) — "
                  f"{sri} SRI-missing, {ctext} cleartext, {vulns} known CVEs")

    async def _run_exploit_modules(self, target: str, result: ScanResult) -> None:
        """Track E — consent-gated exploitation (M4 wiring).

        Auto-stages the scan's VERIFIED RCE / upload / SQLi / SSRF findings
        into live sessions, bounded by ``exploit.max_per_type`` and
        ``exploit.budget``. The consent gate is enforced inside each planner
        (require_consent with per-technique flags: RCE needs ``shells``,
        upload needs ``write``, SQLi needs any valid consent, SSRF pivot is
        read-only and needs any valid consent) — a missing/unexpired consent
        SKIPS that technique as a recorded note, never a thrown exception.
        Pure aiohttp, so the phase runs even if the Playwright driver died
        mid-scan.
        """
        cfg = self.config.get("exploit", {})
        if not cfg.get("enabled", False):
            return
        verified = [f for f in result.findings if f.verified]
        if not verified:
            return

        from pathlib import Path

        from titan.exploit.consent import ConsentError
        from titan.exploit.listener import ExploitListener
        from titan.exploit.planner import (
            PlanningError,
            stage_and_register,
            usable_findings,
        )
        from titan.exploit.sqli_extractor import ExtractionError
        from titan.exploit.sqlidump import sqlidump, usable_sqli_findings
        from titan.exploit.ssrfpivot import (
            PivotError,
            ssrf_pivot,
            usable_ssrf_findings,
        )
        from titan.exploit.upload_planner import (
            stage_webshell,
            usable_upload_findings,
        )

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
        sessions: List[Dict[str, Any]] = []

        async def guarded(what: str, coro):
            """Run one staging attempt with a per-stage cap; degrade, never raise."""
            remaining = deadline - time.time()
            if remaining <= 0:
                # Budget exhausted: the coroutine was already created (the
                # planner call happened). Dispose it cleanly instead of leaving
                # a never-awaited coroutine behind.
                coro.close()
                return None
            try:
                return await asyncio.wait_for(coro, timeout=max(1.0, min(remaining, 60)))
            except (ConsentError, PlanningError, ExtractionError, PivotError, asyncio.TimeoutError) as exc:
                # No/insufficient consent or an unusable finding: the gate doing
                # its job. Skipped quietly but recorded for the report.
                result.errors.append(f"Track E {what}: skipped ({exc})")
                print(f"    [!] Track E {what}: {exc}")
            except Exception as exc:
                result.errors.append(f"Track E {what}: failed ({exc})")
                print(f"    [!] Track E {what}: {exc}")
            return None

        def record(channel: str, store, extra: Optional[Dict[str, Any]] = None) -> None:
            try:
                meta = store.read_meta()
            except Exception:
                meta = {}
            # WHITELIST, never the raw meta: the full session meta carries
            # listener_url and staging_url — the operator's C2 listener
            # address embedded in a weaponized payload. Serializing it into
            # findings.json would leak infrastructure into a report that may
            # be shared with a client. Only safe, useful evidence survives.
            entry: Dict[str, Any] = {
                "channel": channel,
                "session_id": store.session_id,
                "target": target,
                "status": meta.get("status", "active"),
                "dir": str(store.dir),
            }
            dump = meta.get("dump")
            if isinstance(dump, dict):
                entry["dump"] = {
                    k: dump.get(k)
                    for k in ("technique", "table", "rows", "capped_at")
                    if k in dump
                }
            pivot = meta.get("pivot")
            if isinstance(pivot, dict):
                entry["pivot"] = {
                    k: pivot.get(k)
                    for k in ("probes", "responses", "failures")
                    if k in pivot
                }
            if extra:
                entry.update(extra)
            sessions.append(entry)
            print(f"    [+] Track E: {channel} session {entry['session_id']} staged")

        # RCE -> polling-agent channel (consent: shells).
        for f in usable_findings(verified, target)[:max_per_type]:
            store = await guarded(
                f"RCE {f.method} {f.url}",
                stage_and_register(
                    f,
                    target,
                    listener,
                    consent_dir=consent_dir,
                    output_dir=output_dir,
                    key_path=key_path,
                ),
            )
            if store:
                record("rce-agent", store, {"finding_url": f.url})

        # Upload -> webshell channel (consent: write).
        for f in usable_upload_findings(verified, target)[:max_per_type]:
            out = await guarded(
                f"upload {f.method} {f.url}",
                stage_webshell(
                    f,
                    target,
                    listener,
                    consent_dir=consent_dir,
                    output_dir=output_dir,
                    key_path=key_path,
                ),
            )
            if out:
                store, ws_url = out
                record("webshell", store, {"finding_url": f.url, "webshell_url": ws_url})

        # SQLi -> structured dump (consent: any valid).
        for f in usable_sqli_findings(verified, target)[:max_per_type]:
            store = await guarded(
                f"sqli {f.method} {f.url}",
                sqlidump(
                    f,
                    target,
                    consent_dir=consent_dir,
                    output_dir=output_dir,
                    key_path=key_path,
                ),
            )
            if store:
                record("sqli-extraction", store, {"finding_url": f.url})

        # SSRF -> pivot/relay channel (consent: any valid). Relays probe URLs
        # (cloud metadata endpoints by default) through the verified sink and
        # captures the responses as evidence. Read-only — no extra flag.
        for f in usable_ssrf_findings(verified, target)[:max_per_type]:
            store = await guarded(
                f"ssrf {f.method} {f.url}",
                ssrf_pivot(
                    f,
                    target,
                    consent_dir=consent_dir,
                    output_dir=output_dir,
                    key_path=key_path,
                ),
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

    # ------------------------------------------------------------------
    # Omega Phase 5 — Brain Loop Integration
    # ------------------------------------------------------------------
    async def _run_brain_loop(self, target: str, result: ScanResult) -> None:
        """Run the autonomous brain loop against high-value findings.

        After the main scan discovers vulnerabilities, the brain loop takes
        each high-confidence finding and:
          1. Mutates the payload (polymorphic variants)
          2. Re-tests each variant against the target
          3. Verifies whether the mutation bypasses WAF/filtering
          4. Chains multiple bypasses into compound attacks
          5. Feeds successful mutations to the evolution engine

        This is where "found SQLi" becomes "found 12 SQLi bypass variants
        including WAF-evasion payloads nobody manually tested."
        """
        brain_cfg = self.config.get("brain", {})
        if not brain_cfg.get("enabled", True):
            return

        # Only run against high-confidence, attack-type findings
        high_value = [
            f for f in result.findings
            if f.confidence >= 0.6 and f.attack_type.value in (
                "SQLi", "XSS", "SSRF", "RCE", "LFI",
                "SSTI", "XXE", "NoSQLi",
            )
        ]
        if not high_value:
            return

        print(f"[+] Brain loop: {len(high_value)} high-value finding(s) to mutate")

        try:
            from titan.brain.loop import BrainLoop
            from titan.transport import AttackRequest, RequestMethod

            brain = BrainLoop(target=target)
            budget = float(brain_cfg.get("budget", 90))
            deadline = time.time() + budget
            mutations_found = 0
            bypasses_found = 0

            for finding in high_value:
                if time.time() > deadline:
                    break

                # Generate polymorphic variants of the finding's payload
                try:
                    from titan.stealth.advanced import PolymorphicEngine
                    poly = PolymorphicEngine()
                    variants = poly.generate(
                        finding.payload,
                        variant="auto",
                        count=int(brain_cfg.get("variants_per_finding", 5)),
                    )
                except Exception:
                    variants = [finding.payload]

                # Test each variant through the transport layer
                for variant in variants:
                    if time.time() > deadline:
                        break
                    try:
                        # Build the test URL with the mutated payload
                        test_url = self._build_variant_url(finding, variant)
                        if not test_url:
                            continue

                        resp = await self._transport_send(
                            test_url,
                            method=finding.method,
                            timeout=8.0,
                        )
                        if resp is None or resp.is_error:
                            continue

                        # Check if the variant got a different response
                        # (bypass detected = different status or body pattern)
                        is_bypass = self._detect_bypass(finding, resp)
                        mutations_found += 1

                        if is_bypass:
                            bypasses_found += 1
                            # Create a new finding for the bypass
                            from titan.core.models import Finding as _F, Severity, AttackType
                            bypass_finding = _F(
                                url=test_url,
                                method=finding.method,
                                param=finding.param,
                                location=finding.location,
                                payload=variant,
                                attack_type=finding.attack_type,
                                severity=finding.severity,
                                confidence=min(finding.confidence + 0.1, 0.99),
                                status=resp.status,
                                evidence=f"Brain bypass: variant produced different response",
                                tier="suspicious",
                                tags=finding.tags + ["brain:bypass", "mutation:true"],
                                notes=f"Mutated from {finding.attack_type.value} at {finding.url}",
                            )
                            result.findings.append(bypass_finding)
                    except Exception:
                        continue

                # Record the mutation in the strategy for future learning
                try:
                    brain.strategy.record_result(
                        module=f"brain_{finding.attack_type.value.lower()}",
                        success=bypasses_found > 0,
                        value=0.1,
                    )
                except Exception:
                    pass

            if mutations_found:
                print(f"[+] Brain loop: {mutations_found} mutations tested, {bypasses_found} bypass(es) found")
            else:
                print("[+] Brain loop: no viable mutations generated")

        except Exception as exc:
            result.errors.append(f"Brain loop failed: {exc}")
            print(f"[!] Brain loop: {exc}")

    def _build_variant_url(self, finding, variant: str) -> Optional[str]:
        """Build a URL with the mutated payload substituted in."""
        from urllib.parse import quote, urlparse, parse_qs, urlencode, urlunparse
        try:
            parsed = urlparse(finding.url)
            if finding.location == "query":
                qs = parse_qs(parsed.query, keep_blank_values=True)
                if finding.param in qs:
                    qs[finding.param] = [variant]
                new_query = urlencode(qs, doseq=True)
                return urlunparse(parsed._replace(query=new_query))
            elif finding.location == "path":
                # Replace the param value in the path
                return finding.url.replace(finding.param, quote(variant, safe=""))
            else:
                return None
        except Exception:
            return None

    def _detect_bypass(self, original_finding, resp) -> bool:
        """Detect if a mutated payload bypassed filtering.

        A bypass is detected when:
          - Status code changed (e.g., 403 → 200 = WAF bypass)
          - Response body contains proof markers not in baseline
          - Response is significantly larger (data extraction)
        """
        try:
            # Status change = potential bypass
            if resp.status != getattr(original_finding, 'status', 200):
                # 403→200 or error→success = bypass
                if resp.status == 200 and getattr(original_finding, 'status', 200) in (403, 405, 503):
                    return True
                # Error→success for injection types
                if resp.status == 200 and original_finding.attack_type.value in ('SQLi', 'XSS', 'RCE'):
                    return True

            body = resp.text.lower() if hasattr(resp, 'text') else ""
            # SQLi bypass: database error messages appear
            sqli_markers = ['sql', 'syntax', 'mysql', 'sqlite', 'postgres', 'ORA-', 'unterminated']
            if original_finding.attack_type.value == 'SQLi' and any(m in body for m in sqli_markers):
                return True

            # XSS bypass: script execution markers
            xss_markers = ['<script', 'alert(', 'onerror', 'onload']
            if original_finding.attack_type.value == 'XSS' and any(m in body for m in xss_markers):
                return True

            return False
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Omega Phase 6 — Evolution Engine Integration
    # ------------------------------------------------------------------
    async def _run_evolution(self, target: str, result: ScanResult) -> None:
        """Run the evolution engine to generate new detectors from patterns.

        After the brain loop finds bypass patterns, the evolution engine:
          1. Analyzes successful mutations for repeatable patterns
          2. Generates a Python detector function for each pattern
          3. Validates the detector against known findings
          4. Writes working detectors to disk for future scans
        """
        evolution_cfg = self.config.get("brain", {}).get("evolution", {})
        if not evolution_cfg.get("enabled", True):
            return

        # Only evolve if the brain found bypasses
        bypass_findings = [
            f for f in result.findings
            if "brain:bypass" in (f.tags or [])
        ]
        if not bypass_findings:
            return

        print(f"[+] Evolution engine: {len(bypass_findings)} bypass finding(s) to analyze")

        try:
            from titan.brain.evolution import EvolutionEngine

            engine = EvolutionEngine()
            generated = 0

            for finding in bypass_findings[:5]:  # Cap at 5 per scan
                try:
                    # Generate a detector from the bypass pattern
                    detector_code = engine.generate(
                        finding_type=finding.attack_type.value,
                        pattern=finding.payload,
                        context=finding.notes or "",
                    )

                    if not detector_code:
                        continue

                    # Validate the generated code
                    is_valid = engine.validate(detector_code)
                    if not is_valid:
                        continue

                    # Write to disk if enabled
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
            else:
                print("[+] Evolution engine: no new detectors generated")

        except Exception as exc:
            result.errors.append(f"Evolution engine failed: {exc}")
            print(f"[!] Evolution engine: {exc}")

    # ------------------------------------------------------------------
    # Omega Phase 8 — Anti-Forensics Integration
    # ------------------------------------------------------------------
    async def _apply_anti_forensics(self, target: str, result: ScanResult) -> None:
        """Apply anti-forensics measures during the scan.

        Generates:
          1. Decoy traffic to blur scanner signature
          2. Polymorphic payload variants for future scans
          3. Shaped timing profiles for the next scan
        """
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

            # Generate decoy traffic through the transport layer
            if self._transport_http:
                try:
                    sent = await af.decoys.inject(
                        target,
                        self._transport_http,
                        count=int(af_cfg.get("decoy_count", 3)),
                    )
                    if sent:
                        print(f"[+] Anti-forensics: {sent} decoy request(s) sent")
                except Exception:
                    pass

            # Generate polymorphic variants of high-value payloads for the report
            high_value = [
                f for f in result.findings
                if f.confidence >= 0.7 and f.payload
            ][:5]

            if high_value:
                report_data = []
                for finding in high_value:
                    attack = af.prepare_attack(
                        finding.payload,
                        target,
                        variant="auto",
                    )
                    report_data.append({
                        "original": finding.payload,
                        "variants": attack["polymorphic_payloads"],
                        "decoys": len(attack["decoy_requests"]),
                        "timing_spread": attack["timing"][-1] if attack["timing"] else 0,
                    })
                print(f"[+] Anti-forensics: {len(report_data)} payload(s) polymorphized")

        except Exception as exc:
            result.errors.append(f"Anti-forensics failed: {exc}")
            print(f"[!] Anti-forensics: {exc}")

    async def _run_identity_modules(self, context, target: str, api_url: str, fingerprint: Dict[str, Any]) -> List[Finding]:
        """Track B identity-level module matrix for one API URL.

        BOLA needs the object-owner's identity and an attacker identity from
        the SessionPool; mass assignment / JWT / session fixation run on the
        endpoint with identity headers attached. Every detector degrades
        quietly — a non-identity endpoint (no id param, no login path, no
        401 gate) returns no findings.
        """
        findings: List[Finding] = []
        identities = self.session_pool.all()
        if len(identities) < 2:
            return findings

        method = "GET"
        url = api_url.split("?")[0]
        from urllib.parse import parse_qs
        qs = parse_qs(urlparse(api_url).query)
        params = {k: v[0] for k, v in qs.items() if v}

        # BOLA: swap the object id and diff owner vs attacker responses.
        try:
            from titan.modules.bola.detector import BOLADetector
            bola = BOLADetector(self.payload_smith, fingerprint)
            bola_findings = await bola.scan(context, target, method, url, params, identities)
            findings.extend(bola_findings)
        except Exception:
            pass

        # Mass assignment: inject privilege fields on state-changing calls.
        # POSTs role=admin etc. — a state-changing probe that must NEVER be
        # aimed at HTML pages (a login/signup form could be triggered). Only
        # API-shaped endpoints are eligible.
        if self._looks_like_api(url) or self._is_state_changing_path(url):
            try:
                from titan.modules.massassignment.detector import MassAssignmentDetector
                ma = MassAssignmentDetector(self.payload_smith, fingerprint)
                ma_findings = await ma.scan(context, target, "POST", url, params)
                findings.extend(ma_findings)
            except Exception:
                pass

        # JWT: forge alg:none / cracked-secret tokens against protected routes.
        try:
            from titan.modules.jwt.detector import JWTDetector
            jwt_det = JWTDetector(self.payload_smith, fingerprint)
            jwt_findings = await jwt_det.scan(context, target, method, url, params)
            findings.extend(jwt_findings)
        except Exception:
            pass

        # Session fixation: pre-set a session cookie through login. The
        # detector already path-filters to login-ish URLs; keep the POST
        # aimed only at API-shaped endpoints for extra safety.
        if self._looks_like_api(url):
            try:
                from titan.modules.sessionfix.detector import SessionFixationDetector
                sf = SessionFixationDetector(self.payload_smith, fingerprint)
                sf_findings = await sf.scan(context, target, "POST", url, params)
                findings.extend(sf_findings)
            except Exception:
                pass

        return findings

    async def _run_sqli(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.sqli.detector import SQLiDetector
        detector = SQLiDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_xss(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.xss.detector import XSSDetector
        detector = XSSDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_ssrf(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.ssrf.detector import SSRFDetector
        detector = SSRFDetector(self.payload_smith, fingerprint)
        # Same-origin internal endpoints the crawl discovered (e.g. an
        # /internal/meta route). The SSRF module probes these as absolute
        # payloads — the "SSRF to an internal service" shape its cloud-IP
        # list can't catch. Grounded: only paths the crawler actually found.
        # Uses the eager discovery view (populated the moment a URL is found)
        # so a same-page internal route is visible while this page's module
        # matrix runs — self.visited would be too late.
        # SPA hash routes (#!/x) are fragments of the same page, not internal
        # services — probing them as SSRF payloads is noise (they'd fetch the
        # shell, not a distinct backend). Only real paths qualify.
        internal_paths = [
            u for u in sorted(self._discovered_urls)
            if u.startswith("http") and self._is_in_scope(u) and "#" not in u
        ][:8]
        return await detector.scan(context, target, method, url, params, internal_paths=internal_paths)

    async def _run_auth(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.auth.detector import AuthDetector
        detector = AuthDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_idor(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.idor.detector import IDORDetector
        detector = IDORDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_lfi(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.lfi.detector import LFIDetector
        detector = LFIDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_rce(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.rce.detector import RCEDetector
        detector = RCEDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_nosqli(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.nosqli.detector import NoSQLiDetector
        detector = NoSQLiDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_ssti(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.ssti.detector import SSTIDetector
        detector = SSTIDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_xxe(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.xxe.detector import XXEDetector
        detector = XXEDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_upload(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.upload.detector import UploadDetector
        detector = UploadDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_logic(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.logic.detector import LogicDetector
        detector = LogicDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_cors(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.cors.detector import CORSDetector
        detector = CORSDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_headers(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.headers.detector import HeadersDetector
        detector = HeadersDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_sourcesecret(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.sourcesecret.detector import SourceSecretDetector
        detector = SourceSecretDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_apixss(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.apixss.detector import ApiXssDetector
        detector = ApiXssDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_crypto(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.crypto.detector import CryptoDetector
        detector = CryptoDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_deser(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.deser.detector import DeserDetector
        detector = DeserDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_race(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.race.detector import RaceDetector
        detector = RaceDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_cache(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.cache.detector import CacheDetector
        detector = CacheDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_smuggling(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.smuggling.detector import SmugglingDetector
        detector = SmugglingDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_baas(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.baas.detector import SupabaseAuditModule
        module = SupabaseAuditModule(http_client=getattr(context, "request", None))
        return await module.scan(context, target, method, url, params, fingerprint)

    async def _run_fuzzer(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.fuzzer.detector import FuzzerDetector
        detector = FuzzerDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_parserdiff(self, context, target, method, url, params, fingerprint) -> List[Finding]:
        from titan.modules.parserdiff.detector import ParserDiffDetector
        detector = ParserDiffDetector(self.payload_smith, fingerprint)
        return await detector.scan(context, target, method, url, params)

    async def _run_graphql(self, context, target, api_url, fingerprint) -> List[Finding]:
        from titan.modules.api.graphql import GraphQLScanner
        scanner = GraphQLScanner(self.payload_smith, fingerprint)
        return await scanner.scan(context, target, api_url)

    async def _endpoint_is_alive(self, context, base_url: str, params: Dict[str, str]) -> bool:
        """True if the endpoint responds to a benign request like a real route.

        Skips hard 404/410 and soft-404 HTML pages served with 200 (the
        WordPress behaviour behind the false-positive storms). A 401/403/405/
        500 is a REAL route that is gated or method-restricted — keep it, the
        POST phase still probes it and gated endpoints can leak info.

        A 404 on GET is not the final word: some frameworks route unknown
        methods to 404, so a real POST-only endpoint would be skipped without
        a second opinion. Probe POST before declaring it dead.
        """
        try:
            resp = await context.request.get(base_url, params=params, timeout=5000)
            status = resp.status
        except Exception:
            # Network hiccup / slow endpoint: fail open so a reachable but
            # sluggish route is not skipped (modules have their own timeouts).
            return True
        if status in (404, 410):
            return await self._post_probe(context, base_url)
        if status == 200:
            try:
                body = await resp.text()
            except Exception:
                return True
            if self._is_soft_404(body):
                return await self._post_probe(context, base_url)
        return True

    async def _post_probe(self, context, base_url: str) -> bool:
        """Benign POST probe: rescues real POST-only endpoints whose GET
        returns 404/soft-404 (mirrors the discovery POST probe).

        Only a *structured* answer (JSON/XML/plain) or a 2xx page counts as a
        live route. An error-status HTML page — GitHub answers a POST to ANY
        dead route with ``422 Oh no`` — is a branded error shell, not an
        endpoint: rescuing on it would run the module matrix on a dead route
        and every oracle would "verify" against the reflected URL (the
        github.com DVIA SSRF findings were exactly this)."""
        try:
            post_resp = await context.request.post(base_url, data={"test": "1"}, timeout=5000)
        except Exception:
            return False
        if post_resp.status in (404, 410):
            return False
        try:
            body = await post_resp.text()
        except Exception:
            return post_resp.status == 200
        head = body[:4000].lower()
        is_html = "<html" in head or head.startswith("<!doctype")
        if post_resp.status == 200:
            if is_html and self._is_soft_404(body):
                return False
            return True
        # Error status (4xx/5xx) with an HTML body is a branded error page.
        # Structured error bodies (JSON) still mean the route exists.
        return not is_html

    def _is_soft_404(self, body: str) -> bool:
        """Detect an HTML not-found page served with a 200 status."""
        if not body:
            return False
        head = body[:4000].lower()
        if "<html" not in head and not head.startswith("<!doctype"):
            # Structured response (JSON/XML/plain text) — a real API answer,
            # not an HTML 404 page.
            return False
        if len(body) < 100_000 and any(m in head for m in SOFT_404_MARKERS):
            return True
        # Branded 404 pages (GitHub, large SaaS) exceed the size cap while
        # still being pure not-found shells — but their <title> says so. A
        # real page has a meaningful title; a soft-404 has "Page not found" /
        # "404" in it. Catch those before giving up, or the module matrix
        # runs on a dead route and every oracle "verifies" on the reflected
        # error page.
        m = re.search(r"<title[^>]*>(.*?)</title>", head, re.DOTALL)
        if m:
            title = m.group(1).lower()
            if "404" in title or any(mk in title for mk in SOFT_404_MARKERS):
                return True
        return False

    async def _test_rest_api(self, context, target: str, api_url: str, fingerprint: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(api_url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}

        if not params:
            params = {"id": "1", "q": "test", "search": "test", "page": "1", "limit": "10"}

        # Existence gate: never burn the module matrix on an endpoint that does
        # not exist. Discovery probes hand us dead URLs (a WP-style soft-404
        # answers 200 for ANY path), and every oracle then "confirms" on the
        # reflected URL/error page — the genohealth 192 / HTB 249 storms were
        # mostly dead-endpoint findings, not real vulnerabilities.
        base_url = api_url.split("?")[0]
        if not await self._endpoint_is_alive(context, base_url, params):
            print(f"    [i] Skipping dead endpoint {base_url}")
            return []

        # ROUTE-SCORING: compute attack value for this API URL
        api_score = score_url(api_url, params=list(params.keys()), technologies=fingerprint.get("technologies", []) if fingerprint else [])
        findings.extend(await self._run_attack_modules(context, target, "GET", api_url, params, fingerprint, route_score=api_score))

        # POST phase: reuse the URL-derived params (the benchmark manifest's
        # declared vulnerable field, e.g. ``email`` on a login) rather than
        # generic {test,id,q} — otherwise the real sink never gets probed in
        # the body and a genuine POST SQLi is missed (Juice Shop login).
        post_url = api_url.split("?")[0]
        post_data = dict(params) if params else {"test": "1", "id": "1", "q": "test"}
        findings.extend(await self._run_attack_modules(context, target, "POST", post_url, post_data, fingerprint, route_score=api_score))

        return findings

    async def scan_browserless(self, target: str) -> ScanResult:
        """PUSH-TO-100 C1 — browserless benchmark scan.

        Runs the SAME module matrix the full scan uses, but drives it with a
        Playwright API-request context instead of a browser: no Chromium, no
        crawl, no interaction/SPA phases. Each ``crawl.seed_urls`` endpoint
        gets the module matrix directly. This is the honest benchmark path —
        the benchmark certifies the endpoints as known-vulnerable ground
        truth, so DETECTION (does the module matrix fire on a real sink?) is
        what is tested, not crawler discovery.

        Why not the full scan? A heavy SPA target (Juice Shop: ~90 discovered
        APIs, Node server on a 7.8 GB box alongside WebGoat/Java) OOMs the
        target's own server mid-crawl and the scan dies before seeds ever run.
        The browserless path keeps the target alive and the benchmark fast.

        Authorization is enforced exactly like the full scan (S5 gate), and
        every finding goes through the same evidence tier + repro pipeline via
        the caller (run_benchmark scores on the returned ScanResult).
        """
        import time as _time

        t0 = _time.time()
        self._scan_target = target
        result = ScanResult(target=target, started_at=t0, config_snapshot=self.config)

        denial = self._authorization_status(target)
        if denial:
            result.errors.append(denial)
            result.finished_at = _time.time()
            print(f"[!] {denial}")
            return result

        try:
            from playwright.async_api import async_playwright
            p = await async_playwright().start()
        except Exception as exc:  # noqa: BLE001 - a broken driver can't kill the rig
            result.errors.append(f"playwright start failed: {exc}")
            result.finished_at = _time.time()
            return result
        try:
            _api_context = await p.request.new_context(
                ignore_https_errors=True,
            )
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"request context failed: {exc}")
            result.finished_at = _time.time()
            try:
                await p.stop()
            except Exception:
                pass
            return result

        # Every detector calls ``context.request.get/post`` — the shape a
        # Playwright BROWSER context exposes (its ``.request`` is the API
        # request context). The browserless path only has the bare
        # APIRequestContext (``.get``/``.post``, no ``.request``); shim it so
        # the module matrix sees the same interface it gets in a full scan.
        class _RequestShim:
            request = _api_context

        context = _RequestShim()

        # Cookies from the auth config ride every request (WebGoat's
        # JSESSIONID, etc.) exactly as the full scan's AuthEngine would.
        auth_cfg = self.config.get("auth", {})
        if auth_cfg.get("cookies"):
            try:
                cookies = auth_cfg["cookies"]
                if isinstance(cookies, dict):
                    for name, value in cookies.items():
                        await _api_context.add_cookies([
                            {"name": str(name), "value": str(value),
                             "url": target}
                        ])
            except Exception:
                pass

        # Baseline GET for fingerprinting, then fingerprint the target like
        # the full scan does (modules read the fingerprint for tech hints).
        fingerprint: Dict[str, Any] = {}
        try:
            resp = await _api_context.get(target, timeout=15000)
            headers = dict(resp.headers)
            body = await resp.text()
            fingerprint = await self.fingerprinter.analyze(headers, body, target)
            # Ground the SSRF module's same-origin discovery view from the
            # baseline page: the full scan fills ``_discovered_urls`` during
            # its crawl; the browserless path has no crawl, so without this a
            # same-origin internal route (e.g. the lab's /internal/meta) is
            # never probed and SSRF stays suspicious. Extract same-origin
            # hrefs/links only — the exact grounding the crawl provides.
            from urllib.parse import urljoin, urlparse as _up
            import re as _re
            _host = (_up(target).hostname or "").lower()
            for _m in _re.finditer(r'''(?:href|src|action)=["']([^"'#]+)''', body):
                _u = urljoin(target, _m.group(1))
                if _u.startswith("http") and (_up(_u).hostname or "").lower() == _host:
                    self._discovered_urls.add(_u)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"baseline fetch failed: {exc}")
        fingerprint["interactsh"] = self.interactsh

        seeds = self.config.get("crawl", {}).get("seed_urls", []) or []
        if not seeds:
            result.errors.append(
                "scan_browserless requires crawl.seed_urls (the benchmark "
                "manifest's challenge endpoints)"
            )
            result.finished_at = _time.time()
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
                seed_findings = await self._test_rest_api(
                    context, target, seed, fingerprint
                )
                result.findings.extend(seed_findings)
                print(f"    [+] Seed {seed}: {len(seed_findings)} finding(s)")
            except Exception as exc:  # noqa: BLE001 - one broken seed can't kill the run
                result.errors.append(f"seed scan failed {seed}: {exc}")

        self._coverage["urls_crawled"] = len(seeds)
        self._coverage["apis_discovered"] = len(seeds)
        self._coverage["apis_scanned"] = len(seeds)
        self._coverage["queue_exhausted"] = True
        result.coverage = self._finalize_coverage(result)
        result.fingerprint = fingerprint
        result.finished_at = _time.time()

        try:
            await _api_context.dispose()
        except Exception:
            pass
        try:
            await p.stop()
        except Exception:
            pass
        return result
