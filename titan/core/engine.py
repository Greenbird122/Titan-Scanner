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
from titan.verify.chain import ChainDetector
from titan.integrations.dawn import DawnMemory
from titan.integrations.titan_gov import request_scan_approval
from titan.integrations.interactsh import InteractshClient
from titan.core.auth import AuthEngine
from titan.core.proxy import ProxyRotator
from titan.core.stealth import StealthEngine


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


def _consume_task_exception(task: "asyncio.Task") -> None:
    """Done-callback that swallows a task's exception so an abandoned task
    (e.g. a crawl task wedged in a dead-driver await) never logs an orphaned
    "Future exception was never retrieved" warning when the loop tears down.
    """
    try:
        task.exception()
    except Exception:
        pass


class TitanEngine:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.fingerprinter = TechFingerprinter()
        self.payload_smith = PayloadSmith(config.get("ai", {}))
        self.chain_detector = ChainDetector()
        self.auth_engine = AuthEngine(config)
        self.interactsh = InteractshClient()
        self.findings: List[Finding] = []
        self.visited: set = set()
        self.max_pages = config.get("crawl", {}).get("max_pages", 20)
        self.max_depth = config.get("crawl", {}).get("max_depth", 2)
        self._mutation_cache: Dict[str, List[str]] = {}
        self._response_cache: set = set()
        # Module concurrency is configurable (crawl.module_concurrency). The
        # module matrix is the scan's biggest cost center, and the default of 4
        # serializes ~475 module invocations (19 modules x ~25 endpoint groups)
        # into long wall-clock scans.
        self._module_semaphore = asyncio.Semaphore(self.config.get("crawl", {}).get("module_concurrency", 8))
        self._module_timeouts: Dict[str, int] = {}
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

    async def scan(self, target: str) -> ScanResult:
        # Wall-clock (epoch) timestamps: they surface in the per-site reports.
        t0 = time.time()
        self._scan_target = target
        result = ScanResult(target=target, started_at=t0, config_snapshot=self.config)

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
                page = await context.new_page()

                print(f"[+] Loading target: {target}")
                response = await page.goto(target, wait_until="domcontentloaded", timeout=30000)

                headers = dict(response.headers) if response else {}
                body = await page.content()
                title = await page.title()

                print(f"[+] Page title: {title}")
                print(f"[+] Response status: {response.status if response else 'N/A'}")

                if self._is_checkpoint(title, body, headers, response.status if response else 200):
                    result.errors.append(f"Security checkpoint blocked access: {title}")
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

                if self.config.get("auth"):
                    print("[+] Attempting authentication...")
                    logged_in = await self.auth_engine.login(context, page, target)
                    if logged_in:
                        print(f"[+] Authenticated as {self.auth_engine.get_current_role() or 'user'}")
                        auth_headers = self.auth_engine.get_auth_headers()
                        if auth_headers:
                            await context.set_extra_http_headers(auth_headers)
                    else:
                        print("[!] Authentication failed, continuing unauthenticated")

                crawl_timeout = self.config.get("crawl", {}).get("timeout", 300)
                crawl_task = asyncio.ensure_future(
                    self._crawl(context, page, target, result, fingerprint)
                )
                # Consume any exception the abandoned task eventually raises so
                # it is never logged as an orphaned future warning.
                crawl_task.add_done_callback(_consume_task_exception)
                done, pending = await asyncio.wait({crawl_task}, timeout=crawl_timeout)
                if crawl_task in pending:
                    result.errors.append(f"Crawl timed out after {crawl_timeout}s")
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
                                auth_headers = self.auth_engine.get_auth_headers()
                                if auth_headers:
                                    await context.set_extra_http_headers(auth_headers)
                                
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

        result.findings = self._dedupe_findings(result.findings)
        result.findings = [f for f in result.findings if self._is_in_scope(f.url)]

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

        from titan.core.cvss import CVSSScorer
        from titan.core.poc import PoCGenerator
        for f in result.findings:
            if "ai_escalation" in f.metadata or not f.cvss_score:
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
        queue = [(base_url, 0)]
        self.visited.add(base_url)
        captured_apis: set = set()
        processed_count = 0

        while queue and processed_count < self.max_pages:
            if self._driver_dead:
                print("[!] Driver dead; stopping crawl early")
                break
            current, depth = queue.pop(0)

            if depth > self.max_depth:
                continue

            if self._is_spa_shell(current):
                continue

            print(f"[+] Crawling: {current} (depth {depth}, visited {len(self.visited)})")
            page_start = time.monotonic()
            processed_count += 1

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
                    resp = await page.goto(current, wait_until="domcontentloaded", timeout=8000)
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
                        all_apis = list(set(static_apis + js_apis + list(captured_apis)))

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

                        apis = self._dedupe_apis(all_apis)[:15]

                if not resp or resp.status >= 400:
                    print(f"    [!] Skipped (status {resp.status if resp else 'N/A'})")
                    continue

                if is_api_url:
                    print(f"    [+] API: {current} (status {resp.status}, len={len(body)})")
                    apis = self._dedupe_apis([current] + apis)[:5]
                    page_findings = await self._run_api_modules(context, current, current, fingerprint)
                    result.findings.extend(page_findings)
                else:
                    print(f"    [+] Forms: {len(forms)}, Links: {len(links)}, APIs: {len(apis)}")
                    # Streaming: findings are appended to result.findings as each
                    # endpoint group finishes, so a crawl-timeout cancellation can
                    # never discard already-collected evidence (see _run_modules).
                    page_findings = await self._run_modules(context, current, forms, links, apis, fingerprint, result)

                if page_findings:
                    print(f"    [+] Found {len(page_findings)} vulnerabilities on this page")

                for link in links:
                    if link not in self.visited and self._is_in_scope(link):
                        self.visited.add(link)
                        queue.append((link, depth + 1))

                for api in apis:
                    api_base = api.split("?")[0]
                    if api_base not in self.visited and self._is_in_scope(api_base) and len(self.visited) < self.max_pages:
                        self.visited.add(api_base)
                        queue.append((api_base, depth + 1))
                
                elapsed = time.monotonic() - page_start
                print(f"    [i] Page processed in {elapsed:.1f}s")
            except Exception as e:
                print(f"    [!] Error crawling {current}: {e}")
                continue

        chains = self.chain_detector.detect(result.findings)
        for chain in chains:
            for f in chain.findings:
                if f.url != chain.findings[0].url:
                    f.chain = [c.url for c in chain.findings if c.url != f.url]

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
        interaction_targets = list(self.visited)[:5]
        # Clamp to >= 1: asyncio.wait_for raises ValueError on a negative
        # timeout, and 0 would silently skip every interaction.
        budget = max(1, self.config.get("crawl", {}).get("interaction_timeout", 90))

        async def interact_one(vu: str):
            async def _interact():
                i_page = None
                try:
                    i_page = await asyncio.wait_for(context.new_page(), timeout=10)
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
            except Exception:
                pass

        await asyncio.gather(*[interact_one(vu) for vu in interaction_targets])

    async def _interact_and_capture(self, context, page, base_url: str) -> List[str]:
        print(f"[+] Starting interaction on {base_url}")
        api_endpoints: List[str] = []
        
        try:
            await page.goto(base_url, wait_until="domcontentloaded", timeout=15000)
        except Exception:
            return api_endpoints
        
        captured_urls: List[str] = []
        def capture_request(request):
            if self._looks_like_api(request.url):
                captured_urls.append(request.url)
        
        page.on("request", capture_request)
        
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
        
        for url in captured_urls:
            if self._is_in_scope(url):
                api_endpoints.append(url)
        
        print(f"[+] Interaction captured {len(api_endpoints)} API endpoints")
        return list(set(api_endpoints))

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
        failure can never nullify the other nine probes or skip the page.
        """
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
        ) = await asyncio.gather(
            self._extract_forms(page),
            self._extract_links(page, base_url),
            self._discover_apis(page, base_url),
            self._extract_apis_from_js(page, base_url),
            self._crawl_spa_routes(context, page, current),
            self._parse_swagger_spec(context, current),
            self._parse_postman_collection(context, current),
            self._discover_graphql_endpoints(context, current),
            self._brute_force_common_params(context, current, max_endpoints=5),
            self._brute_force_http_methods(context, current, max_endpoints=5),
            return_exceptions=True,
        )
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
        return list(set(apis))

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
        
        return list(set(discovered))

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
        return deduped

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
            form_tasks.append(self._run_attack_modules(context, target, method, action, data, fingerprint))

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
            link_tasks.append(self._run_attack_modules(context, target, "GET", link, params, fingerprint))

        api_tasks = []
        for api in apis:
            if self._is_in_scope(api):
                api_tasks.append(self._run_api_modules(context, target, api, fingerprint))

        if self._driver_dead:
            return []

        all_task_groups = form_tasks + link_tasks + api_tasks
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
        ]

        is_spa_shell = "#" in url
        config_only_modules = {"cors", "headers", "crypto", "deser", "race", "cache", "smuggling"}

        if self._driver_dead:
            return []

        async def run_with_limit(name, runner):
            async with self._module_semaphore:
                return await self._run_single_module(name, runner, context, target, method, url, params, fingerprint)

        tasks = []
        for name, runner in modules:
            if not self.config.get("modules", {}).get(name, {}).get("enabled", True):
                continue
            if is_spa_shell and name not in config_only_modules:
                continue
            tasks.append(run_with_limit(name, runner))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, BaseException):
                # A module task that surfaced a driver-death error instead of
                # swallowing it means the driver is gone — stop scheduling.
                if self._is_driver_death(res):
                    self._driver_dead = True
                continue
            if isinstance(res, list):
                findings.extend(res)

        return findings

    async def _run_single_module(self, name, runner, context, target, method, url, params, fingerprint):
        if self._module_timeouts.get(name, 0) >= 3:
            return []
        await self.stealth.delay()
        # rce/sqli run statistical timing oracles (3 samples per delay-capable
        # payload) — a 15s budget cuts them off mid-confirmation. Everything
        # else keeps the tight 15s cap so slow endpoints don't stall the scan.
        # Per-module override: modules.<name>.timeout (seconds).
        module_cfg = self.config.get("modules", {}).get(name, {})
        budget = module_cfg.get("timeout") if "timeout" in module_cfg else (30 if name in ("rce", "sqli") else 15)
        try:
            module_findings = await asyncio.wait_for(
                runner(context, target, method, url, params, fingerprint),
                timeout=budget,
            )
            if module_findings:
                print(f"      [+] {name}: {len(module_findings)} findings")
            return module_findings or []
        except asyncio.TimeoutError:
            self._module_timeouts[name] = self._module_timeouts.get(name, 0) + 1
            print(f"      [!] {name} timed out")
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
        return await detector.scan(context, target, method, url, params)

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

        findings.extend(await self._run_attack_modules(context, target, "GET", api_url, params, fingerprint))

        post_url = api_url.split("?")[0]
        post_data = {"test": "1", "id": "1", "q": "test"}
        findings.extend(await self._run_attack_modules(context, target, "POST", post_url, post_data, fingerprint))

        return findings
