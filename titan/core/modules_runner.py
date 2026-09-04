"""Module dispatch: runs attack modules against discovered endpoints.

Extracted from TitanEngine. Handles the module matrix, per-module
timeouts, early-exit optimization, identity-level testing, and
browser-side detectors.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any, TYPE_CHECKING

from titan.core.helpers import consume_task_exception

if TYPE_CHECKING:
    from titan.core.models import Finding, ScanResult


class ModuleRunner:
    """Dispatches attack modules against endpoints with concurrency control."""

    def __init__(self, engine: Any) -> None:
        self.engine = engine

    # ------------------------------------------------------------------
    # Module matrix (grouped by forms/links/APIs)
    # ------------------------------------------------------------------

    async def _run_modules(
        self, context: Any, target: str, forms: list, links: list,
        apis: list, fingerprint: dict[str, Any],
        result: Any = None, route_score: int = 5,
    ) -> list[Finding]:
        """Run attack modules against all endpoint groups.

        Groups endpoint tasks by type (forms, links, APIs) and runs them
        as background tasks for concurrent execution.
        """
        e = self.engine
        findings: list[Finding] = []

        form_tasks = []
        for form in forms:
            from urllib.parse import urljoin
            action = form.get("action") or target
            action = urljoin(target, action)
            if not e._is_in_scope(action):
                continue
            method = form.get("method", "GET").upper()
            data = {i["name"]: i["value"] for i in form.get("inputs", []) if i.get("name")}
            if not data:
                continue
            e._coverage["params_discovered"] += len(data)
            form_tasks.append(self.engine._run_attack_modules(context, target, method, action, data, fingerprint, route_score=route_score))

        link_tasks = []
        for link in links:
            if "?" not in link:
                continue
            if not e._is_in_scope(link):
                continue
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(link)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}
            if not params:
                continue
            e._coverage["params_discovered"] += len(params)
            link_tasks.append(self.engine._run_attack_modules(context, target, "GET", link, params, fingerprint, route_score=route_score))

        api_tasks = []
        for api in apis:
            if e._is_in_scope(api):
                api_tasks.append(self.engine._run_api_modules(context, target, api, fingerprint))

        if e._driver_dead:
            return []

        all_task_groups = form_tasks + link_tasks + api_tasks
        e._coverage["endpoint_groups_run"] += len(all_task_groups)

        if all_task_groups:
            pending = [asyncio.ensure_future(c) for c in all_task_groups]
            try:
                for fut in asyncio.as_completed(pending):
                    try:
                        res = await fut
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        if e._is_driver_death(exc):
                            e._driver_dead = True
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

    # ------------------------------------------------------------------
    # Single-endpoint attack modules
    # ------------------------------------------------------------------

    async def run_attack_modules(
        self,
        context: Any,
        target: str,
        method: str,
        url: str,
        params: dict[str, str],
        fingerprint: dict[str, Any],
        route_score: int = 5,
    ) -> list[Finding]:
        """Run all attack modules against a single endpoint.

        Modules are split into cheap/expensive batches. On low-value
        routes, if cheap modules find nothing, expensive ones are skipped.
        """
        e = self.engine
        findings: list[Finding] = []
        url = url.split("?")[0]  # strip query to avoid double-sending

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
            ("fuzzer", self._run_fuzzer),
            ("parserdiff", self._run_parserdiff),
            ("sourcesecret", self._run_sourcesecret),
            ("apixss", self._run_apixss),
            ("baas", self._run_baas),
        ]

        is_spa_shell = "#" in url
        config_only_modules = {"cors", "headers", "crypto", "deser", "race", "cache", "smuggling"}
        expensive_modules = {
            "sqli", "ssti", "nosqli", "xxe", "rce", "lfi",
            "upload", "deser", "race", "smuggling", "parserdiff",
        }
        cheap_modules = {"headers", "cors", "crypto", "auth", "idor", "logic"}

        if e._driver_dead:
            return []

        async def run_with_limit(name: str, runner: Any) -> list[Finding]:
            async with e._module_semaphore:
                return await self._run_single_module(
                    name, runner, context, target, method, url, params, fingerprint,
                )

        # Batch 1: cheap modules
        cheap_tasks = []
        cheap_names = []
        for name, runner in modules:
            if not e.config.get("modules", {}).get(name, {}).get("enabled", True):
                continue
            if is_spa_shell and name not in config_only_modules:
                continue
            if route_score < 3 and name in expensive_modules:
                continue
            if name in cheap_modules:
                cheap_tasks.append(run_with_limit(name, runner))
                cheap_names.append(name)

        cheap_results = await asyncio.gather(*cheap_tasks, return_exceptions=True) if cheap_tasks else []
        for res in cheap_results:
            if isinstance(res, BaseException):
                if e._is_driver_death(res):
                    e._driver_dead = True
                continue
            if isinstance(res, list):
                findings.extend(res)

        # Early exit: skip expensive if cheap found nothing on low-score route
        skip_early = route_score <= 5
        if skip_early and not findings and cheap_tasks:
            return findings

        # Batch 2: expensive modules
        expensive_tasks = []
        for name, runner in modules:
            if not e.config.get("modules", {}).get(name, {}).get("enabled", True):
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
                if e._is_driver_death(res):
                    e._driver_dead = True
                continue
            if isinstance(res, list):
                findings.extend(res)

        # Evidence gate override: force verified=False on all module output
        for f in findings:
            f.verified = False

        return findings

    async def _run_single_module(
        self, name: str, runner: Any, context: Any,
        target: str, method: str, url: str,
        params: dict[str, str], fingerprint: dict[str, Any],
    ) -> list[Finding]:
        """Run a single module with timeout and WAF awareness."""
        e = self.engine
        timeout_count = e._module_timeouts.get(name, 0)
        if timeout_count >= 2:
            return []

        await e.stealth.delay()

        # Dynamic budget based on module size
        module_cfg = e.config.get("modules", {}).get(name, {})
        if "timeout" in module_cfg:
            base_budget = module_cfg["timeout"]
        else:
            base_budget = self._compute_module_budget(name)
        budget = base_budget if timeout_count == 0 else max(3, base_budget // 2)

        try:
            module_findings = await asyncio.wait_for(
                runner(context, target, method, url, params, fingerprint),
                timeout=budget,
            )
            if module_findings:
                for f in module_findings:
                    f.verified = False
                print(f"      [+] {name}: {len(module_findings)} findings")
            return module_findings or []
        except asyncio.TimeoutError:
            e._module_timeouts[name] = timeout_count + 1
            if e._waf_tracker.is_waf_blocked(url):
                waf = e._waf_tracker.get_waf(url)
                if waf:
                    print(f"      [!] {name} timeout + WAF ({waf.waf_name}) — may need bypass variants")
            else:
                print(f"      [!] {name} timed out (budget was {budget}s)")
            return []
        except Exception as exc:
            if e._is_driver_death(exc):
                e._driver_dead = True
                print(f"      [!] {name}: driver connection lost")
            return []

    def _compute_module_budget(self, name: str) -> int:
        """Compute timeout budget based on module line count."""
        e = self.engine
        module_lines = e._module_line_counts.get(name)
        if module_lines is None:
            import os
            try:
                module_path = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "modules", name, "detector.py",
                )
                if os.path.exists(module_path):
                    with open(module_path, "r", encoding="utf-8") as f:
                        module_lines = sum(1 for _ in f)
                        e._module_line_counts[name] = module_lines
            except Exception:
                module_lines = 0
        if module_lines is None:
            module_lines = 0

        if module_lines > 600:
            return 90
        elif module_lines > 400:
            return 60
        elif module_lines > 300:
            return 45
        elif module_lines > 200:
            return 30
        elif module_lines > 100:
            return 20
        return 15

    # ------------------------------------------------------------------
    # Identity modules (Track B)
    # ------------------------------------------------------------------

    async def run_identity_modules(
        self, context: Any, target: str, api_url: str, fingerprint: dict[str, Any],
    ) -> list[Finding]:
        """BOLA, mass assignment, JWT, session fixation across identities."""
        e = self.engine
        findings: list[Finding] = []
        identities = e.session_pool.all()
        if len(identities) < 2:
            return findings

        method = "GET"
        url = api_url.split("?")[0]
        from urllib.parse import parse_qs, urlparse
        qs = parse_qs(urlparse(api_url).query)
        params = {k: v[0] for k, v in qs.items() if v}

        # BOLA
        try:
            from titan.modules.bola.detector import BOLADetector
            bola = BOLADetector(e.payload_smith, fingerprint)
            findings.extend(await bola.scan(context, target, method, url, params, identities))
        except Exception:
            pass

        # Mass assignment
        if e._looks_like_api(url) or e._is_state_changing_path(url):
            try:
                from titan.modules.massassignment.detector import MassAssignmentDetector
                ma = MassAssignmentDetector(e.payload_smith, fingerprint)
                findings.extend(await ma.scan(context, target, "POST", url, params))
            except Exception:
                pass

        # JWT
        try:
            from titan.modules.jwt.detector import JWTDetector
            jwt_det = JWTDetector(e.payload_smith, fingerprint)
            findings.extend(await jwt_det.scan(context, target, method, url, params))
        except Exception:
            pass

        # Session fixation
        if e._looks_like_api(url):
            try:
                from titan.modules.sessionfix.detector import SessionFixationDetector
                sf = SessionFixationDetector(e.payload_smith, fingerprint)
                findings.extend(await sf.scan(context, target, "POST", url, params))
            except Exception:
                pass

        return findings

    # ------------------------------------------------------------------
    # Browser modules (Track A)
    # ------------------------------------------------------------------

    async def run_browser_modules(
        self, context: Any, page: Any, target: str,
        fingerprint: dict[str, Any], result: ScanResult,
    ) -> None:
        """Client-side browser security detectors."""
        e = self.engine
        if e._driver_dead:
            return

        if not getattr(e, "_client_marker", None):
            e._client_marker = "titanmx" + "".join(
                random.choices("0123456789abcdef", k=12)
            )

        targets = [u for u in list(e.visited)[:2] if not e._is_spa_shell(u)]
        if not targets:
            targets = [target]

        modules_cfg = e.config.get("clientside", {})

        for page_url in targets:
            b_page = None
            np_task = asyncio.ensure_future(context.new_page())
            np_task.add_done_callback(consume_task_exception)
            np_done, _ = await asyncio.wait({np_task}, timeout=10)
            if np_task not in np_done:
                np_task.cancel()
                continue
            try:
                b_page = np_task.result()
            except Exception:
                continue
            try:
                from urllib.parse import parse_qs, urlparse
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
                    det_task = asyncio.ensure_future(runner(b_page, target, page_url, params))
                    det_task.add_done_callback(consume_task_exception)
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
                    close_task.add_done_callback(consume_task_exception)
                    close_done, _ = await asyncio.wait({close_task}, timeout=5)
                    if close_task not in close_done:
                        close_task.cancel()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Individual browser detectors
    # ------------------------------------------------------------------

    async def _run_domxss(self, b_page, target: str, page_url: str, params: dict[str, str]):
        from titan.modules.clientside.domxss.detector import DomXSSDetector
        det = DomXSSDetector(self.engine.payload_smith, {})
        return await det.scan(b_page, target, page_url, params, marker=getattr(self.engine, "_client_marker", None))

    async def _run_postmessage(self, b_page, target: str, page_url: str, params: dict[str, str]):
        from titan.modules.clientside.postmessage.detector import PostMessageDetector
        det = PostMessageDetector(self.engine.payload_smith, {})
        return await det.scan(b_page, target, page_url, params)

    async def _run_proto_pollution(self, b_page, target: str, page_url: str, params: dict[str, str]):
        from titan.modules.clientside.prototype.detector import PrototypePollutionDetector
        det = PrototypePollutionDetector(self.engine.payload_smith, {})
        return await det.scan(b_page, target, page_url, params)

    async def _run_third_party(self, b_page, target: str, page_url: str, params: dict[str, str]):
        from titan.modules.clientside.thirdparty.detector import ThirdPartyDetector
        det = ThirdPartyDetector(self.engine.payload_smith, {})
        return await det.scan(b_page, target, page_url, params)

    async def _run_csp(self, b_page, target: str, page_url: str, params: dict[str, str]):
        from titan.modules.clientside.csp.detector import CSPDetector
        det = CSPDetector(self.engine.payload_smith, {})
        return await det.scan(b_page, target, page_url, params)

    async def _run_redirect(self, b_page, target: str, page_url: str, params: dict[str, str]):
        from titan.modules.redirect.detector import RedirectDetector
        det = RedirectDetector(self.engine.payload_smith, {})
        return await det.scan(b_page, target, page_url, params)

    # ------------------------------------------------------------------
    # Individual attack module wrappers
    # ------------------------------------------------------------------

    async def _run_sqli(self, ctx, t, m, u, p, fp):
        from titan.modules.sqli.detector import SQLiDetector
        return await SQLiDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_xss(self, ctx, t, m, u, p, fp):
        from titan.modules.xss.detector import XSSDetector
        return await XSSDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_ssrf(self, ctx, t, m, u, p, fp):
        from titan.modules.ssrf.detector import SSRFDetector
        e = self.engine
        internal_paths = [
            v for v in sorted(e._discovered_urls)
            if v.startswith("http") and e._is_in_scope(v) and "#" not in v
        ][:8]
        return await SSRFDetector(e.payload_smith, fp).scan(ctx, t, m, u, p, internal_paths=internal_paths)

    async def _run_auth(self, ctx, t, m, u, p, fp):
        from titan.modules.auth.detector import AuthDetector
        return await AuthDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_idor(self, ctx, t, m, u, p, fp):
        from titan.modules.idor.detector import IDORDetector
        return await IDORDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_lfi(self, ctx, t, m, u, p, fp):
        from titan.modules.lfi.detector import LFIDetector
        return await LFIDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_rce(self, ctx, t, m, u, p, fp):
        from titan.modules.rce.detector import RCEDetector
        return await RCEDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_nosqli(self, ctx, t, m, u, p, fp):
        from titan.modules.nosqli.detector import NoSQLiDetector
        return await NoSQLiDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_ssti(self, ctx, t, m, u, p, fp):
        from titan.modules.ssti.detector import SSTIDetector
        return await SSTIDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_xxe(self, ctx, t, m, u, p, fp):
        from titan.modules.xxe.detector import XXEDetector
        return await XXEDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_upload(self, ctx, t, m, u, p, fp):
        from titan.modules.upload.detector import UploadDetector
        return await UploadDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_logic(self, ctx, t, m, u, p, fp):
        from titan.modules.logic.detector import LogicDetector
        return await LogicDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_cors(self, ctx, t, m, u, p, fp):
        from titan.modules.cors.detector import CORSDetector
        return await CORSDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_headers(self, ctx, t, m, u, p, fp):
        from titan.modules.headers.detector import HeadersDetector
        return await HeadersDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_crypto(self, ctx, t, m, u, p, fp):
        from titan.modules.crypto.detector import CryptoDetector
        return await CryptoDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_deser(self, ctx, t, m, u, p, fp):
        from titan.modules.deser.detector import DeserDetector
        return await DeserDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_race(self, ctx, t, m, u, p, fp):
        from titan.modules.race.detector import RaceDetector
        return await RaceDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_cache(self, ctx, t, m, u, p, fp):
        from titan.modules.cache.detector import CacheDetector
        return await CacheDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_smuggling(self, ctx, t, m, u, p, fp):
        from titan.modules.smuggling.detector import SmugglingDetector
        return await SmugglingDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_baas(self, ctx, t, m, u, p, fp):
        from titan.modules.baas.detector import SupabaseAuditModule
        return await SupabaseAuditModule(http_client=getattr(ctx, "request", None)).scan(ctx, t, m, u, p, fp)

    async def _run_fuzzer(self, ctx, t, m, u, p, fp):
        from titan.modules.fuzzer.detector import FuzzerDetector
        return await FuzzerDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_parserdiff(self, ctx, t, m, u, p, fp):
        from titan.modules.parserdiff.detector import ParserDiffDetector
        return await ParserDiffDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_sourcesecret(self, ctx, t, m, u, p, fp):
        from titan.modules.sourcesecret.detector import SourceSecretDetector
        return await SourceSecretDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_apixss(self, ctx, t, m, u, p, fp):
        from titan.modules.apixss.detector import ApiXssDetector
        return await ApiXssDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_api_modules(
        self, context: Any, target: str, api_url: str, fingerprint: dict[str, Any],
    ) -> list[Finding]:
        """Run module matrix against a discovered API endpoint."""
        e = self.engine
        findings: list[Finding] = []
        if e._driver_dead:
            return findings
        if "graphql" in api_url.lower():
            findings.extend(await self._run_graphql(context, target, api_url, fingerprint))
        else:
            findings.extend(await e._test_rest_api(context, target, api_url, fingerprint))
        for f in findings:
            f.verified = False
        return findings

    async def _test_rest_api(self, context, target, api_url, fingerprint):
        """Test a REST API endpoint with GET and POST phases."""
        from urllib.parse import urlparse, parse_qs
        from titan.core.helpers import is_soft_404
        from titan.core.route_scorer import score_url

        e = self.engine
        findings: list[Finding] = []
        parsed = urlparse(api_url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}
        if not params:
            params = {"id": "1", "q": "test", "search": "test", "page": "1", "limit": "10"}

        base_url = api_url.split("?")[0]
        if not await self._endpoint_is_alive(context, base_url, params):
            print(f"    [i] Skipping dead endpoint {base_url}")
            return []

        api_score = score_url(api_url, params=list(params.keys()),
                              technologies=fingerprint.get("technologies", []) if fingerprint else [])
        findings.extend(await self.engine._run_attack_modules(
            context, target, "GET", api_url, params, fingerprint, route_score=api_score,
        ))

        post_url = api_url.split("?")[0]
        post_data = dict(params) if params else {"test": "1", "id": "1", "q": "test"}
        findings.extend(await self.engine._run_attack_modules(
            context, target, "POST", post_url, post_data, fingerprint, route_score=api_score,
        ))
        return findings

    async def _endpoint_is_alive(self, context, base_url, params):
        """Check if an endpoint is alive (not a dead route)."""
        try:
            resp = await context.request.get(base_url, params=params, timeout=5000)
            status = resp.status
        except Exception:
            return True
        if status in (404, 410):
            return await self._post_probe(context, base_url)
        if status == 200:
            try:
                body = await resp.text()
            except Exception:
                return True
            from titan.core.helpers import is_soft_404
            if is_soft_404(body):
                return await self._post_probe(context, base_url)
        return True

    async def _post_probe(self, context, base_url):
        """Benign POST probe for endpoint liveness."""
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
            from titan.core.helpers import is_soft_404
            if is_html and is_soft_404(body):
                return False
            return True
        return not is_html

    async def _run_graphql(self, ctx, t, api_url, fp):
        from titan.modules.api.graphql import GraphQLScanner
        return await GraphQLScanner(self.engine.payload_smith, fp).scan(ctx, t, api_url)
