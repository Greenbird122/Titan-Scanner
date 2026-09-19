"""Module dispatch: runs attack modules against discovered endpoints.

Orchestration core, composed of three focused mixins:
  - ``module_bindings.AttackModuleBindings`` — one lazy-import wrapper
    per attack detector,
  - ``module_tracks.IdentityModulesMixin`` / ``BrowserDetectorsMixin``
    — the cross-identity and browser-side tracks,
  - ``api_dispatch.ApiModuleDispatch`` — REST/GraphQL endpoint dispatch.

Inheritance keeps every legacy attribute name on ``ModuleRunner`` so
``engine._modules.run_identity_modules(...)`` and tests patching
``runner._run_sqli`` / ``runner._run_api_modules`` keep working.

Extracted from TitanEngine. Handles the module matrix, per-module
timeouts, and early-exit optimization.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from titan.core.api_dispatch import ApiModuleDispatch
from titan.core.logger import get_logger
from titan.core.module_bindings import AttackModuleBindings
from titan.core.module_tracks import BrowserDetectorsMixin, IdentityModulesMixin

if TYPE_CHECKING:
    from titan.core.models import Finding

logger = get_logger("modules_runner")


class ModuleRunner(
    IdentityModulesMixin,
    BrowserDetectorsMixin,
    ApiModuleDispatch,
    AttackModuleBindings,
):
    """Dispatches attack modules against endpoints with concurrency control."""

    def __init__(self, engine: Any) -> None:
        self.engine = engine

    async def _run_modules(
        self,
        context: Any,
        target: str,
        forms: list,
        links: list,
        apis: list,
        fingerprint: dict[str, Any],
        result: Any = None,
        route_score: int = 5,
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
            form_tasks.append(
                self.engine._run_attack_modules(
                    context, target, method, action, data, fingerprint, route_score=route_score
                )
            )

        link_tasks = []
        for link in links:
            if "?" not in link:
                continue
            if not e._is_in_scope(link):
                continue
            from urllib.parse import parse_qs, urlparse

            parsed = urlparse(link)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}
            if not params:
                continue
            e._coverage["params_discovered"] += len(params)
            link_tasks.append(
                self.engine._run_attack_modules(
                    context, target, "GET", link, params, fingerprint, route_score=route_score
                )
            )

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
            "sqli",
            "ssti",
            "nosqli",
            "xxe",
            "rce",
            "lfi",
            "upload",
            "deser",
            "race",
            "smuggling",
            "parserdiff",
        }
        cheap_modules = {"headers", "cors", "crypto", "auth", "idor", "logic"}

        if e._driver_dead:
            return []

        async def run_with_limit(name: str, runner: Any) -> list[Finding]:
            async with e._module_semaphore:
                return await self._run_single_module(
                    name,
                    runner,
                    context,
                    target,
                    method,
                    url,
                    params,
                    fingerprint,
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
        self,
        name: str,
        runner: Any,
        context: Any,
        target: str,
        method: str,
        url: str,
        params: dict[str, str],
        fingerprint: dict[str, Any],
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
                    "modules",
                    name,
                    "detector.py",
                )
                if os.path.exists(module_path):
                    with open(module_path, encoding="utf-8") as f:
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
