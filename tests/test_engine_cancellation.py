"""Regression tests for engine cancellation / streaming behavior.

Covers three fixes made during scan-performance tuning:

1. ``_run_modules`` previously only cancelled the endpoint-group future it was
   currently blocked on when the crawl budget expired. Every other in-flight
   group kept running *orphaned* — holding the module semaphore and hammering
   the target for minutes after the timeout (observed: ~360s of post-timeout
   bleed). On cancellation it must cancel ALL pending groups.

2. A failing endpoint group must not discard the findings of the other groups
   that already completed (streaming / isolation behavior).

3. A Playwright Node driver that dies mid-scan (EPIPE crash, observed on
   github.com) makes pending protocol futures wedge instead of raising. The
   scan must detect driver death from module-run errors, stop scheduling all
   further driver work, and keep the findings collected so far.
"""

import asyncio
import time

import pytest

from titan.core.engine import TitanEngine
from titan.core.models import AttackType, Finding, ScanResult, Severity


def _engine() -> TitanEngine:
    """Minimal engine with near-zero stealth delay so tests don't sleep."""
    return TitanEngine({"stealth": {"min_delay": 0.01, "max_delay": 0.01}})


def _forms(n: int) -> list:
    return [
        {
            "action": f"http://localhost:5000/page/{i}",
            "method": "GET",
            "inputs": [{"name": "q", "value": "1"}],
        }
        for i in range(n)
    ]


class TestCrawlCancellation:
    async def test_timeout_cancels_all_pending_groups(self):
        """A crawl-timeout must cancel every in-flight endpoint group.

        Regression: only the currently-awaited future was cancelled; the other
        groups leaked for minutes after the timeout.
        """
        engine = _engine()
        cancelled: list = []

        async def fake_attack(context, target, method, url, params, fingerprint):
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                cancelled.append(url)
                raise

        engine._run_attack_modules = fake_attack

        forms = _forms(6)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                engine._run_modules(None, "http://localhost:5000", forms, [], [], {}),
                timeout=0.5,
            )

        # Give the event loop a beat to deliver CancelledError to the children.
        await asyncio.sleep(0.1)

        assert len(cancelled) == 6, f"expected all 6 groups cancelled, got {cancelled}"

    async def test_completed_findings_survive_late_cancellation(self):
        """Findings from groups that finished before the timeout are kept."""
        engine = _engine()
        cancelled: list = []

        async def one_fast_one_slow(context, target, method, url, params, fingerprint):
            if url.endswith("/0"):
                return ["kept-finding"]
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                cancelled.append(url)
                raise

        engine._run_attack_modules = one_fast_one_slow

        # One group completes immediately, the other hangs until cancelled.
        result = ScanResult(target="http://localhost:5000", started_at=time.time())
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                engine._run_modules(
                    None, "http://localhost:5000", _forms(2), [], [], {}, result
                ),
                timeout=0.5,
            )

        await asyncio.sleep(0.1)

        assert cancelled == ["http://localhost:5000/page/1"]
        assert "kept-finding" in result.findings, (
            "finding verified before the timeout must not be lost"
        )



class TestGroupFailureIsolation:
    async def test_failing_group_does_not_lose_others(self):
        """A raised group is swallowed; other groups' findings still return."""
        engine = _engine()
        calls: list = []

        async def flaky_attack(context, target, method, url, params, fingerprint):
            calls.append(url)
            if url.endswith("/0"):
                raise RuntimeError("probe exploded")
            return ["surviving-finding"]

        engine._run_attack_modules = flaky_attack

        findings = await engine._run_modules(None, "http://localhost:5000", _forms(2), [], [], {})

        assert len(calls) == 2
        assert findings == ["surviving-finding"], f"got {findings}"


class TestDiscoveryIsolation:
    """The concurrent discovery gather must isolate probe failures."""

    PROBE_NAMES = [
        "_extract_forms",
        "_extract_links",
        "_discover_apis",
        "_extract_apis_from_js",
        "_crawl_spa_routes",
        "_parse_swagger_spec",
        "_parse_postman_collection",
        "_discover_graphql_endpoints",
        "_brute_force_common_params",
        "_brute_force_http_methods",
    ]

    async def test_all_probes_failing_degrades_to_empty_defaults(self):
        """Every probe raising must not propagate; each degrades to its empty
        default ({} for the params dict, [] for everything else)."""
        engine = _engine()

        async def boom(*args, **kwargs):
            raise RuntimeError("probe exploded")

        for name in self.PROBE_NAMES:
            setattr(engine, name, boom)

        result = await engine._discover_all(None, None, "http://localhost:5000", "http://localhost:5000")

        (forms, links, static_apis, js_apis, spa_routes, swagger_endpoints,
         postman_endpoints, graphql_eps, common_param_discoveries, http_methods) = result
        assert forms == []
        assert links == []
        assert static_apis == []
        assert js_apis == []
        assert spa_routes == []
        assert swagger_endpoints == []
        assert postman_endpoints == []
        assert graphql_eps == []
        assert common_param_discoveries == {}
        assert http_methods == []

    async def test_one_failing_probe_keeps_others(self):
        """A single flaky probe must not discard the other nine probes' results."""
        engine = _engine()

        async def boom(*args, **kwargs):
            raise RuntimeError("probe exploded")

        async def good_forms(page):
            return [{"action": "http://localhost:5000/form", "method": "GET", "inputs": []}]

        async def good_links(page, base_url):
            return ["http://localhost:5000/some?q=1"]

        async def good_apis(page, base_url):
            return ["http://localhost:5000/api/data"]

        engine._extract_forms = good_forms
        engine._extract_links = good_links
        engine._discover_apis = good_apis
        # Everything else explodes.
        for name in self.PROBE_NAMES:
            if name not in ("_extract_forms", "_extract_links", "_discover_apis"):
                setattr(engine, name, boom)

        result = await engine._discover_all(None, None, "http://localhost:5000", "http://localhost:5000")

        (forms, links, static_apis, js_apis, spa_routes, swagger_endpoints,
         postman_endpoints, graphql_eps, common_param_discoveries, http_methods) = result
        assert forms == [{"action": "http://localhost:5000/form", "method": "GET", "inputs": []}]
        assert links == ["http://localhost:5000/some?q=1"]
        assert static_apis == ["http://localhost:5000/api/data"]
        # The seven failed probes degraded to empty defaults.
        assert js_apis == []
        assert spa_routes == []
        assert swagger_endpoints == []
        assert postman_endpoints == []
        assert graphql_eps == []
        assert common_param_discoveries == {}
        assert http_methods == []


class _StubRestResponse:
    def __init__(self, status, body=""):
        self.status = status
        self.headers = {}
        self.url = "http://localhost:5000/api/x"
        self._body = body

    async def text(self):
        return self._body


class _StubRestContext:
    """context.request stub returning a canned status/body for every call."""

    def __init__(self, status, body=""):
        self._status = status
        self._body = body

    @property
    def request(self):
        return self

    async def get(self, url, params=None, headers=None, timeout=3000, **kw):
        return _StubRestResponse(self._status, self._body)

    async def post(self, url, data=None, headers=None, timeout=3000, **kw):
        return _StubRestResponse(self._status, self._body)


class _StubMethodContext:
    """context.request stub where GET and POST behave differently (GET 404s,
    POST succeeds) — the real POST-only endpoint shape."""

    def __init__(self, get_status=404, post_status=200, post_body='{"ok": true}'):
        self._get_status = get_status
        self._post_status = post_status
        self._post_body = post_body

    @property
    def request(self):
        return self

    async def get(self, url, params=None, headers=None, timeout=3000, **kw):
        return _StubRestResponse(self._get_status, "")

    async def post(self, url, data=None, headers=None, timeout=3000, **kw):
        return _StubRestResponse(self._post_status, self._post_body)


class TestRestApiExistenceGate:
    """Dead endpoints must never reach the module matrix.

    Regression: discovery probes handed ``_test_rest_api`` URLs that do not
    exist — WordPress-style soft-404s answer 200 for ANY path. The full module
    matrix then "verified" every payload because the payload was reflected
    into the error page. The genohealth 192 / HTB 249 storms were mostly
    dead-endpoint findings, not real vulnerabilities.
    """

    async def _run_gated(self, status, body):
        engine = _engine()
        ctx = _StubRestContext(status, body)
        calls: list = []

        async def fake_attack(context, target, method, url, params, fingerprint):
            calls.append((method, url))
            return [f"finding-{method}"]

        engine._run_attack_modules = fake_attack
        findings = await engine._test_rest_api(
            ctx, "http://localhost:5000", "http://localhost:5000/api/auth/token", {},
        )
        return findings, calls

    async def test_hard_404_endpoint_is_skipped(self):
        findings, calls = await self._run_gated(404, "not here")
        assert findings == [] and calls == [], "404 endpoint must not run modules"

    async def test_soft_404_html_endpoint_is_skipped(self):
        body = (
            "<html><title>Page not found</title>"
            "<p>The requested URL was not found on this server.</p></html>"
        )
        findings, calls = await self._run_gated(200, body)
        assert findings == [] and calls == [], "soft-404 endpoint must not run modules"

    async def test_live_json_endpoint_is_scanned(self):
        findings, calls = await self._run_gated(200, '{"ok": true}')
        assert [m for m, _ in calls] == ["GET", "POST"], f"got {calls}"

    async def test_post_only_endpoint_is_scanned(self):
        # 405 on GET = the route exists but only accepts POST; modules must run.
        findings, calls = await self._run_gated(405, "method not allowed")
        assert len(calls) == 2, f"405 endpoint must still run GET+POST modules, got {calls}"

    async def test_post_only_endpoint_404_on_get_is_rescued(self):
        """A framework may route unknown methods to 404 — a real POST-only
        endpoint must survive a GET-404 via the POST rescue probe."""
        engine = _engine()
        ctx = _StubMethodContext(get_status=404, post_status=200, post_body='{"ok": true}')
        calls: list = []

        async def fake_attack(context, target, method, url, params, fingerprint):
            calls.append((method, url))
            return [f"finding-{method}"]

        engine._run_attack_modules = fake_attack
        findings = await engine._test_rest_api(
            ctx, "http://localhost:5000", "http://localhost:5000/api/auth/token", {},
        )
        assert len(calls) == 2, f"POST-rescued endpoint must run modules, got {calls}"

    async def test_error_status_html_post_probe_is_dead(self):
        """GitHub answers a POST to ANY dead route with ``422 Oh no`` (an
        HTML error page). Rescuing on it runs the module matrix on a dead
        route and every oracle "verifies" against the reflected URL — the
        github.com DVIA SSRF findings. Only a *structured* (JSON/XML/plain)
        error body means the route exists."""
        engine = _engine()
        ctx = _StubMethodContext(
            get_status=404,
            post_status=422,
            post_body="<html><title>Oh no</title><p>Something went wrong.</p></html>",
        )
        calls: list = []

        async def fake_attack(context, target, method, url, params, fingerprint):
            calls.append((method, url))
            return [f"finding-{method}"]

        engine._run_attack_modules = fake_attack
        findings = await engine._test_rest_api(
            ctx, "http://localhost:5000", "http://localhost:5000/api/otp", {},
        )
        assert findings == [] and calls == [], \
            f"error-status HTML POST probe must be treated as a dead route, got {calls}"

    async def test_error_status_json_post_probe_is_rescued(self):
        """A structured error body (JSON) on POST still means the route
        exists — 422 with an API error object is a live endpoint."""
        engine = _engine()
        ctx = _StubMethodContext(
            get_status=404,
            post_status=422,
            post_body='{"error": "unprocessable entity"}',
        )
        calls: list = []

        async def fake_attack(context, target, method, url, params, fingerprint):
            calls.append((method, url))
            return [f"finding-{method}"]

        engine._run_attack_modules = fake_attack
        findings = await engine._test_rest_api(
            ctx, "http://localhost:5000", "http://localhost:5000/api/otp", {},
        )
        assert len(calls) == 2, f"structured-error POST must still run modules, got {calls}"

    async def test_branded_404_title_is_soft_404(self):
        """GitHub-style branded 404 pages exceed the 100KB size cap, but
        their <title> says "Page not found" — they must still be skipped, or
        the module matrix runs on a dead route and every oracle "verifies" on
        the reflected error page (the github.com DVIA dead-endpoint findings)."""
        body = (
            "<html><head><title>Page not found · GitHub</title></head><body>"
            + "x" * 150_000
            + "</body></html>"
        )
        findings, calls = await self._run_gated(200, body)
        assert findings == [] and calls == [], "branded >100KB 404 must not run modules"

    async def test_big_real_page_with_not_found_phrase_is_scanned(self):
        """A real page larger than 100KB that merely mentions "page not found"
        in its head (but has a meaningful title) must still be scanned — the
        title fallback must not swallow real content."""
        body = (
            "<html><head><title>Documentation · Acme</title></head><body>"
            + "<p>If you see a 'page not found' error, contact support.</p>"
            + "y" * 150_000
            + "</body></html>"
        )
        findings, calls = await self._run_gated(200, body)
        assert len(calls) == 2, f"big real page mentioning the phrase must run modules, got {calls}"


class TestContentScanDedupe:
    """Identical body/header-scan verdicts across URLs collapse site-wide."""

    @staticmethod
    def _finding(url, param, location, payload):
        return Finding(
            target="http://localhost:5000",
            url=url,
            method="GET",
            param=param,
            location=location,
            payload=payload,
            attack_type=AttackType.CRYPTO_WEAKNESS if param == "body" else AttackType.INFO_LEAK,
            severity=Severity.HIGH,
            verified=True,
            confidence=0.85,
            status=200,
        )

    def test_identical_body_scan_collapses_to_one(self):
        engine = _engine()
        findings = [
            self._finding(
                f"http://localhost:5000/p{i}", "body", "body",
                "Hardcoded credential: hardcoded_aws_access_key_id",
            )
            for i in range(3)
        ]
        out = engine._dedupe_findings(findings)
        assert len(out) == 1, f"shared bundle leak must be reported once, got {len(out)}"

    def test_distinct_body_payloads_are_kept(self):
        engine = _engine()
        findings = [
            self._finding("http://localhost:5000/p1", "body", "body", "payload-A"),
            self._finding("http://localhost:5000/p2", "body", "body", "payload-B"),
        ]
        out = engine._dedupe_findings(findings)
        assert len(out) == 2

    def test_query_injection_findings_not_collapsed(self):
        """Per-endpoint injection findings (real param names) stay per-URL."""
        engine = _engine()
        findings = [
            self._finding(f"http://localhost:5000/p{i}", "id", "query", "' OR 1=1--")
            for i in range(2)
        ]
        out = engine._dedupe_findings(findings)
        assert len(out) == 2, "distinct endpoints with the same injection must not collapse"


class _FakeInteractionPage:
    async def close(self):
        pass


class TestInteractionBudget:
    """The interaction phase must be bounded even when the Playwright driver
    is wedged by a crawl-timeout cancellation (observed: 42 minutes of dead
    silence after a crawl timeout, and a process that never exited)."""

    async def test_hanging_new_page_is_bounded(self):
        engine = _engine()
        engine.config["crawl"] = {"interaction_timeout": 0.5}
        engine.visited = {"http://localhost:5000/a", "http://localhost:5000/b"}

        class WedgedContext:
            async def new_page(self):
                # A wedged driver: the driver call never returns.
                await asyncio.sleep(60)

        result = ScanResult(target="http://localhost:5000", started_at=time.time())
        t0 = time.monotonic()
        await engine._run_interactions(WedgedContext(), "http://localhost:5000", {}, result)
        elapsed = time.monotonic() - t0

        assert elapsed < 5, f"wedged interaction must be budget-bounded, took {elapsed:.1f}s"
        assert result.findings == []

    async def test_hanging_capture_is_bounded(self):
        engine = _engine()
        engine.config["crawl"] = {"interaction_timeout": 0.5}
        engine.visited = {"http://localhost:5000/a"}

        class HealthyContext:
            async def new_page(self):
                return _FakeInteractionPage()

        async def hanging_capture(context, page, url):
            await asyncio.sleep(60)
            return []

        engine._interact_and_capture = hanging_capture
        result = ScanResult(target="http://localhost:5000", started_at=time.time())
        t0 = time.monotonic()
        await engine._run_interactions(HealthyContext(), "http://localhost:5000", {}, result)
        elapsed = time.monotonic() - t0

        assert elapsed < 5, f"hanging capture must be budget-bounded, took {elapsed:.1f}s"

    async def test_healthy_interaction_still_captures(self):
        engine = _engine()
        engine.visited = {"http://localhost:5000/a"}

        class HealthyContext:
            async def new_page(self):
                return _FakeInteractionPage()

        async def fake_capture(context, page, url):
            return ["http://localhost:5000/api/captured"]

        async def fake_api_modules(context, target, api_url, fingerprint):
            return [f"api-finding:{api_url}"]

        engine._interact_and_capture = fake_capture
        engine._run_api_modules = fake_api_modules
        result = ScanResult(target="http://localhost:5000", started_at=time.time())
        await engine._run_interactions(HealthyContext(), "http://localhost:5000", {}, result)

        assert result.findings == ["api-finding:http://localhost:5000/api/captured"]


class TestDriverDeathResilience:
    """A Playwright Node driver that dies mid-scan wedges protocol futures
    instead of raising (the github.com EPIPE crash: no traceback, no report,
    silent hang until the process was killed). Once a driver-death error is
    seen the scan must stop scheduling driver work and keep findings.
    """

    def test_driver_death_error_is_classified(self):
        engine = _engine()
        # The exact message Playwright raises after the Node driver dies.
        from playwright._impl._errors import Error as PlaywrightError
        exc = PlaywrightError("APIRequestContext.get: Connection closed while reading from the driver")
        assert engine._is_driver_death(exc)
        # A plain network error is NOT driver death.
        assert not engine._is_driver_death(RuntimeError("timeout"))
        assert not engine._is_driver_death(ValueError("bad value"))

    async def test_module_group_driver_death_cancels_remaining_groups(self):
        """One group surfacing a driver-death error must set the flag, cancel
        every other in-flight group, and keep the findings already collected.
        """
        engine = _engine()
        cancelled: list = []
        calls: list = []

        async def death_then_hang(context, target, method, url, params, fingerprint):
            calls.append(url)
            if url.endswith("/0"):
                from playwright._impl._errors import Error as PlaywrightError
                raise PlaywrightError("Connection closed while reading from the driver")
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                cancelled.append(url)
                raise

        engine._run_attack_modules = death_then_hang

        # Group /0 raises driver death immediately; the other 5 hang until
        # the matrix aborts them. _run_modules must return promptly with the
        # flag set and no orphaned groups left running. The hard wait_for is
        # the assertion: if the matrix does NOT abort on driver death it would
        # block on the 5 sleeping groups forever, and the test times out.
        t0 = time.monotonic()
        findings = await asyncio.wait_for(
            engine._run_modules(None, "http://localhost:5000", _forms(6), [], [], {}),
            timeout=3,
        )
        elapsed = time.monotonic() - t0
        # Give the event loop a beat to deliver CancelledError to the children.
        await asyncio.sleep(0.1)

        assert elapsed < 3, f"driver death must abort the matrix fast, took {elapsed:.1f}s"
        assert engine._driver_dead is True
        assert len(cancelled) == 5, f"all other groups must be cancelled, got {cancelled}"
        assert findings == [], "no findings completed before the death"

    async def test_attack_modules_driver_death_sets_flag(self):
        """A module task that raises a driver-death error propagates the flag
        out of _run_attack_modules (the per-module wait_for is the last
        swallow point before the gather sees the exception)."""
        engine = _engine()

        async def dead_runner(context, target, method, url, params, fingerprint):
            from playwright._impl._errors import Error as PlaywrightError
            raise PlaywrightError("Connection closed while reading from the driver")

        # A single module; the runner raises driver death, which _run_single_module
        # must classify and propagate to the flag.
        await engine._run_single_module(
            "xss", dead_runner, None, "http://localhost:5000", "GET",
            "http://localhost:5000/x?q=1", {"q": "1"}, {},
        )
        assert engine._driver_dead is True

    async def test_interactions_skip_when_driver_dead(self):
        """Once the driver is dead the interaction phase must not touch the
        driver at all — it returns immediately instead of wedging. The context
        records any new_page attempt so the test fails if the guard is removed
        (a dead driver's new_page can hang, not just raise)."""
        engine = _engine()
        engine._driver_dead = True
        engine.visited = {"http://localhost:5000/a"}
        touched: list = []
        new_page_attempts: list = []

        class SpyingContext:
            async def new_page(self):
                new_page_attempts.append(1)
                await asyncio.sleep(60)

        async def should_never_run(context, page, url):
            touched.append(url)
            return []

        engine._interact_and_capture = should_never_run
        result = ScanResult(target="http://localhost:5000", started_at=time.time())
        t0 = time.monotonic()
        await engine._run_interactions(SpyingContext(), "http://localhost:5000", {}, result)

        assert time.monotonic() - t0 < 1, "dead driver must skip interactions entirely"
        assert new_page_attempts == [], "must not touch the driver when it is dead"
        assert touched == [], "interaction must not run on a dead driver"

    async def test_api_modules_skip_when_driver_dead(self):
        engine = _engine()
        engine._driver_dead = True
        findings = await engine._run_api_modules(None, "http://localhost:5000", "http://localhost:5000/api/x", {})
        assert findings == []

    async def test_abandoned_cancellation_returns_within_budget(self):
        """The crawl timeout must not hang even when the crawl task ignores
        cancellation (the wedge: a task stuck in a dead-driver await neither
        resolves nor raises, so wait_for's cancel never completes). The fix
        uses asyncio.wait + bounded abandon — this test pins that pattern.
        """
        engine = _engine()

        async def wedged():
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                # Ignore cancellation entirely — the dead-driver wedge.
                await asyncio.sleep(60)

        task = asyncio.ensure_future(wedged())
        t0 = time.monotonic()
        done, pending = await asyncio.wait({task}, timeout=0.3)
        assert task in pending, "wedged task must still be pending at the budget"
        assert time.monotonic() - t0 < 2, "bounded wait must return at the budget"

        # The scan abandons the task (cancel issued, short bounded window, then
        # moves on) — exactly what the crawl block does. Verifying the cancel
        # + short-window does not hang.
        task.cancel()
        t1 = time.monotonic()
        await asyncio.wait({task}, timeout=0.3)
        assert time.monotonic() - t1 < 2, "abandon window must be bounded"
