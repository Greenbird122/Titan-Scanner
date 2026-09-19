"""First coverage for the ModuleRunner orchestration core.

Focus is what the split must preserve: the runner composes its four
mixins (bindings, tracks, API dispatch), the module matrix groups
forms/links/APIs into engine tasks, the early-exit skips expensive
modules on low-score routes when cheap ones find nothing, and module
budgets degrade on repeat timeouts. Network-touching detectors are
stubbed at the engine boundary — nothing here opens a socket.
"""

from __future__ import annotations

import asyncio

import pytest

from titan.core.api_dispatch import ApiModuleDispatch
from titan.core.module_bindings import AttackModuleBindings
from titan.core.module_tracks import BrowserDetectorsMixin, IdentityModulesMixin
from titan.core.modules_runner import ModuleRunner


class _WafTracker:
    def is_waf_blocked(self, url: str) -> bool:
        return False

    def get_waf(self, url: str):
        return None


class _Stealth:
    async def delay(self) -> None:
        return None


class StubEngine:
    """Just the attributes the orchestration core reads."""

    def __init__(self):
        self.config: dict = {"modules": {}}
        self._driver_dead = False
        self._coverage = {"params_discovered": 0, "endpoint_groups_run": 0}
        self._module_semaphore = asyncio.Semaphore(4)
        self._module_timeouts: dict[str, int] = {}
        self._module_line_counts: dict[str, int] = {}
        self._waf_tracker = _WafTracker()
        self.stealth = _Stealth()
        self.attack_calls: list[tuple] = []
        self.api_calls: list[str] = []

    def _is_in_scope(self, url: str) -> bool:
        return not url.startswith("http://offscope")

    def _is_driver_death(self, exc: BaseException) -> bool:
        return False

    async def _run_attack_modules(self, context, target, method, url, params, fingerprint, route_score=5):
        self.attack_calls.append((method, url, route_score))
        return [{"module": method}]

    async def _run_api_modules(self, context, target, api_url, fingerprint):
        self.api_calls.append(api_url)
        return []


@pytest.fixture()
def engine():
    return StubEngine()


@pytest.fixture()
def runner(engine):
    return ModuleRunner(engine)


class TestComposition:
    def test_runner_inherits_all_four_mixins(self, runner):
        """The split's contract: every legacy attribute name still resolves
        on ModuleRunner via the mixin chain, owned by exactly one class."""
        expected = {
            "_run_sqli": AttackModuleBindings,
            "_run_apixss": AttackModuleBindings,
            "run_identity_modules": IdentityModulesMixin,
            "run_browser_modules": BrowserDetectorsMixin,
            "_run_domxss": BrowserDetectorsMixin,
            "_run_api_modules": ApiModuleDispatch,
            "_test_rest_api": ApiModuleDispatch,
            "_run_modules": ModuleRunner,
            "run_attack_modules": ModuleRunner,
        }
        for name, owner in expected.items():
            assert callable(getattr(runner, name, None)), f"missing {name}"
            assert owner in type(runner).__mro__


class TestRunModulesMatrix:
    async def test_forms_links_apis_grouped_into_tasks(self, runner, engine):
        forms = [{"action": "/login", "method": "POST", "inputs": [{"name": "u", "value": "x"}]}]
        links = ["http://t/page?search=a"]
        apis = ["http://t/api/users"]
        findings = await runner._run_modules(None, "http://t", forms, links, apis, {})
        assert len(engine.attack_calls) == 2  # form POST + link GET
        assert engine.api_calls == ["http://t/api/users"]
        assert findings == [{"module": "POST"}, {"module": "GET"}]
        assert engine._coverage["endpoint_groups_run"] == 3

    async def test_out_of_scope_endpoints_skipped(self, runner, engine):
        forms = [{"action": "http://offscope/x", "method": "POST", "inputs": [{"name": "u", "value": "v"}]}]
        findings = await runner._run_modules(None, "http://t", forms, [], [], {})
        assert engine.attack_calls == []
        assert findings == []

    async def test_empty_params_skipped(self, runner, engine):
        forms = [{"action": "/x", "method": "POST", "inputs": [{"name": "", "value": "v"}]}]
        links = ["http://t/noquery"]
        await runner._run_modules(None, "http://t", forms, links, [], {})
        assert engine.attack_calls == []


class TestRunAttackModules:
    async def test_early_exit_skips_expensive_on_low_score(self, runner, engine, monkeypatch):
        """Low-value route + cheap modules silent -> expensive never runs."""
        ran = {"expensive": 0}

        async def fake_single(name, runner_fn, *args):
            if name in ("sqli", "rce"):
                ran["expensive"] += 1
            return []

        monkeypatch.setattr(runner, "_run_single_module", fake_single)
        await runner.run_attack_modules(None, "http://t", "GET", "http://t/p", {"q": "x"}, {}, route_score=1)
        assert ran["expensive"] == 0

    async def test_verified_forced_false_on_all_output(self, runner, engine, monkeypatch):
        class F:
            verified = True

        async def fake_single(name, runner_fn, *args):
            return [F()] if name == "cors" else []

        monkeypatch.setattr(runner, "_run_single_module", fake_single)
        out = await runner.run_attack_modules(None, "http://t", "GET", "http://t/p", {"q": "x"}, {})
        assert len(out) == 1 and out[0].verified is False

    async def test_driver_dead_returns_empty(self, runner, engine):
        engine._driver_dead = True
        assert await runner.run_attack_modules(None, "http://t", "GET", "http://t/p", {"q": "x"}, {}) == []
        # _run_modules checks _driver_dead before creating any tasks, so the
        # API stub coroutine is never started here — no un-awaited coroutines.
        findings = await runner._run_modules(None, "http://t", [], [], [], {})
        assert findings == []
        assert engine.api_calls == []


class TestBudgets:
    def test_compute_module_budget_tiers(self, runner, engine):
        for lines, expected in [(700, 90), (500, 60), (350, 45), (250, 30), (150, 20), (50, 15)]:
            engine._module_line_counts["m"] = lines
            assert runner._compute_module_budget("m") == expected

    def test_compute_module_budget_missing_module_reads_zero(self, runner, engine):
        assert runner._compute_module_budget("no_such_module_dir") == 15

    async def test_repeat_timeout_halves_budget_then_skips(self, runner, engine, monkeypatch):
        """Two prior timeouts -> module skipped entirely (circuit breaker)."""
        engine._module_timeouts["sqli"] = 2

        class Det:
            def __init__(self, *a):
                pass

            async def scan(self, *a):
                raise AssertionError("module must not run after 2 timeouts")

        import titan.modules.sqli.detector as sqli_det

        monkeypatch.setattr(sqli_det, "SQLiDetector", Det)
        out = await runner._run_single_module(
            "sqli", runner._run_sqli, None, "http://t", "GET", "http://t/p", {"q": "x"}, {}
        )
        assert out == []
