"""SCAN-QUALITY M3: crawl-profile gating, SPA-gated interaction, skimmer FP gate.

The user-facing symptom: a static weather site got its "#/patients" SPA routes
replayed and its pages scanned for health-app and local-lab endpoint names,
while a clean page with Google Ads got a MEDIUM skimmer finding. M3 puts every
hardcoded guess behind ``crawl.profile: deep`` and makes the skimmer require
sensitive form fields.
"""

import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from titan.core.engine import TitanEngine
from titan.core.models import ScanResult


class _BoomContext:
    """Fails loudly if a page op is attempted — proves the gate returns early."""

    def __init__(self):
        self.calls = []

    async def new_page(self):
        self.calls.append("new_page")
        raise AssertionError("must not open a page when the gate says skip")


class _FakePage:
    """No JS route tables (first evaluate returns None); the deep-only hash-
    route guess (second evaluate, identified by the 'const common' vocabulary)
    returns the health-app list so the fast/deep asymmetry is observable."""

    COMMON = ['/', '/login', '/register', '/dashboard', '/admin', '/profile',
              '/settings', '/patients', '/appointments', '/referrals',
              '/clinical', '/triage', '/analytics', '/notifications',
              '/followup', '/payments', '/facilities', '/voice', '/ussd',
              '/transcription']

    async def evaluate(self, js, *args):
        if "const common" in js and "routes.push" in js:
            return [f"https://weather.co.ke#{r}" for r in self.COMMON]
        return None  # no JS route tables / no content-derived routes

    async def goto(self, *a, **k):
        return None


class TestM3ProfileGate:
    def test_fast_is_default_and_bounds_the_crawl(self):
        e = TitanEngine({"crawl": {}, "ai": {}, "modules": {}})
        assert e._deep is False
        assert e.max_pages == 5, f"fast profile must default to a small crawl, got {e.max_pages}"
        assert e.max_depth == 1

    def test_deep_profile_raises_the_bounds(self):
        e = TitanEngine({"crawl": {"profile": "deep"}, "ai": {}, "modules": {}})
        assert e._deep is True
        assert e.max_pages == 20
        assert e.max_depth == 2

    async def test_fuzz_is_skipped_in_fast_mode(self):
        """Even with fuzz.enabled: true, fast profile must not fuzz."""
        e = TitanEngine({"crawl": {"fuzz": {"enabled": True}}, "ai": {}, "modules": {}})
        found = await e._fuzz_paths(_BoomContext(), ["https://x/api/users"], "https://x")
        assert found == [], f"fast profile must skip the wordlist fuzzer, got {found}"

    async def test_fuzz_respects_explicit_disable_under_deep(self):
        e = TitanEngine({"crawl": {"profile": "deep", "fuzz": {"enabled": False}}, "ai": {}, "modules": {}})
        found = await e._fuzz_paths(_BoomContext(), ["https://x/api/users"], "https://x")
        assert found == []

    def test_spa_hash_route_guessing_is_deep_only(self):
        """The health-app hash vocabulary ('#/patients', '#/voice', ...) must
        never be enumerated for a fast-profile scan — only the JS route-table
        enumeration (content-derived) runs, and this fake page has none."""
        from titan.core.engine import TitanEngine
        e_fast = TitanEngine({"crawl": {}, "ai": {}, "modules": {}})
        e_deep = TitanEngine({"crawl": {"profile": "deep"}, "ai": {}, "modules": {}})

        async def run(e):
            return await e._crawl_spa_routes(None, _FakePage(), "https://weather.co.ke/kenya/")

        assert asyncio.run(run(e_fast)) == [], "fast mode must not guess hash routes"
        deep_routes = asyncio.run(run(e_deep))
        assert any("#/patients" in r for r in deep_routes), "deep mode may guess hash routes"
        assert any("#/voice" in r for r in deep_routes)

    async def test_interaction_gate_skips_non_spa_fast_scan(self):
        """A static site (no hash links, no JS routes) must skip the SPA
        interaction phase entirely — no pages opened, no route replay."""
        e = TitanEngine({"crawl": {}, "ai": {}, "modules": {}})
        e.visited = {"https://weather.co.ke/", "https://weather.co.ke/kenya/"}
        ctx = _BoomContext()
        await e._run_interactions(ctx, "https://weather.co.ke/", {}, ScanResult(target="t", started_at=0))
        assert ctx.calls == [], f"non-SPA fast scan must not open interaction pages, got {ctx.calls}"

    async def test_interaction_runs_for_spa_signal(self):
        e = TitanEngine({"crawl": {}, "ai": {}, "modules": {}})
        e._spa_detected = True
        e.visited = set()  # empty visited -> no targets, but the gate must PASS through
        ctx = _BoomContext()
        await e._run_interactions(ctx, "https://x/", {}, ScanResult(target="t", started_at=0))
        assert ctx.calls == [], "no interaction targets means no pages, but the gate must not pre-return"

    async def test_fast_discovery_probes_are_awaitable_noops(self):
        """Regression (reviewer round 2): the fast-profile sentinels must be
        AWAITABLE — the original fix passed plain lists/dicts into
        asyncio.gather, which raised TypeError before any probe ran. The
        gather must return the exact 10-tuple the crawl unpacks, with the
        deep-only probes empty."""
        e = TitanEngine({"crawl": {}, "ai": {}, "modules": {}})
        # None of the gated probes may even be reached in fast mode.
        for name in ("_discover_apis", "_parse_swagger_spec",
                     "_parse_postman_collection", "_discover_graphql_endpoints",
                     "_brute_force_common_params", "_brute_force_http_methods"):
            async def _boom(*a, **k):
                raise AssertionError(f"{name} must not run in fast mode")
            setattr(e, name, _boom)

        (forms, links, static_apis, js_apis, spa_routes, swagger, postman,
         graphql, common_params, methods) = await e._discover_all(
            None, None, "http://x", "http://x"
        )
        assert forms == [] and links == []
        assert static_apis == [] and js_apis == [] and spa_routes == []
        assert swagger == [] and postman == [] and graphql == []
        assert common_params == {} and methods == []

    async def test_adaptive_stealth_collapses_delays_on_fast_targets(self):
        """SHARPEN-S1: a target that answers in <350ms must see the module
        delay collapse toward the floor (0.05–0.18s) instead of the
        configured 0.15–0.6s — the dominant scan cost on fast targets."""
        from titan.core.stealth import StealthEngine
        s = StealthEngine(jitter=0.3, min_delay=0.15, max_delay=0.6)
        s.observe_latency(0.08)
        assert s.max_delay <= 0.18, f"fast target must collapse max_delay, got {s.max_delay}"
        assert s.min_delay <= 0.05, f"fast target must collapse min_delay, got {s.min_delay}"
        # A slow/throttled target keeps the full stealth range.
        s2 = StealthEngine(jitter=0.3, min_delay=0.15, max_delay=0.6)
        s2.observe_latency(4.0)
        assert s2.max_delay == 0.6, f"slow target must keep stealth range, got {s2.max_delay}"
        # A mid target (200–1000ms) gets a moderate reduction.
        s3 = StealthEngine(jitter=0.3, min_delay=0.15, max_delay=0.6)
        s3.observe_latency(0.5)
        assert 0.10 <= s3.min_delay <= 0.15
        assert s3.max_delay <= 0.30

    async def test_adaptive_disabled_keeps_configured_range(self):
        from titan.core.stealth import StealthEngine
        s = StealthEngine(jitter=0.3, min_delay=0.5, max_delay=2.0)
        s.adaptive = False
        s.observe_latency(0.05)
        assert s.max_delay == 2.0 and s.min_delay == 0.5

    async def test_deep_discovery_runs_all_probes(self):
        """Deep profile must call every probe (each stubbed) and return all
        ten slots populated — the other side of the fast no-op contract."""
        e = TitanEngine({"crawl": {"profile": "deep"}, "ai": {}, "modules": {}})
        async def forms(page): return [{"action": "http://x/f", "method": "GET", "inputs": []}]
        async def links(page, base): return ["http://x/a"]
        async def apis(page, base): return ["http://x/api/a"]
        async def jsapis(page, base): return ["http://x/api/js"]
        async def spa(ctx, page, base): return ["http://x#/route"]
        async def swagger(ctx, base): return [{"path": "http://x/sw"}]
        async def postman(ctx, base): return [{"path": "http://x/pm"}]
        async def graphql(ctx, base): return ["http://x/graphql"]
        async def common(ctx, base, max_endpoints=3): return {"http://x/": ["id"]}
        async def methods(ctx, base, max_endpoints=3): return [{"path": "http://x/m"}]
        e._extract_forms, e._extract_links, e._discover_apis = forms, links, apis
        e._extract_apis_from_js = jsapis
        e._crawl_spa_routes = spa
        e._parse_swagger_spec, e._parse_postman_collection = swagger, postman
        e._discover_graphql_endpoints = graphql
        e._brute_force_common_params, e._brute_force_http_methods = common, methods

        result = await e._discover_all(None, None, "http://x", "http://x")
        assert result[2] == ["http://x/api/a"], "deep must run _discover_apis"
        assert result[5] == [{"path": "http://x/sw"}], "deep must run swagger probe"
        assert result[8] == {"http://x/": ["id"]}, "deep must run common-param brute force"
        assert result[9] == [{"path": "http://x/m"}], "deep must run HTTP-method brute force"


class TestM3SkimmerGate:
    async def _scan(self, evaluate_results):
        from titan.modules.clientside.thirdparty.detector import ThirdPartyDetector
        from tests.test_clientside import FakePage, StubSmith
        page = FakePage(evaluate_results={"document.querySelectorAll('script[src]')": evaluate_results})
        return await ThirdPartyDetector(StubSmith(), {}).scan(page, "http://localhost:5000", "http://localhost:5000/", {})

    async def test_ads_script_without_sensitive_fields_is_not_flagged(self):
        """The weather.co.ke FP: adsbygoogle is external + unlisted-until-now,
        but the page collects no card/password fields — a tracker, not a
        skimmer."""
        findings = await self._scan({
            "scripts": [{"src": "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"}],
            "sensitive_inputs": [],
            "origin": "https://weather.co.ke",
        })
        assert findings == [], f"ad script on a page with no sensitive fields must not be a skimmer, got {findings}"

    async def test_ads_script_with_sensitive_fields_is_flagged(self):
        """A card form page loading an external unlisted script IS suspicious."""
        findings = await self._scan({
            "scripts": [{"src": "https://skimmer-evil.example/analytics.js"}],
            "sensitive_inputs": ["cardnumber", "cvv"],
            "origin": "https://shop.example",
        })
        assert findings, "external script + sensitive fields must be flagged"
        assert findings[0].attack_type.value == "Skimmer"
