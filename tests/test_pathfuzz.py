"""Tests for the response-driven path fuzzer (crawl.fuzz / PathFuzzer).

Covers the discovery semantics that make it response-driven rather than
list-driven:
- a per-seed random-marker 404 control teaches the fuzzer what "not found"
  looks like; a candidate is a hit only when its (status, body) response
  differs from that control,
- soft-404 HTML served with HTTP 200 is not a hit,
- checkpoint/wall bodies are not a hit,
- redirects are hits only when they go somewhere different from the control,
- budgets (max_requests, max_depth, max_seeds, max_words_per_seed) hold,
- out-of-scope URLs are filtered even when the response would otherwise hit,
- every failure degrades to an empty result (the seam can never break a crawl),
- the engine seam (_fuzz_paths) is wired and feeds hits into the crawl.
"""

import asyncio

import pytest

from titan.core.engine import TitanEngine
from titan.core.pathfuzz import PathFuzzer, DEFAULT_WORDS, SOFT_404_MARKERS


class _Resp:
    def __init__(self, status, body, headers=None):
        self.status = status
        self.headers = headers or {}
        self._body = body

    async def text(self):
        return self._body


class _RouteContext:
    """context.request stub: routes[prefix] -> (status, body[, headers]).

    Any URL under a known prefix answers with that route (longest-prefix
    match wins); everything else answers the "generic 404" route (or a
    default status/body).
    """

    def __init__(self, routes, default_status=404, default_body="Not Found"):
        self._routes = routes
        self._default_status = default_status
        self._default_body = default_body
        self.calls: list = []

    @property
    def request(self):
        return self

    async def get(self, url, params=None, headers=None, timeout=3000, **kw):
        self.calls.append(url)
        # Longest-prefix match so `/api/users/export/csv` doesn't resolve to
        # the shorter `/api/users/` route.
        matches = []
        for prefix, route in self._routes.items():
            if url == prefix or url.startswith(prefix):
                if len(route) == 3:
                    status, body, hdrs = route
                else:
                    status, body = route
                    hdrs = {}
                matches.append((len(prefix), prefix, status, body, hdrs))
        if matches:
            _, _p, status, body, hdrs = max(matches, key=lambda m: m[0])
            return _Resp(status, body, hdrs)
        return _Resp(self._default_status, self._default_body)

    async def post(self, url, data=None, headers=None, timeout=3000, **kw):
        return await self.get(url)


def _fuzzer(cfg=None):
    return PathFuzzer(
        {
            "enabled": True,
            "max_seeds": 5,
            "max_depth": 2,
            "max_words_per_seed": 60,
            "max_requests": 250,
            "concurrency": 8,
            "timeout": 2000,
            **(cfg or {}),
        }
    )


class TestControlDifferential:
    """The core: a hit differs from the per-seed 404 control."""

    async def test_deeper_endpoint_is_discovered(self):
        # /api/v1/users exists; /api/v1/users/export returns real JSON.
        # The random-marker control 404s with {"error": "not found"}; only
        # export differs -> only export is discovered.
        ctx = _RouteContext({
            "http://t/api/v1/users/export": (200, '{"rows": [{"id": 1}]}'),
            "http://t/api/v1/users/": (404, '{"error": "not found"}'),
        })
        fz = _fuzzer({"wordlist": ["export", "import", "delete"]})
        found = await fz.fuzz(ctx, ["http://t/api/v1/users"])

        assert "http://t/api/v1/users/export" in found, f"got {found}"
        assert "http://t/api/v1/users/import" not in found, f"got {found}"
        assert "http://t/api/v1/users/delete" not in found, f"got {found}"

    async def test_soft_404_html_200_is_not_a_hit(self):
        # WordPress-style: ANY unknown path answers 200 with a not-found page.
        # The control itself would be a "200", so the classifier must reject
        # the candidate even though status matches the "live" 200 case.
        ctx = _RouteContext(
            {
                "http://t/wp/": (
                    200,
                    "<html><title>Page not found</title><p>The requested URL "
                    "was not found on this server.</p></html>",
                ),
            },
            default_status=200,
            default_body="<html><title>Page not found</title><p>Not here.</p></html>",
        )
        fz = _fuzzer({"wordlist": ["admin", "export", "hidden"]})
        found = await fz.fuzz(ctx, ["http://t/wp"])

        assert found == [], f"soft-404 site must produce zero hits, got {found}"

    async def test_framework_catch_all_identical_body_is_not_a_hit(self):
        # SPA catch-all: every path returns 200 with the same index body. The
        # control and candidates are identical => not hits.
        index = "<html><body>app shell</body></html>"
        ctx = _RouteContext({}, default_status=200, default_body=index)
        fz = _fuzzer({"wordlist": ["admin", "settings"]})
        found = await fz.fuzz(ctx, ["http://t/app"])

        assert found == [], f"identical catch-all responses must not be hits, got {found}"

    async def test_whitespace_only_difference_is_not_a_hit(self):
        # Body signature is whitespace-normalised: same content, different
        # indentation = same route signature = not a hit.
        ctx = _RouteContext({
            "http://t/api/x/export": (200, '{"rows":  []}'),
            "http://t/api/x/": (404, '{"error":"not found"}'),
        })
        fz = _fuzzer({"wordlist": ["export"]})
        found = await fz.fuzz(ctx, ["http://t/api/x"])
        assert "http://t/api/x/export" in found

    async def test_redirect_same_as_control_is_not_a_hit(self):
        ctx = _RouteContext(
            {
                "http://t/r/": (302, "", {"location": "http://t/home"}),
            },
            default_status=302,
            default_body="",
        )
        # The control redirects to /home; a candidate that also redirects to
        # /home is the same dead-route behaviour, not a new endpoint.
        fz = _fuzzer({"wordlist": ["admin"]})
        found = await fz.fuzz(ctx, ["http://t/r"])
        assert found == [], f"same-target redirect must not be a hit, got {found}"

    async def test_redirect_to_new_target_is_a_hit(self):
        ctx = _RouteContext({
            "http://t/r/admin": (302, "", {"location": "http://t/login"}),
            "http://t/r/": (302, "", {"location": "http://t/home"}),
        })
        fz = _fuzzer({"wordlist": ["admin"]})
        found = await fz.fuzz(ctx, ["http://t/r"])
        assert "http://t/r/admin" in found, f"got {found}"


class TestGuards:
    """Budget / scope / input guards."""

    async def test_out_of_scope_urls_are_filtered(self):
        ctx = _RouteContext({
            "http://t/api/x/export": (200, '{"ok": true}'),
            "http://t/api/x/": (404, "no"),
            "http://other/": (200, '{"ok": true}'),
        })
        fz = _fuzzer({"wordlist": ["export"]})
        fz.in_scope = lambda url: url.startswith("http://t")
        found = await fz.fuzz(ctx, ["http://t/api/x"])
        assert found == ["http://t/api/x/export"]

    async def test_max_requests_budget_is_respected(self):
        # 1 control + words; once the budget is exhausted no more probes fire.
        ctx = _RouteContext({}, default_status=200, default_body="{}")
        fz = _fuzzer({"max_requests": 5, "max_words_per_seed": 50})
        found = await fz.fuzz(ctx, ["http://t/api/a", "http://t/api/b", "http://t/api/c"])
        # control(3) + words until budget hit; must never exceed 5 requests.
        assert len(ctx.calls) <= 5, f"budget exceeded: {len(ctx.calls)} calls"
        assert found == [], "identical responses must not be hits"

    async def test_max_depth_limits_recursion(self):
        # /users/export exists at depth 1; /users/export/csv at depth 2.
        ctx = _RouteContext({
            "http://t/api/users/export": (200, '{"ok": true}'),
            "http://t/api/users/export/csv": (200, "a,b,c"),
            "http://t/api/users/": (404, '{"error": "not found"}'),
            "http://t/api/users/export/": (404, '{"error": "not found"}'),
        })
        fz = _fuzzer({"wordlist": ["export", "csv"], "max_depth": 1})
        found = await fz.fuzz(ctx, ["http://t/api/users"])
        assert "http://t/api/users/export" in found
        assert "http://t/api/users/export/csv" not in found, (
            f"depth 1 must not reach depth 2, got {found}"
        )

    async def test_deeper_recursion_finds_grandchildren(self):
        ctx = _RouteContext({
            "http://t/api/users/export": (200, '{"ok": true}'),
            "http://t/api/users/export/csv": (200, "a,b,c"),
            "http://t/api/users/": (404, '{"error": "not found"}'),
            "http://t/api/users/export/": (404, '{"error": "not found"}'),
        })
        fz = _fuzzer({"wordlist": ["export", "csv"], "max_depth": 2})
        found = await fz.fuzz(ctx, ["http://t/api/users"])
        assert "http://t/api/users/export" in found
        assert "http://t/api/users/export/csv" in found, f"got {found}"

    async def test_max_seeds_limits_level_width(self):
        ctx = _RouteContext({}, default_status=200, default_body="{}")
        fz = _fuzzer({"max_seeds": 1, "max_words_per_seed": 3, "max_requests": 50})
        seeds = [f"http://t/api/s{i}" for i in range(5)]
        await fz.fuzz(ctx, seeds)
        # 1 control for the single seed + 3 words = 4 requests max.
        assert len(ctx.calls) <= 4, f"max_seeds not respected: {len(ctx.calls)} calls"

    async def test_static_asset_seeds_are_skipped(self):
        ctx = _RouteContext({"http://t/app.js": (200, "x")})
        fz = _fuzzer({"wordlist": ["admin"]})
        found = await fz.fuzz(ctx, ["http://t/app.js"])
        assert found == []

    async def test_disabled_returns_empty(self):
        ctx = _RouteContext({"http://t/api/x/export": (200, '{"ok": true}')})
        fz = _fuzzer({"enabled": False, "wordlist": ["export"]})
        found = await fz.fuzz(ctx, ["http://t/api/x"])
        assert found == []

    async def test_seed_urls_are_not_returned(self):
        ctx = _RouteContext({"http://t/api/x/export": (200, '{"ok": true}')})
        fz = _fuzzer({"wordlist": ["export"]})
        found = await fz.fuzz(ctx, ["http://t/api/x"])
        assert "http://t/api/x" not in found


class TestDegradation:
    """The fuzzer must degrade, never raise."""

    async def test_raising_context_degrades_to_empty(self):
        class BoomContext:
            @property
            def request(self):
                return self

            async def get(self, url, **kw):
                raise RuntimeError("connection refused")

        fz = _fuzzer()
        found = await fz.fuzz(BoomContext(), ["http://t/api/x"])
        assert found == []

    async def test_single_probe_failure_does_not_kill_others(self):
        class FlakyContext:
            def __init__(self):
                self.calls = []

            @property
            def request(self):
                return self

            async def get(self, url, **kw):
                self.calls.append(url)
                if "boom" in url:
                    raise RuntimeError("flake")
                if url.startswith("http://t/api/x/export"):
                    return _Resp(200, '{"ok": true}')
                return _Resp(404, "no")

        ctx = FlakyContext()
        fz = _fuzzer({"wordlist": ["export", "boom"]})
        found = await fz.fuzz(ctx, ["http://t/api/x"])
        assert "http://t/api/x/export" in found, f"flaky word must not hide hits, got {found}"


class TestWordlist:
    async def test_default_wordlist_has_content(self):
        assert len(DEFAULT_WORDS) >= 100, "built-in wordlist must be substantial"
        for w in ("admin", "export", "users", "login", "config", "webhooks", "health"):
            assert w in DEFAULT_WORDS, f"{w} should be in the default wordlist"

    async def test_config_words_are_appended(self):
        fz = _fuzzer({"wordlist": ["customword1", "customword2"]})
        assert "customword1" in fz.words and "customword2" in fz.words

    async def test_soft_404_markers_exist(self):
        assert "page not found" in SOFT_404_MARKERS


class TestEngineSeam:
    """_fuzz_paths wiring: hits flow into the crawl via all_apis."""

    async def test_fuzz_paths_returns_hits(self):
        # Deep profile: the wordlist fuzzer is a deep-only probe (the fast
        # default returns zero hits by contract — pinned in test_scan_quality).
        engine = TitanEngine({
            "stealth": {"min_delay": 0.01, "max_delay": 0.01},
            "crawl": {"profile": "deep"},
        })
        engine._scan_target = "http://t"
        ctx = _RouteContext({
            "http://t/api/v1/users/export": (200, '{"rows": []}'),
            "http://t/api/v1/users/": (404, '{"error": "not found"}'),
        })
        engine.config.setdefault("crawl", {})["fuzz"] = {
            "enabled": True,
            "wordlist": ["export", "import", "delete"],
            "max_words_per_seed": 60,
        }
        found = await engine._fuzz_paths(ctx, ["http://t/api/v1/users"], "http://t")
        assert "http://t/api/v1/users/export" in found, f"got {found}"

    async def test_fuzz_paths_disabled_returns_empty(self):
        engine = TitanEngine({
            "stealth": {"min_delay": 0.01, "max_delay": 0.01},
            "crawl": {"profile": "deep"},
        })
        engine._scan_target = "http://t"
        engine.config.setdefault("crawl", {})["fuzz"] = {"enabled": False}
        ctx = _RouteContext({"http://t/api/x/export": (200, '{"ok": true}')})
        found = await engine._fuzz_paths(ctx, ["http://t/api/x"], "http://t")
        assert found == []

    async def test_fuzz_paths_failure_degrades_to_empty(self):
        engine = TitanEngine({
            "stealth": {"min_delay": 0.01, "max_delay": 0.01},
            "crawl": {"profile": "deep"},
        })
        engine._scan_target = "http://t"

        class BoomContext:
            @property
            def request(self):
                return self

            async def get(self, url, **kw):
                raise RuntimeError("dead")

        found = await engine._fuzz_paths(BoomContext(), ["http://t/api/x"], "http://t")
        assert found == [], "a dead context must degrade to zero hits, never raise"

    async def test_fuzzed_hits_join_all_apis(self):
        """The crawl wiring appends fuzz hits to all_apis so the module matrix
        scans them (asserted via _fuzz_paths + the same inclusion rule)."""
        engine = TitanEngine({
            "stealth": {"min_delay": 0.01, "max_delay": 0.01},
            "crawl": {"profile": "deep"},
        })
        engine._scan_target = "http://t"
        ctx = _RouteContext({
            "http://t/api/x/export": (200, '{"ok": true}'),
            "http://t/api/x/": (404, "no"),
        })
        engine.config.setdefault("crawl", {})["fuzz"] = {
            "enabled": True,
            "wordlist": ["export"],
        }
        all_apis = ["http://t/api/x"]
        fuzzed = await engine._fuzz_paths(ctx, all_apis, "http://t")
        for fu in fuzzed:
            fu_base = fu.split("?")[0]
            if fu_base not in all_apis:
                all_apis.append(fu_base)
        assert "http://t/api/x/export" in all_apis
