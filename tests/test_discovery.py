"""First coverage for ``titan/core/discovery.py`` and ``titan/core/api_probes.py``.

Focus is the discovery contract the crawl loop depends on: ``discover_all``
returns a fixed 10-tuple, a failing probe degrades to its empty default instead
of poisoning the rest, and the pure helpers behave on real inputs. Network
touching probes are exercised through stubs only — nothing here opens a socket.
"""

import pytest

from titan.core.api_probes import ApiProbes, _flatten_postman_items
from titan.core.discovery import DiscoveryEngine, _parse_api_patterns


class StubEngine:
    """Just the attributes DiscoveryEngine and its probes read."""

    _deep = False
    _hostile = False
    visited: set[str] = set()
    _platform_extra_params: list[str] = []

    def _is_spa_shell(self, url: str) -> bool:
        return False

    def _is_in_scope(self, url: str) -> bool:
        return True


@pytest.fixture()
def engine():
    return DiscoveryEngine(StubEngine())


class TestDiscoverAll:
    async def test_returns_the_ten_slot_contract(self, engine):
        """The crawl loop unpacks 10 values in a fixed order — pin it."""

        async def noop_page_get(url, **kwargs):
            class R:
                status = 200

                async def text(self):
                    return "<html></html>"

            return R()

        context = type("Ctx", (), {"request": type("Req", (), {"get": noop_page_get})})()
        page = type("P", (), {})()
        result = await engine.discover_all(context, page, "http://t", "http://t")
        assert isinstance(result, tuple) and len(result) == 10
        forms, links, static_apis, js_apis, spa_routes, swagger, postman, graphql, params, methods = result
        assert all(
            isinstance(x, list)
            for x in (forms, links, static_apis, js_apis, spa_routes, swagger, postman, graphql, methods)
        )
        assert isinstance(params, dict)

    async def test_failing_probe_degrades_to_its_default(self, engine):
        """One probe raising must not poison the others (report item: silent
        failure handling)."""

        async def boom(*args, **kwargs):
            raise RuntimeError("probe exploded")

        engine._extract_links = boom  # type: ignore[method-assign]

        async def noop_page_get(url, **kwargs):
            class R:
                status = 200

                async def text(self):
                    return "<html></html>"

            return R()

        context = type("Ctx", (), {"request": type("Req", (), {"get": noop_page_get})})()
        page = type("P", (), {})()
        result = await engine.discover_all(context, page, "http://t", "http://t")
        links = result[1]
        assert links == []  # degraded, not propagated
        assert result[0] == []  # neighbours unaffected

    async def test_engine_monkeypatch_wins_over_self_method(self, engine):
        """The documented monkey-patch seam: engine's version takes precedence."""

        async def patched(page):
            return [{"patched": True}]

        engine_stub = engine.engine
        engine_stub._extract_forms = patched  # type: ignore[attr-defined]

        async def noop_page_get(url, **kwargs):
            class R:
                status = 200

                async def text(self):
                    return "<html></html>"

            return R()

        context = type("Ctx", (), {"request": type("Req", (), {"get": noop_page_get})})()
        page = type("P", (), {})()
        result = await engine.discover_all(context, page, "http://t", "http://t")
        assert result[0] == [{"patched": True}]


class TestApiProbesBinding:
    def test_api_probes_shares_the_engine_handle(self, engine):
        assert isinstance(engine._api_probes, ApiProbes)
        assert engine._api_probes.engine is engine.engine


class TestPureHelpers:
    def test_parse_api_patterns_finds_versioned_api_urls(self):
        js = 'fetch("https://api.corp.io/v1/users"); const x = "https://api.corp.io/v2/items"'
        found = _parse_api_patterns(js, "https://api.corp.io")
        assert "https://api.corp.io/v1/users" in found
        assert "https://api.corp.io/v2/items" in found

    def test_parse_api_patterns_no_matches(self):
        assert _parse_api_patterns("no urls here", "https://t") == []

    def test_flatten_postman_items_walks_nested_folders(self):
        # Contract: takes the collection's `item` list (what the production
        # caller at api_probes.py passes), not the whole collection dict.
        items = [
            {"name": "leaf", "request": {"url": "http://x"}},
            {"name": "folder", "item": [{"name": "inner", "request": {"url": "http://y"}}]},
        ]
        flat = _flatten_postman_items(items)
        assert [i["name"] for i in flat] == ["leaf", "inner"]


class TestDelegation:
    async def test_moved_probe_reachable_through_the_bundle(self, engine):
        """The five probes moved to ApiProbes are still what discover_all runs."""
        calls: list[str] = []

        async def fake_swagger(context, base_url):
            calls.append("swagger")
            return [{"path": "/v1/x"}]

        engine._api_probes._parse_swagger_spec = fake_swagger  # type: ignore[method-assign]
        engine.engine._deep = True  # type: ignore[attr-defined]

        async def noop_page_get(url, **kwargs):
            class R:
                status = 200

                async def text(self):
                    return "<html></html>"

            return R()

        context = type("Ctx", (), {"request": type("Req", (), {"get": noop_page_get})})()
        page = type("P", (), {})()
        result = await engine.discover_all(context, page, "http://t", "http://t")
        assert calls == ["swagger"]
        assert result[5] == [{"path": "/v1/x"}]

    async def test_legacy_attribute_names_resolve_on_engine(self, engine):
        """Regression: the split moved five probes to ApiProbes but discover_all
        dispatches by string name with a getattr(self, name) fallback — without
        delegators, every probe name would raise AttributeError at dispatch
        time. Pin the legacy attribute names on DiscoveryEngine."""
        for name in (
            "_parse_swagger_spec",
            "_parse_postman_collection",
            "_discover_graphql_endpoints",
            "_brute_force_common_params",
            "_brute_force_http_methods",
        ):
            assert callable(getattr(engine, name, None)), f"DiscoveryEngine lost {name}"

    async def test_deep_run_reaches_moved_probes_without_engine_forwarders(self, engine):
        """With _deep on, the three probes that have NO engine forwarder
        (postman, graphql, common_params) must still run via DiscoveryEngine's
        own delegators — engine.py only forwards swagger and methods."""
        engine.engine._deep = True  # type: ignore[attr-defined]

        calls: list[str] = []

        async def fake_postman(context, base_url):
            calls.append("postman")
            return []

        async def fake_graphql(context, base_url):
            calls.append("graphql")
            return []

        async def fake_params(context, base_url, max_endpoints=3):
            calls.append("params")
            return {}

        engine._api_probes._parse_postman_collection = fake_postman  # type: ignore[method-assign]
        engine._api_probes._discover_graphql_endpoints = fake_graphql  # type: ignore[method-assign]
        engine._api_probes._brute_force_common_params = fake_params  # type: ignore[method-assign]

        async def noop_page_get(url, **kwargs):
            class R:
                status = 200

                async def text(self):
                    return "<html></html>"

            return R()

        context = type("Ctx", (), {"request": type("Req", (), {"get": noop_page_get})})()
        page = type("P", (), {})()
        result = await engine.discover_all(context, page, "http://t", "http://t")
        assert calls == ["postman", "graphql", "params"]
        assert result[6] == [] and result[7] == [] and result[8] == {}
