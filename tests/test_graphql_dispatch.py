"""Regression tests for GraphQL dispatch in ModuleRunner._run_api_modules.

GraphQL scanning must fire when the URL path says graphql OR when the
fingerprint identifies GraphQL tech — targets running GraphQL at
nonstandard paths (/gql, /query) previously escaped the module.
"""

from __future__ import annotations

from typing import Any

import pytest

from titan.core.modules_runner import ModuleRunner


class _FakeEngine:
    def __init__(self) -> None:
        self._driver_dead = False
        self.payload_smith = None
        self.rest_calls: list[str] = []

    async def _test_rest_api(self, context, target, api_url, fingerprint):
        self.rest_calls.append(api_url)
        return []


class _FakeScanner:
    calls: list[tuple[str, dict[str, Any]]] = []

    def __init__(self, payload_smith, fingerprint: dict[str, Any]):
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, api_url: str):
        _FakeScanner.calls.append((api_url, self.fingerprint))
        return []


@pytest.fixture()
def fake_scanner(monkeypatch):
    _FakeScanner.calls = []
    import titan.modules.api.graphql as gql

    monkeypatch.setattr(gql, "GraphQLScanner", _FakeScanner)
    return _FakeScanner


def _runner() -> tuple[ModuleRunner, _FakeEngine]:
    engine = _FakeEngine()
    return ModuleRunner(engine), engine


async def test_graphql_fires_on_url_path(fake_scanner):
    runner, _ = _runner()
    await runner._run_api_modules(None, "http://x", "http://x/api/graphql", {})
    assert len(fake_scanner.calls) == 1
    assert fake_scanner.calls[0][0] == "http://x/api/graphql"


async def test_graphql_fires_on_fingerprint_at_nonstandard_path(fake_scanner):
    runner, engine = _runner()
    fp = {"technologies": ["GraphQL", "Next.js"]}
    await runner._run_api_modules(None, "http://x", "http://x/gql", fp)
    assert len(fake_scanner.calls) == 1
    assert engine.rest_calls == []


async def test_fingerprint_none_falls_back_to_url_check(fake_scanner):
    runner, engine = _runner()
    await runner._run_api_modules(None, "http://x", "http://x/api/users", None)
    assert fake_scanner.calls == []
    assert engine.rest_calls == ["http://x/api/users"]


async def test_non_graphql_target_goes_to_rest(fake_scanner):
    runner, engine = _runner()
    await runner._run_api_modules(None, "http://x", "http://x/api/users", {})
    assert fake_scanner.calls == []
    assert engine.rest_calls == ["http://x/api/users"]
