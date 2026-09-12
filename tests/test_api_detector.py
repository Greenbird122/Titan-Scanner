"""Tests for titan.modules.api.detector — APIDetector discovery engines.

Drives Swagger discovery, GraphQL introspection/batching, and hidden-path
discovery against a route-table fake mirroring the context.request surface.
No network.
"""

import json
from types import SimpleNamespace

import pytest

from titan.core.models import AttackType, Severity
from titan.modules.api.detector import APIDetector

SWAGGER_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "T", "version": "1"},
    "paths": {"/a": {"get": {}}, "/b": {"post": {}}},
}

INTROSPECTION_BODY = json.dumps(
    {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [{"name": "Query"}, {"name": "User"}],
            }
        }
    }
)


class _Resp:
    def __init__(self, status=200, text="", headers=None):
        self.status = status
        self._text = text
        self.headers = headers or {}

    async def text(self):
        return self._text


class _FakeRequest:
    """context.request fake with exact-URL-routed GETs and scripted POSTs."""

    def __init__(self, get_routes=None, post_routes=None):
        self.get_routes = get_routes or {}  # exact url -> _Resp
        self.post_routes = post_routes or {}  # exact url -> [_Resp, ...]
        self.get_calls: list[str] = []
        self.post_calls: list[str] = []

    async def get(self, url, **kw):
        self.get_calls.append(url)
        return self.get_routes.get(url, _Resp(404, ""))

    async def post(self, url, **kw):
        self.post_calls.append(url)
        responses = self.post_routes.get(url)
        if responses is None:
            return _Resp(404, "")
        if isinstance(responses, list):
            return responses.pop(0) if responses else _Resp(404, "")
        return responses


def _detector() -> APIDetector:
    return APIDetector(payload_smith=None, fingerprint={})


def _ctx(fake: _FakeRequest) -> SimpleNamespace:
    return SimpleNamespace(request=fake)


@pytest.mark.asyncio
class TestSwaggerDiscovery:
    async def test_exposed_spec_produces_finding(self):
        fake = _FakeRequest(
            get_routes={
                "https://t.example/openapi.json": _Resp(200, json.dumps(SWAGGER_SPEC)),
            }
        )
        findings = await _detector().scan(_ctx(fake), "https://t.example", "GET", "https://t.example", {})
        assert findings, "expected the exposed spec to be flagged"
        f = findings[0]
        assert f.payload.startswith("Swagger/OpenAPI spec exposed")
        assert "openapi.json" in f.url
        assert f.attack_type == AttackType.API_EXPOSURE
        assert f.severity == Severity.MEDIUM
        assert f.verified is True
        assert f.metadata["endpoint_count"] == 2
        assert f.diffs[0] == "api:swagger_spec_exposed"

    async def test_json_without_spec_shape_is_ignored(self):
        fake = _FakeRequest(
            get_routes={
                "https://t.example/openapi.json": _Resp(200, json.dumps({"not": "a spec"})),
            }
        )
        findings = await _detector().scan(_ctx(fake), "https://t.example", "GET", "https://t.example", {})
        assert findings == []

    async def test_missing_spec_produces_nothing(self):
        findings = await _detector().scan(_ctx(_FakeRequest()), "https://t.example", "GET", "https://t.example", {})
        assert findings == []


@pytest.mark.asyncio
class TestGraphqlDiscovery:
    async def test_introspection_without_batching(self):
        fake = _FakeRequest(
            post_routes={
                "https://t.example/graphql": [_Resp(200, INTROSPECTION_BODY), _Resp(404, "")],
            }
        )
        findings = await _detector().scan(_ctx(fake), "https://t.example", "GET", "https://t.example", {})
        f = findings[0]
        assert f.payload.startswith("GraphQL introspection enabled")
        assert "2 types exposed" in f.payload
        assert f.metadata["batch_supported"] is False
        assert f.diffs == ["graphql:introspection_enabled"]
        # two POSTs: introspection query, then the batch probe
        assert len(fake.post_calls) == 2

    async def test_introspection_with_batching(self):
        fake = _FakeRequest(
            post_routes={
                "https://t.example/graphql": [
                    _Resp(200, INTROSPECTION_BODY),
                    _Resp(200, json.dumps([{"data": {}}])),
                ],
            }
        )
        findings = await _detector().scan(_ctx(fake), "https://t.example", "GET", "https://t.example", {})
        f = findings[0]
        assert f.metadata["batch_supported"] is True
        assert "graphql:batch_queries_supported" in f.diffs
        assert "+ batching" in f.payload

    async def test_non_json_introspection_response_ignored(self):
        fake = _FakeRequest(
            post_routes={
                "https://t.example/graphql": [_Resp(200, "<html>not graphql</html>")],
            }
        )
        findings = await _detector().scan(_ctx(fake), "https://t.example", "GET", "https://t.example", {})
        assert findings == []


@pytest.mark.asyncio
class TestHiddenPaths:
    async def test_json_hidden_endpoint_flagged(self):
        fake = _FakeRequest(
            get_routes={
                "https://t.example/api/v2": _Resp(200, json.dumps({"service": "v2"})),
            }
        )
        findings = await _detector().scan(_ctx(fake), "https://t.example", "GET", "https://t.example", {})
        f = findings[0]
        assert f.payload.startswith("Shadow/hidden API endpoint accessible")
        assert f.metadata["hidden_path"] == "/api/v2"
        assert f.metadata["is_json"] is True
        assert f.severity == Severity.LOW
        assert f.confidence == 0.75

    async def test_html_hidden_endpoint_not_flagged(self):
        fake = _FakeRequest(
            get_routes={
                "https://t.example/api/v2": _Resp(200, "<html>login</html>", {"Content-Type": "text/html"}),
            }
        )
        findings = await _detector().scan(_ctx(fake), "https://t.example", "GET", "https://t.example", {})
        assert findings == []

    async def test_json_content_type_without_json_body_still_flagged(self):
        fake = _FakeRequest(
            get_routes={
                "https://t.example/v2": _Resp(200, "not really json", {"Content-Type": "application/json"}),
            }
        )
        findings = await _detector().scan(_ctx(fake), "https://t.example", "GET", "https://t.example", {})
        assert len(findings) == 1
        assert findings[0].metadata["is_json"] is False


class TestBaseUrl:
    def test_strips_path_and_query(self):
        assert APIDetector._base_url("https://t.example/app/page?q=1") == "https://t.example"

    def test_plain_host(self):
        assert APIDetector._base_url("http://localhost:5000") == "http://localhost:5000"
