"""Tests for titan.modules.api.graphql.GraphQLScanner engines.

Covers introspection (Engine 1), depth abuse (Engine 5), and mutation
abuse (Engine 6), including the rules that a 400 "depth limit exceeded"
reply is a working defense — NOT a finding — and that an accepted
mutation proves acceptance, not real-world effect.
"""

from __future__ import annotations

import json

from titan.core.models import Severity
from titan.modules.api.graphql import GraphQLScanner


class _FakeResponse:
    def __init__(self, status: int, body: str):
        self.status = status
        self._body = body
        self.headers = {"content-type": "application/json"}

    async def text(self) -> str:
        return self._body


class _FakeRequest:
    """Routes POSTs to a handler based on the query content."""

    def __init__(self, responder):
        self._responder = responder
        self.queries: list[str] = []

    async def post(self, url, data=None, headers=None, timeout=None):
        payload = json.loads(data)
        query = payload.get("query", "")
        self.queries.append(query)
        status, body = self._responder(query)
        return _FakeResponse(status, body)


class _FakeContext:
    def __init__(self, responder):
        self.request = _FakeRequest(responder)


def _introspection_responder(query: str):
    if "__schema" in query:
        return 200, json.dumps({"data": {"__schema": {"types": []}}})
    return 200, json.dumps({"errors": [{"message": "not found"}]})


async def test_introspection_enabled_produces_finding():
    ctx = _FakeContext(_introspection_responder)
    scanner = GraphQLScanner(payload_smith=None, fingerprint={})
    findings = await scanner.scan(ctx, "http://t", "http://t/gql")
    intro = [f for f in findings if f.diffs == ["graphql:introspection_enabled"]]
    assert intro, "introspection-enabled target must yield a finding"
    assert intro[0].status == 200


def _depth_responder(query: str):
    if "friends{friends" in query:
        # depth_20 passes the (bad) guard and returns nested data
        if query.count("friends{") >= 19:
            return 200, json.dumps({"data": {"user": {"name": "x"}}})
        # depth_10 is rejected by a depth guard
        return 400, json.dumps({"errors": [{"message": "query depth limit exceeded"}]})
    return 404, json.dumps({"errors": [{"message": "not found"}]})


async def test_depth_attack_processing_yields_finding():
    ctx = _FakeContext(_depth_responder)
    scanner = GraphQLScanner(payload_smith=None, fingerprint={})
    findings = await scanner.scan(ctx, "http://t", "http://t/gql")
    depth = [f for f in findings if "depth" in (f.diffs or [""])[0]]
    assert any("depth_20" in d for f in depth for d in f.diffs), (
        "server that PROCESSES a depth-20 query must be flagged"
    )


async def test_depth_guard_rejection_is_not_a_finding():
    ctx = _FakeContext(_depth_responder)
    scanner = GraphQLScanner(payload_smith=None, fingerprint={})
    findings = await scanner.scan(ctx, "http://t", "http://t/gql")
    depth = [f for f in findings if "depth" in (f.diffs or [""])[0]]
    assert not any("depth_10" in d for f in depth for d in f.diffs), (
        "a 400 depth-limit reply means the server defended itself — no finding"
    )


async def test_depth_crash_flags_5xx():
    def crash_responder(query: str):
        if "friends{friends" in query:
            return 500, "Internal Server Error"
        return 404, json.dumps({"errors": [{"message": "not found"}]})

    ctx = _FakeContext(crash_responder)
    scanner = GraphQLScanner(payload_smith=None, fingerprint={})
    findings = await scanner.scan(ctx, "http://t", "http://t/gql")
    depth = [f for f in findings if "depth" in (f.diffs or [""])[0]]
    assert any(f.status >= 500 for f in depth), "server crash under depth must be flagged"


def _mutation_responder(query: str):
    if query.startswith("mutation"):
        # Unauthenticated GraphQL gateway that blindly accepts mutations
        if "updateUser" in query:
            return 200, json.dumps({"data": {"updateUser": {"id": "1", "role": "admin"}}})
        if "createUser" in query:
            return 200, json.dumps({"data": {"createUser": {"id": "42"}}})
        return 200, json.dumps({"data": {"ok": True}})
    return 404, json.dumps({"errors": [{"message": "not found"}]})


async def test_accepted_mutation_yields_finding():
    ctx = _FakeContext(_mutation_responder)
    scanner = GraphQLScanner(payload_smith=None, fingerprint={})
    findings = await scanner.scan(ctx, "http://t", "http://t/gql")
    names = {d for f in findings for d in (f.diffs or [])}
    assert "graphql:role_escalation" in names, "accepted role-escalation mutation must be flagged"
    assert "graphql:user_creation" in names, "accepted user-creation mutation must be flagged"
    muts = [f for f in findings if f.diffs and f.diffs[0].startswith("graphql:")]
    assert all(f.severity == Severity.CRITICAL for f in muts)
