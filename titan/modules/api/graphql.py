"""GraphQL API scanner for Titan Scanner."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer


class GraphQLScanner:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, api_url: str) -> List[Finding]:
        findings: List[Finding] = []

        # ── Engine 1: Introspection ─────────────────────────────────────
        introspection_queries = [
            "query IntrospectionQuery { __schema { types { name } } }",
            "query { __type(name: \"Query\") { name fields { name type { name } } } }",
            "query { __type(name: \"Mutation\") { name fields { name type { name } } } }",
            "query { __type(name: \"Subscription\") { name fields { name type { name } } } }",
            "query { __schema { queryType { name } mutationType { name } subscriptionType { name } } }",
            "query { __schema { directives { name locations } } }",
            "query { __type(name: \"User\") { name fields { name type { name } args { name type { name } } } } }",
            "query { __type(name: \"Query\") { fields { name args { name type { name } } } } }",
            "query { __type(name: \"User\") { enumValues { name } } }",
            "query { __type(name: \"User\") { inputFields { name type { name } } } }",
            "query { __schema { types { name enumValues { name } } } }",
        ]

        for iq in introspection_queries:
            try:
                resp = await context.request.post(
                    api_url,
                    data=json.dumps({"query": iq}),
                    headers={"Content-Type": "application/json", "Referer": target},
                    timeout=10000,
                )
                body = await resp.text()
                if "__schema" in body or "__type" in body:
                    findings.append(Finding(
                        target=target,
                        url=api_url,
                        method="POST",
                        param="query",
                        location="body",
                        payload=f"GraphQL Introspection: {iq[:80]}",
                        attack_type=AttackType.INFO_LEAK,
                        severity=Severity.MEDIUM,
                        verified=True,
                        confidence=0.95,
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body[:2000],
                        diffs=["graphql:introspection_enabled"],
                    ))
                    break
            except Exception:
                continue

        # ── Engine 2: Field suggestion / enum exhaustion ────────────────
        field_probes = [
            '{"query": "{ user { id } }"}',
            '{"query": "{ user { email } }"}',
            '{"query": "{ user { password } }"}',
            '{"query": "{ user { role } }"}',
            '{"query": "{ users { id email } }"}',
            '{"query": "{ admin { id } }"}',
            '{"query": "{ secret { id } }"}',
            '{"query": "{ internal { id } }"}',
            '{"query": "{ debug { id } }"}',
            '{"query": "{ config { id } }"}',
            '{"query": "{ __schema { types { name fields { name } } } }"}',
        ]

        for probe in field_probes:
            try:
                test_data = json.loads(probe)
                resp = await context.request.post(
                    api_url,
                    data=json.dumps(test_data),
                    headers={"Content-Type": "application/json", "Referer": target},
                    timeout=10000,
                )
                body = await resp.text()

                baseline_body = ""
                baseline_status = None
                try:
                    baseline_resp = await context.request.post(
                        api_url,
                        data=json.dumps({"query": "{ __schema { types { name } } }"}),
                        headers={"Content-Type": "application/json", "Referer": target},
                        timeout=10000,
                    )
                    baseline_body = await baseline_resp.text()
                    baseline_status = baseline_resp.status
                except Exception:
                    pass

                diffs = BaselineAnalyzer.diff_responses(baseline_body, body, probe)

                if diffs or resp.status >= 500:
                    sev = Severity.MEDIUM if resp.status >= 500 else Severity.LOW
                    findings.append(Finding(
                        target=target,
                        url=api_url,
                        method="POST",
                        param="query",
                        location="body",
                        payload=probe[:200],
                        attack_type=AttackType.INFO_LEAK,
                        severity=sev,
                        verified=bool(diffs),
                        confidence=0.7 if diffs else 0.4,
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body[:2000],
                        diffs=diffs,
                    ))
            except Exception:
                continue

        # ── Engine 3: Batching / aliasing abuse ─────────────────────────
        batch_probes = [
            json.dumps([
                {"query": "{ user(id: \"1\") { id } }"},
                {"query": "{ user(id: \"2\") { id } }"},
                {"query": "{ user(id: \"3\") { id } }"},
            ]),
            json.dumps([
                {"query": "query A { user(id: \"1\") { id } }"},
                {"query": "query B { user(id: \"2\") { id } }"},
            ]),
            json.dumps([
                {"query": "{ user: user(id: \"1\") { id } }"},
                {"query": "{ user: user(id: \"2\") { id } }"},
            ]),
        ]

        for batch in batch_probes:
            try:
                resp = await context.request.post(
                    api_url,
                    data=batch,
                    headers={"Content-Type": "application/json", "Referer": target},
                    timeout=10000,
                )
                body = await resp.text()

                baseline_body = ""
                try:
                    baseline_resp = await context.request.post(
                        api_url,
                        data=json.dumps({"query": "{ __schema { types { name } } }"}),
                        headers={"Content-Type": "application/json", "Referer": target},
                        timeout=10000,
                    )
                    baseline_body = await baseline_resp.text()
                except Exception:
                    pass

                diffs = BaselineAnalyzer.diff_responses(baseline_body, body, batch)
                if diffs or resp.status >= 500:
                    findings.append(Finding(
                        target=target,
                        url=api_url,
                        method="POST",
                        param="query",
                        location="body",
                        payload=f"GraphQL batch/alias probe ({len(json.loads(batch))} ops)",
                        attack_type=AttackType.INFO_LEAK,
                        severity=Severity.MEDIUM if resp.status >= 500 else Severity.LOW,
                        verified=bool(diffs),
                        confidence=0.6 if diffs else 0.4,
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body[:2000],
                        diffs=diffs,
                    ))
            except Exception:
                continue

        # ── Engine 4: AI-mutated payloads ───────────────────────────────
        context_data = {
            "fingerprint": self.fingerprint,
            "attack_type": "graphql",
            "param_type": "json",
            "location": "body",
        }
        base_payloads = [
            '{"query": "{ __schema { types { name } } }"}',
            '{"query": "{ user { id email password } }"}',
            '{"query": "mutation { createUser(input: {name: \\"test\\"}) { user { id } } }"}',
        ]
        payloads = await self.payload_smith.mutate(base_payloads, context_data)

        for payload in payloads:
            try:
                test_data = json.loads(payload)
                resp = await context.request.post(
                    api_url,
                    data=json.dumps(test_data),
                    headers={"Content-Type": "application/json", "Referer": target},
                    timeout=10000,
                )
                body = await resp.text()

                baseline_body = ""
                try:
                    baseline_resp = await context.request.post(
                        api_url,
                        data=json.dumps({"query": "{ __schema { types { name } } }"}),
                        headers={"Content-Type": "application/json", "Referer": target},
                        timeout=10000,
                    )
                    baseline_body = await baseline_resp.text()
                except Exception:
                    pass

                diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)
                if diffs or resp.status >= 500:
                    findings.append(Finding(
                        target=target,
                        url=api_url,
                        method="POST",
                        param="query",
                        location="body",
                        payload=payload[:200],
                        attack_type=AttackType.INFO_LEAK,
                        severity=Severity.MEDIUM if resp.status >= 500 else Severity.LOW,
                        verified=bool(diffs),
                        confidence=0.6 if diffs else 0.4,
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body[:2000],
                        diffs=diffs,
                    ))
            except Exception:
                continue

        return findings
