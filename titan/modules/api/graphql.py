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

        introspection_query = {
            "query": "query IntrospectionQuery { __schema { types { name } } }",
            "operationName": "IntrospectionQuery"
        }

        try:
            resp = await context.request.post(
                api_url,
                data=json.dumps(introspection_query),
                headers={"Content-Type": "application/json", "Referer": target},
                timeout=10000,
            )
            body = await resp.text()
            if "__schema" in body:
                findings.append(Finding(
                    target=target,
                    url=api_url,
                    method="POST",
                    param="query",
                    location="body",
                    payload="GraphQL Introspection Query",
                    attack_type=AttackType.INFO_LEAK,
                    severity=Severity.MEDIUM,
                    verified=True,
                    confidence=0.95,
                    status=resp.status,
                    headers=dict(resp.headers),
                    body=body[:2000],
                    diffs=["graphql:introspection_enabled"],
                ))
        except Exception:
            pass

        base_payloads = [
            '{"query": "{ __schema { types { name } } }"}',
            '{"query": "{ __type(name: \"User\") { name fields { name type { name } } } }"}',
            '{"query": "query { user(id: \\"1\\") { id email password } }"}',
            '{"query": "mutation { createUser(input: {name: \\"test\\", email: \\"test@test.com\\"}) { user { id } } }"}',
        ]

        context_data = {
            "fingerprint": self.fingerprint,
            "attack_type": "graphql",
            "param_type": "json",
            "location": "body",
        }
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
                        confidence=0.7 if diffs else 0.4,
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body[:2000],
                        diffs=diffs,
                    ))
            except Exception:
                continue

        return findings
