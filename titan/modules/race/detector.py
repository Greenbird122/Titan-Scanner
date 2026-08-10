"""Race condition detection module for Titan Scanner."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer


class RaceDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        # Race conditions are about concurrent *state mutations*. Concurrent
        # reads (GET) are harmless and a changed response to a different id is
        # normal lookup behaviour, not a TOCTOU race. Only state-changing
        # methods can exhibit a real race.
        if method not in ("POST", "PUT", "PATCH", "DELETE"):
            return findings

        race_params = [p for p in params if any(k in p.lower() for k in ["id", "user", "account", "order", "invoice", "transaction", "payment", "cart", "stock", "quantity", "balance", "token", "code", "referral", "promo", "voucher"])]
        if not race_params:
            return findings

        for param_name in race_params[:2]:
            finding = await self._test_race(context, target, method, url, param_name, params)
            if finding:
                findings.append(finding)
                break

        return findings

    @staticmethod
    def _is_counter_divergence(bodies: List[str]) -> bool:
        """True when the divergent bodies differ ONLY in embedded digit runs —
        the monotonic-counter shape of a TOCTOU double-spend. Random noise
        (alphanumeric CSRF tokens, different error pages) differs in text too,
        so it fails the digit-only test."""
        import re
        stripped = {re.sub(r"\d+", "", b) for b in bodies}
        return len(stripped) == 1

    async def _test_race(self, context, target, method, url, param_name, all_params) -> Optional[Finding]:
        try:
            async def make_request():
                p = dict(all_params)
                try:
                    if method == "GET":
                        r = await context.request.get(url, params=p, headers={"Referer": target}, timeout=3000)
                    else:
                        r = await context.request.post(url, data=p, headers={"Referer": target}, timeout=3000)
                    return await r.text(), r.status, dict(r.headers)
                except Exception:
                    return "", 0, {}

            # Serial baseline: one request.
            baseline_body, baseline_status, _ = await make_request()

            # Concurrency: K *identical* requests. A TOCTOU race means the same
            # request mutates shared state, so identical concurrent requests
            # produce *inconsistent* responses (e.g. a double redemption where
            # only the first succeeds, or both succeed).
            tasks = [make_request() for _ in range(5)]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            race_bodies = []
            race_statuses = []
            for res in results:
                if isinstance(res, tuple) and res[1] == 200:
                    race_bodies.append(res[0])
                    race_statuses.append(res[1])

            if len(race_bodies) < 3:
                return None

            # Race signal: the concurrent *identical* requests disagreed with
            # each other.  A normal endpoint returns the same body for the same
            # request; divergence among identical concurrent requests is the
            # inconsistent-state signature.
            unique_bodies = set(race_bodies)
            if len(unique_bodies) <= 1:
                return None

            # Divergence is only a race when it is a *counter*: identical
            # requests mutate shared state into a monotonic sequence ('use 1',
            # 'use 2', 'use 3'). Real endpoints diverge for NORMAL reasons
            # (alphanumeric CSRF tokens, redirect targets, session nonces,
            # error pages) — text differences, not digit-only differences.
            # Without this gate, hellboundhackers produced 15 'Race Condition'
            # FPs on its login/register/logout endpoints.
            if not self._is_counter_divergence(list(unique_bodies)):
                return None

            diffs = []
            for body in race_bodies:
                diffs.extend(BaselineAnalyzer.diff_responses(baseline_body, body, ""))

            return Finding(
                target=target,
                url=url,
                method=method.upper(),
                param=param_name,
                location="query" if method == "GET" else "body",
                payload=f"Race: {len(race_bodies)} identical concurrent requests diverged",
                attack_type=AttackType.RACE_CONDITION,
                severity=Severity.HIGH,
                verified=True,
                confidence=0.6,
                status=race_statuses[0] if race_statuses else 0,
                headers={},
                body=race_bodies[0][:2000],
                diffs=["race:concurrent_divergence"] + diffs,
                baseline_body=baseline_body[:2000],
                baseline_status=baseline_status,
                verification_body=race_bodies[0][:2000],
                verification_status=race_statuses[0] if race_statuses else 0,
            )
        except Exception:
            pass
        return None
