"""BOLA (Broken Object Level Authorization) detection module.

The stateless IDOR module swaps an id and diffs the response within ONE
identity — it cannot distinguish \"I fetched another record I'm allowed to
see\" from \"I fetched another tenant's record\". BOLA is proven only by a
cross-identity differential:

    1. identity A (owner) requests  /records?id=1  -> A's unique record
    2. identity B (attacker) requests /records?id=1  -> if B receives A's
       unique content (markers present in A's record, absent from B's own),
       B read another tenant's data. Verified BOLA.

The oracle requires the response to A's id to contain OWNER-UNIQUE content —
a static page, a per-request token, or an unauthenticated endpoint cannot
self-verify (same content is visible to every identity).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify.identity_oracles import unique_owner_markers, markers_present

ID_PARAM_KEYWORDS = ["id", "user", "account", "profile", "order", "invoice", "document", "file", "uuid", "guid", "pk", "key", "number", "tenant", "org"]


class BOLADetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str], identities) -> List[Finding]:
        """``identities``: list of Identity objects (>= 2 for a meaningful test).

        Uses the first two authenticated identities as owner/attacker.
        """
        authed = [i for i in identities if i and i.is_authenticated]
        if len(authed) < 2:
            return []

        owner, attacker = authed[0], authed[1]
        findings: List[Finding] = []

        id_params = [
            p for p in params
            if any(k in p.lower() for k in ID_PARAM_KEYWORDS)
        ]
        if not id_params:
            return findings

        for param_name in id_params[:3]:
            finding = await self._test_bola(
                context, target, method, url, param_name, params,
                owner, attacker,
            )
            if finding:
                findings.append(finding)
                break
        return findings

    async def _test_bola(self, context, target, method, url, param_name, all_params,
                         owner, attacker) -> Optional[Finding]:
        try:
            # 1. Owner requests their own object -> the unique record.
            owner_resp = await self._request(context, owner, method, url, all_params)
            owner_body = await owner_resp.text()
            if owner_resp.status != 200 or len(owner_body) < 5:
                return None

            # 2. Attacker requests a DIFFERENT id -> their own record baseline.
            other_params = dict(all_params)
            original = str(all_params.get(param_name, "1"))
            other_id = str(int(original) + 1) if original.isdigit() else "2"
            other_params[param_name] = other_id
            own_resp = await self._request(context, attacker, method, url, other_params)
            own_body = await own_resp.text()

            # 3. Attacker requests the OWNER's id -> the cross-tenant request.
            cross_resp = await self._request(context, attacker, method, url, all_params)
            cross_body = await cross_resp.text()

            if cross_resp.status != 200 or len(cross_body) < 5:
                return None

            # The attacker's cross request must DIFFER from their own record
            # (otherwise the endpoint returns the same thing to everyone and
            # there is nothing to prove).
            if cross_body == own_body:
                return None

            ignored = [original, other_id, str(attacker.name), str(owner.name)]
            markers = unique_owner_markers(owner_body, own_body, ignored)
            if not markers:
                return None

            present = markers_present(cross_body, markers)
            if not present:
                return None

            return Finding(
                target=target,
                url=str(cross_resp.url or url),
                method=method.upper(),
                param=param_name,
                location="query" if method == "GET" else "body",
                payload=f"BOLA: {attacker.name} read {owner.name}'s record (id={original})",
                attack_type=AttackType.BOLA,
                severity=Severity.CRITICAL,
                verified=True,
                confidence=0.9,
                status=cross_resp.status,
                headers=dict(cross_resp.headers),
                body=cross_body[:2000],
                diffs=[f"bola:cross_identity_markers:{','.join(present[:3])}"] + [
                    f"bola:{param_name}:{owner.name}->{attacker.name}"
                ],
                baseline_body=own_body[:2000],
                baseline_status=own_resp.status,
                verification_body=cross_body[:2000],
                verification_status=cross_resp.status,
                metadata={
                    "identities": {"owner": owner.name, "attacker": attacker.name},
                    "markers": present[:5],
                },
                tags=[f"identity:{attacker.name}", f"owner:{owner.name}"],
            )
        except Exception:
            return None

    async def _request(self, context, identity, method, url, params):
        headers = dict(identity.headers)
        headers.setdefault("Referer", "http://localhost")
        if method == "GET":
            return await context.request.get(url, params=params, headers=headers, timeout=3000)
        return await context.request.post(url, data=params, headers=headers, timeout=3000)
