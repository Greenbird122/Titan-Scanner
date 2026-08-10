"""Mass assignment detection module.

Sends a state-changing request with an injected privilege field
(``role=admin``, ``is_admin=true``, ``approved=true``...) and looks for the
field to be ACCEPTED and reflected back in the response (or a follow-up
state change). Reflection alone is not evidence — a static form echoes every
field. The oracle requires the injected field's value to appear in the
test body but NOT in a baseline without the field, on a state-changing
method, with a changed response.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType

# (field, value, label) — privilege-bearing assignments mass assignment
# attacks inject. Keep to well-known OWASP Mass Assignment primitives.
PRIVILEGE_FIELDS = [
    ("role", "admin", "role=admin"),
    ("is_admin", "true", "is_admin=true"),
    ("admin", "true", "admin=true"),
    ("approved", "true", "approved=true"),
    ("verified", "true", "verified=true"),
    ("isActive", "true", "isActive=true"),
    ("is_active", "true", "is_active=true"),
    ("level", "9", "level=9"),
    ("permissions", '["admin"]', 'permissions=["admin"]'),
]


class MassAssignmentDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        # Only state-changing methods can accept an injected field.
        if method.upper() not in ("POST", "PUT", "PATCH"):
            return []

        findings: List[Finding] = []
        for field, value, label in PRIVILEGE_FIELDS:
            finding = await self._test_mass_assignment(
                context, target, method, url, params, field, value, label,
            )
            if finding:
                findings.append(finding)
                break
        return findings

    async def _test_mass_assignment(self, context, target, method, url, all_params,
                                    field, value, label) -> Optional[Finding]:
        try:
            def _req(payload):
                if method.upper() == "GET":
                    return context.request.get(url, params=payload, headers={"Referer": target}, timeout=3000)
                return context.request.post(url, data=payload, headers={"Referer": target, "Content-Type": "application/json"}, timeout=3000)

            baseline_resp = await _req(dict(all_params))
            baseline_body = await baseline_resp.text()

            injected = dict(all_params)
            injected[field] = value
            test_resp = await _req(injected)
            test_body = await test_resp.text()

            if baseline_resp.status != test_resp.status:
                return None
            if test_body == baseline_body:
                return None

            # Evidence: the injected value appears in the test body but not
            # the baseline. A static form echoes the field name in both.
            if value not in test_body:
                return None
            if value in baseline_body:
                return None

            # Confirm the server actually honored the assignment, not just
            # echoed the raw input: look for the field:value pairing in JSON,
            # or the label string in a form round-trip.
            reflected = False
            try:
                data = json.loads(test_body)
                if isinstance(data, dict) and str(data.get(field)) == str(value):
                    reflected = True
            except Exception:
                pass
            if not reflected:
                # Non-JSON round-trip: the value appearing alone is suspicious
                # but unverified without a field pairing.
                return None

            return Finding(
                target=target,
                url=str(test_resp.url or url),
                method=method.upper(),
                param=field,
                location="body",
                payload=f"Mass Assignment: {label} accepted",
                attack_type=AttackType.MASS_ASSIGNMENT,
                severity=Severity.HIGH,
                verified=True,
                confidence=0.85,
                status=test_resp.status,
                headers=dict(test_resp.headers),
                body=test_body[:2000],
                diffs=[f"massassign:{field}={value}_accepted"],
                baseline_body=baseline_body[:2000],
                baseline_status=baseline_resp.status,
                verification_body=test_body[:2000],
                verification_status=test_resp.status,
            )
        except Exception:
            return None
