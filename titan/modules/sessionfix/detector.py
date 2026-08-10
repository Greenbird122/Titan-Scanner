"""Session fixation detection module.

An attacker-chosen session id is sent on a login request. If the app keeps
using the attacker's id after authentication (same value in the response
Set-Cookie / body / subsequent request), the session is fixable — an attacker
can pre-set the victim's session before they log in.

The oracle requires the ATTACKER-CHOSEN value to survive authentication:
if the app issues a fresh random id, nothing was fixed. Login endpoints that
are not found (404/405) or return no session evidence degrade to no finding.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType

# A value unlikely to appear by chance, so presence-after-login is proof.
PROBE_VALUE = "titanfixationprobe42"
COOKIE_NAMES = ["session", "sessionid", "sess", "sid", "jwt", "token", "auth", "connect.sid"]


class SessionFixationDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        # Only login-ish POST endpoints can fix a session.
        if method.upper() != "POST":
            return []
        if not any(k in url.lower() for k in ["login", "auth", "session", "signin", "token"]):
            return []

        findings: List[Finding] = []
        for cookie_name in COOKIE_NAMES:
            finding = await self._test_fixation(context, target, method, url, params, cookie_name)
            if finding:
                findings.append(finding)
                break
        return findings

    async def _test_fixation(self, context, target, method, url, all_params, cookie_name) -> Optional[Finding]:
        try:
            resp = await context.request.post(
                url, data=all_params,
                headers={"Referer": target, "Cookie": f"{cookie_name}={PROBE_VALUE}"},
                timeout=3000,
            )
            body = await resp.text()
            set_cookie = resp.headers.get("set-cookie", "") or resp.headers.get("Set-Cookie", "")

            if resp.status in (404, 405, 501):
                return None

            # Evidence: the attacker-chosen value survives authentication —
            # in the Set-Cookie response header or echoed in the body.
            survived = PROBE_VALUE in set_cookie or PROBE_VALUE in body

            # A Set-Cookie that OVERWRITES with a fresh value is the secure
            # behavior — never a finding.
            if not survived:
                return None

            return Finding(
                target=target,
                url=str(resp.url or url),
                method=method.upper(),
                param=cookie_name,
                location="cookie",
                payload=f"Session fixation: attacker-chosen {cookie_name} survives login",
                attack_type=AttackType.SESSION_FIXATION,
                severity=Severity.HIGH,
                verified=True,
                confidence=0.85,
                status=resp.status,
                headers=dict(resp.headers),
                body=body[:2000],
                diffs=[f"sessionfix:{cookie_name}_survived"],
                baseline_status=None,
                verification_body=body[:2000],
                verification_status=resp.status,
                metadata={"cookie_name": cookie_name, "probe_value": PROBE_VALUE},
            )
        except Exception:
            return None
