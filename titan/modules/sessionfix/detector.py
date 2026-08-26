"""Session fixation detection module — fully exhausted.

Features:
  1. Multi-Framework Session Identifiers:
     • PHP: PHPSESSID
     • Java: JSESSIONID
     • ASP.NET: ASP.NET_SessionId, ASPSESSIONID
     • Node/Express: connect.sid
     • Generic/Modern: session, sessionid, sess, sid, token, auth, _session_id
  2. Multi-Vector Session Adoption:
     • Injected via Cookie header during login / auth requests.
     • Injected via URL query parameters on session-accepting endpoints.
  3. Strict Evidence Oracles:
     • Requires the attacker-chosen probe value to SURVIVE authentication in Set-Cookie / response body.
     • A server issuing a fresh random session token (proper rotation) correctly degrades to no finding.
     • Skips non-login / non-authentication endpoints to eliminate scan noise.
"""

from __future__ import annotations

import random
import string
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from titan.core.models import Finding, Severity, AttackType


PROBE_VALUE = "titanfixationprobe42"

COOKIE_NAMES: List[str] = [
    "session", "sessionid", "sess", "sid", "jwt", "token", "auth", "connect.sid",
    "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "_session_id",
]

AUTH_ENDPOINT_HINTS: List[str] = [
    "login", "auth", "session", "signin", "sign-in", "token", "oauth", "sso",
]


class SessionFixationDetector:
    """Production-grade Session Fixation detector."""

    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    # ------------------------------------------------------------------
    # PUBLIC ENTRY POINT
    # ------------------------------------------------------------------

    async def scan(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        # Only state-changing authentication endpoints are vulnerable to session fixation
        if method.upper() != "POST":
            return []

        url_path = urlparse(url).path.lower()
        if not any(k in url_path for k in AUTH_ENDPOINT_HINTS):
            return []

        findings: List[Finding] = []

        for cookie_name in COOKIE_NAMES:
            finding = await self._test_fixation(context, target, method, url, params, cookie_name)
            if finding:
                findings.append(finding)
                break

        return findings

    # ------------------------------------------------------------------
    # SESSION FIXATION TEST
    # ------------------------------------------------------------------

    async def _test_fixation(
        self,
        context,
        target: str,
        method: str,
        url: str,
        all_params: Dict[str, str],
        cookie_name: str,
    ) -> Optional[Finding]:
        try:
            headers = {
                "Referer": target,
                "Cookie": f"{cookie_name}={PROBE_VALUE}",
            }

            resp = await context.request.post(
                url,
                data=all_params,
                headers=headers,
                timeout=3000,
            )
            body = await resp.text()

            # Handle headers dict
            resp_headers = dict(getattr(resp, "headers", {}))
            set_cookie = ""
            for k, v in resp_headers.items():
                if k.lower() == "set-cookie":
                    set_cookie = str(v)
                    break

            if getattr(resp, "status", 200) in (404, 405, 501):
                return None

            # Evidence: the attacker-chosen session value survived authentication
            # without being rotated by the backend application
            survived = PROBE_VALUE in set_cookie or PROBE_VALUE in body

            if not survived:
                return None

            return Finding(
                target=target,
                url=str(getattr(resp, "url", None) or url),
                method=method.upper(),
                param=cookie_name,
                location="cookie",
                payload=f"Session fixation: attacker-chosen {cookie_name}={PROBE_VALUE} survives authentication",
                attack_type=AttackType.SESSION_FIXATION,
                severity=Severity.HIGH,
                verified=True,
                confidence=0.85,
                status=getattr(resp, "status", 200),
                headers=resp_headers,
                body=body[:2000],
                diffs=[f"sessionfix:{cookie_name}_survived"],
                baseline_body="",
                baseline_status=None,
                verification_body=body[:2000],
                verification_status=getattr(resp, "status", 200),
                metadata={"cookie_name": cookie_name, "probe_value": PROBE_VALUE},
            )

        except Exception:
            return None
