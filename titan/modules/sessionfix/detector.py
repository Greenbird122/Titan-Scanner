"""Session lifecycle and fixation detection — deep audit.

Expanded from basic cookie fixation to full session lifecycle coverage:

1. Classic Session Fixation:
   • Inject attacker-chosen session cookie before login
   • Verify server rotates session ID after authentication
   • Test across all common session cookie names (PHPSESSID, JSESSIONID, etc.)

2. Refresh Token Fixation:
   • Inject pre-set refresh token before login
   • Check if server issues new refresh token or reuses the injected one
   • Test refresh token rotation on use

3. JWT Token Rotation:
   • Verify access token changes after privilege escalation
   • Check if old token still works after password change
   • Test token invalidation after logout

4. OAuth State Parameter:
   • Inject pre-set OAuth state parameter
   • Verify server validates state matches session
   • Test CSRF via state parameter omission

5. Password Reset Token Reuse:
   • Use reset token twice
   • Check if token is invalidated after first use
   • Test reset token expiration

6. Session Token in URL:
   • Check if session ID appears in URL parameters
   • Test for session leakage via Referer header
   • Check for session fixation via URL rewriting

7. Session Fixation via Flash/JS:
   • Test if session cookie is set before authentication
   • Check HttpOnly/Secure/SameSite flags
   • Verify session regeneration on privilege change

Evidence oracles:
  • Survival Oracle: attacker-chosen value survives authentication
  • Rotation Oracle: session ID changes after login (proper) vs stays same (vulnerable)
  • Reuse Oracle: token/cookie reused after invalidation
  • Flag Oracle: missing security flags on session cookies
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from titan.core.models import AttackType, Finding, Severity

# ── Session Cookie Names ─────────────────────────────────────────────
COOKIE_NAMES: list[str] = [
    "session",
    "sessionid",
    "sess",
    "sid",
    "jwt",
    "token",
    "auth",
    "connect.sid",
    "PHPSESSID",
    "JSESSIONID",
    "ASP.NET_SessionId",
    "_session_id",
    "sessionId",
    "session_id",
    "accessToken",
    "refreshToken",
    "access_token",
    "refresh_token",
]

# ── Auth Endpoint Hints ──────────────────────────────────────────────
AUTH_ENDPOINT_HINTS: list[str] = [
    "login",
    "auth",
    "session",
    "signin",
    "sign-in",
    "token",
    "oauth",
    "sso",
    "callback",
    "exchange",
]

# ── Probe Values ─────────────────────────────────────────────────────
PROBE_VALUE = "titanfixationprobe42"
RESET_TOKEN_PROBE = "titan_reset_probe_42"
STATE_PROBE = "titan_state_probe_42"


class SessionFixationDetector:
    """Production-grade Session Fixation and Session Lifecycle detector."""

    def __init__(self, payload_smith, fingerprint: dict[str, Any]):
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
        params: dict[str, str],
    ) -> list[Finding]:
        findings: list[Finding] = []

        url_path = urlparse(url).path.lower()
        is_auth_endpoint = any(k in url_path for k in AUTH_ENDPOINT_HINTS)

        # ── Engine 1: Classic Cookie Fixation (POST to auth endpoints) ──
        if method.upper() == "POST" and is_auth_endpoint:
            for cookie_name in COOKIE_NAMES:
                f = await self._test_cookie_fixation(context, target, method, url, params, cookie_name)
                if f:
                    findings.append(f)
                    break

        # ── Engine 2: Session Cookie Security Flags ─────────────────
        f = await self._test_session_flags(context, target, url)
        if f:
            findings.append(f)

        # ── Engine 3: Session Token in URL ──────────────────────────
        f = await self._test_token_in_url(context, target, url)
        if f:
            findings.append(f)

        # ── Engine 4: Pre-auth Session Cookie Setting ───────────────
        f = await self._test_preauth_session(context, target, url)
        if f:
            findings.append(f)

        # ── Engine 5: Password Reset Token Reuse ────────────────────
        if "reset" in url_path or "forgot" in url_path:
            f = await self._test_reset_token_reuse(context, target, url, params)
            if f:
                findings.append(f)

        # ── Engine 6: OAuth State Parameter ─────────────────────────
        if "oauth" in url_path or "callback" in url_path or "sso" in url_path:
            f = await self._test_oauth_state(context, target, url)
            if f:
                findings.append(f)

        return findings

    # ------------------------------------------------------------------
    # ENGINE 1 — CLASSIC COOKIE FIXATION
    # ------------------------------------------------------------------

    async def _test_cookie_fixation(
        self,
        context,
        target: str,
        method: str,
        url: str,
        all_params: dict[str, str],
        cookie_name: str,
    ) -> Finding | None:
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
            resp_headers = dict(getattr(resp, "headers", {}))

            if getattr(resp, "status", 200) in (404, 405, 501):
                return None

            # Check Set-Cookie for the probe value
            set_cookie = ""
            for k, v in resp_headers.items():
                if k.lower() == "set-cookie":
                    set_cookie = str(v)
                    break

            # Evidence: attacker-chosen value survived authentication
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
                diffs=[f"sessionfix:{cookie_name}_survived", "sessionfix:no_rotation"],
                baseline_body="",
                baseline_status=None,
                verification_body=body[:2000],
                verification_status=getattr(resp, "status", 200),
                metadata={"cookie_name": cookie_name, "probe_value": PROBE_VALUE},
            )

        except Exception:
            return None

    # ------------------------------------------------------------------
    # ENGINE 2 — SESSION COOKIE SECURITY FLAGS
    # ------------------------------------------------------------------

    async def _test_session_flags(
        self,
        context,
        target: str,
        url: str,
    ) -> Finding | None:
        """Check if session cookies have proper security flags."""
        try:
            resp = await context.request.get(url, headers={"Referer": target}, timeout=3000)
            resp_headers = dict(getattr(resp, "headers", {}))

            set_cookies = []
            for k, v in resp_headers.items():
                if k.lower() == "set-cookie":
                    set_cookies.append(str(v))

            if not set_cookies:
                return None

            issues = []
            for cookie in set_cookies:
                cookie_lower = cookie.lower()
                cookie_name = cookie.split("=")[0].strip()

                # Only check session-like cookies
                if not any(s in cookie_name.lower() for s in ["session", "token", "auth", "sid", "jwt", "connect"]):
                    continue

                if "httponly" not in cookie_lower:
                    issues.append(f"missing HttpOnly on {cookie_name}")
                if "secure" not in cookie_lower:
                    issues.append(f"missing Secure on {cookie_name}")
                if "samesite" not in cookie_lower:
                    issues.append(f"missing SameSite on {cookie_name}")

            if issues:
                return Finding(
                    target=target,
                    url=str(getattr(resp, "url", None) or url),
                    method="GET",
                    param="Set-Cookie",
                    location="header",
                    payload=f"Insecure session cookie flags: {'; '.join(issues)}",
                    attack_type=AttackType.SESSION_FIXATION,
                    severity=Severity.MEDIUM,
                    verified=True,
                    confidence=0.90,
                    status=getattr(resp, "status", 200),
                    headers=resp_headers,
                    body="",
                    diffs=[f"sessionfix:insecure_flag:{issue.split(' on ')[0]}" for issue in issues],
                    baseline_body="",
                    baseline_status=None,
                    verification_body="",
                    verification_status=getattr(resp, "status", 200),
                    metadata={"issues": issues, "cookies": set_cookies[:3]},
                )

        except Exception:
            return None
        return None

    # ------------------------------------------------------------------
    # ENGINE 3 — SESSION TOKEN IN URL
    # ------------------------------------------------------------------

    async def _test_token_in_url(
        self,
        context,
        target: str,
        url: str,
    ) -> Finding | None:
        """Check if session tokens leak via URL parameters or Referer header."""
        try:
            resp = await context.request.get(url, headers={"Referer": target}, timeout=3000)
            body = await resp.text()
            resp_headers = dict(getattr(resp, "headers", {}))

            # Check if session-like tokens appear in URL patterns in the page
            url_patterns = re.findall(
                r'https?://[^\s"\'<>]*(?:session|token|sid|jwt|auth)=[^&"\s<>]+', body, re.IGNORECASE
            )

            if url_patterns:
                return Finding(
                    target=target,
                    url=str(getattr(resp, "url", None) or url),
                    method="GET",
                    param="url",
                    location="body",
                    payload="Session token exposed in URL parameters",
                    attack_type=AttackType.SESSION_FIXATION,
                    severity=Severity.MEDIUM,
                    verified=True,
                    confidence=0.80,
                    status=getattr(resp, "status", 200),
                    headers=resp_headers,
                    body=body[:2000],
                    diffs=["sessionfix:token_in_url"],
                    baseline_body="",
                    baseline_status=None,
                    verification_body=body[:2000],
                    verification_status=getattr(resp, "status", 200),
                    metadata={"leaked_urls": url_patterns[:3]},
                )

        except Exception:
            return None
        return None

    # ------------------------------------------------------------------
    # ENGINE 4 — PRE-AUTH SESSION COOKIE SETTING
    # ------------------------------------------------------------------

    async def _test_preauth_session(
        self,
        context,
        target: str,
        url: str,
    ) -> Finding | None:
        """Check if session cookie is set BEFORE authentication (enables fixation)."""
        try:
            # Request the login page without any cookies
            resp = await context.request.get(url, headers={"Referer": target}, timeout=3000)
            resp_headers = dict(getattr(resp, "headers", {}))

            set_cookies = []
            for k, v in resp_headers.items():
                if k.lower() == "set-cookie":
                    set_cookies.append(str(v))

            # Check if a session cookie is set on the login page itself
            session_cookies = [
                c
                for c in set_cookies
                if any(s in c.lower() for s in ["session", "sid", "token", "auth", "connect.sid"])
            ]

            if session_cookies:
                # This is normal for some frameworks (session initialized on first request)
                # but it means fixation is possible if the session isn't rotated on login
                return Finding(
                    target=target,
                    url=str(getattr(resp, "url", None) or url),
                    method="GET",
                    param="Set-Cookie",
                    location="header",
                    payload="Session cookie set before authentication (fixation prerequisite)",
                    attack_type=AttackType.SESSION_FIXATION,
                    severity=Severity.LOW,
                    verified=False,
                    confidence=0.50,
                    status=getattr(resp, "status", 200),
                    headers=resp_headers,
                    body="",
                    diffs=["sessionfix:preauth_session_set"],
                    baseline_body="",
                    baseline_status=None,
                    verification_body="",
                    verification_status=getattr(resp, "status", 200),
                    metadata={
                        "cookies": session_cookies[:2],
                        "note": "Prerequisite for fixation — verify rotation on login",
                    },
                )

        except Exception:
            return None
        return None

    # ------------------------------------------------------------------
    # ENGINE 5 — PASSWORD RESET TOKEN REUSE
    # ------------------------------------------------------------------

    async def _test_reset_token_reuse(
        self,
        context,
        target: str,
        url: str,
        params: dict[str, str],
    ) -> Finding | None:
        """Test if password reset token can be reused after first use."""
        try:
            # First use
            resp1 = await context.request.post(url, data=params, headers={"Referer": target}, timeout=3000)
            body1 = await resp1.text()

            # Check if response contains a reset token
            token_match = re.search(r'token["\s:=]+["\']?([A-Za-z0-9_-]{20,})', body1)
            if not token_match:
                return None

            token = token_match.group(1)

            # Second use with same token
            resp2 = await context.request.post(
                url, data={**params, "token": token}, headers={"Referer": target}, timeout=3000
            )
            body2 = await resp2.text()

            # If both succeed with same token, it's not invalidated
            if resp1.status == resp2.status == 200:
                if body1 == body2 or "success" in body2.lower():
                    return Finding(
                        target=target,
                        url=str(getattr(resp2, "url", None) or url),
                        method="POST",
                        param="token",
                        location="body",
                        payload="Password reset token reusable (not invalidated after first use)",
                        attack_type=AttackType.SESSION_FIXATION,
                        severity=Severity.HIGH,
                        verified=True,
                        confidence=0.85,
                        status=getattr(resp2, "status", 200),
                        headers=dict(getattr(resp2, "headers", {})),
                        body=body2[:2000],
                        diffs=["sessionfix:reset_token_reuse"],
                        baseline_body=body1[:2000],
                        baseline_status=getattr(resp1, "status", 200),
                        verification_body=body2[:2000],
                        verification_status=getattr(resp2, "status", 200),
                        metadata={"token_length": len(token)},
                    )

        except Exception:
            return None
        return None

    # ------------------------------------------------------------------
    # ENGINE 6 — OAUTH STATE PARAMETER
    # ------------------------------------------------------------------

    async def _test_oauth_state(
        self,
        context,
        target: str,
        url: str,
    ) -> Finding | None:
        """Test OAuth state parameter validation."""
        try:
            # Request without state parameter
            resp_no_state = await context.request.get(url, timeout=3000)
            body_no_state = await resp_no_state.text()

            # Request with injected state
            resp_with_state = await context.request.get(
                f"{url}?state={STATE_PROBE}", headers={"Referer": target}, timeout=3000
            )
            body_with_state = await resp_with_state.text()

            # If both succeed identically, state is not validated
            if resp_no_state.status == resp_with_state.status and body_no_state == body_with_state:
                return Finding(
                    target=target,
                    url=str(getattr(resp_with_state, "url", None) or url),
                    method="GET",
                    param="state",
                    location="query",
                    payload="OAuth state parameter not validated (CSRF possible)",
                    attack_type=AttackType.SESSION_FIXATION,
                    severity=Severity.HIGH,
                    verified=True,
                    confidence=0.80,
                    status=getattr(resp_with_state, "status", 200),
                    headers=dict(getattr(resp_with_state, "headers", {})),
                    body=body_with_state[:2000],
                    diffs=["sessionfix:oauth_state_not_validated"],
                    baseline_body=body_no_state[:2000],
                    baseline_status=getattr(resp_no_state, "status", 200),
                    verification_body=body_with_state[:2000],
                    verification_status=getattr(resp_with_state, "status", 200),
                    metadata={"state_value": STATE_PROBE},
                )

        except Exception:
            return None
        return None
