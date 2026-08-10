"""Crypto weakness detection module for Titan Scanner."""

from __future__ import annotations

import hashlib
import hmac
import base64
import re
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer


class CryptoDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        # Crypto checks are *body scans* (hardcoded credentials, JWT none-alg,
        # weak algorithm mentions) — they don't depend on any parameter. A
        # /config-style endpoint with creds in the body but no params must
        # still be scanned, so we always test at least one request.  When
        # crypto-named params exist we limit to those (focused), otherwise a
        # single anonymous body scan.
        crypto_params = [p for p in params if any(k in p.lower() for k in ["token", "key", "secret", "password", "hash", "signature", "jwt", "iv", "nonce", "salt", "encrypt", "decrypt", "cipher", "aes", "rsa", "md5", "sha1", "sha256"])]
        params_to_test = crypto_params[:3] if crypto_params else [None]

        for param_name in params_to_test:
            finding = await self._test_crypto_weakness(context, target, method, url, param_name, params)
            if finding:
                findings.append(finding)

        return findings

    async def _test_crypto_weakness(self, context, target, method, url, param_name, all_params) -> Optional[Finding]:
        try:
            if method == "GET":
                baseline_resp = await context.request.get(url, params=all_params, headers={"Referer": target}, timeout=3000)
            else:
                baseline_resp = await context.request.post(url, data=all_params, headers={"Referer": target}, timeout=3000)
            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status
        except Exception:
            return None

        # A body scan doesn't need a named parameter — label it "body".
        param_label = param_name or "body"
        body_lower = baseline_body.lower()

        weak_algorithms = {
            "md5": ["md5", "message-digest"],
            "sha1": ["sha1", "sha-1"],
            "des": ["des ", "des-", "tripledes"],
            "rc4": ["rc4"],
            "ecb": ["ecb", "electronic codebook"],
        }

        for algo, patterns in weak_algorithms.items():
            for pattern in patterns:
                if re.search(r'\b' + re.escape(pattern) + r'\b', body_lower):
                    return Finding(
                        target=target,
                        url=str(baseline_resp.url or url),
                        method=method.upper(),
                        param=param_label,
                        location="query" if method == "GET" else "body",
                        payload=f"Weak algorithm detected: {algo}",
                        attack_type=AttackType.CRYPTO_WEAKNESS,
                        severity=Severity.HIGH,
                        verified=True,
                        confidence=0.85,
                        status=baseline_status,
                        headers=dict(baseline_resp.headers),
                        body=baseline_body[:2000],
                        diffs=[f"crypto:weak_algorithm:{algo}"],
                        baseline_body=baseline_body[:2000],
                        baseline_status=baseline_status,
                        verification_body=baseline_body[:2000],
                        verification_status=baseline_status,
                    )

        # Raw hex digests: MD5 hashes are exactly 32 lowercase hex chars and
        # SHA-1 exactly 40. Many weak-crypto endpoints return the digest alone
        # (e.g. {"hash": "d41d8cd98f00b204e9800998ecf8427e"}) with no algorithm
        # name in the response, so word-based detection never fires. Require the
        # value to sit under a hash-named JSON key so random hex tokens (UUIDs,
        # colors, base16 ids) don't false-positive.
        digest_ctx = re.compile(
            r'"[a-z0-9_]*(?:hash|digest|checksum|md5|sha1|sha-?1|password)[a-z0-9_]*"\s*:\s*"([0-9a-f]{32}|[0-9a-f]{40})"'
        )
        digest_match = digest_ctx.search(baseline_body)
        if digest_match:
            digest = digest_match.group(1)
            algo = "sha1" if len(digest) == 40 else "md5"
            return Finding(
                target=target,
                url=str(baseline_resp.url or url),
                method=method.upper(),
                param=param_label,
                location="query" if method == "GET" else "body",
                payload=f"Weak hashing detected: {algo} hex digest {digest[:16]}...",
                attack_type=AttackType.CRYPTO_WEAKNESS,
                severity=Severity.HIGH,
                verified=True,
                confidence=0.85,
                status=baseline_status,
                headers=dict(baseline_resp.headers),
                body=baseline_body[:2000],
                diffs=[f"crypto:weak_hash:{algo}"],
                baseline_body=baseline_body[:2000],
                baseline_status=baseline_status,
                verification_body=baseline_body[:2000],
                verification_status=baseline_status,
            )

        # JWT none-algorithm: first passive (token already in the response),
        # then active (login endpoints that mint a token on POST).
        jwt_finding = self._find_jwt_none(
            target, url, baseline_resp, baseline_body, baseline_status, method, param_label
        )
        if jwt_finding:
            return jwt_finding

        # Active probe: form-style login endpoints (request.form based) return
        # a token only when credentials are posted as urlencoded form data —
        # Playwright's `data=` sends JSON, which many apps ignore. Try once
        # with real-looking creds and scan the response for an alg:none token.
        from urllib.parse import urlparse
        login_hint = urlparse(url).path.lower()
        if any(k in login_hint for k in ["login", "auth", "signin", "sign-in", "token", "jwt", "session"]):
            for creds in ({"username": "admin", "password": "admin"}, {"email": "admin@test.com", "password": "admin123"}):
                try:
                    login_resp = await context.request.post(
                        url, form=creds, headers={"Referer": target, "Content-Type": "application/x-www-form-urlencoded"}, timeout=5000
                    )
                    login_body = await login_resp.text()
                except Exception:
                    continue
                jwt_finding = self._find_jwt_none(
                    target, url, login_resp, login_body, login_resp.status, "POST", param_label
                )
                if jwt_finding:
                    return jwt_finding

        # JSON keys are quoted ("database_password"), so the key name must be
        # allowed to end with an optional closing quote before the colon.
        # Values may contain hyphens, slashes, +/= (AWS-style) and be shorter
        # than the old {16,}/{35,} requirements — real credentials in the wild
        # (and in test fixtures) come in many shapes.
        # Provider-specific signatures first: a Google key is ALSO an api_key,
        # so the generic pattern must never shadow the more precise verdict.
        hardcoded_patterns = [
            (r'AIza[0-9A-Za-z_\-]{12,}', "hardcoded_google_api_key"),
            (r'sk_live_[0-9a-zA-Z]{16,}', "hardcoded_stripe_key"),
            (r'(?i)["\']?(aws[_-]?secret[_-]?access[_-]?key|aws_secret)["\']?\s*[:=]\s*["\'][A-Za-z0-9/+=]{16,}["\']', "hardcoded_aws_key"),
            # AKIA/ASIA access-key IDs must sit in a credential assignment
            # (accessKeyId: "AKIA...", aws_access_key_id = "ASIA...", or the
            # unquoted .env/docker form AWS_ACCESS_KEY_ID=AKIA...). A bare
            # AKIA string anywhere in a shared JS bundle (docs examples, SDK
            # samples) used to fire on every page of a site (the HTB 249
            # storm) — context is what separates a leak from a mention.
            (r'(?i)["\']?(?:aws[_-]?)?(?:access[_-]?key[_-]?id|access[_-]?key|accesskey|secret[_-]?access[_-]?key|aws[_-]?key|key[_-]?id)["\']?\s*[:=]\s*["\']?(AKIA|ASIA)[0-9A-Z]{16}', "hardcoded_aws_access_key_id"),
            (r'(?i)(-----BEGIN (RSA )?PRIVATE KEY-----)', "hardcoded_private_key"),
            (r'(?i)(ghp_|github_pat_)[0-9A-Za-z_]{20,}', "hardcoded_github_token"),
            (r'(?i)["\']?(api[_-]?key|apikey|api_secret)["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{12,}["\']', "hardcoded_api_key"),
            (r'(?i)["\']?[a-z0-9_]*password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']', "hardcoded_password"),
            (r'(?i)["\']?[a-z0-9_]*(secret|passwd|pwd)["\']?\s*[:=]\s*["\'][^"\']{8,}["\']', "hardcoded_secret"),
            # Token keys are risky: session tokens, CSRF tokens and JWTs in
            # response bodies are normal, not hardcoded credentials. Only flag
            # credential-looking keys (access_token, api_token, secret_token,
            # auth_token) and never values shaped like a JWT (eyJ...).
            (r'(?i)["\']?(access[_-]?token|api[_-]?token|secret[_-]?token|auth[_-]?token|client[_-]?secret)["\']?\s*[:=]\s*["\'](?!eyJ)[A-Za-z0-9_\-]{12,}["\']', "hardcoded_token"),
        ]

        for pattern, indicator in hardcoded_patterns:
            matches = re.findall(pattern, baseline_body)
            if matches:
                return Finding(
                    target=target,
                    url=str(baseline_resp.url or url),
                    method=method.upper(),
                    param=param_label,
                    location="query" if method == "GET" else "body",
                    payload=f"Hardcoded credential: {indicator}",
                    attack_type=AttackType.CRYPTO_WEAKNESS,
                    severity=Severity.HIGH,
                    verified=True,
                    confidence=0.8,
                    status=baseline_status,
                    headers=dict(baseline_resp.headers),
                    body=baseline_body[:2000],
                    diffs=[f"crypto:{indicator}"],
                    baseline_body=baseline_body[:2000],
                    baseline_status=baseline_status,
                    verification_body=baseline_body[:2000],
                    verification_status=baseline_status,
                )

        # NOTE: missing-TLS-header checks (HSTS, X-Content-Type-Options) are
        # deliberately NOT reported here — they belong to the headers module and
        # would fire on every response without them, drowning real crypto
        # findings in noise.
        return None

    def _find_jwt_none(
        self, target, url, resp, body, status, method, param_label
    ) -> Optional[Finding]:
        # alg:none tokens are signed with an EMPTY signature
        # (header.payload. with nothing after the final dot), so the third
        # segment must be allowed to be empty — a {10,} requirement silently
        # misses the classic none-algorithm JWT.
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*')
        jwt_matches = jwt_pattern.findall(body)
        for jwt in jwt_matches:
            try:
                parts = jwt.split(".")
                if len(parts) == 3:
                    header = base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4))
                    header_data = header.decode("utf-8", errors="ignore")
                    if '"alg":"none"' in header_data or '"alg": "none"' in header_data:
                        return Finding(
                            target=target,
                            url=str(resp.url if hasattr(resp, "url") else url),
                            method=method.upper(),
                            param=param_label,
                            location="query" if method == "GET" else "body",
                            payload=f"JWT none algorithm: {jwt[:50]}...",
                            attack_type=AttackType.CRYPTO_WEAKNESS,
                            severity=Severity.CRITICAL,
                            verified=True,
                            confidence=0.95,
                            status=status,
                            headers=dict(resp.headers) if hasattr(resp, "headers") else {},
                            body=body[:2000],
                            diffs=["crypto:jwt_none_algorithm"],
                            baseline_body=body[:2000],
                            baseline_status=status,
                            verification_body=body[:2000],
                            verification_status=status,
                        )
            except Exception:
                continue
        return None
