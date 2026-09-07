"""HS256 JWT helpers for Supabase JWT manipulation testing.

Generates unsigned-forged JWTs (valid header/payload structure with an
HMAC signature over a guessable secret) used to probe how a Supabase
instance treats role claims, expiry, and arbitrary claims.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any


def _sign(secret: str, claims: dict[str, Any]) -> str:
    """Build and sign an HS256 JWT from raw claims."""
    header = json.dumps({"alg": "HS256", "typ": "JWT"})
    header_b64 = base64.urlsafe_b64encode(header.encode()).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def jwt_with_role(secret: str, role: str) -> str:
    """Generate a JWT with a specified role claim."""
    return _sign(secret, {
        "role": role,
        "aud": "authenticated",
        "exp": 9999999999,
        "sub": "fake-user-id",
        "email": "fake@evil.com",
        "app_metadata": {"provider": "email", "providers": ["email"]},
        "user_metadata": {"role": role},
    })


def expired_jwt(secret: str) -> str:
    """Generate a long-expired JWT."""
    return _sign(secret, {
        "role": "authenticated",
        "aud": "authenticated",
        "exp": 1000000000,  # Long expired
        "sub": "fake-user-id",
    })


def jwt_with_claims(secret: str, claims: dict[str, Any]) -> str:
    """Generate a JWT with arbitrary claims merged into the payload."""
    return _sign(secret, {
        "role": "authenticated",
        "aud": "authenticated",
        "exp": 9999999999,
        **claims,
    })
