"""SHARPEN-S2: pre-supplied credential auth.

Real-world targets authenticate via OAuth/SSO/Bearer flows that a form-filling
login cannot drive. The auth engine must accept an operator-supplied token,
API key, or cookie map directly and expose it through the same
get_auth_headers/get_cookies surface the scan + identity pool consume.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from titan.core.auth import AuthEngine


class TestPreSuppliedBearer:
    async def test_token_short_circuits_login(self):
        """A configured token must authenticate without any browser work."""
        engine = AuthEngine({"auth": {"token": "eyJhbGciOiJIUzI1NiJ9.abc"}})
        # Any context/page would blow up if touched — login must not touch them.
        ok = await engine.login(None, None, "https://example.com")
        assert ok is True
        assert engine.get_auth_headers() == {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.abc"}
        assert engine.is_authenticated()

    async def test_token_with_custom_scheme(self):
        engine = AuthEngine({"auth": {"token": "t-123", "token_type": "ApiKey"}})
        ok = await engine.login(None, None, "https://x.com")
        assert ok is True
        assert engine.get_auth_headers() == {"Authorization": "ApiKey t-123"}

    async def test_api_key_uses_x_api_key_header(self):
        engine = AuthEngine({"auth": {"api_key": "sk-secret"}})
        assert await engine.login(None, None, "https://x.com") is True
        assert engine.get_auth_headers() == {"X-API-Key": "sk-secret"}

    async def test_api_key_custom_header_name(self):
        engine = AuthEngine({"auth": {"api_key": "abc", "api_key_header": "X-Client-Key"}})
        assert await engine.login(None, None, "https://x.com") is True
        assert engine.get_auth_headers() == {"X-Client-Key": "abc"}

    async def test_cookie_map_identity(self):
        engine = AuthEngine({"auth": {"cookies": {"sessionid": "s3cr3t"}}})
        assert await engine.login(None, None, "https://x.com") is True
        assert engine.get_cookies() == {"sessionid": "s3cr3t"}

    async def test_cookie_map_json_string(self):
        engine = AuthEngine({"auth": {"cookies": '{"sid": "v1", "csrftoken": "t"}'}})
        assert await engine.login(None, None, "https://x.com") is True
        assert engine.get_cookies() == {"sid": "v1", "csrftoken": "t"}

    async def test_no_credentials_returns_false(self):
        engine = AuthEngine({})
        assert await engine.login(None, None, "https://x.com") is False
        assert engine.is_authenticated() is False
