"""Tests for stealth engine."""

import pytest
from titan.core.stealth import StealthEngine


class TestStealthEngine:
    def test_user_agent_selection(self):
        stealth = StealthEngine()
        ua = stealth.get_user_agent()
        assert isinstance(ua, str)
        assert len(ua) > 10

    def test_headers_generation(self):
        stealth = StealthEngine()
        headers = stealth.get_headers()
        assert "User-Agent" in headers
        assert "Accept" in headers
        assert "Referer" not in headers

    def test_headers_include_optional_fields(self):
        stealth = StealthEngine(jitter=1.0)
        headers = stealth.get_headers()
        assert isinstance(headers, dict)

    @pytest.mark.asyncio
    async def test_delay_completes(self):
        stealth = StealthEngine(jitter=0.1)
        await stealth.delay()
