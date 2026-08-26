"""Tests for the Titan Omega Transport Abstraction Layer.

Covers:
  - Base types: AttackRequest, AttackResponse, TargetDescriptor, RequestMethod
  - HttpTransport: send, session pooling, error handling, close
  - TransportRegistry: auto_register, get, get_for_protocol, protocol routing
  - Integration: transport fallback pattern (transport → context.request)
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from titan.transport.base import (
    AttackRequest,
    AttackResponse,
    RequestMethod,
    TargetDescriptor,
    Transport,
    TransportIdentity,
    TransportProtocol,
    TransportRegistry,
)


# ---------------------------------------------------------------------------
# Base type tests
# ---------------------------------------------------------------------------

class TestAttackRequest:
    def test_defaults(self):
        req = AttackRequest(url="https://example.com")
        assert req.method == RequestMethod.GET
        assert req.headers == {}
        assert req.body is None
        assert req.params == {}
        assert req.timeout == 30.0
        assert req.metadata == {}

    def test_is_onion(self):
        req = AttackRequest(url="http://xyz.onion/api")
        assert req.is_onion is True

    def test_not_onion(self):
        req = AttackRequest(url="https://example.com")
        assert req.is_onion is False

    def test_host_parsing(self):
        req = AttackRequest(url="https://example.com:8443/api/v1")
        assert req.host == "example.com"

    def test_path_parsing(self):
        req = AttackRequest(url="https://example.com/api/v1/users")
        assert req.path == "/api/v1/users"

    def test_path_default(self):
        req = AttackRequest(url="https://example.com")
        assert req.path == "/"


class TestAttackResponse:
    def test_ok_status(self):
        resp = AttackResponse(status=200)
        assert resp.ok is True

    def test_ok_range(self):
        resp = AttackResponse(status=301)
        assert resp.ok is True

    def test_not_ok(self):
        resp = AttackResponse(status=404)
        assert resp.ok is False

    def test_error_status(self):
        resp = AttackResponse(status=500)
        assert resp.ok is False

    def test_text_property(self):
        resp = AttackResponse(status=200, body=b"hello world")
        assert resp.text == "hello world"

    def test_text_empty(self):
        resp = AttackResponse(status=200, body=b"")
        assert resp.text == ""

    def test_json_property(self):
        resp = AttackResponse(status=200, body=b'{"key": "value"}')
        assert resp.json == {"key": "value"}

    def test_json_invalid(self):
        resp = AttackResponse(status=200, body=b"not json")
        assert resp.json is None

    def test_is_error(self):
        resp = AttackResponse(status=0, error="connection refused")
        assert resp.is_error is True

    def test_is_not_error(self):
        resp = AttackResponse(status=200)
        assert resp.is_error is False


class TestTargetDescriptor:
    def test_host_from_url(self):
        target = TargetDescriptor(url="https://example.com:8443/api")
        assert target.host == "example.com"
        assert target.port == 8443

    def test_default_port_https(self):
        target = TargetDescriptor(url="https://example.com")
        assert target.port == 443

    def test_default_port_http(self):
        target = TargetDescriptor(url="http://example.com")
        assert target.port == 80

    def test_explicit_host(self):
        target = TargetDescriptor(url="https://example.com", host="custom.host")
        assert target.host == "custom.host"


class TestTransportProtocol:
    def test_all_protocols(self):
        assert TransportProtocol.HTTP.value == "http"
        assert TransportProtocol.HTTPS.value == "https"
        assert TransportProtocol.ONION.value == "onion"
        assert TransportProtocol.GRPC.value == "grpc"
        assert TransportProtocol.WEBSOCKET.value == "websocket"
        assert TransportProtocol.MQTT.value == "mqtt"
        assert TransportProtocol.SSH.value == "ssh"


class TestRequestMethod:
    def test_all_methods(self):
        assert RequestMethod.GET.value == "GET"
        assert RequestMethod.POST.value == "POST"
        assert RequestMethod.PUT.value == "PUT"
        assert RequestMethod.DELETE.value == "DELETE"
        assert RequestMethod.PATCH.value == "PATCH"


# ---------------------------------------------------------------------------
# HttpTransport tests
# ---------------------------------------------------------------------------

class TestHttpTransport:
    @pytest.fixture
    def http(self):
        from titan.transport.http_transport import HttpTransport
        return HttpTransport(timeout=10.0)

    def test_supports_http(self, http):
        assert http.supports(TransportProtocol.HTTP) is True

    def test_supports_https(self, http):
        assert http.supports(TransportProtocol.HTTPS) is True

    def test_does_not_support_onion(self, http):
        assert http.supports(TransportProtocol.ONION) is False

    def test_identity(self, http):
        assert http.identity.protocol == "http"

    @pytest.mark.asyncio
    async def test_send_returns_error_on_invalid_url(self, http):
        """Sending to an invalid URL should return an error response, not crash."""
        resp = await http.send(AttackRequest(url="http://192.0.2.1:1", timeout=1.0))
        # Should return error response, not raise
        assert resp.status == 0
        assert resp.is_error is True
        assert resp.error is not None

    @pytest.mark.asyncio
    async def test_send_custom_timeout(self, http):
        """Per-request timeout should override the default."""
        resp = await http.send(AttackRequest(url="http://192.0.2.1:1", timeout=0.5))
        assert resp.is_error  # Connection will fail, but should not hang

    @pytest.mark.asyncio
    async def test_close(self, http):
        mock_session = AsyncMock()
        mock_session.closed = False
        http._session = mock_session

        await http.close()
        mock_session.close.assert_called_once()
        assert http._session is None

    @pytest.mark.asyncio
    async def test_close_already_closed(self, http):
        mock_session = AsyncMock()
        mock_session.closed = True
        http._session = mock_session

        await http.close()
        mock_session.close.assert_not_called()

    def test_custom_user_agent(self):
        from titan.transport.http_transport import HttpTransport
        http = HttpTransport(user_agent="CustomBot/1.0")
        assert http.user_agent == "CustomBot/1.0"

    def test_default_user_agent(self, http):
        assert "Mozilla" in http.user_agent


# ---------------------------------------------------------------------------
# TransportRegistry tests
# ---------------------------------------------------------------------------

class TestTransportRegistry:
    @pytest.fixture
    def registry(self):
        return TransportRegistry()

    def test_register_and_get(self, registry):
        mock_transport = MagicMock(spec=Transport)
        registry.register("http", mock_transport, [TransportProtocol.HTTP])
        assert registry.get("http") is mock_transport

    def test_get_unknown_returns_none(self, registry):
        assert registry.get("unknown") is None

    def test_get_for_protocol(self, registry):
        mock_transport = MagicMock(spec=Transport)
        registry.register("http", mock_transport, [TransportProtocol.HTTP])
        assert registry.get_for_protocol(TransportProtocol.HTTP) is mock_transport

    def test_get_for_protocol_fallback_to_http(self, registry):
        mock_http = MagicMock(spec=Transport)
        registry.register("http", mock_http, [TransportProtocol.HTTP])
        # Unknown protocol falls back to http
        assert registry.get_for_protocol(TransportProtocol.ONION) is mock_http

    def test_available(self, registry):
        mock_transport = MagicMock(spec=Transport)
        registry.register("http", mock_transport)
        registry.register("tor", mock_transport)
        assert sorted(registry.available) == ["http", "tor"]

    @pytest.mark.asyncio
    async def test_auto_register_http(self, registry):
        await registry.auto_register()
        assert "http" in registry.available
        http = registry.get("http")
        assert http is not None
        assert http.supports(TransportProtocol.HTTP)

    @pytest.mark.asyncio
    async def test_auto_register_skips_missing_deps(self, registry):
        # tor may or may not be available — just verify no crash
        await registry.auto_register()
        assert "http" in registry.available


# ---------------------------------------------------------------------------
# Transport fallback integration test
# ---------------------------------------------------------------------------

class TestTransportFallback:
    """Test the transport → context.request fallback pattern used in TitanEngine."""

    @pytest.mark.asyncio
    async def test_transport_send_returns_none_when_unavailable(self):
        """When transport is None, _transport_send returns None (caller falls back)."""
        from titan.core.engine import TitanEngine

        config = {"crawl": {"profile": "fast"}}
        engine = TitanEngine(config)
        engine._transport_ready = True
        engine._transport_http = None  # Simulate unavailable

        result = await engine._transport_send("https://example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_transport_send_uses_transport_when_available(self):
        """When transport is available, _transport_send routes through it."""
        from titan.core.engine import TitanEngine

        config = {"crawl": {"profile": "fast"}}
        engine = TitanEngine(config)

        # Mock the transport
        mock_http = AsyncMock()
        mock_response = AttackResponse(status=200, body=b"ok")
        mock_http.send.return_value = mock_response

        engine._transport_ready = True
        engine._transport_http = mock_http

        result = await engine._transport_send("https://example.com", method="GET")
        assert result is not None
        assert result.status == 200
        mock_http.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_transport_send_handles_exception(self):
        """Transport exceptions are caught and return None."""
        from titan.core.engine import TitanEngine

        config = {"crawl": {"profile": "fast"}}
        engine = TitanEngine(config)

        mock_http = AsyncMock()
        mock_http.send.side_effect = Exception("timeout")

        engine._transport_ready = True
        engine._transport_http = mock_http

        result = await engine._transport_send("https://example.com")
        assert result is None
