"""Titan Omega — Transport Base Types.

Defines the protocol-agnostic interface that all transports implement.
Detectors never know which transport they're using — they just call
transport.send(request) and get a response back.
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TransportProtocol(enum.Enum):
    """Supported transport protocols."""
    HTTP = "http"
    HTTPS = "https"
    ONION = "onion"
    GRPC = "grpc"
    WEBSOCKET = "websocket"
    MQTT = "mqtt"
    SSH = "ssh"
    SERIAL = "serial"


class RequestMethod(enum.Enum):
    """HTTP methods (also used for gRPC, WebSocket, etc.)."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AttackRequest:
    """A request to send through any transport.

    This is the transport-agnostic equivalent of an HTTP request.
    Detectors create AttackRequests; transports convert them to
    protocol-specific wire format (HTTP headers, gRPC messages, etc.).
    """
    url: str
    method: RequestMethod = RequestMethod.GET
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | str | None = None
    params: dict[str, str] = field(default_factory=dict)
    timeout: float = 30.0
    metadata: dict[str, Any] = field(default_factory=dict)  # Transport-specific

    @property
    def is_onion(self) -> bool:
        return ".onion" in self.url

    @property
    def host(self) -> str:
        from urllib.parse import urlparse
        return urlparse(self.url).hostname or ""

    @property
    def path(self) -> str:
        from urllib.parse import urlparse
        return urlparse(self.url).path or "/"


@dataclass
class AttackResponse:
    """Response from any transport.

    Normalized across all transports — detectors see the same
    interface whether the target is HTTP, gRPC, WebSocket, or MQTT.
    """
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed: float = 0.0
    url: str = ""
    protocol: str = "http"
    error: str | None = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    @property
    def text(self) -> str:
        try:
            return self.body.decode("utf-8", errors="replace")
        except Exception:
            return ""

    @property
    def json(self) -> Any:
        import json
        try:
            return json.loads(self.body)
        except Exception:
            return None

    @property
    def is_error(self) -> bool:
        return self.error is not None or self.status == 0


@dataclass
class TargetDescriptor:
    """Describes a target for transport-level operations."""
    url: str
    protocol: TransportProtocol = TransportProtocol.HTTPS
    host: str = ""
    port: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.host:
            from urllib.parse import urlparse
            parsed = urlparse(self.url)
            self.host = parsed.hostname or ""
            self.port = parsed.port or (443 if parsed.scheme == "https" else 80)


@dataclass
class TransportIdentity:
    """Current transport identity (for tracking circuit rotation, IP changes, etc.)."""
    protocol: str = ""
    circuit_id: str = ""
    source_ip: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Transport Protocol (the interface every transport implements)
# ---------------------------------------------------------------------------

class Transport(Protocol):
    """Protocol-agnostic transport interface.

    Every transport (HTTP, Tor, gRPC, WebSocket, MQTT, SSH) implements this.
    Detectors only interact with this interface — they never know which
    transport is being used.
    """

    async def send(self, request: AttackRequest) -> AttackResponse:
        """Send an attack request and return the response."""
        ...

    async def connect(self, target: TargetDescriptor) -> None:
        """Establish a persistent connection (for WebSocket, MQTT, etc.)."""
        ...

    def supports(self, protocol: TransportProtocol) -> bool:
        """Does this transport handle the given protocol?"""
        ...

    @property
    def identity(self) -> TransportIdentity:
        """Current transport identity (for tracking)."""
        ...


# ---------------------------------------------------------------------------
# Transport Registry
# ---------------------------------------------------------------------------

class TransportRegistry:
    """Registry of available transports.

    Detects which transports are available and routes requests to
    the appropriate one based on protocol.

    Usage:
        registry = TransportRegistry()
        await registry.auto_register()  # Detect available transports

        # Get transport by protocol
        transport = registry.get_for_protocol(TransportProtocol.TOR)

        # Or get by name
        transport = registry.get("tor")
    """

    def __init__(self):
        self._transports: dict[str, Transport] = {}
        self._protocol_map: dict[TransportProtocol, str] = {}

    def register(self, name: str, transport: Transport, protocols: list[TransportProtocol] | None = None):
        """Register a transport by name."""
        self._transports[name] = transport
        if protocols:
            for p in protocols:
                self._protocol_map[p] = name

    def get(self, name: str) -> Transport | None:
        """Get a transport by name."""
        return self._transports.get(name)

    def get_for_protocol(self, protocol: TransportProtocol) -> Transport | None:
        """Get the transport registered for a given protocol."""
        name = self._protocol_map.get(protocol)
        if name:
            return self._transports.get(name)
        # Fallback: try HTTP for any unknown protocol
        return self._transports.get("http")

    async def auto_register(self):
        """Auto-detect and register available transports."""
        # Always register HTTP (it's the baseline)
        from titan.transport.http_transport import HttpTransport
        http = HttpTransport()
        self.register("http", http, [TransportProtocol.HTTP, TransportProtocol.HTTPS])

        # Try to register Tor
        try:
            from titan.transport.tor import TorTransport
            tor = TorTransport()
            if TorTransport.is_available():
                self.register("tor", tor, [TransportProtocol.ONION])
        except ImportError:
            pass

        # Try to register gRPC
        try:
            import grpc  # noqa: F401
            from titan.transport.grpc import GrpcTransport
            self.register("grpc", GrpcTransport(), [TransportProtocol.GRPC])
        except ImportError:
            pass

        # Try to register WebSocket
        try:
            import aiohttp  # noqa: F401
            from titan.transport.websocket import WebSocketTransport
            self.register("websocket", WebSocketTransport(), [TransportProtocol.WEBSOCKET])
        except ImportError:
            pass

        # Try to register MQTT
        try:
            import aiomqtt  # noqa: F401
            from titan.transport.mqtt import MqttTransport
            self.register("mqtt", MqttTransport(), [TransportProtocol.MQTT])
        except ImportError:
            pass

    @property
    def available(self) -> list[str]:
        """List of registered transport names."""
        return list(self._transports.keys())
