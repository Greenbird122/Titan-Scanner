"""Titan Omega — Transport Abstraction Layer.

Protocol-agnostic target reach. Every detector module works with any transport.
The transport layer handles HTTP, Tor, gRPC, WebSocket, MQTT, and SSH.

Usage:
    from titan.transport import TransportRegistry, AttackRequest, RequestMethod

    registry = TransportRegistry()
    await registry.auto_register()

    transport = registry.get("http")  # or "tor", "grpc", "websocket", etc.
    response = await transport.send(AttackRequest(
        url="https://target.com/api",
        method=RequestMethod.GET,
    ))
"""

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

__all__ = [
    "AttackRequest",
    "AttackResponse",
    "RequestMethod",
    "TargetDescriptor",
    "Transport",
    "TransportIdentity",
    "TransportProtocol",
    "TransportRegistry",
]
