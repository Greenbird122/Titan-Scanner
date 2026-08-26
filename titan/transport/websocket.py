"""WebSocket Transport — Exploit WebSocket endpoints.

Supports WS and WSS connections, message injection, protocol fuzzing,
and authentication testing over WebSocket.

Features:
  - Connect to WS/WSS endpoints
  - Send arbitrary messages (text/binary)
  - Message injection and fuzzing
  - Authentication bypass testing (connect without auth)
  - Protocol downgrade testing (ws:// vs wss://)
  - Persistent connection management

Requirements: pip install aiohttp
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from titan.transport.base import (
    AttackRequest,
    AttackResponse,
    TargetDescriptor,
    Transport,
    TransportIdentity,
    TransportProtocol,
)

logger = logging.getLogger(__name__)


class WebSocketTransport(Transport):
    """WebSocket transport for real-time protocol exploitation.

    Usage:
        transport = WebSocketTransport()
        response = await transport.send(AttackRequest(
            url="wss://target.com/ws",
            body='{"action": "subscribe", "channel": "admin"}',
        ))
        await transport.close_all()  # Clean up persistent connections.
    """

    PROTOCOLS = {TransportProtocol.WEBSOCKET}

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self._identity = TransportIdentity(protocol="websocket")
        self._connections: dict[str, Any] = {}  # host -> aiohttp.ClientWebSocketResponse
        self._sessions: dict[str, Any] = {}     # host -> aiohttp.ClientSession

    @property
    def identity(self) -> TransportIdentity:
        return self._identity

    def supports(self, protocol: TransportProtocol) -> bool:
        return protocol in self.PROTOCOLS

    def _to_ws_url(self, url: str) -> str:
        """Convert http(s) URLs to ws(s) if needed."""
        if url.startswith("http://"):
            return url.replace("http://", "ws://", 1)
        elif url.startswith("https://"):
            return url.replace("https://", "wss://", 1)
        return url

    async def send(self, request: AttackRequest) -> AttackResponse:
        """Send a message over WebSocket and wait for the response.

        For one-shot operations: opens a connection, sends the message,
        waits for one response, then closes.
        """
        import aiohttp

        start = time.time()
        ws_url = self._to_ws_url(request.url)

        try:
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                async with session.ws_connect(
                    ws_url,
                    headers=request.headers,
                    timeout=timeout_obj,
                ) as ws:
                    # Send the message
                    message = request.body or b""
                    if isinstance(message, str):
                        await ws.send_str(message)
                    else:
                        await ws.send_bytes(message)

                    # Wait for response (with timeout)
                    try:
                        msg = await asyncio.wait_for(
                            ws.receive(),
                            timeout=self.timeout,
                        )
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            body = msg.data.encode()
                        elif msg.type == aiohttp.WSMsgType.BINARY:
                            body = msg.data
                        elif msg.type in (
                            aiohttp.WSMsgType.ERROR,
                            aiohttp.WSMsgType.CLOSED,
                        ):
                            error = str(ws.exception()) if ws.exception() else "Connection closed"
                            return AttackResponse(
                                status=0,
                                headers={},
                                body=b"",
                                elapsed=time.time() - start,
                                url=ws_url,
                                protocol="websocket",
                                error=error,
                            )
                        else:
                            body = b""

                        return AttackResponse(
                            status=200,
                            headers={"ws-type": str(msg.type)},
                            body=body,
                            elapsed=time.time() - start,
                            url=ws_url,
                            protocol="websocket",
                        )
                    except asyncio.TimeoutError:
                        return AttackResponse(
                            status=0,
                            headers={},
                            body=b"",
                            elapsed=time.time() - start,
                            url=ws_url,
                            protocol="websocket",
                            error="No response within timeout",
                        )

        except Exception as e:
            return AttackResponse(
                status=0,
                headers={},
                body=b"",
                elapsed=time.time() - start,
                url=request.url,
                protocol="websocket",
                error=str(e),
            )

    async def connect(self, target: TargetDescriptor) -> None:
        """Establish a persistent WebSocket connection."""
        import aiohttp

        ws_url = self._to_ws_url(target.url)
        host = target.host

        try:
            session = aiohttp.ClientSession()
            ws = await session.ws_connect(ws_url)
            self._connections[host] = ws
            self._sessions[host] = session
            logger.info(f"WebSocket connected: {host}")
        except Exception as e:
            logger.warning(f"WebSocket connection failed: {e}")

    async def send_raw(self, host: str, message: str) -> Any:
        """Send a raw message on an existing persistent connection."""
        ws = self._connections.get(host)
        if ws and not ws.closed:
            await ws.send_str(message)
            try:
                return await asyncio.wait_for(ws.receive(), timeout=self.timeout)
            except asyncio.TimeoutError:
                return None
        return None

    async def disconnect(self, host: str) -> None:
        """Close a persistent connection."""
        ws = self._connections.pop(host, None)
        session = self._sessions.pop(host, None)
        if ws:
            try:
                await ws.close()
            except Exception:
                pass
        if session:
            try:
                await session.close()
            except Exception:
                pass

    async def close_all(self) -> None:
        """Close all persistent connections."""
        hosts = list(self._connections.keys())
        for host in hosts:
            await self.disconnect(host)
