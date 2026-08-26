"""Tor Transport — Route requests through the Tor network.

Supports .onion hidden services and anonymized HTTP requests.
Requires a running Tor service with SOCKS5 proxy (default: 127.0.0.1:9050).

Features:
  - SOCKS5 proxy via Tor for all HTTP requests
  - Circuit rotation (NEWNYM) for identity isolation
  - Longer timeouts (Tor is slower than direct connections)
  - Per-circuit identity tracking

Requirements:
  - Tor service running: sudo systemctl start tor
  - SOCKS5 proxy on port 9050
  - ControlPort on 9051 (for circuit rotation)
  - pip install aiohttp aiohttp-socks
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import time

from titan.transport.base import (
    AttackRequest,
    AttackResponse,
    RequestMethod,
    TargetDescriptor,
    Transport,
    TransportIdentity,
    TransportProtocol,
)

logger = logging.getLogger(__name__)

DEFAULT_SOCKS_PROXY = "socks5://127.0.0.1:9050"
DEFAULT_CONTROL_PORT = 9051


class TorTransport(Transport):
    """Transport through the Tor network for .onion hidden services.

    Usage:
        transport = TorTransport()
        response = await transport.send(AttackRequest(
            url="http://xyz.onion/api/users",
            method=RequestMethod.GET,
        ))
    """

    PROTOCOLS = {TransportProtocol.HTTP, TransportProtocol.HTTPS, TransportProtocol.ONION}

    def __init__(
        self,
        socks_proxy: str | None = None,
        control_port: int | None = None,
        timeout: float = 60.0,
        circuit_rotate_after: int = 10,
    ):
        self.socks_proxy = socks_proxy or os.getenv("TOR_SOCKS_PROXY", DEFAULT_SOCKS_PROXY)
        self.control_port = control_port or int(os.getenv("TOR_CONTROL_PORT", str(DEFAULT_CONTROL_PORT)))
        self.timeout = timeout
        self.circuit_rotate_after = circuit_rotate_after
        self._request_count = 0
        self._circuit_id = 0
        self._identity = TransportIdentity(
            protocol="tor",
            circuit_id=str(self._circuit_id),
        )

    @property
    def identity(self) -> TransportIdentity:
        return self._identity

    def supports(self, protocol: TransportProtocol) -> bool:
        return protocol in self.PROTOCOLS

    async def send(self, request: AttackRequest) -> AttackResponse:
        """Send request through Tor SOCKS5 proxy."""
        import aiohttp
        from aiohttp_socks import ProxyConnector

        self._request_count += 1

        # Rotate circuit periodically for identity isolation
        if self._request_count % self.circuit_rotate_after == 0:
            await self.rotate_circuit()

        start = time.time()

        try:
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            connector = ProxyConnector.from_url(self.socks_proxy)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj) as session:
                async with session.request(
                    method=request.method.value,
                    url=request.url,
                    headers=request.headers,
                    data=request.body,
                    ssl=False,
                    allow_redirects=False,
                ) as resp:
                    body = await resp.read()
                    return AttackResponse(
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        elapsed=time.time() - start,
                        url=str(resp.url),
                        protocol="tor",
                    )
        except Exception as e:
            elapsed = time.time() - start
            logger.warning(f"Tor request failed: {e}")
            return AttackResponse(
                status=0,
                headers={},
                body=b"",
                elapsed=elapsed,
                url=request.url,
                protocol="tor",
                error=str(e),
            )

    async def connect(self, target: TargetDescriptor) -> None:
        """Verify Tor connectivity before scanning."""
        try:
            response = await self.send(AttackRequest(
                url="https://check.torproject.org/api/ip",
                method=RequestMethod.GET,
                timeout=30.0,
            ))
            if response.status == 200:
                data = response.json
                logger.info(f"Tor connected: IP={data.get('IP')}, IsTor={data.get('IsTor')}")
            else:
                logger.warning(f"Tor check failed: status={response.status}")
        except Exception as e:
            logger.error(f"Tor not available: {e}")

    async def rotate_circuit(self) -> bool:
        """Request a new Tor circuit for identity isolation."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self.control_port),
                timeout=5.0,
            )
            try:
                writer.write(b'AUTHENTICATE ""\r\n')
                await writer.drain()
                await reader.readline()

                writer.write(b'SIGNAL NEWNYM\r\n')
                await writer.drain()
                await reader.readline()
            finally:
                writer.close()
                await writer.wait_closed()

            self._circuit_id += 1
            self._identity = TransportIdentity(
                protocol="tor",
                circuit_id=str(self._circuit_id),
            )
            logger.info(f"Tor circuit rotated: #{self._circuit_id}")
            return True
        except Exception as e:
            logger.warning(f"Circuit rotation failed: {e}")
            return False

    @staticmethod
    def is_available() -> bool:
        """Check if Tor SOCKS5 proxy is reachable."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(("127.0.0.1", 9050))
            sock.close()
            return result == 0
        except Exception:
            return False
