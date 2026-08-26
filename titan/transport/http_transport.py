"""HTTP/HTTPS Transport — wraps existing aiohttp for the transport abstraction.

This is the baseline transport. All other transports are alternatives to this.
Detectors call transport.send() and this handles the HTTP details.

Features:
  - Connection pooling via a shared aiohttp.ClientSession
  - Configurable SSL verification, proxy, user-agent
  - Timeout control per-request
  - Automatic redirect following (disabled by default for security testing)
"""

from __future__ import annotations

import logging
import time
from typing import Any

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


class HttpTransport(Transport):
    """HTTP/HTTPS transport via aiohttp with connection pooling.

    This wraps the existing aiohttp-based HTTP handling into the
    transport abstraction layer. All existing detector modules
    automatically work through this transport.

    Usage:
        transport = HttpTransport()
        response = await transport.send(AttackRequest(
            url="https://target.com/api",
            method=RequestMethod.GET,
        ))
        # Session is reused across calls — no connection overhead.
        await transport.close()  # Call when done.
    """

    PROTOCOLS = {TransportProtocol.HTTP, TransportProtocol.HTTPS}

    def __init__(
        self,
        timeout: float = 30.0,
        verify_ssl: bool = True,
        proxy: str | None = None,
        user_agent: str | None = None,
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        )
        self._identity = TransportIdentity(protocol="http")
        self._session: Any = None  # Lazy-init on first send()

    @property
    def identity(self) -> TransportIdentity:
        return self._identity

    def supports(self, protocol: TransportProtocol) -> bool:
        return protocol in self.PROTOCOLS

    async def _get_session(self):
        """Get or create the shared aiohttp session."""
        import aiohttp

        if self._session is None or self._session.closed:
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(
                timeout=timeout_obj,
                connector=aiohttp.TCPConnector(
                    ssl=self.verify_ssl if self.verify_ssl else False,
                    limit=50,  # Connection pool limit
                    enable_cleanup_closed=True,
                ),
            )
        return self._session

    async def send(self, request: AttackRequest) -> AttackResponse:
        """Send HTTP request via aiohttp with connection pooling."""
        import aiohttp

        start = time.time()
        headers = dict(request.headers)
        if self.user_agent and "User-Agent" not in headers:
            headers["User-Agent"] = self.user_agent

        try:
            session = await self._get_session()
            timeout_override = (
                aiohttp.ClientTimeout(total=request.timeout)
                if request.timeout
                else None
            )
            async with session.request(
                method=request.method.value,
                url=request.url,
                headers=headers,
                data=request.body,
                params=request.params or None,
                ssl=self.verify_ssl if self.verify_ssl else False,
                proxy=self.proxy,
                allow_redirects=False,
                timeout=timeout_override,
            ) as resp:
                body = await resp.read()
                return AttackResponse(
                    status=resp.status,
                    headers=dict(resp.headers),
                    body=body,
                    elapsed=time.time() - start,
                    url=str(resp.url),
                    protocol="http",
                )
        except Exception as e:
            elapsed = time.time() - start
            logger.debug(f"HTTP request failed: {e}")
            return AttackResponse(
                status=0,
                headers={},
                body=b"",
                elapsed=elapsed,
                url=request.url,
                protocol="http",
                error=str(e),
            )

    async def connect(self, target: TargetDescriptor) -> None:
        """Verify target is reachable."""
        response = await self.send(AttackRequest(
            url=target.url,
            method=RequestMethod.GET,
            timeout=10.0,
        ))
        if response.is_error:
            logger.warning(f"Target unreachable: {target.url} — {response.error}")

    async def close(self) -> None:
        """Close the shared session. Call when the transport is done."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
