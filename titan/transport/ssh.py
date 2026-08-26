"""SSH Transport — Exploit SSH services.

Supports key-based and password authentication testing, command injection,
credential brute-forcing, and key extraction.

Features:
  - Connect via key or password authentication
  - Execute remote commands
  - Test for weak credentials
  - Extract host keys
  - Port forwarding for pivoting

Requirements: pip install asyncssh
"""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import urlparse

from titan.transport.base import (
    AttackRequest,
    AttackResponse,
    TargetDescriptor,
    Transport,
    TransportIdentity,
    TransportProtocol,
)

logger = logging.getLogger(__name__)


class SshTransport(Transport):
    """SSH transport for service exploitation.

    Usage:
        transport = SshTransport()
        response = await transport.send(AttackRequest(
            url="ssh://user@host:22/id",
            headers={"password": "secret"},
        ))
    """

    PROTOCOLS = {TransportProtocol.SSH}

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self._identity = TransportIdentity(protocol="ssh")
        self._connections: dict[str, Any] = {}

    @property
    def identity(self) -> TransportIdentity:
        return self._identity

    def supports(self, protocol: TransportProtocol) -> bool:
        return protocol in self.PROTOCOLS

    async def send(self, request: AttackRequest) -> AttackResponse:
        """Execute a command over SSH.

        URL format: ssh://user@host:port/command
        Headers can include: password, key_path
        """
        start = time.time()

        try:
            import asyncssh

            parsed = urlparse(request.url)
            host = parsed.hostname
            port = parsed.port or 22
            user = parsed.username or "root"
            command = parsed.path.lstrip("/") or "id"

            if not host:
                return AttackResponse(
                    status=0,
                    headers={},
                    body=b"",
                    elapsed=time.time() - start,
                    url=request.url,
                    protocol="ssh",
                    error="No host in URL",
                )

            # Get credentials from headers
            password = request.headers.get("password")
            key_path = request.headers.get("key_path")

            # Build connection kwargs
            connect_kwargs: dict[str, Any] = {
                "host": host,
                "port": port,
                "username": user,
            }
            if key_path:
                connect_kwargs["client_keys"] = [key_path]
            elif password:
                connect_kwargs["password"] = password
            else:
                connect_kwargs["known_hosts"] = None  # Accept unknown hosts

            async with asyncssh.connect(**connect_kwargs) as conn:
                result = await conn.run(command, timeout=self.timeout)

                return AttackResponse(
                    status=200 if result.exit_status == 0 else result.exit_status,
                    headers={
                        "stdout": result.stdout or "",
                        "stderr": result.stderr or "",
                        "exit_status": str(result.exit_status),
                    },
                    body=result.stdout.encode() if result.stdout else b"",
                    elapsed=time.time() - start,
                    url=request.url,
                    protocol="ssh",
                )

        except ImportError:
            return AttackResponse(
                status=0,
                headers={},
                body=b"",
                elapsed=time.time() - start,
                url=request.url,
                protocol="ssh",
                error="asyncssh not installed: pip install asyncssh",
            )
        except Exception as e:
            return AttackResponse(
                status=0,
                headers={},
                body=b"",
                elapsed=time.time() - start,
                url=request.url,
                protocol="ssh",
                error=str(e),
            )

    async def connect(self, target: TargetDescriptor) -> None:
        """Verify SSH service is reachable."""
        try:
            import asyncssh

            async with asyncssh.connect(
                target.host,
                port=target.port or 22,
                known_hosts=None,
            ) as conn:
                logger.info(f"SSH reachable: {target.host}:{target.port}")
        except ImportError:
            logger.warning("asyncssh not installed")
        except Exception as e:
            logger.warning(f"SSH unreachable: {e}")

    async def brute_force(
        self,
        host: str,
        port: int,
        username: str,
        passwords: list[str],
    ) -> dict | None:
        """Test a list of passwords against SSH."""
        try:
            import asyncssh
        except ImportError:
            logger.warning("asyncssh not installed")
            return None

        for password in passwords:
            try:
                async with asyncssh.connect(
                    host,
                    port=port,
                    username=username,
                    password=password,
                    known_hosts=None,
                    login_timeout=5,
                ) as conn:
                    logger.info(f"SSH brute force SUCCESS: {username}:{password}")
                    return {"username": username, "password": password}
            except asyncssh.AuthenticationFailed:
                continue
            except Exception:
                continue

        logger.info(f"SSH brute force: all {len(passwords)} passwords failed")
        return None
