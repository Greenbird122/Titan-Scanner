"""Transport abstraction for TitanEngine.

Extracted from titan/core/engine.py. Provides the lazy HTTP transport
registry init, the request-send path, and transport cleanup. The engine
initializes the ``_transport_*`` state attributes in ``__init__`` before any
transport use; the mixin only supplies the behavior.
"""

from __future__ import annotations

from typing import Any

from titan.core.logger import get_logger

logger = get_logger("transport_mixin")


class TransportMixin:
    """Lazy transport registry + HTTP send/close lifecycle for TitanEngine."""

    async def _ensure_transport(self) -> None:
        if self._transport_ready:
            return
        try:
            from titan.transport import TransportRegistry

            self._transport_registry = TransportRegistry()
            await self._transport_registry.auto_register()
            self._transport_http = self._transport_registry.get("http")
            self._transport_ready = True
            avail = self._transport_registry.available
            print(f"[+] Transport layer ready: {', '.join(avail)}")
        except Exception as exc:
            print(f"[!] Transport layer init failed (continuing without): {exc}")
            self._transport_ready = True
        # Install the scan's egress policy into the HTTP transport: detector
        # traffic is then pinned to the consented target's IP space, so DNS
        # rebinding or SSRF payloads can't walk the scanner onto internal or
        # IMDS addresses.
        try:
            from titan.core.egress import from_config

            policy = from_config(self._scan_target, self.config.get("egress"))
            if self._transport_http is not None and hasattr(self._transport_http, "set_egress_policy"):
                self._transport_http.set_egress_policy(policy)
                logger.info(f"[+] Egress policy pinned to {policy.target_host} ({len(policy.pinned_ips)} IPs)")
        except Exception as exc:
            # Fail CLOSED: no policy -> no transport. A scan without the
            # IP-level backstop must not run wide open.
            self._transport_ready = False
            if self._transport_http is not None and hasattr(self._transport_http, "set_egress_policy"):
                self._transport_http.set_egress_policy(None)
            raise RuntimeError(f"egress policy init failed ({exc}); refusing to scan without egress pinning") from exc

    async def _transport_send(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: Any = None,
        params: dict[str, str] | None = None,
        timeout: float = 15.0,
    ) -> Any | None:
        await self._ensure_transport()
        if not self._transport_http:
            return None
        try:
            from titan.transport import AttackRequest, RequestMethod

            _method = RequestMethod(method.upper())
            return await self._transport_http.send(
                AttackRequest(
                    url=url,
                    method=_method,
                    headers=headers or {},
                    body=body,
                    params=params,
                    timeout=timeout,
                )
            )
        except Exception:
            return None

    async def _close_transport(self) -> None:
        """Close the HTTP transport if it exposes a close method."""
        try:
            http = getattr(self, "_transport_http", None)
            if http is not None and hasattr(http, "close"):
                await http.close()
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass
