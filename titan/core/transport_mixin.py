"""Transport abstraction for TitanEngine.

Extracted from titan/core/engine.py. Provides the lazy HTTP transport
registry init, the request-send path, and transport cleanup. The engine
initializes the ``_transport_*`` state attributes in ``__init__`` before any
transport use; the mixin only supplies the behavior.
"""

from __future__ import annotations

from typing import Any


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

    async def _transport_send(
        self, url: str, method: str = "GET",
        headers: dict[str, str] | None = None,
        body: Any = None, params: dict[str, str] | None = None,
        timeout: float = 15.0,
    ) -> Any | None:
        await self._ensure_transport()
        if not self._transport_http:
            return None
        try:
            from titan.transport import AttackRequest, RequestMethod
            _method = RequestMethod(method.upper())
            return await self._transport_http.send(AttackRequest(
                url=url, method=_method, headers=headers or {},
                body=body, params=params, timeout=timeout,
            ))
        except Exception:
            return None

    async def _close_transport(self) -> None:
        """Close the HTTP transport if it exposes a close method."""
        try:
            http = getattr(self, "_transport_http", None)
            if http is not None and hasattr(http, "close"):
                await http.close()
        except Exception:
            pass