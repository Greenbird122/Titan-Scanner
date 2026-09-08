"""Browser/crawler lifecycle for TitanEngine.

Extracted from titan/core/engine.py. Supplies hardened Playwright launch
(system Chrome fallback + persistent profiles), teardown, popup/dialog/
download suppression, redirect capture, and driver-death detection. The
engine owns the state these touch (``config``, ``proxy_rotator``,
``stealth``, ``redirect_chain``); the mixin only supplies behavior.
"""


from __future__ import annotations

import asyncio
from typing import Any

from titan.core.constants import DRIVER_DEATH_MARKERS
from titan.core.logger import get_logger

logger = get_logger("browser_lifecycle")



class BrowserLifecycleMixin:
    """Playwright browser lifecycle + page hardening for TitanEngine."""

    # State supplied by the host engine before any mixin method runs.
    config: dict
    stealth: Any
    proxy_rotator: Any
    redirect_chain: list[dict[str, Any]]

    # ==================================================================
    # Driver health
    # ==================================================================

    def _is_driver_death(self, exc: BaseException) -> bool:
        msg = f"{type(exc).__name__}: {exc}".lower()
        return any(marker in msg for marker in DRIVER_DEATH_MARKERS)

    # ==================================================================
    # Page hardening (popups, dialogs, downloads, redirects)
    # ==================================================================

    async def _launch_crawler(self, p: Any, target: str):
        """Launch hardened Playwright browser; returns (browser, context).

        - ``browser: auto|system|bundled`` — ``system``/``auto`` uses the real
          installed Chrome via ``channel=chrome`` (genuine TLS fingerprint,
          defeats naive bot-gates); ``bundled`` forces Playwright's Chromium.
          Falls back to bundled if system Chrome is unavailable.
        - ``browser_profile: <path>`` — when set, uses a persistent context so
          cookies/sessions survive between runs (credentialed rounds); the
          returned ``browser`` is None and teardown closes the context.
        """
        browser_args = {"headless": self.config.get("headless", True)}
        proxy_config = self.config.get("proxy", {})
        if proxy_config.get("enabled") and proxy_config.get("list"):
            proxy_url = self.proxy_rotator.get_proxy(target)
            if proxy_url:
                browser_args["proxy"] = {"server": proxy_url}

        mode = str(self.config.get("browser", "auto")).lower()
        if mode in ("system", "auto"):
            browser_args["channel"] = "chrome"

        profile_dir = self.config.get("browser_profile") or None
        context_kwargs = dict(
            user_agent=self.stealth.get_user_agent(),
            extra_http_headers=self.stealth.get_headers(),
            ignore_https_errors=True,
        )

        def _persistent() -> Any:
            return p.chromium.launch_persistent_context(
                user_data_dir=profile_dir, **browser_args, **context_kwargs
            )

        try:
            if profile_dir:
                return None, await _persistent()
            browser = await p.chromium.launch(**browser_args)
            return browser, await browser.new_context(**context_kwargs)
        except Exception:
            if not browser_args.get("channel"):
                raise
            # System Chrome unavailable (e.g. CI runner) — fall back to bundled.
            browser_args.pop("channel")
            if profile_dir:
                return None, await _persistent()
            browser = await p.chromium.launch(**browser_args)
            return browser, await browser.new_context(**context_kwargs)

    async def _close_crawler(self, browser: Any, context: Any) -> None:
        """Close the crawler handle — browser for ephemeral launches, the
        persistent context itself when a profile dir is in use."""
        try:
            handle = browser or context
            await asyncio.wait_for(handle.close(), timeout=10)
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

    def _harden_page(self, page: Any) -> None:
        try:
            page.on("popup", lambda p: asyncio.create_task(self._close_popup(p)))
            page.on("dialog", lambda d: asyncio.create_task(self._dismiss_dialog(d)))
            page.on("download", lambda dl: asyncio.create_task(self._suppress_download(dl)))
            page.on("response", self._record_redirect)
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

    async def _close_popup(self, popup: Any) -> None:
        try:
            await asyncio.wait_for(popup.close(), timeout=3)
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

    async def _dismiss_dialog(self, dialog: Any) -> None:
        try:
            await asyncio.wait_for(dialog.dismiss(), timeout=3)
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

    async def _suppress_download(self, download: Any) -> None:
        try:
            await asyncio.wait_for(download.cancel(), timeout=3)
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

    def _record_redirect(self, response: Any) -> None:
        try:
            if response.status in (301, 302, 303, 307, 308):
                req = getattr(response, "request", None)
                src = req.url if req is not None else ""
                self.redirect_chain.append({
                    "from": src,
                    "status": response.status,
                    "to": (response.headers or {}).get("location", ""),
                })
                if len(self.redirect_chain) > 200:
                    self.redirect_chain.pop(0)
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass
