"""Tests for the extracted BrowserLifecycleMixin.

Covers the Playwright lifecycle plumbing that moved out of engine.py:
redirect capture, driver-death classification, page hardening handler
registration, crawler launch (system-Chrome channel + bundled fallback +
persistent profile), teardown, and popup/dialog/download suppression.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from titan.core.engine import TitanEngine


def _engine() -> TitanEngine:
    return TitanEngine({
        "target": "http://localhost:5000",
        "headless": True,
        "browser": "auto",
        "stealth": {"min_delay": 0.01, "max_delay": 0.01},
    })


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Redirect capture
# ---------------------------------------------------------------------------

class _Req:
    def __init__(self, url):
        self.url = url


class _Resp:
    def __init__(self, status, url, location):
        self.status = status
        self.request = _Req(url)
        self.headers = {"location": location}


class TestRecordRedirect:
    def test_redirect_status_appends_chain_entry(self):
        engine = _engine()
        engine._record_redirect(_Resp(302, "http://localhost:5000/a", "/b"))
        assert engine.redirect_chain[-1] == {
            "from": "http://localhost:5000/a",
            "status": 302,
            "to": "/b",
        }

    def test_non_redirect_status_is_ignored(self):
        engine = _engine()
        engine._record_redirect(_Resp(200, "http://localhost:5000/a", ""))
        assert engine.redirect_chain == []

    def test_chain_is_capped(self):
        engine = _engine()
        for i in range(250):
            engine._record_redirect(_Resp(301, f"http://localhost:5000/{i}", f"/{i + 1}"))
        assert len(engine.redirect_chain) == 200
        # oldest entries evicted, newest kept
        assert engine.redirect_chain[0]["from"] == "http://localhost:5000/50"
        assert engine.redirect_chain[-1]["from"] == "http://localhost:5000/249"


# ---------------------------------------------------------------------------
# Driver-death classification
# ---------------------------------------------------------------------------

class TestIsDriverDeath:
    def test_playwright_driver_death_message(self):
        engine = _engine()
        assert engine._is_driver_death(
            RuntimeError("APIRequestContext.get: Connection closed while reading from the driver")
        )

    def test_unrelated_exceptions_are_not_driver_death(self):
        engine = _engine()
        assert not engine._is_driver_death(RuntimeError("timeout"))
        assert not engine._is_driver_death(ValueError("bad value"))


# ---------------------------------------------------------------------------
# Page hardening
# ---------------------------------------------------------------------------

class TestHardenPage:
    def test_registers_popup_dialog_download_and_response_handlers(self):
        engine = _engine()
        page = MagicMock()
        engine._harden_page(page)
        events = [c.args[0] for c in page.on.call_args_list]
        assert events == ["popup", "dialog", "download", "response"]

    def test_handlers_swallow_hardening_failures(self):
        engine = _engine()
        page = MagicMock()
        page.on.side_effect = RuntimeError("detached page")
        engine._harden_page(page)  # must not raise


# ---------------------------------------------------------------------------
# Crawler launch
# ---------------------------------------------------------------------------

class _FakeChromium:
    def __init__(self, fail_first=False):
        self.launch = AsyncMock()
        self.launch_persistent_context = AsyncMock()
        self.browser = MagicMock()
        self.browser.new_context = AsyncMock(return_value=MagicMock())
        if fail_first:
            calls = []

            def _launch(**kwargs):
                calls.append(kwargs)
                if len(calls) == 1:
                    raise RuntimeError("no system chrome")
                return self.browser

            self.launch.side_effect = _launch
        else:
            self.launch.return_value = self.browser


class _FakePlaywright:
    def __init__(self, fail_first=False):
        self.chromium = _FakeChromium(fail_first)


class TestLaunchCrawler:
    def test_auto_mode_uses_system_chrome_channel(self):
        engine = _engine()
        pw = _FakePlaywright()
        browser, context = _run(engine._launch_crawler(pw, "http://localhost:5000"))
        assert browser is pw.chromium.browser
        assert context is pw.chromium.browser.new_context.return_value
        assert pw.chromium.launch.call_args.kwargs["channel"] == "chrome"
        assert pw.chromium.launch.call_args.kwargs["headless"] is True
        # stealth headers passed into the context
        ctx_kwargs = pw.chromium.browser.new_context.call_args.kwargs
        assert "user_agent" in ctx_kwargs and "extra_http_headers" in ctx_kwargs

    def test_falls_back_to_bundled_when_system_chrome_missing(self):
        engine = _engine()
        pw = _FakePlaywright(fail_first=True)
        browser, context = _run(engine._launch_crawler(pw, "http://localhost:5000"))
        assert browser is pw.chromium.browser
        # second launch drops the channel
        second = pw.chromium.launch.await_args_list[-1]
        assert "channel" not in second.kwargs

    def test_bundled_mode_never_sets_channel(self):
        engine = TitanEngine({
            "target": "http://localhost:5000",
            "headless": True,
            "browser": "bundled",
        })
        pw = _FakePlaywright()
        _run(engine._launch_crawler(pw, "http://localhost:5000"))
        assert "channel" not in pw.chromium.launch.call_args.kwargs


# ---------------------------------------------------------------------------
# Teardown + popup/dialog/download suppression
# ---------------------------------------------------------------------------

class TestTeardown:
    def test_close_crawler_closes_browser_handle(self):
        engine = _engine()
        browser = AsyncMock()
        _run(engine._close_crawler(browser, None))
        browser.close.assert_awaited_once()

    def test_close_crawler_closes_context_when_no_browser(self):
        engine = _engine()
        context = AsyncMock()
        _run(engine._close_crawler(None, context))
        context.close.assert_awaited_once()

    def test_close_crawler_tolerates_failures(self):
        engine = _engine()
        browser = AsyncMock()
        browser.close.side_effect = RuntimeError("already closed")
        _run(engine._close_crawler(browser, None))  # must not raise

    def test_popup_dialog_download_suppression_swallows_errors(self):
        engine = _engine()
        for make in (
            lambda: AsyncMock(close=AsyncMock(side_effect=RuntimeError("gone"))),
            lambda: AsyncMock(dismiss=AsyncMock(side_effect=RuntimeError("gone"))),
            lambda: AsyncMock(cancel=AsyncMock(side_effect=RuntimeError("gone"))),
        ):
            handle = make()
            _run(engine._close_popup(handle))
            _run(engine._dismiss_dialog(handle))
            _run(engine._suppress_download(handle))
