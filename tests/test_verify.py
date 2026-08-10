"""Behavioral tests for the verification core (titan.verify)."""

import asyncio
from types import SimpleNamespace

import pytest

from titan.verify import BaselineAnalyzer, BlindDetector


class TestBaselineAnalyzer:
    def test_detects_payload_reflection(self):
        diffs = BaselineAnalyzer.diff_responses(
            "hello world",
            "hello <script>alert(1)</script>",
            "<script>alert(1)</script>",
        )
        assert "payload_reflected" in diffs

    def test_detects_length_increase(self):
        diffs = BaselineAnalyzer.diff_responses("short", "this response is much much longer than baseline", "zzz")
        assert "response_length_increased" in diffs

    def test_detects_sql_error_signature(self):
        diffs = BaselineAnalyzer.diff_responses(
            "SELECT ok",
            "SELECT ok -- you have an error in your SQL syntax",
            "x",
        )
        assert any(d.startswith("error:") for d in diffs)

    def test_identical_responses_no_diffs(self):
        body = "identical content"
        assert BaselineAnalyzer.diff_responses(body, body, "payload") == []

    def test_json_key_diff(self):
        diffs = BaselineAnalyzer.diff_json({"a": 1}, {"a": 2})
        assert "json:a" in diffs


class _TimedContext:
    """Fake playwright-style context: responses are delayed when the payload
    contains 'sleep', mimicking a time-based injection.

    Faithful to the real APIRequestContext: unknown kwargs (like the historical
    `cookies=`) raise TypeError, exactly as Playwright does."""

    def __init__(self, sleep_delay: float = 0.25, base_delay: float = 0.01):
        self.sleep_delay = sleep_delay
        self.base_delay = base_delay
        self.last_params = None
        self.request = self._Request(self)

    class _Request:
        def __init__(self, parent):
            self.parent = parent

        async def get(self, url, params=None, headers=None, timeout=10000, **kwargs):
            if kwargs:
                raise TypeError(f"APIRequestContext.get() got an unexpected keyword argument {next(iter(kwargs))!r}")
            self.parent.last_params = params
            injected = " ".join(str(v) for v in (params or {}).values()).lower()
            delay = self.parent.sleep_delay if "sleep" in injected else self.parent.base_delay
            await asyncio.sleep(delay)
            return SimpleNamespace(status=200, url=url, headers={}, text=async_fn())


def async_fn():
    async def _text():
        return "ok"
    return _text


class TestBlindDetector:
    def test_detects_time_based_injection(self):
        detector = BlindDetector(samples=2, confidence=0.95)
        # The fixture must simulate what SLEEP(3) actually does: the injected
        # request takes ~3s, not 0.25s (the declared-delay gate rejects a
        # 0.24s delta as load variance, not a real sleep).
        ctx = _TimedContext(sleep_delay=3.05)
        params = {"id": "1"}
        is_blind, elapsed = asyncio.run(detector.detect_time_based(
            ctx, "http://t/", "GET", params, {}, {},
            "1 AND SLEEP(3)--", "query", [0.01, 0.01, 0.01], param_name="id",
        ))
        assert is_blind is True
        assert elapsed > 0.1
        # The payload must be injected into the *actual* parameter, not a
        # made-up "q" key (the historical bug).
        assert ctx.last_params.get("id") == "1 AND SLEEP(3)--"

    def test_no_injection_returns_false(self):
        detector = BlindDetector(samples=3, confidence=0.95)
        ctx = _TimedContext()
        # Baseline stats must reflect a realistic baseline (here 0.05s, matching
        # the fake's base_delay+margin). A tight 0.01 threshold would let CPU
        # contention overshoot a 10ms sleep and flip this negative case.
        is_blind, _ = asyncio.run(detector.detect_time_based(
            ctx, "http://t/", "GET", {"id": "1"}, {}, {},
            "1", "query", [0.05, 0.05, 0.05], param_name="id",
        ))
        assert is_blind is False

    def test_samples_one_is_clamped_to_two(self):
        # samples=1 used to silently disable detection; it must now run.
        detector = BlindDetector(samples=1, confidence=0.95)
        # Realistic 3s delay (see declared-delay gate note above).
        ctx = _TimedContext(sleep_delay=3.05)
        is_blind, _ = asyncio.run(detector.detect_time_based(
            ctx, "http://t/", "GET", {"id": "1"}, {}, {},
            "1 AND SLEEP(3)--", "query", [0.01, 0.01, 0.01], param_name="id",
        ))
        assert is_blind is True

    def test_body_location_injection(self):
        detector = BlindDetector(samples=2, confidence=0.95)
        # Realistic 3s delay (see declared-delay gate note above).
        ctx = _TimedContext(sleep_delay=3.05)

        class _BodyRequest(_TimedContext._Request):
            async def post(self, url, data=None, headers=None, timeout=10000, **kwargs):
                if kwargs:
                    raise TypeError(f"APIRequestContext.post() got an unexpected keyword argument {next(iter(kwargs))!r}")
                self.parent.last_params = data
                injected = " ".join(str(v) for v in (data or {}).values()).lower()
                delay = self.parent.sleep_delay if "sleep" in injected else self.parent.base_delay
                await asyncio.sleep(delay)
                return SimpleNamespace(status=200, url=url, headers={}, text=async_fn())

        ctx.request = _BodyRequest(ctx)
        is_blind, _ = asyncio.run(detector.detect_time_based(
            ctx, "http://t/", "POST", {}, {"q": "1"}, {},
            "1 OR SLEEP(3)--", "body", [0.01, 0.01, 0.01], param_name="q",
        ))
        assert is_blind is True
        assert ctx.last_params.get("q") == "1 OR SLEEP(3)--"

    def test_unexpected_exception_is_surfaced_not_silent(self, capsys):
        """Regression: the historical `cookies=` TypeError was swallowed by a
        bare except and timing silently returned elapsed=0.0. Now an unexpected
        error must surface once (one-time diagnostic) instead of hiding."""
        class _ExplodingContext:
            class _Request:
                async def get(self, url, params=None, headers=None, timeout=10000, **kwargs):
                    raise RuntimeError("boom")

            def __init__(self):
                self.request = self._Request()

        BlindDetector._warned_unexpected = False  # deterministic
        detector = BlindDetector(samples=2, confidence=0.95)
        is_blind, elapsed = asyncio.run(detector.detect_time_based(
            _ExplodingContext(), "http://t/", "GET", {"id": "1"}, {}, {},
            "1 AND SLEEP(3)--", "query", [0.01, 0.01, 0.01], param_name="id",
        ))
        assert is_blind is False and elapsed == 0.0
        assert "BlindDetector unexpected error" in capsys.readouterr().out
        # A second failure must not spam the console.
        is_blind, _ = asyncio.run(detector.detect_time_based(
            _ExplodingContext(), "http://t/", "GET", {"id": "1"}, {}, {},
            "1 AND SLEEP(3)--", "query", [0.01, 0.01, 0.01], param_name="id",
        ))
        assert "BlindDetector unexpected error" not in capsys.readouterr().out
