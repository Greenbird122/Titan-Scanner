"""Tests for the uncaught-exception crash hook in titan.core.logger.

The hook must:
  1. Be idempotent (calling install_crash_hook twice is safe).
  2. Log the exception to the structured sink before the default handler runs.
  3. Not swallow the exception — sys.__excepthook__ still fires.
"""
from __future__ import annotations

import sys

from titan.core.logger import (
    _SINK,
    _crash_hook,
    install_crash_hook,
)


class TestInstallCrashHook:
    def test_idempotent(self):
        original = sys.excepthook
        install_crash_hook()
        first = sys.excepthook
        install_crash_hook()
        second = sys.excepthook
        assert first is _crash_hook
        assert second is _crash_hook
        sys.excepthook = original

    def test_hook_logs_and_raises(self, tmp_path):
        """Simulate an uncaught exception via the hook directly.

        The hook calls sys.__excepthook__ which prints to stderr; we
        suppress that by temporarily replacing it with a no-op, then
        verify the structured sink received a crash entry.
        """
        import io

        original_hook = sys.excepthook
        sink_entries_before = len(_SINK._entries)

        try:
            # Suppress the default stderr output during the test
            sys.__excepthook__ = lambda *a: None

            try:
                raise ValueError("test-crash-signal")
            except ValueError:
                exc_type, exc_value, exc_tb = sys.exc_info()
                _crash_hook(exc_type, exc_value, exc_tb)

            # The sink should now have a crash entry
            crash_entries = [
                e
                for e in _SINK._entries[sink_entries_before:]
                if e.category == "error"
                and "test-crash-signal" in e.message
            ]
            assert len(crash_entries) >= 1
            assert "ValueError" in crash_entries[0].message
        finally:
            sys.__excepthook__ = sys.__excepthook__
            sys.excepthook = original_hook
