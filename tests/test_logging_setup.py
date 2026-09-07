"""Structured logging facade tests — get_logger records + mirrors.

Covers:
  - info/warning/error entries recorded with the expected level
  - structured fields (module + extras) captured on the entry
  - console mirroring preserves the raw message
  - all facades share one sink
"""

from __future__ import annotations

import pytest

from titan.core.logger import _SINK, get_logger


@pytest.fixture(autouse=True)
def _clear_sink():
    _SINK.clear()
    yield
    _SINK.clear()


def test_info_records_level_and_structured_fields():
    logger = get_logger("engine")
    logger.info("[+] something happened", count=3, url="https://x")

    entries = _SINK.get_entries()
    assert len(entries) == 1
    entry = entries[0]
    assert entry.level == "info"
    assert entry.message == "[+] something happened"
    assert entry.data["module"] == "engine"
    assert entry.data["count"] == 3
    assert entry.data["url"] == "https://x"


def test_warning_and_error_record_their_levels():
    logger = get_logger("engine")
    logger.warning("[!] warn me")
    logger.error("[-] broke")

    assert [e.level for e in _SINK.get_entries()] == ["warning", "error"]


def test_facades_share_one_sink():
    get_logger("engine").info("from a")
    get_logger("verify").info("from b")

    assert [e.data["module"] for e in _SINK.get_entries()] == ["engine", "verify"]


def test_console_mirror_preserves_message(capsys):
    get_logger("engine").info("[+] hello")

    assert "[+] hello" in capsys.readouterr().out
