"""Structured logging facade tests — get_logger records + mirrors.

Covers:
  - info/warning/error entries recorded with the expected level
  - structured fields (module + extras) captured on the entry
  - console mirroring preserves the raw message
  - all facades share one sink
  - stdlib logging emits machine-readable JSON (stderr stream + file)
"""

from __future__ import annotations

import json
import logging

import pytest

from titan.core.logger import _SINK, _json_log_formatter, get_logger


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


def test_stderr_stream_emits_json(capsys):
    stdlib_logger = logging.getLogger("titan.stderrtest")
    stdlib_logger.info("json stream test", extra={"op": "probe"})

    err = capsys.readouterr().err
    records = [json.loads(line) for line in err.splitlines() if line.strip()]
    target = [r for r in records if r.get("message") == "json stream test"]
    assert target, "stdlib record must reach stderr as JSON"
    record = target[0]
    assert record["level"] == "INFO"
    assert record["module"] == "titan.stderrtest"
    assert record["op"] == "probe"
    assert "timestamp" in record


def test_json_formatter_emits_expected_keys(tmp_path):
    handler = logging.FileHandler(tmp_path / "out.log", encoding="utf-8")
    handler.setFormatter(_json_log_formatter())
    lg = logging.Logger("titan.fmttest", level=logging.INFO)
    lg.addHandler(handler)
    lg.info("structured hello", extra={"scan_id": "abc123"})
    handler.close()

    line = (tmp_path / "out.log").read_text(encoding="utf-8").strip().splitlines()[0]
    record = json.loads(line)
    assert record["level"] == "INFO"
    assert record["module"] == "titan.fmttest"
    assert record["message"] == "structured hello"
    assert record["scan_id"] == "abc123"
    assert "timestamp" in record
