"""REPL smoke tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from titan_repl import _load_scan, TitanREPL  # noqa: E402


@pytest.fixture
def scan_dir():
    d = ROOT / "findings" / "localhost-5000"
    if not d.exists():
        pytest.skip("localhost-5000 scan not present")
    return d


def test_load_scan(scan_dir):
    result, meta = _load_scan(scan_dir)
    assert len(result.findings) > 0
    assert result.target
    assert "findings" in meta


def test_repl_commands(scan_dir):
    repl = TitanREPL(scan_dir)
    assert len(repl.findings) > 0
    assert len(repl._filtered) == len(repl.findings)

    # filter
    repl.cmd_filter(["severity", "high"])
    assert all(f.severity.value == "high" for f in repl._filtered)
    repl.cmd_reset([])
    assert len(repl._filtered) == len(repl.findings)

    # count
    repl.cmd_count([])  # should not raise

    # meta
    repl.cmd_meta([])  # should not raise

    # show valid
    repl.cmd_show(["0"])  # should not raise

    # show invalid
    repl.cmd_show(["9999"])  # should print invalid, not raise

    # help
    repl.cmd_help([])  # should not raise
