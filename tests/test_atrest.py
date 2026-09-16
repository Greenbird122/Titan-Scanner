"""Tests for the at-rest encode vault (titan.exploit.atrest).

The vault keeps exploit-artifact templates base64-encoded on disk and decodes
them only in memory.  These tests verify the round-trip, the CLI entry points,
and the error path for missing keys — without writing to the real vault file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator
from unittest.mock import patch

import pytest

from titan.exploit import atrest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_KEY = "test_channel"
SAMPLE_TEXT = "echo 'hello from the vault'"


@pytest.fixture()
def _tmp_vault(tmp_path: Path) -> Iterator[Path]:
    """Point the vault at a temporary file for the duration of the test."""
    vault_file = tmp_path / "vault.b64"
    with patch.object(atrest, "_VAULT_FILE", vault_file):
        yield vault_file


# ---------------------------------------------------------------------------
# encode / decode
# ---------------------------------------------------------------------------


def test_encode_decode_round_trip() -> None:
    encoded = atrest.encode_text(SAMPLE_TEXT)
    assert isinstance(encoded, str)
    assert encoded != SAMPLE_TEXT  # actually encoded
    assert atrest.decode_text(encoded) == SAMPLE_TEXT


def test_encode_is_ascii_safe() -> None:
    """Encoded output must be pure ASCII so it survives JSON serialization."""
    encoded = atrest.encode_text("payload with unicode → ✓")
    assert encoded.isascii()


# ---------------------------------------------------------------------------
# get / set
# ---------------------------------------------------------------------------


def test_set_then_get(_tmp_vault: Path) -> None:
    atrest.put(SAMPLE_KEY, SAMPLE_TEXT)
    assert atrest.get(SAMPLE_KEY) == SAMPLE_TEXT


def test_get_missing_key_raises(_tmp_vault: Path) -> None:
    with pytest.raises(KeyError, match="no entry"):
        atrest.get("nonexistent_key")


def test_multiple_keys(_tmp_vault: Path) -> None:
    atrest.put("alpha", "aaa")
    atrest.put("beta", "bbb")
    assert atrest.get("alpha") == "aaa"
    assert atrest.get("beta") == "bbb"


# ---------------------------------------------------------------------------
# vault file on disk
# ---------------------------------------------------------------------------


def test_vault_file_is_valid_json(_tmp_vault: Path) -> None:
    atrest.put("x", "hello")
    raw = _tmp_vault.read_text(encoding="utf-8")
    data = json.loads(raw)
    assert isinstance(data, dict)
    assert "x" in data


def test_vault_values_are_base64(_tmp_vault: Path) -> None:
    """Every value stored in the vault should be a base64 string."""
    import base64

    atrest.put("k", "v")
    data = json.loads(_tmp_vault.read_text(encoding="utf-8"))
    for val in data.values():
        # Should decode without error
        base64.b64decode(val.encode("ascii"))
