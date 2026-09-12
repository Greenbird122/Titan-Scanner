"""The external-network guard must actually fire, and must not block loopback.

Without these, the autouse fixture in conftest.py is an unverified claim: it
could be silently absent and every other test would still pass.
"""
import socket

import pytest

# 93.184.216.34 is a well-known public address. The guard raises before any
# packet is sent, so this test performs no network I/O.
EXTERNAL = ("93.184.216.34", 80)


def test_guard_blocks_external_connect():
    sock = socket.socket()
    try:
        with pytest.raises(RuntimeError, match="blocked external network call"):
            sock.connect(EXTERNAL)
    finally:
        sock.close()


def test_guard_blocks_external_connect_ex():
    sock = socket.socket()
    try:
        with pytest.raises(RuntimeError, match="blocked external network call"):
            sock.connect_ex(EXTERNAL)
    finally:
        sock.close()


def test_guard_allows_loopback():
    """Loopback must pass the guard (the OS may still refuse the connection)."""
    sock = socket.socket()
    try:
        sock.connect(("127.0.0.1", 1))
    except OSError as exc:  # refused / unreachable is fine — that is the OS
        assert "blocked external network call" not in str(exc)
    finally:
        sock.close()


@pytest.mark.allow_network
def test_allow_network_marker_lifts_the_guard():
    """With the marker set the fixture returns early, so stdlib connect is intact."""
    assert "_guard" not in getattr(socket.socket.connect, "__qualname__", "")
