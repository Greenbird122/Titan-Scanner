"""Pins the hermetic-suite guarantee: tests cannot reach external hosts.

The autouse guard in ``tests/conftest.py`` blocks any non-loopback socket for
every test. This file proves the guard itself works — external connects are
refused, loopback stays allowed, and the ``allow_network`` marker is the only
escape hatch — so the README's offline claim is enforced, not aspirational.
"""

import socket

import pytest


def _connect_to(address) -> bool:
    """Attempt a TCP connect; return True when the socket is open."""
    family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.0)
        return sock.connect_ex(address) == 0


def test_external_connection_is_blocked():
    # TEST-NET-3 (RFC 5737, documentation-only): never routable, and the
    # guard raises before any syscall anyway.
    with pytest.raises(RuntimeError, match="blocked external network call"):
        _connect_to(("203.0.113.1", 80))


def test_loopback_connection_is_permitted():
    # ~148 test files spin up local aiohttp/flask servers; loopback must
    # stay reachable under the guard.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        assert _connect_to(("127.0.0.1", port)), "loopback listener unreachable"
    finally:
        listener.close()


def test_guard_is_installed_by_default():
    # The autouse fixture wraps socket methods for every unmarked test.
    assert socket.socket.connect.__name__ == "wrapper"


@pytest.mark.allow_network
def test_allow_network_marker_disables_the_guard():
    # The escape hatch removes the wrapper entirely (no network is touched
    # here — the assertion is on the socket method itself).
    assert socket.socket.connect.__name__ == "connect"
