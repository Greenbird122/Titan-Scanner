import asyncio
import os
import socket

import pytest

# Hermetic arena tests: the real DeepSeek token lives in .env AND may be
# exported by the operator's shell; the arena LLM loader only fills unset env
# keys, so force-blanking (not setdefault — a shell-exported var survives
# setdefault) keeps every test on the canned offline path (no network,
# deterministic).
os.environ["DEEPSEEK_API_KEY"] = ""
os.environ["DEEPSEEK_AUTH_TOKEN"] = ""
os.environ["OLLAMA_HOST"] = ""


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# External-network guard.
#
# The suite is meant to be hermetic (see the env blanking above), but nothing
# enforced it: a module that silently reached crt.sh or a cloud metadata
# endpoint would pass here and fail, or worse, go live, anywhere else. Loopback
# stays allowed because ~148 test files spin up local aiohttp/flask servers.
#
# If a test genuinely needs the internet, mark it `@pytest.mark.allow_network`.
# ---------------------------------------------------------------------------
_LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost", "0.0.0.0", ""}


def _is_local(address) -> bool:
    # AF_UNIX passes a str path; TCP passes (host, port).
    if isinstance(address, str):
        return True
    if isinstance(address, (tuple, list)) and address:
        return str(address[0]) in _LOCAL_HOSTS
    return False


@pytest.fixture(autouse=True)
def _block_external_network(monkeypatch, request):
    if request.node.get_closest_marker("allow_network"):
        return

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def _guard(real):
        def wrapper(self, address, *args, **kwargs):
            if not _is_local(address):
                raise RuntimeError(
                    f"blocked external network call to {address!r}. Tests must "
                    "be hermetic — mock the call, or mark the test "
                    "@pytest.mark.allow_network if it truly needs the internet."
                )
            return real(self, address, *args, **kwargs)

        return wrapper

    monkeypatch.setattr(socket.socket, "connect", _guard(real_connect))
    monkeypatch.setattr(socket.socket, "connect_ex", _guard(real_connect_ex))
