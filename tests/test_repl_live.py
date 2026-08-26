"""Track E — live REPL wiring (`titan session <id>` serves the agent channel).

Pins the fix that makes the REPL a real shell: for agent sessions it starts a
listener bound to the REPL's OWN JobQueue (re-binding the session's recorded
listener URL) and waits on the live queue for results. Data sessions get no
listener; a busy port degrades to a queue-only REPL, never a crash.
"""

import asyncio
import base64
import json
import socket
from pathlib import Path

import pytest
from aiohttp import ClientSession

from titan.exploit.listener import ExploitListener, JobQueue
from titan.exploit.session import SessionStore

from titan_exploit_cli import _repl_listener, cmd_session_async


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def test_repl_listener_binds_recorded_port(tmp_path: Path):
    """The REPL listener re-binds the session's recorded URL so a surviving
    agent (still polling that address) reaches the REPL's queue."""
    port = _free_port()
    store = SessionStore(tmp_path / "sessions", session_id="sess-1")
    meta = store.init_meta(
        "http://lab.local", "rce-agent", "consent/lab-local.json",
        listener_url=f"http://127.0.0.1:{port}",
    )
    listener = await _repl_listener(meta, JobQueue(), store)
    try:
        assert listener is not None
        assert listener.port == port
        # The queue is actually served over HTTP (empty poll round-trips).
        async with ClientSession() as client:
            async with client.post(
                f"{listener.bound_url}/poll", json={"sid": "sess-1"}
            ) as r:
                assert (await r.json())["job"] is None
    finally:
        if listener:
            await listener.stop()


async def test_repl_listener_none_for_data_session(tmp_path: Path):
    """sqli-extraction has no agent — no listener, no crash."""
    store = SessionStore(tmp_path / "sessions", session_id="sess-d")
    meta = store.init_meta(
        "http://lab.local", "sqli-extraction", "consent/lab-local.json"
    )
    assert await _repl_listener(meta, JobQueue(), store) is None


async def test_repl_listener_busy_port_degrades(tmp_path: Path):
    """Port already owned (operator's own listener process) -> None, not an
    exception: the REPL runs queue-only."""
    busy = ExploitListener(host="127.0.0.1", port=0)
    await busy.start()
    try:
        store = SessionStore(tmp_path / "sessions", session_id="sess-b")
        meta = store.init_meta(
            "http://lab.local", "rce-agent", "consent/lab-local.json",
            listener_url=busy.bound_url,
        )
        assert await _repl_listener(meta, JobQueue(), store) is None
    finally:
        await busy.stop()


async def test_repl_listener_none_without_meta():
    assert await _repl_listener(None, JobQueue(), None) is None  # type: ignore[arg-type]


async def test_cmd_session_live_agent_roundtrip(tmp_path: Path, monkeypatch, capsys):
    """Full `titan session <id>` flow: the REPL serves its queue over HTTP, a
    fake agent polls, executes, reports — and the REPL prints the REAL output
    (not the 'agent may be offline' stub path)."""
    port = _free_port()
    base = tmp_path / "findings" / "lab-local" / "sessions"
    store = SessionStore(base, session_id="sess-live")
    store.init_meta(
        "http://lab.local", "rce-agent", "consent/lab-local.json",
        listener_url=f"http://127.0.0.1:{port}",
    )

    lines = iter(["id", "exit"])
    monkeypatch.setattr("builtins.input", lambda _p: next(lines))

    async def fake_agent(listener_url: str, sid: str):
        # Fresh ClientSession per request: a persistent keep-alive connection
        # would make the REPL's listener.stop() (aiohttp cleanup) wait on it
        # and hang the test.
        while True:
            try:
                async with ClientSession() as client:
                    async with client.post(
                        f"{listener_url}/poll", json={"sid": sid}
                    ) as r:
                        resp = await r.json()
            except Exception:
                resp = None
            job = (resp or {}).get("job")
            if not job:
                await asyncio.sleep(0.05)
                continue
            out = base64.b64encode(b"uid=0(root) fake\n").decode("ascii")
            try:
                async with ClientSession() as client:
                    async with client.post(
                        f"{listener_url}/report",
                        json={
                            "sid": sid,
                            "job_id": job["job_id"],
                            "exit_code": 0,
                            "output": out,
                        },
                    ) as r:
                        await r.read()
            except Exception:
                pass
            await asyncio.sleep(0.05)

    repl_task = asyncio.create_task(
        cmd_session_async(["sess-live", "--store", str(tmp_path / "findings")])
    )
    # Wait for the REPL's listener to come up on the recorded port.
    for _ in range(100):
        try:
            async with ClientSession() as client:
                async with client.get(
                    f"http://127.0.0.1:{port}/agent.sh", params={"sid": "x"}
                ) as r:
                    if r.status == 200:
                        break
        except Exception:
            pass
        await asyncio.sleep(0.05)

    agent_task = asyncio.create_task(
        fake_agent(f"http://127.0.0.1:{port}", "sess-live")
    )
    try:
        await asyncio.wait_for(repl_task, timeout=30)
    finally:
        agent_task.cancel()
        try:
            await agent_task
        except (asyncio.CancelledError, Exception):
            pass

    out = capsys.readouterr().out
    assert "serving agent channel on" in out
    assert "uid=0(root) fake" in out, out  # the agent's real output, printed
    assert "agent may be offline" not in out
    transcript = store.transcript_path.read_text(encoding="utf-8")
    assert "JOB" in transcript and "RESULT" in transcript
