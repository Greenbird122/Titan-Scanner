"""Track E — remote REPL join: drive a survivor through ANOTHER process's
listener over HTTP (POST /job + GET /job/<id>).

This completes M5's persistence story: after `reattach` re-points channels at
a listener the operator keeps up, a fresh `titan session <id> --listener-url
URL` can drive them from a new process — no port handoff, no local listener.
Covers the /job endpoints, the RemoteQueue adapter (roundtrip + timeout), and
the full CLI path against a live listener + fake agent.
"""

import asyncio
import base64
import builtins
import socket
import time
from pathlib import Path

import pytest
from aiohttp import ClientSession

from titan.exploit.listener import ExploitListener, JobQueue, RemoteQueue
from titan.exploit.session import SessionStore

from titan_exploit_cli import cmd_session_async


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _fake_agent(base: str, sid: str):
    """Poll -> echo command -> report, mirroring the real bash agent's loop."""
    for _ in range(60):
        resp = None
        async with ClientSession() as c:
            try:
                async with c.post(f"{base}/poll", json={"sid": sid}) as r:
                    resp = await r.json()
            except Exception:
                await asyncio.sleep(0.1)
                continue
        job = (resp or {}).get("job")
        if not job:
            await asyncio.sleep(0.1)
            continue
        cmd = job.get("command", "")
        out = base64.b64encode(f"executed:{cmd}".encode("utf-8")).decode("ascii")
        async with ClientSession() as c:
            await c.post(
                f"{base}/report",
                json={"sid": sid, "job_id": job["job_id"], "exit_code": 0, "output": out},
            )


async def _session_store(tmp_path: Path, sid: str, port: int) -> SessionStore:
    store = SessionStore(tmp_path / "findings" / "lab-local" / "sessions", session_id=sid)
    store.init_meta(
        "http://lab.local",
        "http-poll",
        "consent/lab-local.json",
        listener_url=f"http://127.0.0.1:{port}",
        extra={"finding": {"url": "http://lab.local/cmd", "method": "GET", "param": "host"}},
    )
    return store


# ---------------------------------------------------------------------------
# Listener /job endpoints
# ---------------------------------------------------------------------------


async def test_job_endpoints_roundtrip():
    q = JobQueue()
    listener = ExploitListener(host="127.0.0.1", port=0, queue=q)
    await listener.start()
    try:
        base = listener.bound_url
        async with ClientSession() as c:
            # submit -> 201 + job_id
            async with c.post(f"{base}/job", json={"sid": "s-x", "command": "id"}) as r:
                assert r.status == 201
                job_id = (await r.json())["job_id"]
            # pending until claimed by the agent
            async with c.get(f"{base}/job/{job_id}") as r:
                assert (await r.json())["status"] == "pending"
            # validation: missing command / unknown job
            async with c.post(f"{base}/job", json={"sid": "s-x", "command": ""}) as r:
                assert r.status == 400
            async with c.get(f"{base}/job/nope") as r:
                assert r.status == 404
            # agent claims + reports over HTTP (exercises the base64 decode)
            job = await q.poll("s-x")
            assert job["command"] == "id"
            out = base64.b64encode(b"uid=0(root)").decode("ascii")
            async with c.post(
                f"{base}/report",
                json={"sid": "s-x", "job_id": job_id, "exit_code": 0, "output": out},
            ) as r:
                assert (await r.json())["ok"] is True
            # result readable, output decoded back to text
            async with c.get(f"{base}/job/{job_id}") as r:
                data = await r.json()
            assert data["result"]["exit_code"] == 0
            assert data["result"]["output"] == "uid=0(root)"
    finally:
        await listener.stop()


# ---------------------------------------------------------------------------
# RemoteQueue adapter
# ---------------------------------------------------------------------------


async def test_remote_queue_roundtrip():
    q = JobQueue()
    listener = ExploitListener(host="127.0.0.1", port=0, queue=q)
    await listener.start()
    agent = None
    try:
        rq = RemoteQueue(listener.bound_url)
        job_id = await rq.submit("s-x", "echo hi")
        agent = asyncio.create_task(_fake_agent(listener.bound_url, "s-x"))
        result = await asyncio.wait_for(rq.wait_result(job_id, timeout=15), timeout=20)
        assert result["output"] == "executed:echo hi"
        assert result["exit_code"] == 0
    finally:
        if agent:
            agent.cancel()
        await listener.stop()


async def test_remote_queue_timeout_returns_none():
    q = JobQueue()
    listener = ExploitListener(host="127.0.0.1", port=0, queue=q)
    await listener.start()
    try:
        rq = RemoteQueue(listener.bound_url)
        job_id = await rq.submit("s-x", "sleep 60")  # nobody reports it
        t0 = time.monotonic()
        result = await rq.wait_result(job_id, timeout=0.7)
        assert result is None  # None, not a raise: the REPL prints "no result"
        assert time.monotonic() - t0 < 5
    finally:
        await listener.stop()


# ---------------------------------------------------------------------------
# Full CLI path: session <id> --listener-url <URL>
# ---------------------------------------------------------------------------


async def test_cmd_session_remote_join(tmp_path: Path, capsys):
    port = _free_port()
    store = await _session_store(tmp_path, "s-rem", port)
    q = JobQueue()
    listener = ExploitListener(host="127.0.0.1", port=port, queue=q)
    await listener.start()
    orig_input = builtins.input
    lines = iter(["id", "exit"])
    builtins.input = lambda _p: next(lines)
    agent = asyncio.create_task(_fake_agent(listener.bound_url, "s-rem"))
    try:
        code = await asyncio.wait_for(
            cmd_session_async(
                ["s-rem", "--store", str(tmp_path / "findings"),
                 "--listener-url", listener.bound_url]
            ),
            timeout=30,
        )
        assert code == 0
    finally:
        builtins.input = orig_input
        agent.cancel()
        await listener.stop()
    out = capsys.readouterr().out
    assert "joined remote listener" in out
    assert "executed:id" in out  # real output streamed back through HTTP
    text = store.transcript_path.read_text(encoding="utf-8")
    assert "JOB" in text and "RESULT" in text


async def test_cmd_session_remote_join_dead_listener_fails_soft(tmp_path: Path, capsys):
    """A dead remote listener must not crash the REPL — submit fails soft."""
    port = _free_port()
    await _session_store(tmp_path, "s-dead", port)
    orig_input = builtins.input
    lines = iter(["ls", "exit"])
    builtins.input = lambda _p: next(lines)
    try:
        code = await asyncio.wait_for(
            cmd_session_async(
                ["s-dead", "--store", str(tmp_path / "findings"),
                 "--listener-url", f"http://127.0.0.1:{port}"]
            ),
            timeout=30,
        )
        assert code == 0
    finally:
        builtins.input = orig_input
    out = capsys.readouterr().out
    assert "submit failed" in out
