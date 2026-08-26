"""Track E M5 tests — reattach planner (persistence across operator restart).

Covers: webshell re-point via the ?rep= protocol, agent re-stage through the
original injection point with the same session id, the consent gate
(no consent / wrong flag), scope + session-id filtering, fail-soft behavior
(a dead channel never aborts the rest), --listener-url mode, the verify ping,
and the CLI dispatch.
"""

import asyncio
import json
from pathlib import Path
from urllib.parse import unquote

import pytest
from aiohttp import ClientSession, web

from titan.exploit.consent import ConsentError, create_consent, write_consent
from titan.exploit.listener import ExploitListener
from titan.exploit.reattach import REATTACH_TOKEN, list_target_sessions, reattach_target
from titan.exploit.session import SessionStore

from titan_exploit_cli import cmd_reattach_async


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _ws_server(status: int = 200):
    """A fake webshell: ?rep= decodes + acks; anything else answers probe."""
    captured = {}

    async def handle(request: web.Request) -> web.Response:
        rep = request.query.get("rep")
        if rep:
            captured["rep"] = json.loads(rep)
            if status >= 400:
                return web.Response(text="boom", status=status)
            return web.Response(text=REATTACH_TOKEN)
        return web.Response(text="t1t4n_ws_ok")

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]  # type: ignore[attr-defined]
    return f"http://127.0.0.1:{port}", runner, captured


async def _rce_endpoint():
    """A fake RCE injection point that records the re-stage query."""
    captured = {}

    async def ok(request: web.Request) -> web.Response:
        captured["query"] = request.query_string
        return web.Response(text="pong")

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", ok)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]  # type: ignore[attr-defined]
    return f"http://127.0.0.1:{port}", runner, captured


def _consent(tmp_path: Path, flags=("persistence",)):
    key = tmp_path / "k.pem"
    doc = create_consent("http://lab.local", flags=list(flags), expiry="1h", key_path=key)
    write_consent(doc, consent_dir=tmp_path / "consent")
    return key


def _store(tmp_path: Path, session_id: str, channel: str, extra=None) -> SessionStore:
    store = SessionStore(tmp_path / "findings" / "lab-local" / "sessions", session_id=session_id)
    store.init_meta(
        "http://lab.local", channel, "consent/lab-local.json",
        listener_url="http://127.0.0.1:9999",
        extra=extra,
    )
    return store


# ---------------------------------------------------------------------------
# Webshell reattach
# ---------------------------------------------------------------------------


async def test_reattach_webshell_rep(tmp_path: Path):
    ws, runner, captured = await _ws_server()
    try:
        store = _store(tmp_path, "s-1", "webshell", extra={"webshell_url": f"{ws}/uploads/titan_ws.php"})
        key = _consent(tmp_path)
        summary = await reattach_target(
            "http://lab.local",
            listener_url="http://127.0.0.1:19999",
            store_root=tmp_path / "findings",
            consent_dir=tmp_path / "consent",
            key_path=key,
        )
        assert len(summary["reattached"]) == 1 and not summary["failed"]
        assert summary["reattached"][0]["session_id"] == "s-1"
        # the ?rep= payload carried the new listener + same sid
        assert captured["rep"] == {"listener": "http://127.0.0.1:19999", "sid": "s-1"}
        # session meta: listener_url updated + event recorded
        meta = store.read_meta()
        assert meta["listener_url"] == "http://127.0.0.1:19999"
        assert meta["reattach_events"][-1]["ok"] is True
        assert "REATTACH OK" in store.transcript_path.read_text(encoding="utf-8")
    finally:
        await runner.cleanup()


async def test_reattach_webshell_failure_records_and_keeps_meta(tmp_path: Path):
    ws, runner, _ = await _ws_server(status=500)
    try:
        store = _store(tmp_path, "s-1", "webshell", extra={"webshell_url": f"{ws}/x.php"})
        key = _consent(tmp_path)
        summary = await reattach_target(
            "http://lab.local",
            listener_url="http://127.0.0.1:19999",
            store_root=tmp_path / "findings",
            consent_dir=tmp_path / "consent",
            key_path=key,
        )
        assert not summary["reattached"] and len(summary["failed"]) == 1
        meta = store.read_meta()
        assert meta["listener_url"] == "http://127.0.0.1:9999"  # unchanged
        assert meta["reattach_events"][-1]["ok"] is False
    finally:
        await runner.cleanup()


# ---------------------------------------------------------------------------
# Agent reattach
# ---------------------------------------------------------------------------


async def test_reattach_agent_reuses_same_sid_and_new_listener(tmp_path: Path):
    rce, runner, captured = await _rce_endpoint()
    try:
        store = _store(
            tmp_path, "s-2", "http-poll",
            extra={"finding": {"url": f"{rce}/cmd?host=x", "method": "GET", "param": "host"}},
        )
        key = _consent(tmp_path)
        summary = await reattach_target(
            "http://lab.local",
            listener_url="http://127.0.0.1:19999",
            store_root=tmp_path / "findings",
            consent_dir=tmp_path / "consent",
            key_path=key,
        )
        assert len(summary["reattached"]) == 1
        q = unquote(captured["query"])
        assert "agent.sh" in q and "sid=s-2" in q and "19999" in q
        meta = store.read_meta()
        assert meta["listener_url"] == "http://127.0.0.1:19999"
        assert meta["reattach_events"][-1]["ok"] is True
    finally:
        await runner.cleanup()


# ---------------------------------------------------------------------------
# Consent gate
# ---------------------------------------------------------------------------


async def test_reattach_requires_consent(tmp_path: Path):
    with pytest.raises(ConsentError, match="no consent"):
        await reattach_target(
            "http://lab.local",
            listener_url="http://127.0.0.1:19999",
            store_root=tmp_path / "findings",
            consent_dir=tmp_path / "consent",
            key_path=tmp_path / "k.pem",
        )


async def test_reattach_requires_persistence_flag(tmp_path: Path):
    _consent(tmp_path, flags=["shells"])  # persistence NOT granted
    with pytest.raises(ConsentError, match="lacks flag 'persistence'"):
        await reattach_target(
            "http://lab.local",
            listener_url="http://127.0.0.1:19999",
            store_root=tmp_path / "findings",
            consent_dir=tmp_path / "consent",
            key_path=tmp_path / "k.pem",
        )


async def test_reattach_requires_listener_or_url(tmp_path: Path):
    key = _consent(tmp_path)
    with pytest.raises(Exception, match="need a started listener"):
        await reattach_target(
            "http://lab.local",
            store_root=tmp_path / "findings",
            consent_dir=tmp_path / "consent",
            key_path=key,
        )


# ---------------------------------------------------------------------------
# Discovery / filtering
# ---------------------------------------------------------------------------


async def test_reattach_no_sessions(tmp_path: Path):
    key = _consent(tmp_path)
    summary = await reattach_target(
        "http://lab.local",
        listener_url="http://127.0.0.1:19999",
        store_root=tmp_path / "findings",
        consent_dir=tmp_path / "consent",
        key_path=key,
    )
    assert summary["reattached"] == [] and summary["failed"] == []


async def test_reattach_scope_ignores_other_targets_and_sid_filter(tmp_path: Path):
    other = SessionStore(tmp_path / "findings" / "evil-com" / "sessions", session_id="s-other")
    other.init_meta("http://evil.com", "webshell", "consent/evil-com.json",
                    listener_url="http://127.0.0.1:9999",
                    extra={"webshell_url": "http://evil.com/x.php"})
    keep = _store(tmp_path, "s-keep", "http-poll",
                  extra={"finding": {"url": "http://lab.local/cmd", "method": "GET", "param": "host"}})
    key = _consent(tmp_path)
    sessions = list_target_sessions(tmp_path / "findings", "http://lab.local")
    assert [s["session_id"] for s in sessions] == ["s-keep"]
    sessions2 = list_target_sessions(tmp_path / "findings", "http://lab.local", session_id="nope")
    assert sessions2 == []


# ---------------------------------------------------------------------------
# Fail-soft + verify
# ---------------------------------------------------------------------------


async def test_reattach_fail_soft_mixed(tmp_path: Path):
    dead, r1, _ = await _ws_server(status=500)
    live, r2, _ = await _ws_server()
    try:
        _store(tmp_path, "s-dead", "webshell", extra={"webshell_url": f"{dead}/d.php"})
        _store(tmp_path, "s-live", "webshell", extra={"webshell_url": f"{live}/l.php"})
        key = _consent(tmp_path)
        summary = await reattach_target(
            "http://lab.local",
            listener_url="http://127.0.0.1:19999",
            store_root=tmp_path / "findings",
            consent_dir=tmp_path / "consent",
            key_path=key,
        )
        assert len(summary["reattached"]) == 1 and len(summary["failed"]) == 1
    finally:
        await r1.cleanup()
        await r2.cleanup()


async def test_reattach_verify_ping_unconfirmed(tmp_path: Path):
    """verify=True with a live listener but no agent: the ping times out and
    the entry is marked verified=False — still reattached, not fatal."""
    rce, runner, _ = await _rce_endpoint()
    listener = ExploitListener(host="127.0.0.1", port=0)
    await listener.start()
    try:
        _store(tmp_path, "s-3", "http-poll",
               extra={"finding": {"url": f"{rce}/cmd", "method": "GET", "param": "host"}})
        key = _consent(tmp_path)
        summary = await reattach_target(
            "http://lab.local",
            listener=listener,
            store_root=tmp_path / "findings",
            consent_dir=tmp_path / "consent",
            key_path=key,
            verify=True,
            verify_timeout=1.0,
        )
        entry = summary["reattached"][0]
        assert entry["ok"] is True and entry["verified"] is False
        assert "ping unconfirmed" in entry["detail"]
    finally:
        await listener.stop()
        await runner.cleanup()


# ---------------------------------------------------------------------------
# CLI dispatch
# ---------------------------------------------------------------------------


async def test_cmd_reattach_usage_returns_2():
    assert await cmd_reattach_async([]) == 2


async def test_cmd_reattach_listener_url_mode(tmp_path: Path):
    ws, runner, _ = await _ws_server()
    try:
        _store(tmp_path, "s-cli", "webshell", extra={"webshell_url": f"{ws}/u.php"})
        _consent(tmp_path)
        code = await cmd_reattach_async(
            ["http://lab.local", "--listener-url", "http://127.0.0.1:19999",
             "--store", str(tmp_path / "findings"),
             "--consent-dir", str(tmp_path / "consent"),
             "--key-path", str(tmp_path / "k.pem")]
        )
        assert code == 0
    finally:
        await runner.cleanup()
