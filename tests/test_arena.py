"""Tests for the arena: turn machine, pause, chat, persistence, server smoke."""
import importlib.util
import json
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "purple"


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


engine = _load("arena_engine", "arena/engine.py")
server = _load("arena_server", "arena/server.py")
agents = _load("arena_agents", "arena/agents.py")


def _fresh(tmp_path):
    return engine.ArenaEngine(tmp_path / "state.json")


# ---------------------------------------------------------------------------
# turn machine
# ---------------------------------------------------------------------------

def test_idle_waits(tmp_path):
    a = _fresh(tmp_path)
    assert a.next_action() == "wait"
    a.start("http://lab")
    assert a.next_action() == "plan_red"


def test_full_round_cycle(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab", only=["SCN-007"])
    a.begin_red(["SCN-007"])
    assert a.next_action() == "wait", "red_running must wait for the executor"
    a.finish_red({"findings": 3, "verified": 2, "batch_id": "B-1"})
    assert a.next_action() == "plan_blue"
    a.begin_blue(["SPEC-1"])
    assert a.next_action() == "wait", "blue_drafting must wait for the drafter"
    a.finish_blue({"drafted": ["SPEC-1"]})
    assert a.next_action() == "next_round"
    a.next_round()
    assert a.state["round_no"] == 1
    assert a.next_action() == "plan_red", "auto round must hand back to red"


def test_pause_holds_the_fight(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.pause()
    assert a.state["paused"] is True
    assert a.next_action() == "wait"
    a.resume()
    assert a.next_action() == "plan_red"


def test_stop_closes_arena(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.stop()
    assert a.next_action() == "wait"


# ---------------------------------------------------------------------------
# chat + persistence
# ---------------------------------------------------------------------------

def test_chat_routes_and_persists(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.chat("red", "what are you doing?")
    a.chat("lobby", "who is winning?")
    assert a.state["channels"]["red"][-1]["role"] == "user"
    assert a.state["channels"]["lobby"][-1]["text"] == "who is winning?"
    b = engine.ArenaEngine(tmp_path / "state.json")
    assert len(b.state["channels"]["red"]) == 1, "state must survive reload"
    assert b.state["channels"]["red"][0]["role"] == "user"
    assert b.state["channels"]["lobby"][0]["role"] == "system"  # ARENA OPEN post


def test_log_is_capped(tmp_path):
    a = _fresh(tmp_path)
    for i in range(engine.MAX_LOG + 50):
        a.post("lobby", "system", "line " + str(i))
    assert len(a.state["channels"]["lobby"]) == engine.MAX_LOG
    assert a.state["channels"]["lobby"][-1]["text"] == "line " + str(engine.MAX_LOG + 49)


def test_summary_mentions_target_and_phase(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab.local")
    a.begin_red(["SCN-001"])
    s = a.summary_for("red")
    assert "lab.local" in s and "red_running" in s


# ---------------------------------------------------------------------------
# server smoke (offline: no provider configured, canned replies)
# ---------------------------------------------------------------------------

def _run_server(arena):
    import http.server as _hs

    handler = server._ArenaHandler
    handler.arena = arena
    httpd = _hs.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    return httpd, httpd.server_address[1]


def _get(url, data=None):
    import urllib.request

    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, r.read().decode("utf-8")


def test_state_endpoint_and_chat_offline(tmp_path):
    import urllib.error

    arena = server.ArenaServer(tmp_path / "arena_state.json")
    httpd, port = _run_server(arena)
    try:
        status, body = _get(f"http://127.0.0.1:{port}/api/arena/state")
        assert status == 200
        st = json.loads(body)
        assert st["phase"] == "idle" and "lobby" in st["channels"]

        status, body = _get(f"http://127.0.0.1:{port}/arena")
        assert status == 200 and "Titan Arena" in body

        status, body = _get(f"http://127.0.0.1:{port}/api/arena/chat",
                            json.dumps({"channel": "red", "text": "hello"}).encode())
        assert status == 200
        channels = json.loads(body)
        roles = [m["role"] for m in channels["red"]]
        assert roles[-2] == "user" and roles[-1] == "red_cross", "cross-checker must answer"
        assert "[offline]" in channels["red"][-1]["text"], "offline reply must be canned"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_pause_endpoint(tmp_path):
    arena = server.ArenaServer(tmp_path / "arena_state.json")
    httpd, port = _run_server(arena)
    try:
        _get(f"http://127.0.0.1:{port}/api/arena/pause", b"{}")
        st = json.loads(_get(f"http://127.0.0.1:{port}/api/arena/state")[1])
        assert st["paused"] is True
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_server_recovers_interrupted_phase(tmp_path):
    """A restart mid-round must roll the transient phase back to planning."""
    arena = server.ArenaServer(tmp_path / "arena_state.json")
    arena.engine.start("http://lab", only=["SCN-007"])
    arena.engine.begin_red(["SCN-007"])
    assert arena.engine.state["phase"] == "red_running"
    arena._recover()
    assert arena.engine.state["phase"] == "red_planning"
    arena.engine.begin_blue(["SPEC-1"])
    assert arena.engine.state["phase"] == "blue_drafting"
    arena._recover()
    assert arena.engine.state["phase"] == "blue_planning"


# ---------------------------------------------------------------------------
# /status - deterministic truth channel (no LLM)
# ---------------------------------------------------------------------------

def test_status_table_is_raw_state(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab.local")
    a.finish_red({"findings": 12, "verified": 12, "batch_id": "B-9",
                  "scenarios": ["SCN-007", "SCN-009", "SCN-011"]})
    table = server._status_table(a)
    assert "round=" in table and "phase=" in table
    assert "findings=12" in table and "verified=12" in table
    assert "SCN-007" in table
    assert "paused=no" in table
    assert "red:" in table and "blue:" in table


def test_status_command_bypasses_llm(tmp_path):
    arena = server.ArenaServer(tmp_path / "arena_state.json")
    arena.engine.start("http://lab.local", only=["SCN-007"])
    arena.engine.finish_red({"findings": 4, "verified": 3, "batch_id": "B-4",
                             "scenarios": ["SCN-007", "SCN-009"]})
    httpd, port = _run_server(arena)
    try:
        status, body = _get(f"http://127.0.0.1:{port}/api/arena/chat",
                            json.dumps({"channel": "red", "text": "/status"}).encode())
        assert status == 200
        channels = json.loads(body)
        last = channels["red"][-1]
        assert last["role"] == "system", "status must come from system, not the LLM"
        assert "findings=4" in last["text"] and "verified=3" in last["text"]
        assert "SCN-007" in last["text"]
        assert "[offline]" not in last["text"], "status must not be LLM prose"
    finally:
        httpd.shutdown()
        httpd.server_close()
