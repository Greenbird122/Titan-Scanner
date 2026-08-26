"""UI/UX redesign backend tests: round ledger, round-tagged messages,
provenance + trace capture, LLM heartbeat stats, static assets."""
import http.server as _hs
import importlib.util
import json
import threading
import urllib.request
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
# round ledger (M2)
# ---------------------------------------------------------------------------

def test_round_ledger_tracks_full_round(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab", only=["SCN-007"])
    a.begin_red(["SCN-007"])
    a.finish_red({"findings": 3, "verified": 2, "batch_id": "B-1",
                  "scenarios": ["SCN-007"], "error": None})
    a.finish_blue({"drafted": ["SPEC-1", "SPEC-2"], "count": 2})
    rounds = a.state["rounds"]
    assert len(rounds) == 1
    r = rounds[0]
    assert r["no"] == 0
    assert r["red"]["findings"] == 3 and r["red"]["verified"] == 2
    assert r["red"]["batch_id"] == "B-1"
    assert r["red"]["scenarios"] == ["SCN-007"]
    assert r["blue"]["drafted"] == 2
    assert r["blue"]["spec_ids"] == ["SPEC-1", "SPEC-2"]
    assert r["ts_start"] and r["ts_end"]
    assert r["phase"] == "blue_done"


def test_round_ledger_caps_at_50(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab")
    for _ in range(60):
        a.begin_red(["SCN-007"])
        a.finish_red({"findings": 1, "verified": 1, "batch_id": "B"})
        a.finish_blue({"drafted": [], "count": 0})
        a.next_round()
    assert len(a.state["rounds"]) == engine.MAX_ROUNDS == 50
    assert a.state["rounds"][0]["no"] == 10, "oldest ledger entries must be evicted"
    assert a.state["rounds"][-1]["no"] == 59


def test_round_ledger_counts_llm_calls(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.begin_red(["SCN-007"])
    a.note_llm_call()
    a.note_llm_call()
    a.finish_red({"findings": 1, "verified": 1, "batch_id": "B"})
    assert a.state["rounds"][0]["llm_calls"] == 2


def test_messages_are_round_tagged(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.chat("red", "hello")
    a.next_round()  # round 1
    a.chat("red", "again")
    msgs = a.state["channels"]["red"]
    assert msgs[-1]["round"] == 1, "message after next_round must carry round 1"
    assert a.state["channels"]["lobby"][-1]["round"] == 1  # "ROUND 1 begins" post


# ---------------------------------------------------------------------------
# provenance + trace capture (M1)
# ---------------------------------------------------------------------------

def test_provenance_and_trace_stored_on_post(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab")
    trace = {"facts": "round=0", "calls": [{"ms": 42, "ok": True, "reply": "hi"}]}
    a.post("red", "red_cross", "hello there", provenance="grounded", trace=trace)
    m = a.state["channels"]["red"][-1]
    assert m["provenance"] == "grounded"
    assert m["trace"]["facts"] == "round=0"
    assert m["round"] == 0
    # system posts carry no provenance
    assert "provenance" not in a.state["channels"]["lobby"][0]


def test_trace_cap_keeps_newest_20(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab")
    for i in range(25):
        a.post("red", "red_cross", "msg " + str(i),
               provenance="grounded", trace={"n": i})
    msgs = a.state["channels"]["red"]
    traced = [m for m in msgs if m.get("trace")]
    assert len(traced) == engine.TRACE_CAP == 20
    assert traced[0]["trace"]["n"] == 5, "oldest 5 traces must be nulled"
    assert traced[-1]["trace"]["n"] == 24


# ---------------------------------------------------------------------------
# LLM heartbeat stats (M1)
# ---------------------------------------------------------------------------

def test_llm_stats_record_calls_and_cap(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab")
    for i in range(120):
        server._record_llm_call(a, "lobby", 100 + i, True, "grounded")
    stats = a.state["llm_stats"]
    assert len(stats["log"]) == server.LLM_LOG_CAP == 100
    assert stats["calls_ok"] == 120
    assert stats["calls_total"] == 120
    assert stats["last_ms"] == 219
    assert stats["last_result"] == "grounded"
    assert stats["log"][-1]["channel"] == "lobby"


def test_llm_stats_track_failures(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab")
    server._record_llm_call(a, "red", 10, False, "error")
    stats = a.state["llm_stats"]
    assert stats["calls_fail"] == 1
    assert stats["last_result"] == "error"


def test_llm_stats_in_flight_flag(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab")
    server._llm_stats(a)["in_flight"] = True
    assert a.state["llm_stats"]["in_flight"] is True
    server._llm_stats(a)["in_flight"] = False
    assert a.state["llm_stats"]["in_flight"] is False


# ---------------------------------------------------------------------------
# grounded wrapper returns provenance + trace (M1)
# ---------------------------------------------------------------------------

def test_grounded_returns_meta(tmp_path, monkeypatch):
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.finish_red({"findings": 2, "verified": 2, "batch_id": "B-1"})
    monkeypatch.setattr(server.arena_llm, "chat",
                        lambda *x, **k: "2 verified findings, as reported.")
    text, meta = server._grounded(a, "red", agents.RED_CROSS_SYSTEM, "status?",
                                  agents.OFFLINE_ACKS, 0, "chat", "red")
    assert meta["provenance"] == "grounded"
    assert meta["trace"]["facts"]
    assert len(meta["trace"]["calls"]) == 1
    assert "2 verified findings" in text


def test_grounded_records_call_log(tmp_path, monkeypatch):
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.finish_red({"findings": 2, "verified": 2, "batch_id": "B-1"})
    monkeypatch.setattr(server.arena_llm, "chat",
                        lambda *x, **k: "2 verified findings, as reported.")
    server._grounded(a, "red", agents.RED_CROSS_SYSTEM, "status?",
                     agents.OFFLINE_ACKS, 0, "chat", "red")
    log = a.state["llm_stats"]["log"]
    assert log and log[-1]["channel"] == "red"
    assert log[-1]["result"] == "grounded"
    assert log[-1]["ms"] >= 0


def test_grounded_canned_records_fallback(tmp_path, monkeypatch):
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.finish_red({"findings": 2, "verified": 2, "batch_id": "B-1"})
    # provider "fails": returns the fallback line itself -> canned
    monkeypatch.setattr(server.arena_llm, "chat",
                        lambda system, user, fallback: fallback)
    text, meta = server._grounded(a, "red", agents.RED_CROSS_SYSTEM, "status?",
                                  agents.OFFLINE_ACKS, 0, "chat", "lobby")
    assert meta["provenance"] == "canned"
    assert "[offline]" in text
    assert a.state["llm_stats"]["log"][-1]["result"] == "canned"


def test_round_banter_posts_provenance(tmp_path, monkeypatch):
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.finish_red({"findings": 3, "verified": 2, "batch_id": "B-9"})
    monkeypatch.setattr(server.arena_llm, "chat",
                        lambda *x, **k: "we found 3 verified findings.")
    server.red_round_banter(a, {"findings": 3, "verified": 2}, 1)
    lobby = a.state["channels"]["lobby"]
    # red_cross roasts with red facts in scope -> grounded; the blue rebuttal
    # claims red's numbers without blue facts -> correctly flagged by the layer
    red_post = lobby[-2]
    assert red_post["role"] == "red_cross"
    assert red_post["provenance"] == "grounded"
    assert red_post["round"] == 0
    assert lobby[-1]["role"] == "blue_cross"
    assert lobby[-1]["round"] == 0


# ---------------------------------------------------------------------------
# static assets + page skeleton
# ---------------------------------------------------------------------------

def _run_server(arena):
    handler = server._ArenaHandler
    handler.arena = arena
    httpd = _hs.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    return httpd, httpd.server_address[1]


def test_static_assets_served(tmp_path):
    arena = server.ArenaServer(tmp_path / "arena_state.json")
    httpd, port = _run_server(arena)
    try:
        for path, ctype in (("/arena.css", "text/css"),
                            ("/arena.js", "text/javascript")):
            with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path),
                                        timeout=5) as r:
                assert r.status == 200
                assert ctype in r.headers["Content-Type"]
                assert len(r.read()) > 200
        with urllib.request.urlopen("http://127.0.0.1:%d/arena" % port,
                                    timeout=5) as r:
            html = r.read().decode("utf-8")
            assert 'href="arena.css"' in html
            assert 'src="arena.js"' in html
            for needle in ("scoreband", "stepper", "drawer", "llmLogBtn"):
                assert needle in html, "skeleton missing: " + needle
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_llm_stats_migrates_partial_old_state(tmp_path):
    """A state file with a bare llm_stats dict (pre-upgrade) must be
    padded to the full shape so recording never KeyErrors."""
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.state["llm_stats"] = {"online": True, "in_flight": False}
    server._llm_stats(a)  # defensive fill
    assert a.state["llm_stats"]["log"] == []
    assert a.state["llm_stats"]["calls_total"] == 0
    server._record_llm_call(a, "lobby", 5, True, "grounded")
    assert len(a.state["llm_stats"]["log"]) == 1
    assert a.state["llm_stats"]["calls_total"] == 1


def test_state_exposes_rounds_and_llm_stats(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.begin_red(["SCN-007"])
    a.finish_red({"findings": 2, "verified": 2, "batch_id": "B-1"})
    st = a.state
    assert isinstance(st.get("rounds"), list)
    assert isinstance(st.get("llm_stats"), dict)
    assert st["llm_stats"]["online"] is False
    assert st["rounds"][0]["red"]["verified"] == 2
