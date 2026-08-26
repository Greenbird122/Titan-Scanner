"""Grounding layer tests: roast gating, fact-pinning, numeric cross-check."""
import importlib.util
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
# fact-pinning contract
# ---------------------------------------------------------------------------

def test_grounding_rule_defined_and_fact_binding():
    assert len(agents.GROUNDING_RULE) > 40
    assert "FACTS" in agents.GROUNDING_RULE
    assert "never about numbers" in agents.GROUNDING_RULE


# ---------------------------------------------------------------------------
# numeric cross-check
# ---------------------------------------------------------------------------

def test_check_numbers_clean_when_facts_only():
    summary = ("round=10 | phase=red_done | last_findings=2 | verified=2 "
               "| lead=done | target=http://127.0.0.1:5000")
    assert server.check_numbers("2 verified findings in round 10",
                                summary) == []
    # target port is NOT a fact - mentioning it is now flagged
    assert server.check_numbers("2 verified, port 5000", summary) == [5000]


def test_check_numbers_flags_zero_and_one_despite_ip_target():
    summary = ("round=10 | phase=red_done | last_findings=2 | verified=2 "
               "| lead=done | target=http://127.0.0.1:5000")
    assert server.check_numbers("we found 1 more this time", summary) == [1]
    assert server.check_numbers("that leaves 0 findings", summary) == [0]


def test_check_numbers_flags_invented_counts():
    summary = ("round=10 | phase=red_done | last_findings=2 | verified=2 "
               "| lead=done | target=http://127.0.0.1:5000")
    assert server.check_numbers("we found 5 more this time", summary) == [5]
    assert server.check_numbers("took down SCN-007 cleanly",
                                summary + " | scenarios=SCN-007,SCN-009") == []


# ---------------------------------------------------------------------------
# roast gating
# ---------------------------------------------------------------------------

def test_red_banter_silent_on_zero_findings(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.finish_red({"findings": 0, "verified": 0, "batch_id": None, "error": None})
    posts = server.red_round_banter(a, {"findings": 0, "verified": 0}, 0)
    assert [r for _, r, _ in posts] == ["system"]
    assert "Quiet round" in posts[0][2]
    assert a.state["channels"]["lobby"][-1]["role"] == "system"


def test_red_banter_error_posts_only_system(tmp_path):
    a = _fresh(tmp_path)
    posts = server.red_round_banter(a, {"error": "no lab reachable", "findings": 0}, 0)
    assert [r for _, r, _ in posts] == ["system"]
    assert "error" in posts[0][2].lower()
    assert a.state["channels"]["lobby"][-1]["role"] == "system"


def test_red_banter_posts_roasts_on_findings(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.finish_red({"findings": 3, "verified": 2, "batch_id": "B-9"})
    posts = server.red_round_banter(a, {"findings": 3, "verified": 2}, 1)
    assert [r for _, r, _ in posts] == ["red_cross", "blue_cross"]
    assert a.state["channels"]["lobby"][-1]["role"] == "blue_cross"


def test_blue_banter_silent_when_nothing_absorbed(tmp_path):
    a = _fresh(tmp_path)
    a.finish_blue({"drafted": [], "count": 0})
    posts = server.blue_round_banter(a, {"drafted": [], "count": 0}, 0)
    assert [r for _, r, _ in posts] == ["system"]
    assert "nothing new" in posts[0][2]


def test_blue_banter_posts_when_drafted(tmp_path):
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.finish_blue({"drafted": ["SPEC-1"], "count": 1})
    posts = server.blue_round_banter(a, {"drafted": ["SPEC-1"], "count": 1}, 0)
    assert [r for _, r, _ in posts] == ["blue_cross", "red_cross"]


# ---------------------------------------------------------------------------
# grounded wrapper
# ---------------------------------------------------------------------------

def test_grounded_degrades_to_facts_when_numbers_fail(tmp_path, monkeypatch):
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.finish_red({"findings": 2, "verified": 2, "batch_id": "B-1"})
    monkeypatch.setattr(server.arena_llm, "chat",
                        lambda *a, **k: "we found 99 vulnerabilities")
    reply, meta = server._grounded(a, "red", agents.RED_CROSS_SYSTEM, "status?",
                                     agents.OFFLINE_ACKS, 0, "chat")
    assert reply.startswith("[grounded]")
    assert "round=" in reply
    assert meta["provenance"] == "canned"


def test_grounded_passes_clean_reply(tmp_path, monkeypatch):
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.finish_red({"findings": 2, "verified": 2, "batch_id": "B-1"})
    monkeypatch.setattr(server.arena_llm, "chat",
                        lambda *a, **k: "2 verified findings, as reported.")
    reply, meta = server._grounded(a, "red", agents.RED_CROSS_SYSTEM, "status?",
                                     agents.OFFLINE_ACKS, 0, "chat")
    assert reply == "2 verified findings, as reported. [r0]"
    assert meta["provenance"] == "grounded"


def test_grounded_strict_retry_rescues(tmp_path, monkeypatch):
    a = _fresh(tmp_path)
    a.start("http://lab")
    a.finish_red({"findings": 2, "verified": 2, "batch_id": "B-1"})
    calls = {"n": 0}

    def fake(system, user, fallback):
        calls["n"] += 1
        if calls["n"] == 1:
            return "we found 99 problems"
        return "2 verified findings, nothing more."

    monkeypatch.setattr(server.arena_llm, "chat", fake)
    reply, meta = server._grounded(a, "red", agents.RED_CROSS_SYSTEM, "status?",
                                     agents.OFFLINE_ACKS, 0, "chat")
    assert calls["n"] == 2
    assert reply == "2 verified findings, nothing more. [r0]"
    assert meta["provenance"] == "rewritten"
