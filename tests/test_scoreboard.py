"""Tests for the war-journal scoreboard (titan-lab private tooling)."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent / "purple"


def _load():
    spec = importlib.util.spec_from_file_location("sb", ROOT / "scoreboard.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sb = _load()


@pytest.fixture()
def board(tmp_path):
    return sb.Scoreboard(tmp_path / "scoreboard.json")


BASE = {"scenario": "s1", "technique": "t", "check": "c1", "test": "t1"}


def test_add_persists_and_auto_ids(board):
    r1 = board.add(dict(BASE, outcome="caught"))
    r2 = board.add(dict(BASE, scenario="s2", outcome="evaded"))
    assert r1["round_id"] == "R1"
    assert r2["round_id"] == "R2"
    assert board.store.exists()
    assert len(board.load()) == 2


def test_duplicate_round_rejected(board):
    board.add(dict(BASE, round_id="R7"))
    with pytest.raises(ValueError):
        board.add(dict(BASE, round_id="R7"))


def test_required_fields_enforced(board):
    with pytest.raises(ValueError):
        board.add({"scenario": "s1"})


def test_outcome_and_confidence_validated(board):
    with pytest.raises(ValueError):
        board.add(dict(BASE, outcome="maybe"))
    with pytest.raises(ValueError):
        board.add(dict(BASE, confidence=1.5))
    with pytest.raises(ValueError):
        board.add(dict(BASE, severity="fatal"))


def test_add_accepts_missing_or_empty_confidence(board):
    r1 = board.add(dict(BASE, outcome="caught", confidence=None))
    assert r1["confidence"] is None
    r2 = board.add(dict(BASE, scenario="s2", outcome="caught", confidence=""))
    assert r2["round_id"] == "R2"


def test_metrics_compute_catch_rate(board):
    board.add(dict(BASE, threat_class="cloud", outcome="caught", status="merged", confidence=0.9))
    board.add(dict(BASE, scenario="s2", threat_class="client", outcome="evaded", status="merged",
                   confidence=0.8, check="c2", test="t2"))
    board.add(dict(BASE, scenario="s3", threat_class="cloud", outcome="partial", status="proposed"))
    m = board.metrics()
    assert m["rounds"] == 3
    assert m["decided"] == 2
    assert m["catch_rate"] == 0.5
    assert m["evasion_rate"] == 0.5
    assert m["checks_implemented"] == 2
    assert m["tests_added"] == 2
    assert set(m["classes"]) == {"cloud", "client"}
    assert m["avg_confidence"] == pytest.approx(0.85)


def test_set_fields_updates_lifecycle(board):
    board.add(dict(BASE))
    r = board.set_fields("R1", {"status": "merged", "outcome": "caught", "crossing": "public"})
    assert r["status"] == "merged"
    assert r["outcome"] == "caught"
    with pytest.raises(ValueError):
        board.set_fields("R1", {"status": "banana"})


def test_export_markdown_contains_chain_and_metrics(board):
    board.add(dict(BASE, threat_class="cloud", outcome="caught", severity="critical", confidence=0.95, status="merged"))
    md = board.to_markdown()
    assert "| Round |" in md
    assert "R1" in md
    assert "**caught**" in md
    assert "catch rate 100%" in md


def test_markdown_escapes_pipes_and_newlines(board):
    board.add(dict(BASE, scenario="pipe | here\nand newline", outcome="caught"))
    md = board.to_markdown()
    assert "pipe \\| here and newline" in md
