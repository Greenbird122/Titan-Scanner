"""PUSH-TO-100 Phase C — benchmark rig (pure scoring + scorecard).

The backing must be checkable by anyone: a challenge is HIT only when the
expected attack type was reported VERIFIED for that endpoint; an unreached
endpoint is N/A (never a false MISS); suspicious-only is a distinct partial
outcome. All scoring is pure — these tests pin exactly what the runner and
scorecard use.
"""

import json

from bench.benchmark import (
    load_manifest,
    score_challenge,
    summarize,
)
from bench.scorecard import (
    merge_runs,
    render_scorecard,
    render_table,
)
from titan.core.models import AttackType, Finding, ScanResult, Severity


def _finding(url, attack_type, tier="confirmed", verified=True, diffs=None):
    return Finding(
        target="http://127.0.0.1:5000",
        url=url,
        method="GET",
        param="id",
        location="query",
        payload="x",
        attack_type=attack_type,
        severity=Severity.HIGH,
        verified=verified,
        confidence=0.9,
        status=200,
        diffs=diffs or ["sanity_pair:boolean_confirmed"],
        tier=tier,
        evidence="confirmed",
    )


def _challenge(**over):
    base = {
        "id": "local-lab-sqli",
        "name": "SQLi",
        "endpoint": "http://127.0.0.1:5000/sqli",
        "attack_type": "SQLi",
    }
    base.update(over)
    return base


def _result(findings):
    r = ScanResult(target="http://127.0.0.1:5000", started_at=0, finished_at=1)
    r.findings = findings
    return r


# ---------------------------------------------------------------------------
# Challenge scoring (pure)
# ---------------------------------------------------------------------------

def test_hit_when_verified_matching_finding():
    ch = _challenge()
    r = _result([_finding("http://127.0.0.1:5000/sqli?id=1", AttackType.SQLI)])
    row = score_challenge(ch, r)
    assert row["outcome"] == "hit"
    assert "sanity_pair" in row["evidence"]


def test_hit_matches_substring_endpoint():
    """A finding URL that embeds the challenge endpoint (query string
    appended by the scanner) still counts as a hit."""
    ch = _challenge()
    r = _result([_finding("http://127.0.0.1:5000/sqli?id=' OR 1=1--", AttackType.SQLI)])
    assert score_challenge(ch, r)["outcome"] == "hit"


def test_miss_when_scanned_but_wrong_attack_type():
    ch = _challenge(attack_type="LFI")
    r = _result([_finding("http://127.0.0.1:5000/sqli?id=1", AttackType.SQLI)])
    row = score_challenge(ch, r)
    assert row["outcome"] == "miss"
    assert "not reported" in row["evidence"]


def test_suspicious_partial_never_counts_as_hit():
    """A suspicious-only report (behavioral signal, unverified) is NOT the
    challenge captured — it's the partial outcome."""
    ch = _challenge()
    f = _finding("http://127.0.0.1:5000/sqli?id=1", AttackType.SQLI,
                 tier="suspicious", verified=False,
                 diffs=["reflection"])
    row = score_challenge(ch, _result([f]))
    assert row["outcome"] == "suspicious"


def test_na_when_endpoint_not_reached():
    ch = _challenge()
    r = _result([_finding("http://127.0.0.1:5000/other", AttackType.SQLI)])
    row = score_challenge(ch, r)
    assert row["outcome"] == "na"
    assert "not reached" in row["evidence"]


def test_na_on_scan_error():
    ch = _challenge()
    row = score_challenge(ch, None, scan_error="Security checkpoint blocked access")
    assert row["outcome"] == "na"
    assert "checkpoint" in row["evidence"]


def test_na_on_no_result():
    row = score_challenge(_challenge(), None)
    assert row["outcome"] == "na"


# ---------------------------------------------------------------------------
# Aggregation (pure)
# ---------------------------------------------------------------------------

def test_summarize_pass_rate():
    rows = [
        {"outcome": "hit"}, {"outcome": "hit"}, {"outcome": "miss"},
        {"outcome": "na"}, {"outcome": "suspicious"},
    ]
    s = summarize(rows)
    assert s["total"] == 5
    assert s["hits"] == 2
    assert s["reachable"] == 4  # N/A excluded from denominator
    assert s["pass_rate"] == 50.0


def test_summarize_zero_reachable():
    s = summarize([{"outcome": "na"}, {"outcome": "na"}])
    assert s["pass_rate"] == 0.0
    assert s["reachable"] == 0


# ---------------------------------------------------------------------------
# Scorecard rendering (pure)
# ---------------------------------------------------------------------------

def test_render_table_columns():
    rows = [
        {"name": "SQLi", "endpoint": "/sqli", "attack_type": "SQLi",
         "outcome": "hit", "evidence": "sanity_pair"},
        {"name": "LFI", "endpoint": "/lfi", "attack_type": "LFI",
         "outcome": "na", "evidence": "endpoint not reached"},
    ]
    md = render_table(rows)
    assert "| Challenge | Endpoint | Attack type | Outcome | Evidence |" in md
    assert "**hit**" in md
    assert "**na**" in md


def test_render_scorecard_summary():
    benchmark = {
        "target": "http://127.0.0.1:5000",
        "scanned_at": "2026-08-16T10:00:00",
        "scan_seconds": 42,
        "rows": [{"name": "SQLi", "endpoint": "/sqli", "attack_type": "SQLi",
                  "outcome": "hit", "evidence": "sanity_pair"}],
        "summary": {"pass_rate": 100.0, "hits": 1, "reachable": 1,
                    "suspicious": 0, "misses": 0, "na": 0},
    }
    md = render_scorecard(benchmark)
    assert "Pass rate" in md
    assert "100.0%" in md
    assert "methodology" in md.lower()


def test_merge_runs_keeps_best_outcome():
    prev = {"rows": [
        {"id": "a", "outcome": "miss"}, {"id": "b", "outcome": "na"},
    ], "runs": 1}
    new = {"rows": [
        {"id": "a", "outcome": "hit"}, {"id": "b", "outcome": "miss"},
    ], "scanned_at": "t2"}
    merged = merge_runs(prev, new)
    by_id = {r["id"]: r["outcome"] for r in merged["rows"]}
    assert by_id == {"a": "hit", "b": "miss"}
    assert merged["runs"] == 2


def test_manifest_load(tmp_path):
    mf = tmp_path / "m.json"
    mf.write_text(json.dumps({"challenges": [{"id": "x"}]}), encoding="utf-8")
    out = load_manifest(str(mf))
    assert out["challenges"] == [{"id": "x"}]
    assert out["target"] == ""


def test_manifest_load_with_target(tmp_path):
    mf = tmp_path / "m.json"
    mf.write_text(json.dumps({"target": "http://127.0.0.1:3000",
                              "challenges": [{"id": "x"}]}), encoding="utf-8")
    out = load_manifest(str(mf))
    assert out["target"] == "http://127.0.0.1:3000"
    assert out["challenges"] == [{"id": "x"}]
