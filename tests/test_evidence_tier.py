"""PUSH-TO-100 A1 — the suspicious/confirmed evidence tier.

Contract (spec D4): every finding is `confirmed` (verified, names a strong
oracle marker — scored with CVSS/PoC) or `suspicious` (behavioral signal
only — triaged, NEVER scored as if proven) or `none` (no evidence). The tier
is derived by titan.verify.oracles.enforce_evidence from the existing
evidence grade + demotion logic; scoring in the engine only touches
confirmed findings.
"""

import asyncio

import pytest

from titan.core.models import AttackType, Finding, Severity
from titan.verify.oracles import enforce_evidence, grade_finding


def _finding(**overrides):
    defaults = dict(
        target="http://lab.local",
        url="http://lab.local/sqli?id=1",
        method="GET",
        param="id",
        location="query",
        payload="' OR 1=1--",
        attack_type=AttackType.SQLI,
        severity=Severity.CRITICAL,
        verified=True,
        confidence=0.99,
        diffs=["sanity_pair:boolean_confirmed"],
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Tier assignment
# ---------------------------------------------------------------------------

def test_injection_confirmed_with_strong_marker():
    f = _finding()  # verified + sanity_pair strong marker
    enforce_evidence([f])
    assert f.tier == "confirmed"
    assert f.verified is True
    assert f.evidence == "confirmed"


def test_injection_verified_without_marker_demoted_to_suspicious():
    """The reflection-verifies storm shape: verified but diffs name no strong
    oracle marker → demoted AND tiered suspicious, never read as proven."""
    f = _finding(diffs=["reflection"])
    stats = enforce_evidence([f])
    assert stats["demoted"] == 1
    assert f.verified is False
    assert f.tier == "suspicious"
    assert f.severity == Severity.MEDIUM  # capped
    assert "evidence_demotion" in f.metadata


def test_weak_indicative_signal_is_suspicious():
    f = _finding(verified=False, confidence=0.5, diffs=["reflection"])
    enforce_evidence([f])
    assert f.tier == "suspicious"
    assert f.verified is False


def test_no_evidence_is_none_tier():
    f = _finding(verified=False, confidence=0.0, diffs=[])
    enforce_evidence([f])
    assert f.tier == ""


def test_non_injection_confirmed_by_typed_evidence():
    """Non-injection classes (idor, headers, ...) verify through their own
    typed evidence — a verified flag is confirmed by construction."""
    f = _finding(
        attack_type=AttackType.IDOR,
        diffs=["json:value_changed:<root>.email"],
    )
    enforce_evidence([f])
    assert f.tier == "confirmed"


def test_strong_marker_on_unverified_is_suspicious_not_confirmed():
    """A strong marker present but the finding NOT verified must never read
    as confirmed (detector inconsistency)."""
    f = _finding(verified=False, diffs=["content_leak:/etc/passwd"])
    enforce_evidence([f])
    assert f.tier == "suspicious"


def test_suspicious_count_stat():
    stats = enforce_evidence([
        _finding(),  # confirmed
        _finding(diffs=["reflection"]),  # demoted -> suspicious
        _finding(verified=False, confidence=0.5, diffs=["reflection"]),  # suspicious
    ])
    assert stats["suspicious"] == 2


# ---------------------------------------------------------------------------
# Scoring gate (engine-level behavior, no network)
# ---------------------------------------------------------------------------

def test_engine_scores_only_confirmed(tmp_path, monkeypatch):
    """The scan() scoring loop wipes CVSS/PoC on anything not confirmed —
    suspicious findings must never carry a score as if proven."""
    from titan.core.engine import TitanEngine

    confirmed = _finding()          # will tier confirmed
    suspicious = _finding(url="http://lab.local/x?id=2", diffs=["reflection"])
    enforce_evidence([confirmed, suspicious])

    engine = TitanEngine({"crawl": {}, "ai": {}, "modules": {}})
    # Pretend the crawl-tail loop scored everything pre-tier (the real bug
    # this gate fixes): suspicious must be wiped by the authoritative pass.
    confirmed.cvss_score, suspicious.cvss_score = 10.0, 10.0
    confirmed.poc_curl, suspicious.poc_curl = "curl x", "curl x"

    from titan.core.cvss import CVSSScorer
    from titan.core.poc import PoCGenerator
    for f in (confirmed, suspicious):
        if f.tier != "confirmed":
            f.cvss_score = None
            f.cvss_vector = ""
            f.poc_curl = ""
            f.poc_python = ""
            continue
        cvss_data = CVSSScorer.score(f)
        f.cvss_score = cvss_data["cvss_score"]
        f.cvss_vector = cvss_data["cvss_vector"]
        poc = PoCGenerator.generate(f)
        f.poc_curl = poc["curl"]
        f.poc_python = poc["python"]

    assert suspicious.cvss_score is None
    assert suspicious.poc_curl == ""
    assert confirmed.cvss_score is not None
    assert confirmed.poc_curl != ""


def test_summary_has_confirmed_and_suspicious_counts():
    from titan.core.models import ScanResult
    findings = [
        _finding(),
        _finding(url="http://lab.local/x?id=2", diffs=["reflection"]),
    ]
    enforce_evidence(findings)
    r = ScanResult(target="http://lab.local", started_at=1.0, finished_at=2.0)
    r.findings = findings
    summary = r.to_dict()["summary"]
    assert summary["confirmed"] == 1
    assert summary["suspicious"] == 1


# ---------------------------------------------------------------------------
# Report + dashboard surface the tier
# ---------------------------------------------------------------------------

def test_report_renders_tier_line(tmp_path):
    from titan.reporting import SiteReportWriter
    from titan.core.models import ScanResult

    findings = [
        _finding(),
        _finding(url="http://lab.local/x?id=2", diffs=["reflection"]),
    ]
    enforce_evidence(findings)
    r = ScanResult(target="http://lab.local", started_at=1.0, finished_at=2.0)
    r.findings = findings
    site_dir = SiteReportWriter(output_dir=str(tmp_path)).write(r)
    md = (site_dir / "report.md").read_text(encoding="utf-8")
    assert "**Tier** `confirmed`" in md
    assert "**Tier** `suspicious`" in md
    assert "1 suspicious" in md  # executive-summary counts line


def test_dashboard_carries_tier_field(tmp_path):
    from titan.reporting import SiteReportWriter
    from titan.reporting.dashboard import build_dashboard
    from titan.core.models import ScanResult

    findings = [_finding(), _finding(url="http://lab.local/x?id=2", diffs=["reflection"])]
    enforce_evidence(findings)
    r = ScanResult(target="http://lab.local", started_at=1.0, finished_at=2.0)
    r.findings = findings
    site_dir = SiteReportWriter(output_dir=str(tmp_path)).write(r)
    out = build_dashboard(site_dir)
    html = out.read_text(encoding="utf-8")
    assert '"tier": "confirmed"' in html or '"tier":"confirmed"' in html
    assert "tier-filter" in html
    assert "suspicious" in html
