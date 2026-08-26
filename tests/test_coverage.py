"""PUSH-TO-100 A3 — coverage-complete stop and the coverage verdict.

Contract (spec D6): the scan proves it covered the discovered surface and
reports `coverage: complete` + stops instead of running the clock; a
`coverage: partial` outcome MUST say WHY (checkpoint, crawl budget, driver
death, max_pages cap, API cap, depth cap). Every verdict is auditable — the
raw counters ride along in the same dict.

The verdict logic lives in titan.verify.coverage.finalize_coverage (pure), so
these tests pin the REAL function the engine calls — never a copy.
"""

import pytest

from titan.core.models import AttackType, Finding, ScanResult, Severity
from titan.reporting import SiteReportWriter
from titan.verify.coverage import finalize_coverage


def _coverage(**overrides):
    """A coverage counter dict in its default (all-clear) state."""
    base = {
        "urls_crawled": 3,
        "duplicate_bodies_skipped": 1,
        "endpoint_groups_run": 12,
        "apis_discovered": 8,
        "apis_scanned": 8,
        "params_discovered": 14,
        "fuzz_budget_spent": 0.0,
        "queue_exhausted": True,
        "capped_max_pages": False,
        "capped_depth": False,
        "capped_apis": False,
        "crawl_timed_out": False,
        "checkpoint_blocked": False,
    }
    base.update(overrides)
    return base


def _verdict(**coverage):
    return finalize_coverage(
        _coverage(**coverage),
        driver_dead=False,
        max_pages=5,
        max_depth=2,
    )


# ---------------------------------------------------------------------------
# Verdict logic
# ---------------------------------------------------------------------------

def test_complete_when_queue_drained_and_nothing_capped():
    cov = _verdict()
    assert cov["status"] == "complete"
    assert "drained" in cov["reason"]


def test_checkpoint_is_partial_with_reason():
    cov = _verdict(checkpoint_blocked=True)
    assert cov["status"] == "partial"
    assert "checkpoint" in cov["reason"]


def test_crawl_timeout_is_partial_with_reason():
    cov = _verdict(crawl_timed_out=True)
    assert cov["status"] == "partial"
    assert "timeout" in cov["reason"] or "budget" in cov["reason"]


def test_driver_death_is_partial_with_reason():
    cov = finalize_coverage(
        _coverage(), driver_dead=True, max_pages=5, max_depth=2
    )
    assert cov["status"] == "partial"
    assert "driver" in cov["reason"]


def test_max_pages_cap_is_partial_with_reason():
    cov = _verdict(queue_exhausted=False, capped_max_pages=True)
    assert cov["status"] == "partial"
    assert "max_pages" in cov["reason"]
    assert "5" in cov["reason"]  # the cap value is named


def test_api_cap_is_partial_with_reason():
    cov = _verdict(capped_apis=True)
    assert cov["status"] == "partial"
    assert "endpoints never ran" in cov["reason"]


def test_depth_cap_is_partial_with_reason():
    cov = _verdict(capped_depth=True)
    assert cov["status"] == "partial"
    assert "depth" in cov["reason"]


def test_priority_checkpoint_beats_budget():
    cov = _verdict(checkpoint_blocked=True, crawl_timed_out=True)
    assert "checkpoint" in cov["reason"]


def test_counters_ride_along_auditable():
    cov = _verdict(urls_crawled=7, params_discovered=22)
    assert cov["urls_crawled"] == 7
    assert cov["params_discovered"] == 22
    assert cov["endpoint_groups_run"] == 12
    # the input dict is untouched (returns a copy)
    assert finalize_coverage(_coverage())["status"] == "complete"


# ---------------------------------------------------------------------------
# Report surface
# ---------------------------------------------------------------------------

def _result_with_coverage(coverage):
    f = Finding(
        target="http://lab.local",
        url="http://lab.local/search",
        method="GET",
        param="q",
        location="query",
        payload="' OR 1=1--",
        attack_type=AttackType.SQLI,
        severity=Severity.HIGH,
        verified=True,
        confidence=0.95,
        status=200,
        tier="confirmed",
        evidence="confirmed",
        diffs=["sanity_pair:boolean_confirmed"],
    )
    result = ScanResult(target="http://lab.local", started_at=0, finished_at=5, findings=[f])
    # Mirror the engine: the verdict is computed from the counters before the
    # report writer ever sees the dict.
    result.coverage = finalize_coverage(
        _coverage(**coverage), driver_dead=False, max_pages=5, max_depth=2
    )
    return result


def test_report_surfaces_coverage_line(tmp_path):
    result = _result_with_coverage({})
    writer = SiteReportWriter(output_dir=str(tmp_path))
    site_dir = writer.write(result)

    report = (site_dir / "report.md").read_text(encoding="utf-8")
    assert "**Coverage**" in report
    assert "`complete`" in report
    assert "URLs crawled" in report
    assert "endpoint groups" in report

    meta = (site_dir / "scan_meta.json").read_text(encoding="utf-8")
    assert '"coverage"' in meta
    assert '"status": "complete"' in meta


def test_report_partial_coverage_names_reason(tmp_path):
    result = _result_with_coverage({"capped_max_pages": True, "queue_exhausted": False})
    writer = SiteReportWriter(output_dir=str(tmp_path))
    site_dir = writer.write(result)

    report = (site_dir / "report.md").read_text(encoding="utf-8")
    assert "`partial`" in report
    assert "max_pages cap" in report


def test_no_coverage_no_line(tmp_path):
    result = ScanResult(target="http://lab.local", started_at=0, finished_at=1)
    writer = SiteReportWriter(output_dir=str(tmp_path))
    site_dir = writer.write(result)

    report = (site_dir / "report.md").read_text(encoding="utf-8")
    assert "**Coverage**" not in report
