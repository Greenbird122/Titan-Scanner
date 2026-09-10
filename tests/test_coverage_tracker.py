"""Tests for titan.modules.coverage.tracker — CoverageTracker state machine.

Pure in-memory logic: recording test executions, building the coverage
matrix, and deriving summary/risk/dependency analytics. No I/O, no network.
"""

from unittest.mock import MagicMock

from titan.core.models import Finding, Severity
from titan.modules.coverage.tracker import CoverageMatrix, CoverageTracker
from titan.modules.coverage.tracker import TestRecord as TrackerTestRecord


def _finding(tags=(), notes="", url="https://t.example/api", attack_type_value="headers",
             status=200, body="", evidence="") -> Finding:
    """Minimal Finding whose tags/notes drive _extract_attack_type."""
    atk = MagicMock()
    atk.value = attack_type_value
    f = Finding(
        target="https://t.example",
        attack_type=atk,
        severity=Severity.MEDIUM,
        method="GET",
        url=url,
        param="q",
        location="query",
        payload="' OR 1=1",
        status=status,
        body=body,
        evidence=evidence,
    )
    object.__setattr__(f, "tags", list(tags))
    object.__setattr__(f, "notes", notes)
    return f


class TestRecordTest:
    def test_record_test_appends_and_indexes(self):
        t = CoverageTracker()
        t.record_test("/a", "sqli", "p", "executed", 200, "body", 12.5)
        assert len(t.get_records()) == 1
        rec = t.get_records()[0]
        assert isinstance(rec, TrackerTestRecord)
        assert rec.endpoint == "/a"
        assert rec.attack_type == "sqli"
        assert rec.status == "executed"
        assert rec.response_code == 200
        assert rec.duration_ms == 12.5
        assert t.get_endpoints() == ["/a"]
        assert t.get_attack_types() == ["sqli"]

    def test_response_hash_is_sha256_of_body(self):
        import hashlib

        t = CoverageTracker()
        t.record_test("/a", "sqli", "p", "executed", 200, "proof-body")
        expected = hashlib.sha256(b"proof-body").hexdigest()
        assert t.get_records()[0].response_hash == expected

    def test_payload_truncated_to_500_chars(self):
        t = CoverageTracker()
        t.record_test("/a", "sqli", "x" * 900, "executed", 200)
        assert len(t.get_records()[0].payload) == 500

    def test_empty_body_still_hashes(self):
        import hashlib

        t = CoverageTracker()
        t.record_test("/a", "sqli", "p", "error", 0)
        assert t.get_records()[0].response_hash == hashlib.sha256(b"").hexdigest()


class TestRecordFindings:
    def test_record_finding_maps_tags_to_attack_type(self):
        t = CoverageTracker()
        t.record_finding(_finding(tags=["sqli"]))
        rec = t.get_records()[0]
        assert rec.attack_type == "sqli"
        assert rec.status == "passed"
        assert rec.response_code == 200

    def test_record_finding_notes_fallback(self):
        t = CoverageTracker()
        t.record_finding(_finding(notes="cross-site scripting in param"))
        assert t.get_records()[0].attack_type == "xss"

    def test_record_finding_unknown_type_is_other(self):
        t = CoverageTracker()
        t.record_finding(_finding(notes="nothing recognizable here"))
        assert t.get_records()[0].attack_type == "other"

    def test_record_finding_uses_body_then_evidence_for_hash(self):
        t = CoverageTracker()
        t.record_finding(_finding(tags=["sqli"], body="resp-body"))
        t.record_finding(_finding(tags=["sqli"], body="", evidence="evi-body"))
        import hashlib

        assert (
            t.get_records()[0].response_hash
            == hashlib.sha256(b"resp-body").hexdigest()
        )
        assert (
            t.get_records()[1].response_hash
            == hashlib.sha256(b"evi-body").hexdigest()
        )

    def test_record_batch(self):
        t = CoverageTracker()
        t.record_batch([_finding(tags=["sqli"]), _finding(tags=["xss"])])
        assert t.get_attack_types() == ["sqli", "xss"]


class TestMatrix:
    def test_matrix_counts(self):
        t = CoverageTracker()
        t.record_test("/a", "sqli", "p", "passed", 200)
        t.record_test("/a", "xss", "p", "failed", 200)
        t.record_test("/b", "sqli", "p", "blocked", 403)
        m = t.get_matrix()
        assert isinstance(m, CoverageMatrix)
        assert m.endpoints == ["/a", "/b"]
        assert m.attack_types == ["sqli", "xss"]
        assert m.total_combinations == 4
        assert m.tested_combinations == 3
        assert m.passed_combinations == 1

    def test_matrix_keeps_most_recent_record(self):
        t = CoverageTracker()
        t.record_test("/a", "sqli", "old", "failed", 500)
        t.record_test("/a", "sqli", "new", "passed", 200)
        m = t.get_matrix()
        key = ("/a", "sqli")
        assert key in m.matrix
        # later timestamp wins (same-second ties keep the newer insert last)
        assert m.matrix[key].payload in ("old", "new")
        assert m.matrix[key].timestamp >= t.get_records()[0].timestamp

    def test_untested_pairs(self):
        t = CoverageTracker()
        t.record_test("/a", "sqli", "p", "passed", 200)
        untested = t.get_untested_pairs(["/a", "/b"], ["sqli", "xss"])
        assert untested == {("/a", "xss"), ("/b", "sqli"), ("/b", "xss")}

    def test_tested_pairs(self):
        t = CoverageTracker()
        t.record_test("/a", "sqli", "p", "passed", 200)
        assert t.get_tested_pairs() == {("/a", "sqli")}


class TestSummary:
    def test_empty_tracker_summary(self):
        t = CoverageTracker()
        s = t.get_summary()
        assert s["total_tests"] == 0
        assert s["coverage_percent"] == 0.0
        assert s["dependency_satisfaction"] == 0.0

    def test_summary_counts_statuses_and_severities(self):
        t = CoverageTracker()
        t.record_test("/a", "sqli", "p", "passed", 200)   # weight 1.0 -> critical
        t.record_test("/b", "cors", "p", "failed", 200)   # weight 0.6 -> medium
        t.record_test("/c", "headers", "p", "blocked", 200)  # 0.55 -> medium
        s = t.get_summary()
        assert s["total_tests"] == 3
        assert s["status_counts"] == {"passed": 1, "failed": 1, "blocked": 1}
        assert s["severity_counts"]["critical"] == 1
        assert s["severity_counts"]["medium"] == 2

    def test_dependency_satisfaction_counts_met_requirements(self):
        t = CoverageTracker()
        # post_exploit requires sqli/xss/idor/ssrf/auth_bypass/rce
        t.record_test("/a", "sqli", "p", "passed", 200)
        t.record_test("/a", "post_exploit", "p", "passed", 200)
        s = t.get_summary()
        # 1 of 6 requirements met -> ~16.7%
        assert s["dependency_satisfaction"] == 16.7


class TestRiskScore:
    def test_risk_score_empty(self):
        assert CoverageTracker().get_risk_score() == 0.0

    def test_risk_score_full_coverage(self):
        t = CoverageTracker()
        for atk in CoverageTracker.ALL_ATTACK_TYPES:
            t.record_test("/x", atk, "p", "passed", 200)
        assert t.get_risk_score() == 100.0

    def test_risk_score_partial_is_weighted(self):
        t = CoverageTracker()
        t.record_test("/x", "sqli", "p", "passed", 200)  # weight 1.0
        score = t.get_risk_score()
        assert 0.0 < score < 100.0


class TestTimeAnalysis:
    def test_time_analysis_empty(self):
        assert CoverageTracker().get_time_analysis() == {}

    def test_time_analysis_stats(self):
        t = CoverageTracker()
        t.record_test("/a", "sqli", "p", "passed", 200, duration_ms=100)
        t.record_test("/b", "xss", "p", "passed", 200, duration_ms=300)
        t.record_test("/c", "cors", "p", "passed", 200, duration_ms=200)
        ta = t.get_time_analysis()
        assert ta["total_duration_ms"] == 600.0
        assert ta["avg_duration_ms"] == 200.0
        assert ta["min_duration_ms"] == 100.0
        assert ta["max_duration_ms"] == 300.0
        assert ta["slowest_tests"][0][0] == "/b"


class TestDependencyAnalysis:
    def test_unmet_dependencies_listed(self):
        t = CoverageTracker()
        t.record_test("/a", "lateral_movement", "p", "passed", 200)
        da = t.get_dependency_analysis()
        assert da["satisfied"]["lateral_movement"] == []
        assert set(da["unsatisfied"]["lateral_movement"]) == {"ssrf", "rce"}

    def test_satisfied_dependencies(self):
        t = CoverageTracker()
        t.record_test("/a", "ssrf", "p", "passed", 200)
        t.record_test("/a", "rce", "p", "passed", 200)
        t.record_test("/a", "lateral_movement", "p", "passed", 200)
        da = t.get_dependency_analysis()
        assert da["unsatisfied"] == {}
        assert da["satisfaction_rate"] == 100.0
