"""Tests for titan.modules.coverage.report — CoverageReportGenerator.

End-to-end report pipeline over recorded tracker data: scoring, gap
identification, proof generation, and the JSON/HTML/Markdown/CSV renders.
Pure computation — no I/O, no network.
"""

import json

from titan.modules.coverage.report import CoverageReportGenerator
from titan.modules.coverage.tracker import CoverageTracker


def _tracker_with_data() -> CoverageTracker:
    t = CoverageTracker()
    t.record_test("/api/users", "sqli", "' OR 1=1", "passed", 200, "ok", duration_ms=50)
    t.record_test("/api/users", "xss", "<svg>", "failed", 200, "echo", duration_ms=30)
    t.record_test("/api/users", "idor", "../1", "blocked", 403, "", duration_ms=10)
    t.record_test("/api/orders", "sqli", "' OR 1=1", "executed", 200, "ok", duration_ms=20)
    return t


class TestGenerateReport:
    def test_report_shape(self):
        gen = CoverageReportGenerator(_tracker_with_data())
        report = gen.generate("http://t.example")
        assert report.target == "http://t.example"
        assert report.timestamp
        assert report.executive_summary
        assert report.coverage_score.overall_score >= 0
        assert report.matrix["endpoints"] == ["/api/orders", "/api/users"]
        assert report.matrix["tested_combinations"] == 4
        assert report.raw_data["total_tests"] == 4

    def test_summary_mentions_score_and_root_hash(self):
        gen = CoverageReportGenerator(_tracker_with_data())
        report = gen.generate("http://t.example")
        assert f"{report.coverage_score.overall_score}%" in report.executive_summary
        assert report.proof["root_hash"][:16] in report.executive_summary

    def test_recommendations_respond_to_low_score(self):
        gen = CoverageReportGenerator(_tracker_with_data())
        report = gen.generate("http://t.example")
        assert report.recommendations
        assert len(report.recommendations) <= 10

    def test_gap_dicts_have_required_fields(self):
        gen = CoverageReportGenerator(_tracker_with_data())
        report = gen.generate("http://t.example")
        for gap in report.gaps:
            assert {"gap_type", "description", "reason", "severity", "recommendation"} <= set(gap)

    def test_low_quality_recs_surface(self):
        # no confirmed findings -> quality dimension low -> quality rec present
        t = _tracker_with_data()
        gen = CoverageReportGenerator(t)
        report = gen.generate("http://t.example")
        joined = " ".join(report.recommendations).lower()
        assert any(k in joined for k in ("quality", "gap", "coverage"))


class TestMatrix:
    def test_untested_cells_marked(self):
        gen = CoverageReportGenerator(_tracker_with_data())
        report = gen.generate("http://t.example")
        cell = report.matrix["matrix"]["/api/orders"]["xss"]
        assert cell == {"status": "not_tested"}

    def test_tested_cells_carry_status_code(self):
        gen = CoverageReportGenerator(_tracker_with_data())
        report = gen.generate("http://t.example")
        cell = report.matrix["matrix"]["/api/users"]["idor"]
        assert cell["status"] == "blocked"
        assert cell["response_code"] == 403
        assert cell["timestamp"]


class TestRenders:
    def test_to_json_is_valid_and_complete(self):
        gen = CoverageReportGenerator(_tracker_with_data())
        report = gen.generate("http://t.example")
        data = json.loads(gen.to_json(report))
        assert data["target"] == "http://t.example"
        assert "coverage_score" in data
        assert "proof" in data
        assert "gaps" in data
        assert "matrix" in data

    def test_to_html_contains_score_and_matrix(self):
        gen = CoverageReportGenerator(_tracker_with_data())
        report = gen.generate("http://t.example")
        html = gen.to_html(report)
        assert "<!DOCTYPE html>" in html
        assert f"{report.coverage_score.overall_score}%" in html
        assert "/api/users" in html
        assert report.proof["root_hash"] in html

    def test_to_markdown_tables_and_proof(self):
        gen = CoverageReportGenerator(_tracker_with_data())
        report = gen.generate("http://t.example")
        md = gen.to_markdown(report)
        assert "# Coverage Report: http://t.example" in md
        assert "✅" in md  # at least one passed cell
        assert "❌" in md  # at least one failed cell
        assert "⚠️" in md  # at least one blocked cell
        assert f"`{report.proof['root_hash']}`" in md

    def test_to_csv_rows_match_matrix(self):
        gen = CoverageReportGenerator(_tracker_with_data())
        report = gen.generate("http://t.example")
        csv = gen.to_csv(report)
        lines = csv.strip().split("\n")
        header, *rows = lines
        assert header == "Endpoint,Attack Type,Status,Response Code,Timestamp"
        # endpoints × attack_types rows, one per combination
        assert len(rows) == report.matrix["total_combinations"]
        # a tested cell's status appears
        assert any("blocked,403" in r for r in rows)
