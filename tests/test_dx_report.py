"""SCAN-QUALITY M4: report shape and dependency pre-flight.

The report must open with a human-readable executive summary, version its
JSON schema (schema_version: 2), separate low-confidence findings from the
verified list, and expose evidence grades — while the ``--doctor`` preflight
must pass in the project's own venv (the environment this suite runs in).
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from titan.core.models import AttackType, Finding, ScanResult, Severity
from titan.reporting import SiteReportWriter


def _result(findings):
    r = ScanResult(target="https://example.com", started_at=0.0, finished_at=1.0)
    r.findings = findings
    return r


def _weak_lfi():
    return Finding(
        target="https://example.com", url="https://example.com/a", method="GET",
        param="page", location="query", payload="../../etc/passwd",
        attack_type=AttackType.LFI, severity=Severity.HIGH, verified=False,
        confidence=0.4, evidence="indicative",
    )


def _confirmed_xss():
    return Finding(
        target="https://example.com", url="https://example.com/search?q=x",
        method="GET", param="q", location="query",
        payload="<script>alert(1)</script>", attack_type=AttackType.XSS,
        severity=Severity.CRITICAL, verified=True, confidence=0.9,
        evidence="confirmed", diffs=["xss:marker_reflected:TITANXSS1234"],
        metadata={"affected_urls": ["https://example.com/search?q=x", "https://example.com/s"]},
    )


class TestReportShape:
    def test_schema_version_2_and_exec_summary(self, tmp_path):
        out = tmp_path / "findings"
        writer = SiteReportWriter(str(out))
        writer.write(_result([_confirmed_xss(), _weak_lfi()]))

        data = json.loads((out / "example-com" / "findings.json").read_text(encoding="utf-8"))
        assert data["schema_version"] == 2, "schema_version must be bumped so consumers know grades exist"
        assert data["findings"][0]["evidence"] == "confirmed"

        report = (out / "example-com" / "report.md").read_text(encoding="utf-8")
        assert "## Executive summary" in report
        assert "Risk posture" in report
        assert "Critical exposure" in report
        assert "## Low-confidence findings" in report
        assert "## Findings" in report

    def test_low_confidence_section_only_when_weak_findings(self, tmp_path):
        out = tmp_path / "findings2"
        writer = SiteReportWriter(str(out))
        writer.write(_result([_confirmed_xss()]))
        report = (out / "example-com" / "report.md").read_text(encoding="utf-8")
        assert "## Low-confidence findings" not in report

    def test_affected_urls_and_demotion_rendered(self, tmp_path):
        out = tmp_path / "findings3"
        f = _confirmed_xss()
        f.metadata["evidence_demotion"] = "verified but diffs name no strong oracle marker"
        writer = SiteReportWriter(str(out))
        writer.write(_result([f]))
        report = (out / "example-com" / "report.md").read_text(encoding="utf-8")
        assert "Affected URLs" in report
        assert "auto-demoted" in report
        assert "https://example.com/s" in report


class TestDoctor:
    def test_doctor_passes_in_project_venv(self):
        """The suite runs inside the project venv, so every dependency the
        doctor checks must be present and Chromium must be installed."""
        import run as run_module
        assert run_module.doctor() == 0, "doctor must pass in the project venv"
