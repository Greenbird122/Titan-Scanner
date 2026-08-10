"""Tests for the per-site reporting subsystem (titan.reporting)."""

import asyncio
import json

from titan.core.models import AttackType, Finding, ScanResult, Severity
from titan.reporting import SiteReportWriter, site_slug


def _finding(**overrides):
    defaults = dict(
        target="http://localhost:5000",
        url="http://localhost:5000/sqli?id=1",
        method="GET",
        param="id",
        location="query",
        payload="' OR 1=1--",
        attack_type=AttackType.SQLI,
        severity=Severity.CRITICAL,
        verified=True,
        confidence=0.99,
        status=200,
        diffs=["sanity_pair:boolean_confirmed"],
        cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        poc_curl="curl 'http://localhost:5000/sqli?id=%27+OR+1%3D1--'",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _result(target="http://localhost:5000", findings=None, errors=None, fingerprint=None):
    r = ScanResult(target=target, started_at=1_700_000_000.0, finished_at=1_700_000_043.0)
    r.findings = findings if findings is not None else []
    r.errors = errors or []
    if fingerprint is not None:
        r.fingerprint = fingerprint
    return r


class TestSiteSlug:
    def test_host_port(self):
        assert site_slug("http://localhost:8080/login.php") == "localhost-8080"

    def test_default_port_dropped(self):
        assert site_slug("https://example.com:443/") == "example-com"

    def test_plain_host(self):
        assert site_slug("https://repairai.co.ke/") == "repairai-co-ke"

    def test_no_scheme(self):
        assert site_slug("localhost:5000") == "localhost-5000"

    def test_subdomain_with_port(self):
        assert site_slug("https://api.vuln.lab:8443/x") == "api-vuln-lab-8443"


class TestReportWriter:
    def test_writes_per_site_docs(self, tmp_path):
        writer = SiteReportWriter(output_dir=str(tmp_path))
        result = _result(
            findings=[_finding()],
            fingerprint={"technologies": ["flask", "python"]},
        )
        site_dir = writer.write(result)

        assert site_dir == tmp_path / "localhost-5000"
        assert (site_dir / "report.md").exists()
        assert (site_dir / "findings.json").exists()
        assert (site_dir / "scan_meta.json").exists()

        data = json.loads((site_dir / "findings.json").read_text(encoding="utf-8"))
        assert data["summary"]["total"] == 1
        assert data["findings"][0]["attack_type"] == "SQLi"

        meta = json.loads((site_dir / "scan_meta.json").read_text(encoding="utf-8"))
        assert meta["duration_seconds"] == 43.0
        assert meta["technologies"] == ["flask", "python"]

        md = (site_dir / "report.md").read_text(encoding="utf-8")
        assert "# Scan Report — http://localhost:5000" in md
        assert "1. [CRITICAL] SQLi — verified" in md
        assert "`sanity_pair:boolean_confirmed`" in md
        assert "PoC (curl)" in md
        assert "localhost-5000" in md  # slug in the meta table

    def test_empty_scan_still_documented(self, tmp_path):
        writer = SiteReportWriter(output_dir=str(tmp_path))
        site_dir = writer.write(_result())
        md = (site_dir / "report.md").read_text(encoding="utf-8")
        assert "No findings recorded for this site" in md
        assert (site_dir / "findings.json").exists()

    def test_sites_index_merges_by_slug(self, tmp_path):
        writer = SiteReportWriter(output_dir=str(tmp_path))
        writer.write(_result(findings=[_finding()]))
        # A second scan of the SAME site replaces the index entry, no duplicates.
        writer.write(_result(findings=[]))
        index = json.loads((tmp_path / "sites.json").read_text(encoding="utf-8"))
        assert [s["slug"] for s in index["sites"]] == ["localhost-5000"]
        assert index["sites"][0]["findings"] == 0  # reflects the latest scan

    def test_multiple_sites_in_index(self, tmp_path):
        writer = SiteReportWriter(output_dir=str(tmp_path))
        writer.write(_result(target="http://localhost:8080", findings=[_finding()]))
        writer.write(_result(target="https://dvwa.example.net", findings=[_finding()]))
        index = json.loads((tmp_path / "sites.json").read_text(encoding="utf-8"))
        assert {s["slug"] for s in index["sites"]} == {"localhost-8080", "dvwa-example-net"}

    def test_payload_goes_in_code_block(self, tmp_path):
        f = _finding(payload="<script>alert(1)</script><!--x-->")
        writer = SiteReportWriter(output_dir=str(tmp_path))
        writer.write(_result(findings=[f]))
        md = (tmp_path / "localhost-5000" / "report.md").read_text(encoding="utf-8")
        assert "```text\n<script>alert(1)</script><!--x-->\n```" in md

    def test_errors_and_ai_escalation_sections(self, tmp_path):
        f = _finding()
        r = _result(findings=[f], errors=["Crawl timed out"])
        r.ai_escalation = {"sent": 1, "confirmed": 0, "rejected": 1, "failed": 0}
        writer = SiteReportWriter(output_dir=str(tmp_path))
        writer.write(r)
        md = (tmp_path / "localhost-5000" / "report.md").read_text(encoding="utf-8")
        assert "## Scan errors" in md and "Crawl timed out" in md
        assert "## AI escalation" in md

    def test_config_snapshot_credentials_redacted(self, tmp_path):
        r = _result(findings=[_finding()])
        r.config_snapshot = {
            "target": "http://x",
            "auth": {
                "username": "admin",
                "password": "hunter2",
                "roles": [{"role": "user", "password": "x"}],
            },
        }
        writer = SiteReportWriter(output_dir=str(tmp_path))
        writer.write(r)
        data = json.loads((tmp_path / "localhost-5000" / "findings.json").read_text(encoding="utf-8"))
        snap = data["config_snapshot"]
        assert snap["auth"]["password"] == "[REDACTED]"
        assert snap["auth"]["username"] == "admin"  # usernames stay
        assert snap["auth"]["roles"][0]["password"] == "[REDACTED]"
        # The in-memory config object must be untouched.
        assert r.config_snapshot["auth"]["password"] == "hunter2"

    def test_payload_fence_guard(self, tmp_path):
        f = _finding(payload="x ``` y")
        writer = SiteReportWriter(output_dir=str(tmp_path))
        writer.write(_result(findings=[f]))
        md = (tmp_path / "localhost-5000" / "report.md").read_text(encoding="utf-8")
        assert "```text\nx `` ` y\n```" in md


def test_governance_denial_keeps_sane_duration(monkeypatch, tmp_path):
    """Regression: the engine switched started_at/finished_at from monotonic
    to wall-clock; the governance-denial early return must not mix clock
    bases (which would persist a garbage negative duration)."""
    import titan.core.engine as engine_mod
    from titan.core.engine import TitanEngine

    async def _deny(*a, **k):
        return False

    monkeypatch.setattr(engine_mod, "request_scan_approval", _deny)
    config = {
        "governance": {"enabled": True},
        "output_dir": str(tmp_path),
        "modules": {},
    }
    result = asyncio.run(TitanEngine(config).scan("http://localhost:5000"))
    assert result.errors == ["Scan not approved by governance"]
    assert result.duration_seconds >= 0, f"clock-basis mismatch: {result.duration_seconds}"
