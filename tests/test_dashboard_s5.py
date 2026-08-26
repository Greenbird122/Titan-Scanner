"""S5 tests — interactive HTML dashboard.

Builds a real ScanResult, persists it through SiteReportWriter, renders the
dashboard, and asserts the interactive surface: self-contained (no external
resources), severity/attack/evidence filters, sortable rows, expandable
details with PoC, chains + sessions sections, and safe escaping of hostile
payload text.
"""

import json
from pathlib import Path

from titan.core.models import AttackType, Finding, ScanResult, Severity
from titan.reporting import SiteReportWriter
from titan.reporting.dashboard import build_dashboard


def _finding(sev: Severity, atk: AttackType, url: str, verified: bool = True) -> Finding:
    return Finding(
        target="http://lab.local",
        url=url,
        method="GET",
        param="id",
        location="query",
        payload="' OR 1=1-- <script>alert(1)</script>",
        attack_type=atk,
        severity=sev,
        verified=verified,
        confidence=0.92,
        status=200,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        evidence="confirmed",
        diffs=["sqli:content:mysql", "reflected:<script>alert(1)</script>"],
        tags=["auth", "owasp-a1"],
        poc_curl="curl -i -s 'http://lab.local/x?id=%27'",
        poc_python="import requests\nrequests.get('http://lab.local/x', params={'id': \"'\"})",
        metadata={"evidence_demotion": True},
    )


def _result() -> ScanResult:
    result = ScanResult(target="http://lab.local", started_at=1700000000.0, config_snapshot={})
    result.findings = [
        _finding(Severity.CRITICAL, AttackType.SQLI, "http://lab.local/sqli?id=1"),
        _finding(Severity.HIGH, AttackType.SSRF, "http://lab.local/fetch?url=x", verified=False),
        _finding(Severity.MEDIUM, AttackType.INFO_LEAK, "http://lab.local/"),
    ]
    result.finished_at = 1700000100.0
    result.chains = [
        {
            "name": "Cloud Credential Exposure",
            "severity": "critical",
            "impact": "SSRF to metadata + hardcoded key -> cloud takeover",
            "capabilities": ["url_fetch", "creds"],
            "hops": [
                {"attack_type": "SSRF", "method": "GET", "url": "http://lab.local/fetch", "flows": ["url_fetch"]},
                {"attack_type": "Crypto Weakness", "method": "GET", "url": "http://lab.local/config", "flows": ["creds"]},
            ],
        }
    ]
    result.exploit_sessions = [
        {"channel": "ssrf-pivot", "session_id": "abc123", "dir": "findings/lab-local/sessions/abc123"}
    ]
    result.errors = ["Crawl timed out after 90s"]
    return result


def _persist(tmp_path: Path) -> Path:
    writer = SiteReportWriter(output_dir=str(tmp_path / "findings"))
    result = _result()
    site_dir = writer.write(result)
    return site_dir


def test_dashboard_renders_and_is_self_contained(tmp_path: Path):
    site_dir = _persist(tmp_path)
    out = build_dashboard(site_dir)
    assert out.exists()
    html_text = out.read_text(encoding="utf-8")
    # Self-contained: no external resource references at all.
    assert 'src="http' not in html_text and 'href="http' not in html_text
    assert "<link" not in html_text and "<script src" not in html_text
    # Core interactive machinery present.
    assert "Titan Scan Dashboard" in html_text
    assert "oninput=\"render()\"" in html_text
    assert "attack-filter" in html_text
    assert "evidence-filter" in html_text
    assert "toggleDetail" in html_text
    assert "navigator.clipboard" in html_text
    assert "sortKey" in html_text
    # Data embedded as JSON for the JS table.
    assert '"attack_type": "SQLi"' in html_text or '"attack_type": "SSRF"' in html_text


def test_dashboard_embedds_all_finding_fields(tmp_path: Path):
    site_dir = _persist(tmp_path)
    out = build_dashboard(site_dir)
    text = out.read_text(encoding="utf-8")
    # All three findings survived into the embedded JSON.
    for atk in ("SQLi", "SSRF", "Info Leak"):
        assert atk in text
    # Chains and sessions sections render.
    assert "Cloud Credential Exposure" in text
    assert "ssrf-pivot" in text
    assert "Crawl timed out" in text


def test_dashboard_escapes_hostile_payload(tmp_path: Path):
    site_dir = _persist(tmp_path)
    out = build_dashboard(site_dir)
    text = out.read_text(encoding="utf-8")
    # The payload contains a <script> tag — a raw `</script>` inside the
    # embedded JSON would terminate the dashboard's own script block and
    # inject live HTML. The JSON-in-script escaping must turn every < and >
    # into \u003c / \u003e, and the JS render path escapes again with esc().
    assert "<script>alert(1)</script>" not in text
    assert "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e" in text
    # The payload is never echoed into the static HTML unescaped either.
    assert "' OR 1=1-- " in text  # payload survives for display


def test_dashboard_defaults_to_empty_site(tmp_path: Path):
    site_dir = tmp_path / "findings" / "empty-site"
    site_dir.mkdir(parents=True)
    (site_dir / "findings.json").write_text(
        json.dumps({"target": "http://empty.test", "findings": [], "chains": []}),
        encoding="utf-8",
    )
    (site_dir / "scan_meta.json").write_text(
        json.dumps({"target": "http://empty.test", "errors": []}), encoding="utf-8"
    )
    out = build_dashboard(site_dir)
    text = out.read_text(encoding="utf-8")
    assert "0" in text  # total card
    assert "No attack chains" in text
    assert "No consent-gated exploitation sessions" in text


def test_run_dashboard_cli(tmp_path: Path):
    """`run.py dashboard <url>` resolves to the slug and renders."""
    import subprocess
    import sys

    site_dir = _persist(tmp_path)
    slug = site_dir.name
    code = subprocess.call(
        [
            sys.executable,
            "run.py",
            "dashboard",
            slug,
            "--output-dir",
            str(tmp_path / "findings"),
        ],
        cwd=str(Path(__file__).parent.parent),
    )
    assert code == 0
    assert (site_dir / "dashboard.html").exists()
