"""PUSH-TO-100 A2 — per-finding repro scripts (the finding's receipt).

Contract (spec D8): every `confirmed` finding ships an executable repro that
asserts the flaw against the live target. PASS (exit 0) = the flaw is STILL
present; FAIL (exit 1) = fixed or no longer reproducible. The assertion is
derived from the finding's OWN verified evidence (verification_body vs
baseline_body differential, error classes, reflection) — never textbook
guessing. Suspicious / no-evidence findings get no repro.
"""

import http.server
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from titan.core.models import AttackType, Finding, Severity
from titan.reporting import SiteReportWriter
from titan.verify.oracles import enforce_evidence
from titan.verify.repro import generate_repro, generate_repros, oracle_signature


def _finding(**overrides):
    defaults = dict(
        target="http://127.0.0.1:9999",
        url="http://127.0.0.1:9999/search",
        method="GET",
        param="q",
        location="query",
        payload="' OR 1=1--",
        attack_type=AttackType.SQLI,
        severity=Severity.HIGH,
        verified=True,
        confidence=0.95,
        status=200,
        diffs=["sanity_pair:boolean_confirmed"],
        # verified SQLi: baseline shows a normal page, verification shows the
        # injected marker (the differential IS the oracle).
        baseline_body="<h1>Search</h1><p>No results for your query.</p>",
        verification_body="<h1>Search</h1><p>No results for your query.</p>"
        " <mark>TITANSQLi_MARKER_7f3a</mark> 1 row returned.",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Signature selection
# ---------------------------------------------------------------------------

def test_oracle_signature_derived_from_differential_not_payload():
    """The signature must come from the verified evidence differential, never
    the raw payload (a reflected payload proves reflection, not the flaw)."""
    f = _finding()
    sig = oracle_signature(f)
    assert "TITANSQLi_MARKER_7f3a" in sig
    assert f.payload not in sig  # not the payload echoed back


def test_oracle_signature_falls_back_to_payload_for_reflection_class():
    f = _finding(
        attack_type=AttackType.LFI,
        verification_body="",
        baseline_body="",
        payload="/etc/passwd",
    )
    assert oracle_signature(f) == "/etc/passwd"


def test_oracle_signature_empty_when_no_evidence():
    f = _finding(payload="", verification_body="", baseline_body="")
    assert oracle_signature(f) == ""


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def test_repro_script_embeds_request_and_oracle():
    f = _finding()
    script = generate_repro(f, ordinal=1)
    assert "TITANSQLi_MARKER_7f3a" in script      # the oracle is embedded
    assert "urllib.request" in script              # dependency-free
    assert "PASS" in script and "FAIL" in script   # ground-truth wording
    assert "sanity_pair" in script.lower() or "SQLi" in script


def test_repros_only_for_confirmed():
    confirmed = _finding()
    suspicious = _finding(diffs=["reflection"])
    enforce_evidence([confirmed, suspicious])
    assert confirmed.tier == "confirmed"
    assert suspicious.tier == "suspicious"
    out = generate_repros([confirmed, suspicious])
    assert set(out) == {0}  # only the confirmed finding ships a repro


# ---------------------------------------------------------------------------
# LIVE Ground-Truth contract: PASS while vulnerable, FAIL after "fix"
# ---------------------------------------------------------------------------

class _VulnerableHandler(http.server.BaseHTTPRequestHandler):
    """Models a real injectable search endpoint: the SQLi payload in the
    query string (' OR 1=1--) triggers the injection oracle in the response.
    After `fixed` is set, the same payload returns a plain page — the flaw
    is gone. The repro replays the PAYLOAD, so the handler must respond to
    the payload, not to the marker itself."""

    fixed = False  # class attr, flipped by the test

    def do_GET(self):
        body = "<h1>Search</h1><p>No results.</p>"
        import urllib.parse as _up
        if not type(self).fixed and "OR 1=1" in _up.unquote(self.path):
            body += " <mark>TITANSQLi_MARKER_7f3a</mark> 1 row returned."
        payload = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture()
def live_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _VulnerableHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def _run_script(script: str) -> int:
    """Execute a repro script in a subprocess and return its exit code."""
    tmp = Path(os.environ.get("TMPDIR", "/tmp")) if os.name != "nt" else None
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as fh:
        fh.write(script)
        name = fh.name
    try:
        proc = subprocess.run(
            [sys.executable, name],
            capture_output=True, text=True, timeout=30,
        )
        return proc.returncode
    finally:
        os.unlink(name)


def test_live_repro_passes_on_vulnerable_then_fails_on_fix(live_server):
    f = _finding(target=live_server, url=f"{live_server}/search")
    f.verification_body = (
        "<h1>Search</h1><p>No results.</p>"
        " <mark>TITANSQLi_MARKER_7f3a</mark> 1 row returned."
    )
    script = generate_repro(f, ordinal=1)

    # Vulnerable: the oracle appears -> repro must PASS (exit 0).
    _VulnerableHandler.fixed = False
    assert _run_script(script) == 0, "repro must PASS against the vulnerable app"

    # Fixed: the oracle disappears -> repro must FAIL (exit 1).
    _VulnerableHandler.fixed = True
    assert _run_script(script) == 1, "repro must FAIL after the fix lands"


def test_live_repro_status_check(live_server):
    """A finding whose evidence is only a distinctive status (e.g. 403 vs
    200) asserts the status, and still flips when the server changes."""
    f = _finding(
        target=live_server, url=f"{live_server}/admin", method="GET",
        param="", payload="", status=403, verification_body="", baseline_body="",
        diffs=["status:403"],
    )

    class _AdminHandler(http.server.BaseHTTPRequestHandler):
        code = 403

        def do_GET(self):
            payload = b"forbidden"
            self.send_response(type(self).code)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _AdminHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        _AdminHandler.code = 403
        import dataclasses
        script = generate_repro(
            dataclasses.replace(f, target=url, url=f"{url}/admin"), ordinal=1
        )
        assert _run_script(script) == 0
        _AdminHandler.code = 200  # the fix: endpoint now serves normally
        assert _run_script(script) == 1
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# Report wiring
# ---------------------------------------------------------------------------

def test_report_writer_emits_repros_and_records_path(tmp_path):
    f = _finding()
    enforce_evidence([f])
    assert f.tier == "confirmed"

    from titan.core.models import ScanResult
    result = ScanResult(target=f.target, started_at=0, finished_at=1, findings=[f])
    writer = SiteReportWriter(output_dir=str(tmp_path))
    site_dir = writer.write(result)

    assert f.metadata.get("repro") == "repros/repro_01.py"
    repro_path = site_dir / "repros" / "repro_01.py"
    assert repro_path.exists()
    script = repro_path.read_text(encoding="utf-8")
    assert "TITANSQLi_MARKER_7f3a" in script

    report = (site_dir / "report.md").read_text(encoding="utf-8")
    assert "repros/repro_01.py" in report
    assert "repro scripts" in report

    findings_json = (site_dir / "findings.json").read_text(encoding="utf-8")
    assert "repros/repro_01.py" in findings_json

    meta_json = (site_dir / "scan_meta.json").read_text(encoding="utf-8")
    assert '"repros": 1' in meta_json


def test_report_writer_skips_suspicious(tmp_path):
    suspicious = _finding(diffs=["reflection"])
    enforce_evidence([suspicious])
    assert suspicious.tier == "suspicious"

    from titan.core.models import ScanResult
    result = ScanResult(target=suspicious.target, started_at=0, finished_at=1, findings=[suspicious])
    writer = SiteReportWriter(output_dir=str(tmp_path))
    site_dir = writer.write(result)

    assert "repro" not in suspicious.metadata
    assert not (site_dir / "repros").exists()
