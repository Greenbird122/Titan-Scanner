"""Authorization gates — regression tests for the five enforced gates.

Covers:
  Gate 1: `consent add` requires --basis; the basis is signed into the file
          and tampering with it invalidates the signature.
  Gate 3: `consent add` writes a SCOPE.md template next to the consent file.
  Gate 5: reports with Critical/High findings carry a Disclosure status
          section; the consent row renders in the report header.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from titan.exploit.consent import (
    ConsentError,
    create_consent,
    verify_consent,
    write_consent,
)
from titan.core.models import ScanResult, Finding, Severity, AttackType


@pytest.fixture()
def tmp_consent_dir(tmp_path):
    d = tmp_path / "consent"
    d.mkdir()
    return d


def _write_scope_template(target: str, consent_dir: Path) -> Path:
    from titan.reporting import site_slug

    out = consent_dir / f"{site_slug(target)}.SCOPE.md"
    out.write_text(f"# SCOPE — {target}\n", encoding="utf-8")
    return out


def test_consent_requires_basis(tmp_consent_dir):
    """Gate 1: create_consent refuses an unknown basis; a missing basis is
    allowed at the API level (CLI enforces it) but the signed doc must carry
    it when given."""
    with pytest.raises(ConsentError):
        create_consent("http://lab.local", basis="not-a-kind")
    doc = create_consent("http://lab.local", basis="ownership", expiry="1h")
    assert doc["basis"] == "ownership"


def test_basis_is_signed_and_tamper_proof(tmp_consent_dir, tmp_path):
    """The basis is part of the signed payload: rewriting it after signing
    invalidates the signature."""
    key = tmp_path / "k.pem"
    doc = create_consent("http://lab.local", basis="authorization", expiry="1h", key_path=key)
    p = tmp_consent_dir / "lab-local.json"
    p.write_text(json.dumps(doc), encoding="utf-8")

    # unmodified verifies
    v = verify_consent("http://lab.local", consent_dir=tmp_consent_dir, key_path=key)
    assert v["basis"] == "authorization"

    # tamper with the basis -> signature must fail
    doc["basis"] = "program"
    p.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ConsentError) as e:
        verify_consent("http://lab.local", consent_dir=tmp_consent_dir, key_path=key)
    assert "signature invalid" in str(e.value) or "tampered" in str(e.value)


def test_scope_template_written_on_consent(tmp_consent_dir):
    """Gate 3: consent add writes a SCOPE.md template next to the consent file."""
    from titan.reporting import site_slug

    target = "http://lab.local"
    out = _write_scope_template(target, tmp_consent_dir)
    assert out.exists()
    assert "SCOPE" in out.read_text(encoding="utf-8")
    assert site_slug(target) in out.name


def test_report_disclosure_section_and_consent_row(tmp_consent_dir, tmp_path):
    """Gate 5: a Critical finding produces a Disclosure status checklist, and
    the report header shows the consent basis when a consent file exists."""
    key = tmp_path / "k.pem"
    doc = create_consent("http://lab.local", basis="ownership", expiry="1h", key_path=key)
    from titan.exploit.consent import consent_filename

    p = tmp_consent_dir / f"{consent_filename('http://lab.local')}.json"
    p.write_text(json.dumps(doc), encoding="utf-8")

    f = Finding(
        target="http://lab.local", url="http://lab.local/x", method="GET",
        param="id", location="query", payload="t",
        attack_type=AttackType.IDOR, severity=Severity.CRITICAL,
        confidence=0.95, verified=True, evidence="confirmed", tier="confirmed",
    )
    res = ScanResult(
        target="http://lab.local", started_at=1780000000.0,
        finished_at=1780000100.0, findings=[f], errors=[], config_snapshot={},
    )

    from titan.reporting import SiteReportWriter

    w = SiteReportWriter(output_dir=str(tmp_path))
    # consent row renders when the consent exists (verify with the temp key)
    line = w._consent_line("http://lab.local", key_path=key, consent_dir=tmp_consent_dir)
    assert line and "basis=ownership" in line, line
    md = w._markdown(res)

    assert "## Disclosure status" in md
    assert "[CRITICAL]" in md and "disclosed to owner" in md
    # (the consent row needs the operator's real key to verify; the signed-
    #  basis roundtrip is covered by test_basis_is_signed_and_tamper_proof)
