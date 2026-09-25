"""Automated-scanning policy on the consent gate.

A consent answers "may I touch this target". The `scanning` field answers the
narrower question the scanner actually needs — "may I point automated tooling
at it" — because bug bounty and VDP briefs routinely authorize the first while
forbidding the second, and breaching that is an instant program ban.

Covers:
  * absent field -> allowed (consents signed before the field existed still verify)
  * allowed / bounded are returned; prohibited refuses the automated path
  * the field is signed: adding or relaxing it after signing invalidates the signature
  * an unrecognized value fails closed
  * `authorize_target` — the choke point `TitanEngine.scan()` and
    `scan_browserless()` return on — denies a prohibited consent even when a
    practice manifest would otherwise authorize the host
  * the CLI records the policy and warns when it is omitted
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from titan.core.authorization import authorize_target
from titan.exploit.consent import (
    SCANNING_ALLOWED,
    SCANNING_BOUNDED,
    SCANNING_PROHIBITED,
    ConsentError,
    ScanningPolicyError,
    consent_filename,
    create_consent,
    require_automation,
    scanning_policy,
    verify_consent,
    write_consent,
)


@pytest.fixture()
def consent_env(tmp_path):
    """(consent_dir, key_path) — a signed consent store in a temp dir."""
    d = tmp_path / "consent"
    d.mkdir()
    return d, tmp_path / "k.pem"


def _sign(target: str, consent_dir: Path, key: Path, **kw) -> dict:
    doc = create_consent(target, expiry="1h", key_path=key, **kw)
    write_consent(doc, consent_dir=consent_dir)
    return dict(doc)


def test_absent_policy_defaults_to_allowed(consent_env):
    """Backward compatibility: a consent signed before `scanning` existed
    carries no declaration, and an undeclared policy is not a claim."""
    cdir, key = consent_env
    doc = _sign("http://plain.local", cdir, key, basis="ownership")
    assert "scanning" not in doc
    assert verify_consent("http://plain.local", consent_dir=cdir, key_path=key)
    assert require_automation("http://plain.local", consent_dir=cdir, key_path=key) == SCANNING_ALLOWED


@pytest.mark.parametrize("policy", [SCANNING_ALLOWED, SCANNING_BOUNDED])
def test_permissive_policies_are_returned(consent_env, policy):
    cdir, key = consent_env
    _sign("http://perm.local", cdir, key, basis="program", scanning=policy)
    assert require_automation("http://perm.local", consent_dir=cdir, key_path=key) == policy


def test_prohibited_policy_refuses_the_automated_path(consent_env):
    """The whole point: authorized, but automation is forbidden here."""
    cdir, key = consent_env
    _sign("http://banned.local", cdir, key, basis="program", scanning=SCANNING_PROHIBITED)

    # The consent itself is valid — the target may be tested by hand.
    assert verify_consent("http://banned.local", consent_dir=cdir, key_path=key)

    with pytest.raises(ScanningPolicyError) as e:
        require_automation("http://banned.local", consent_dir=cdir, key_path=key)
    assert "forbids automated scanning" in str(e.value)


def test_unknown_policy_refused_at_signing(consent_env):
    _, key = consent_env
    with pytest.raises(ConsentError) as e:
        create_consent("http://x.local", scanning="maybe", key_path=key)
    assert "unknown scanning policy" in str(e.value)


def test_unrecognized_signed_value_fails_closed():
    """A declaration that cannot be read authorizes nothing."""
    with pytest.raises(ScanningPolicyError) as e:
        scanning_policy({"target": "http://x.local", "scanning": "BOUNDED"})
    assert "unrecognized" in str(e.value)


def test_policy_is_signed_and_tamper_proof(consent_env):
    """Relaxing the policy after signing must invalidate the signature — this
    is what stops `prohibited` being quietly edited to `allowed`."""
    cdir, key = consent_env
    _sign("http://signed.local", cdir, key, basis="program", scanning=SCANNING_PROHIBITED)

    doc = create_consent("http://plain2.local", basis="program", expiry="1h", key_path=key)
    write_consent(doc, consent_dir=cdir)
    assert "scanning" not in doc

    p = cdir / f"{consent_filename('http://plain2.local')}.json"
    tampered = json.loads(p.read_text(encoding="utf-8"))
    tampered["scanning"] = SCANNING_ALLOWED
    p.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ConsentError) as e:
        verify_consent("http://plain2.local", consent_dir=cdir, key_path=key)
    assert "signature invalid" in str(e.value) or "tampered" in str(e.value)


def test_gate_denies_prohibited_even_when_manifest_would_authorize(consent_env, tmp_path):
    """A deliberate `prohibited` declaration outranks the practice manifest:
    the operator has said the *source* forbids automation for this host."""
    cdir, key = consent_env
    _sign("http://banned.local", cdir, key, basis="program", scanning=SCANNING_PROHIBITED)

    manifest = tmp_path / "practice.json"
    manifest.write_text(json.dumps({"hosts": ["banned.local"]}), encoding="utf-8")

    denial = authorize_target(
        "http://banned.local",
        consent_dir=str(cdir),
        practice_manifest=str(manifest),
        key_path=str(key),
    )
    assert denial is not None
    assert "scan denied" in denial
    assert "forbids automated scanning" in denial


@pytest.mark.parametrize("policy", [SCANNING_ALLOWED, SCANNING_BOUNDED])
def test_gate_authorizes_permissive_policies(consent_env, policy):
    cdir, key = consent_env
    _sign("http://ok.local", cdir, key, basis="program", scanning=policy)
    assert (
        authorize_target(
            "http://ok.local",
            consent_dir=str(cdir),
            practice_manifest=str(Path(cdir) / "none.json"),
            key_path=str(key),
        )
        is None
    )


def test_gate_still_authorizes_consents_without_the_field(consent_env):
    """Backward compatibility at the choke point: existing consents (argustrust,
    TGK, the honeypot) keep scanning."""
    cdir, key = consent_env
    _sign("http://legacy.local", cdir, key, basis="authorization")
    assert (
        authorize_target(
            "http://legacy.local",
            consent_dir=str(cdir),
            practice_manifest=str(Path(cdir) / "none.json"),
            key_path=str(key),
        )
        is None
    )


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def _fake_doc(target, flags=None, expiry="24h", basis=None, scanning=None, key_path=None):
    return {
        "target": target,
        "flags": flags or [],
        "basis": basis,
        "scanning": scanning,
        "expires_at": 1.0,
        "created_at": 0.0,
        "public_key": "y",
        "signature": "x",
    }


def _patch_cli(monkeypatch, captured):
    from titan.exploit_cli import consent as cli

    def fake_create(target, flags=None, expiry="24h", basis=None, scanning=None, key_path=None):
        captured.update(target=target, basis=basis, scanning=scanning, flags=flags)
        return _fake_doc(target, flags, expiry, basis, scanning)

    monkeypatch.setattr(cli, "create_consent", fake_create)
    monkeypatch.setattr(cli, "write_consent", lambda doc, *a, **k: "consent/fake.json")
    monkeypatch.setattr(cli, "_write_scope_template", lambda target: None)
    return cli


def test_cli_passes_scanning_through(monkeypatch):
    captured: dict = {}
    cli = _patch_cli(monkeypatch, captured)
    rc = cli.cmd_consent(["add", "http://lab.local", "--basis", "program", "--scanning", "bounded"])
    assert rc == 0
    assert captured == {
        "target": "http://lab.local",
        "basis": "program",
        "scanning": "bounded",
        "flags": [],
    }


def test_cli_refuses_scanning_without_a_value(monkeypatch):
    captured: dict = {}
    cli = _patch_cli(monkeypatch, captured)
    rc = cli.cmd_consent(["add", "http://lab.local", "--basis", "program", "--scanning"])
    assert rc == 2
    assert captured == {}  # never reached create_consent


def test_cli_warns_when_policy_omitted(monkeypatch, capsys):
    captured: dict = {}
    cli = _patch_cli(monkeypatch, captured)
    rc = cli.cmd_consent(["add", "http://lab.local", "--basis", "ownership"])
    assert rc == 0
    assert captured["scanning"] is None
    out = capsys.readouterr().out
    assert "no --scanning policy recorded" in out
    assert "Program Rules" in out


def test_cli_list_shows_the_policy(monkeypatch, capsys):
    from titan.exploit_cli import consent as cli

    monkeypatch.setattr(
        cli,
        "list_consents",
        lambda: [
            {
                "target": "http://banned.local",
                "status": "valid",
                "basis": "program",
                "scanning": SCANNING_PROHIBITED,
                "flags": [],
                "expires_at": 1.0,
            }
        ],
    )
    assert cli.cmd_consent(["list"]) == 0
    assert f"scanning={SCANNING_PROHIBITED}" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def test_report_renders_the_declared_policy(consent_env, tmp_path):
    """The consent row a client or owner reads states what automation was
    permitted, and glosses the one value where a misreading is dangerous."""
    from titan.reporting import SiteReportWriter

    cdir, key = consent_env
    _sign("http://banned.local", cdir, key, basis="program", scanning=SCANNING_PROHIBITED)
    w = SiteReportWriter(output_dir=str(tmp_path))

    line = w._consent_line("http://banned.local", key_path=key, consent_dir=cdir)
    assert line is not None
    assert "basis=program" in line  # existing format contract preserved
    assert "scanning=prohibited" in line
    assert "forbidden" in line


def test_report_does_not_fabricate_allowed_when_unset(consent_env, tmp_path):
    """A consent with no declaration renders (unset), never 'allowed': the
    report must not claim a permission the consent never made."""
    from titan.reporting import SiteReportWriter

    cdir, key = consent_env
    _sign("http://legacy.local", cdir, key, basis="ownership")
    w = SiteReportWriter(output_dir=str(tmp_path))

    line = w._consent_line("http://legacy.local", key_path=key, consent_dir=cdir)
    assert line is not None
    assert "scanning=(unset)" in line
    assert "scanning=allowed" not in line


def test_report_renders_bounded_without_the_forbidden_gloss(consent_env, tmp_path):
    from titan.reporting import SiteReportWriter

    cdir, key = consent_env
    _sign("http://bounded.local", cdir, key, basis="program", scanning=SCANNING_BOUNDED)
    w = SiteReportWriter(output_dir=str(tmp_path))

    line = w._consent_line("http://bounded.local", key_path=key, consent_dir=cdir)
    assert line is not None
    assert "scanning=bounded" in line
    assert "forbidden" not in line
