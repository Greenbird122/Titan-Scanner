"""Tests for the trend & anomaly analyzer."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from titan.learn.trends import (  # noqa: E402
    build_profile,
    build_profiles,
    find_trend_groups,
    flag_anomalies,
    render_trends,
)


def _site(root: Path, slug: str, target: str, findings: list, notes: str = "",
          techs: list | None = None, reverified: bool = False):
    d = root / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "findings.json").write_text(
        json.dumps({"target": target, "findings": findings}), encoding="utf-8"
    )
    meta = {"target": target, "technologies": techs or []}
    if reverified:
        meta["reverification_round"] = "2026-08-17"
    if notes:
        meta["recheck_notes"] = notes
    (d / "scan_meta.json").write_text(json.dumps(meta), encoding="utf-8")


def _fixture(tmp_path: Path) -> Path:
    root = tmp_path / "findings"
    root.mkdir()
    # A git-vizor-shaped site: Firebase key + DOM XSS + missing CSP.
    _site(
        root, "git-vizor-vercel-app", "https://git-vizor.vercel.app",
        [
            {"attack_type": "Hardcoded Secret", "verified": True, "severity": "medium",
             "payload": "Firebase client config exposed: AIzaSyB-wn4pMXrk7GpnTKEUELY290qpQ0kIQgI"},
            {"attack_type": "CSP Weakness", "verified": True, "severity": "medium",
             "diffs": ["headers:missing", "missing:Content-Security-Policy", "missing:X-Frame-Options"]},
            {"attack_type": "DOM XSS", "verified": False, "severity": "high"},
        ],
        notes="NEW F6: DOM XSS via GitHub API description -> innerHTML, verified executing. localStorage architect_access gate.",
        techs=["Vercel", "React"],
        reverified=True,
    )
    # A sibling Vercel SPA with the same two header gaps — no secrets, no XSS.
    _site(
        root, "sales-ten-xi-vercel-app", "https://sales-ten-xi.vercel.app",
        [
            {"attack_type": "CSP Weakness", "verified": True, "severity": "medium",
             "diffs": ["headers:missing", "missing:Content-Security-Policy", "missing:X-Frame-Options"]},
        ],
        notes="Firebase rules exposed via open Firestore reads; write-verified tamper.",
        techs=["Vercel"],
        reverified=True,
    )
    # A clean static site — the control (alone on its lovable platform).
    _site(
        root, "coast-palmresort-lovable-app", "https://coast-palmresort.lovable.app",
        [], notes="static site, no backend, no API.",
        techs=["Lovable"],
        reverified=True,
    )
    # A well-secured Vercel sibling — deviates from its platform peers.
    _site(
        root, "tulia-admin-vercel-app", "https://tulia-admin.vercel.app",
        [],
        techs=["Vercel"],
        reverified=True,
    )
    return root


def test_profiles_signals(tmp_path):
    root = _fixture(tmp_path)
    profiles = build_profiles(str(root), scoreboard_path=str(tmp_path / "nope.json"))
    by_slug = {p["slug"]: p for p in profiles}
    gv = by_slug["git-vizor-vercel-app"]
    assert gv["signals"]["firebase_key"] is True
    assert gv["signals"]["api_dom_sink"] is True
    assert gv["signals"]["missing_csp"] is True
    assert gv["signals"]["clickjackable"] is True
    assert gv["signals"]["localstorage_gate"] is True
    coast = by_slug["coast-palmresort-lovable-app"]
    assert coast["signals"]["static_no_backend"] is True
    assert coast["signals"]["missing_csp"] is False


def test_trend_groups_shared_across_sites(tmp_path):
    root = _fixture(tmp_path)
    profiles = build_profiles(str(root), str(tmp_path / "nope.json"))
    groups = find_trend_groups(profiles)
    by_sig = {g["signal"]: g for g in groups}
    assert "missing_csp" in by_sig
    assert set(by_sig["missing_csp"]["members"]) == {
        "git-vizor-vercel-app", "sales-ten-xi-vercel-app",
    }
    # single-site signals are NOT trends
    assert "firebase_key" not in by_sig


def test_anomalies_unique_and_platform(tmp_path):
    root = _fixture(tmp_path)
    profiles = build_profiles(str(root), str(tmp_path / "nope.json"))
    groups = find_trend_groups(profiles)
    anomalies = flag_anomalies(profiles, groups)
    by_key = {(a["slug"], a["kind"]) for a in anomalies}
    # firebase_key is unique to git-vizor
    assert ("git-vizor-vercel-app", "unique") in by_key
    # the secured Vercel sibling deviates from its 2 CSP-missing peers
    assert ("tulia-admin-vercel-app", "platform") in by_key


def test_note_negation_guards(tmp_path):
    """Discussion of a control must not read as a finding:
    "bucket not listable" != public storage, "client-side auth shell" on the
    hosting platform != the site's auth bypass."""
    root = tmp_path / "guards"
    root.mkdir()
    _site(
        root, "coast-x-lovable-app", "https://coast-x.lovable.app", [],
        notes="R2 bucket listing attempts -> 404 (not listable); "
              "the project page is a client-side auth shell on the hosting platform",
        techs=["Lovable"], reverified=True,
    )
    p = build_profile("coast-x-lovable-app", root)
    assert p["signals"]["public_storage"] is False
    assert p["signals"]["client_auth_bypass"] is False


def test_stored_xss_is_not_dom_sink(tmp_path):
    """"Stored XSS via innerHTML concatenation" is the XSS class, not the
    API-fed DOM-sink (F6) class."""
    root = tmp_path / "gb"
    root.mkdir()
    _site(
        root, "greenbird122-github-io-recipie-api", "https://greenbird122.github.io/recipie-api/", [],
        notes="F1 stored XSS: strings concatenated into innerHTML with zero sanitization; "
              "TheMealDB is community-contributed.",
        techs=["GitHub Pages"], reverified=True,
    )
    p = build_profile("greenbird122-github-io-recipie-api", root)
    assert p["signals"]["api_dom_sink"] is False


def test_render_trends_is_markdown(tmp_path):
    root = _fixture(tmp_path)
    profiles = build_profiles(str(root), str(tmp_path / "nope.json"))
    groups = find_trend_groups(profiles)
    anomalies = flag_anomalies(profiles, groups)
    md = render_trends(profiles, groups, anomalies)
    assert md.startswith("# Estate trends")
    assert "Shared trends" in md
    assert "Anomalies" in md
    assert "Per-site profiles" in md
