"""Tests for the estate benchmark corpus builder."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench.estate import build_estate_manifest  # noqa: E402


def _write_site(root: Path, slug: str, target: str, findings: list, meta: dict | None = None):
    d = root / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "findings.json").write_text(
        json.dumps({"target": target, "findings": findings}), encoding="utf-8"
    )
    if meta is not None:
        (d / "scan_meta.json").write_text(json.dumps(meta), encoding="utf-8")


def _fixture(tmp_path: Path):
    root = tmp_path / "findings"
    root.mkdir()
    # estate site #1: machine ledger carries the verified attack types
    _write_site(
        root, "git-vizor-vercel-app", "https://git-vizor.vercel.app",
        [
            {"attack_type": "Info Leak", "verified": True, "method": "GET", "severity": "medium"},
            {"attack_type": "CSP Weakness", "verified": True, "method": "GET", "severity": "medium"},
            {"attack_type": "DOM XSS", "verified": False, "method": "GET", "severity": "high"},
        ],
        meta={"target": "https://git-vizor.vercel.app", "reverification_round": "2026-08-17"},
    )
    # estate site #2: notes-only deep audit — FINDINGS.md is mined
    _write_site(
        root, "coast-palmresort-lovable-app", "https://coast-palmresort.lovable.app",
        [],
        meta={"target": "https://coast-palmresort.lovable.app", "reverification_round": "2026-08-17"},
    )
    (root / "coast-palmresort-lovable-app" / "FINDINGS.md").write_text(
        "### F1 — CRITICAL · Public Firestore read: visitor data exposed\n", encoding="utf-8"
    )
    # estate site #3: audited but clean — no findings anywhere
    _write_site(
        root, "myportifolio-com", "https://www.myportifolio.com",
        [],
        meta={"target": "https://www.myportifolio.com", "reverification_round": "2026-08-17"},
    )
    # practice host: excluded by default
    _write_site(
        root, "ctflearn-com", "https://ctflearn.com",
        [{"attack_type": "SQLi", "verified": True, "method": "GET", "severity": "high"}],
        meta={"target": "https://ctflearn.com"},
    )
    return root


def test_challenges_from_verified_findings(tmp_path):
    root = _fixture(tmp_path)
    manifest = build_estate_manifest(str(root), consent_dir=str(tmp_path / "empty-consent"))
    slugs = {s["slug"] for s in manifest["sites"]}
    assert slugs == {"git-vizor-vercel-app", "coast-palmresort-lovable-app", "myportifolio-com"}
    gv = next(s for s in manifest["sites"] if s["slug"] == "git-vizor-vercel-app")
    assert gv["estate"] is True
    # verified attack types only — the unverified DOM XSS must not be a challenge
    assert {c["attack_type"] for c in gv["challenges"]} == {"Info Leak", "CSP Weakness"}
    assert all(c["endpoint"] == "https://git-vizor.vercel.app" for c in gv["challenges"])


def test_notes_only_site_is_mined(tmp_path):
    root = _fixture(tmp_path)
    manifest = build_estate_manifest(str(root), consent_dir=str(tmp_path / "empty-consent"))
    coast = next(s for s in manifest["sites"] if s["slug"] == "coast-palmresort-lovable-app")
    assert coast["challenges"], "notes-only site should gain a mined challenge"
    assert coast["challenges"][0]["attack_type"] == "Public Cloud Storage"
    assert coast["challenges"][0]["mined"] is True


def test_clean_site_has_no_challenges(tmp_path):
    root = _fixture(tmp_path)
    manifest = build_estate_manifest(str(root), consent_dir=str(tmp_path / "empty-consent"))
    clean = next(s for s in manifest["sites"] if s["slug"] == "myportifolio-com")
    assert clean["challenges"] == []


def test_practice_included_when_flag_set(tmp_path):
    root = _fixture(tmp_path)
    manifest = build_estate_manifest(str(root), include_practice=True,
                                    consent_dir=str(tmp_path / "empty-consent"))
    slugs = {s["slug"] for s in manifest["sites"]}
    assert "ctflearn-com" in slugs
    ctf = next(s for s in manifest["sites"] if s["slug"] == "ctflearn-com")
    assert ctf["estate"] is False
    assert ctf["challenges"][0]["attack_type"] == "SQLi"
