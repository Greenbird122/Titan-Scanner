"""SCAN-QUALITY M1: engine root-cause dedup + evidence gate integration.

The zairaku.rest storm: one catch-all route echoing the query string produced
21 identical "CRITICAL LFI" findings on 21 fuzzed endpoints. These tests pin
the two-part fix — (1) strict LFI evidence (covered in test_oracle_detectors)
and (2) root-cause dedup that collapses identical (attack, payload, verified)
findings across endpoints into ONE representative finding that still lists
every affected URL.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from titan.core.models import AttackType, Finding, Severity


def _finding(url, attack=AttackType.LFI, payload="../../../../etc/passwd",
             verified=True, confidence=0.9, diffs=None, param="page"):
    return Finding(
        target="https://zairaku.rest",
        url=url,
        method="GET",
        param=param,
        location="query",
        payload=payload,
        attack_type=attack,
        severity=Severity.CRITICAL,
        verified=verified,
        confidence=confidence,
        diffs=list(diffs) if diffs else [],
    )


def _engine():
    from titan.core.engine import TitanEngine
    return TitanEngine({"crawl": {}, "ai": {}, "modules": {}})


class TestRootCauseDedup:
    def test_identical_findings_collapse_to_one(self):
        """21 endpoints, identical attack+payload+verified -> ONE finding with
        all 21 URLs recorded in metadata['affected_urls']."""
        engine = _engine()
        findings = [_finding(f"https://zairaku.rest/{path}?id=1&q=test")
                    for path in ("token", "hash", "login", "signin", "signup",
                                 "register", "session", "refresh", "upload",
                                 "api.raml", "backup", "xss", "manager",
                                 "export", ".DS_Store", "test", "console",
                                 "bak", "dev", "users", "panel")]
        out = engine._dedupe_findings(findings)
        assert len(out) == 1, f"21 identical LFI must collapse to 1, got {len(out)}"
        rep = out[0]
        urls = rep.metadata["affected_urls"]
        assert len(urls) == 21, f"affected_urls must list all 21, got {len(urls)}"
        assert rep.metadata["merged_count"] == 21
        assert rep.verified is True

    def test_verified_and_weak_copies_stay_separate(self):
        """Verification state is part of the root-cause signature: a confirmed
        finding and a weak copy of the same payload are different evidence
        classes and must not merge (one may later be demoted)."""
        engine = _engine()
        confirmed = _finding("https://x/a", verified=True)
        weak = _finding("https://x/b", verified=False, confidence=0.4)
        out = engine._dedupe_findings([confirmed, weak])
        assert len(out) == 2, f"verified/weak copies must stay separate, got {len(out)}"

    def test_different_payloads_stay_separate(self):
        engine = _engine()
        a = _finding("https://x/a", payload="../../etc/passwd")
        b = _finding("https://x/b", payload="../../windows/win.ini")
        out = engine._dedupe_findings([a, b])
        assert len(out) == 2

    def test_non_injection_findings_are_not_root_collapsed(self):
        """Header misconfigs collapse via their own site-wide rule; the
        root-cause pass must not merge identical header findings that live on
        distinct endpoints with distinct params."""
        engine = _engine()
        h1 = _finding("https://x/a", attack=AttackType.INFO_LEAK, param="body",
                      payload="Missing: X-Frame-Options")
        h2 = _finding("https://x/b", attack=AttackType.INFO_LEAK, param="body",
                      payload="Missing: X-Frame-Options")
        out = engine._dedupe_findings([h1, h2])
        # site-wide rule collapses these (same sig) BEFORE the root-cause pass
        assert len(out) == 1, f"identical header leak must collapse via site-wide rule, got {len(out)}"


class TestEvidenceGateIntegration:
    def test_full_scan_tail_cleans_storm(self):
        """End-to-end: 21 reflection-verified LFI copies -> strict dedup leaves
        1, and the evidence gate demotes it because its diffs name no strong
        oracle marker (the pre-fix version emitted 21 CRITICAL)."""
        from titan.verify.oracles import enforce_evidence
        engine = _engine()
        # Reflection-only diffs: exactly what a catch-all echo produces.
        findings = [_finding(f"https://zairaku.rest/{i}", verified=True,
                             diffs=["payload_reflected", "content_hash_changed",
                                    "response_length_increased"])
                    for i in range(21)]
        deduped = engine._dedupe_findings(findings)
        assert len(deduped) == 1
        stats = enforce_evidence(deduped)
        f = deduped[0]
        assert f.verified is False, "reflection-verified LFI must be demoted"
        assert f.severity == Severity.MEDIUM
        assert f.evidence == "corroborated"
        assert stats["demoted"] == 1
        assert len(f.metadata["affected_urls"]) == 21, "URL scope must survive the demotion"

    def test_rce_content_leak_stays_confirmed(self):
        """Regression: the RCE detector's command-output leak (uid=, root:,
        phpinfo) appends ``rce:content:<marker>`` — the canonical ``content:``
        marker — so the gate grades it confirmed instead of auto-demoting a
        genuinely verified CRITICAL RCE to unverified MEDIUM."""
        from titan.verify.oracles import enforce_evidence
        from titan.verify.oracles import grade_finding
        engine = _engine()
        f = _finding("https://x/cmd?host=test", attack=AttackType.RCE,
                     payload="| id", verified=True, confidence=0.93,
                     diffs=["rce:content:uid=", "rce:content:gid=",
                            "content_hash_changed"])
        assert grade_finding(f) == "confirmed"
        stats = enforce_evidence([f])
        assert f.verified is True, "verified RCE content leak must NOT be demoted"
        assert f.severity == Severity.CRITICAL
        assert stats["demoted"] == 0

    def test_rce_marker_reflection_stays_confirmed(self):
        """Unique-marker echo proof of execution keeps the confirmed grade."""
        from titan.verify.oracles import grade_finding
        f = _finding("https://x/cmd?host=test", attack=AttackType.RCE,
                     payload=";echo 8hK2fQ9a", verified=True, confidence=0.92,
                     diffs=["rce:marker_reflected", "payload_reflected"])
        assert grade_finding(f) == "confirmed"

    def test_rce_bare_old_style_diff_is_demoted(self):
        """A pre-fix ``rce:uid=`` diff (no strong marker) still gets demoted:
        the gate is strict about naming the oracle that backed the label."""
        from titan.verify.oracles import enforce_evidence
        engine = _engine()
        f = _finding("https://x/cmd?host=test", attack=AttackType.RCE,
                     payload="| id", verified=True, confidence=0.93,
                     diffs=["rce:uid=", "content_hash_changed"])
        stats = enforce_evidence([f])
        assert f.verified is False
        assert f.severity == Severity.MEDIUM
        assert stats["demoted"] == 1

    def test_deser_signature_content_stays_confirmed(self):
        """Regression (reviewer round 2): the deserialization detector emits
        ``deser:content:<signature>`` — a Java gadget / pickle.loads / etc.
        signature leaked from the app is a content leak, so a verified
        CRITICAL deser finding must NOT be demoted for missing a marker."""
        from titan.verify.oracles import grade_finding
        f = _finding("https://x/api?data=1", attack=AttackType.DESERIALIZATION,
                     payload="Deserialization indicator: Java IO deserialization",
                     verified=True, confidence=0.85,
                     diffs=["deser:content:java_io_deserialization"])
        assert grade_finding(f) == "confirmed"

    def test_smuggling_heuristic_is_demoted_by_design(self):
        """The smuggling detector verifies on heuristic indicator matches
        (400/parse-error/duplicate TE) with conf 0.6 — no named strong oracle.
        The gate demotes those to unverified MEDIUM by design (its own
        docstring admits Playwright may strip the TE header, so the probe is
        best-effort). The demotion is the strictness the program mandates."""
        from titan.verify.oracles import enforce_evidence
        engine = _engine()
        f = _finding("https://x/weather-hourly?next=test",
                     attack=AttackType.REQUEST_SMUGGLING,
                     payload="Smuggling probe: test%0d%0a...",
                     verified=True, confidence=0.6,
                     diffs=["smuggle:duplicate_te_header", "smuggle:bad request"])
        stats = enforce_evidence([f])
        assert f.verified is False, "heuristic smuggling must not keep verified"
        assert f.severity == Severity.MEDIUM
        assert f.evidence == "corroborated"
        assert stats["demoted"] == 1

    def test_strong_marker_on_unverified_finding_grades_indicative(self):
        """A diff naming a strong marker on an UNVERIFIED finding must read
        ``indicative``, never ``confirmed`` — the verified label is what the
        report trusts, and a marker alone (e.g. RCE marker echoed by an app
        that merely echoes the query string) is not proof of execution."""
        from titan.verify.oracles import grade_finding
        f = _finding("https://x/cmd?host=1", attack=AttackType.RCE,
                     payload=";echo 8hK2fQ9a", verified=False, confidence=0.6,
                     diffs=["rce:marker_reflected", "payload_reflected"])
        assert grade_finding(f) == "indicative"

    def test_non_injection_verified_grades_confirmed(self):
        """Headers/crypto/IDOR verify through their own typed evidence — a
        verified flag is ``confirmed`` by construction, never "corroborated"
        (which would read as weak/demoted in the report's evidence column)."""
        from titan.verify.oracles import grade_finding
        f = _finding("https://x/", attack=AttackType.INFO_LEAK, param="body",
                     payload="Missing: X-Frame-Options", verified=True,
                     confidence=0.9, diffs=["Missing: X-Frame-Options"])
        assert grade_finding(f) == "confirmed"
