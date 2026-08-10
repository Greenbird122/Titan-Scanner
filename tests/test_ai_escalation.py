"""Tests for the AI escalation layer (titan/verify/ai_escalation.py).

Covers: the eligibility gate, strict verdict parsing, verdict application
(confirmed / rejected / inconclusive), per-scan cap, and the cardinal rule
that every failure mode leaves findings untouched.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import pytest

from titan.core.models import AttackType, Finding, Severity
from titan.verify.ai_escalation import (
    AIEscalator,
    parse_verdict,
    severity_meets_min,
    should_escalate,
)


class StubAI:
    """Injectable fake model client. Records prompts, replays canned outputs."""

    def __init__(self, responses: List[str] = None, error: bool = False, delay: float = 0.0):
        self.responses = list(responses or [])
        self.error = error
        self.delay = delay
        self.calls: List[str] = []

    async def generate(self, prompt: str) -> str:
        self.calls.append(prompt)
        if self.error:
            raise RuntimeError("model unreachable")
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.responses:
            return self.responses.pop(0)
        return ""


def make_finding(**overrides) -> Finding:
    f = Finding(
        target="http://lab.local",
        url="http://lab.local/lfi?file=app.py",
        method="GET",
        param="file",
        location="query",
        payload="../../../etc/passwd",
        attack_type=AttackType.LFI,
        severity=Severity.HIGH,
        confidence=0.6,
        verified=False,
        status=500,
        baseline_status=200,
        body=(
            "Traceback (most recent call last): FileNotFoundError: "
            "[Errno 2] No such file or directory: '../../../etc/passwd'"
        ),
        baseline_body="Hello world",
        diffs=["error:filesystem", "response_length_increased"],
    )
    for key, value in overrides.items():
        setattr(f, key, value)
    return f


AI_CFG = {
    "enabled": True,
    "escalate": {
        "enabled": True,
        "min_severity": "high",
        "min_confidence": 0.3,
        "max_confidence": 0.85,
        "max_per_scan": 5,
        "timeout": 5,
    },
}


# ---------------------------------------------------------------- parse_verdict


def test_parse_verdict_plain_json():
    v = parse_verdict('{"verdict": "confirmed", "confidence": 0.9, "reason": "sql error"}')
    assert v == {"verdict": "confirmed", "confidence": 0.9, "reason": "sql error"}


def test_parse_verdict_fenced_json():
    v = parse_verdict('```json\n{"verdict": "rejected", "confidence": 0.8}\n```')
    assert v["verdict"] == "rejected"
    assert v["confidence"] == 0.8


def test_parse_verdict_prose_around_json():
    v = parse_verdict('Here is my analysis:\n{"verdict": "inconclusive", "confidence": 0.4, "reason": "unclear"}.\nHope this helps.')
    assert v["verdict"] == "inconclusive"


def test_parse_verdict_garbage_returns_none():
    assert parse_verdict("I think this is vulnerable because the response changed.") is None
    assert parse_verdict("") is None
    assert parse_verdict("not json at all") is None


def test_parse_verdict_invalid_verdict_returns_none():
    assert parse_verdict('{"verdict": "maybe", "confidence": 0.5}') is None


def test_parse_verdict_bad_confidence_returns_none_confidence():
    v = parse_verdict('{"verdict": "confirmed", "confidence": "high"}')
    assert v["verdict"] == "confirmed"
    assert v["confidence"] is None


# --------------------------------------------------------------- should_escalate


def test_gate_passes_ambiguous_high_value():
    assert should_escalate(make_finding(severity=Severity.HIGH, confidence=0.6), AI_CFG)


def test_gate_blocks_escalation_disabled():
    cfg = {"enabled": True, "escalate": {"enabled": False}}
    assert not should_escalate(make_finding(), cfg)


def test_gate_blocks_ai_disabled():
    cfg = {"enabled": False, "escalate": {"enabled": True}}
    assert not should_escalate(make_finding(), cfg)


@pytest.mark.parametrize("confidence", [0.1, 0.29, 0.86, 0.99])
def test_gate_blocks_outside_confidence_band(confidence):
    assert not should_escalate(make_finding(confidence=confidence), AI_CFG)


def test_gate_blocks_low_severity():
    assert not should_escalate(make_finding(severity=Severity.MEDIUM), AI_CFG)


def test_gate_blocks_critical_already_verified_when_unverified_only():
    cfg = dict(AI_CFG)
    cfg["escalate"] = {**AI_CFG["escalate"], "unverified_only": True}
    assert not should_escalate(make_finding(verified=True, confidence=0.6), cfg)
    assert should_escalate(make_finding(verified=False, confidence=0.6), cfg)


def test_gate_default_excludes_already_verified_findings():
    # Default is unverified_only=True: an oracle-verified finding is not ambiguous.
    assert not should_escalate(make_finding(verified=True, confidence=0.7), AI_CFG)


def test_gate_tolerates_malformed_config_values():
    cfg = dict(AI_CFG)
    cfg["escalate"] = {"enabled": True, "min_confidence": None, "max_confidence": "not-a-number"}
    # Falls back to defaults instead of raising.
    assert should_escalate(make_finding(confidence=0.6), cfg)


def test_severity_meets_min_valid_and_invalid_floor():
    assert severity_meets_min(Severity.HIGH, "high")
    assert severity_meets_min(Severity.CRITICAL, "medium")
    assert not severity_meets_min(Severity.MEDIUM, "high")
    # Unknown floor strings fall back to HIGH.
    assert severity_meets_min(Severity.HIGH, "urgent")


# ------------------------------------------------------------------- escalator


def test_escalator_disabled_makes_no_calls():
    cfg = {"enabled": True, "escalate": {"enabled": False}}
    stub = StubAI(['{"verdict": "confirmed", "confidence": 0.9}'])
    esc = AIEscalator(cfg, client=stub)
    report = asyncio.run(esc.escalate([make_finding()]))
    assert report["sent"] == 0
    assert stub.calls == []


def test_escalator_unavailable_client_skips_but_keeps_findings():
    finding = make_finding()
    esc = AIEscalator(AI_CFG, client=None)
    esc._client = None  # simulate no provider
    report = asyncio.run(esc.escalate([finding]))
    assert report["eligible"] == 1
    assert report["skipped"] == 1
    assert finding.confidence == 0.6  # untouched
    assert finding.metadata == {}


def test_escalator_confirmed_upgrades_finding():
    finding = make_finding(confidence=0.6, verified=False)
    stub = StubAI(['{"verdict": "confirmed", "confidence": 0.93, "reason": "query error names payload"}'])
    esc = AIEscalator(AI_CFG, client=stub)
    report = asyncio.run(esc.escalate([finding]))
    assert report["confirmed"] == 1
    assert finding.verified is True
    assert finding.confidence == 0.93
    assert "ai-confirmed" in finding.tags
    assert finding.metadata["ai_escalation"]["verdict"] == "confirmed"
    assert "AI-confirmed" in finding.notes


def test_escalator_confirmed_never_exceeds_097():
    finding = make_finding(confidence=0.5)
    stub = StubAI(['{"verdict": "confirmed", "confidence": 1.0, "reason": "sure"}'])
    esc = AIEscalator(AI_CFG, client=stub)
    asyncio.run(esc.escalate([finding]))
    assert finding.confidence == 0.97


def test_escalator_confirmed_without_confidence_still_confirms():
    # Model says "confirmed" but omits confidence: must be treated as confirmed
    # (verified=True, note says AI-confirmed), never mislabeled inconclusive.
    finding = make_finding(confidence=0.6, verified=False)
    stub = StubAI(['{"verdict": "confirmed", "reason": "query error"}'])
    esc = AIEscalator(AI_CFG, client=stub)
    report = asyncio.run(esc.escalate([finding]))
    assert report["confirmed"] == 1
    assert finding.verified is True
    assert finding.confidence == 0.6  # no numeric bump without a number
    assert finding.metadata["ai_escalation"]["verdict"] == "confirmed"
    assert "ai-confirmed" in finding.tags
    assert "AI-confirmed" in finding.notes
    assert "AI-inconclusive" not in finding.notes


def test_escalator_sanitizes_reason_for_reports():
    finding = make_finding()
    # Escaped newlines keep the canned JSON valid; json.loads turns them into
    # real newlines inside the reason, which _sanitize_reason must collapse.
    dirty = "sql error <script>alert(1)</script>\\nwith\\n\\nnewlines"
    stub = StubAI([f'{{"verdict": "confirmed", "confidence": 0.9, "reason": "{dirty}"}}'])
    esc = AIEscalator(AI_CFG, client=stub)
    asyncio.run(esc.escalate([finding]))
    assert "<script>" not in finding.notes
    assert "\n" not in finding.notes
    assert "sql error alert(1) with newlines" in finding.notes


def test_escalator_rejected_downgrades_but_keeps_finding():
    # Rejection semantics for a finding a deterministic oracle already verified:
    # only reachable when the operator opts into second opinions on verified
    # findings (unverified_only: false).
    cfg = dict(AI_CFG)
    cfg["escalate"] = {**AI_CFG["escalate"], "unverified_only": False}
    finding = make_finding(confidence=0.6, verified=True)
    stub = StubAI(['{"verdict": "rejected", "confidence": 0.9, "reason": "just an echo"}'])
    esc = AIEscalator(cfg, client=stub)
    report = asyncio.run(esc.escalate([finding]))
    assert report["rejected"] == 1
    assert finding.verified is False
    assert finding.confidence == 0.25
    assert "ai-rejected" in finding.tags


def test_escalator_inconclusive_leaves_finding_unchanged():
    finding = make_finding(confidence=0.6, verified=False)
    stub = StubAI(['{"verdict": "inconclusive", "confidence": 0.5, "reason": "unclear"}'])
    esc = AIEscalator(AI_CFG, client=stub)
    report = asyncio.run(esc.escalate([finding]))
    assert report["inconclusive"] == 1
    assert finding.confidence == 0.6
    assert finding.verified is False
    assert "ai-inconclusive" in finding.tags


def test_escalator_unparseable_output_is_inconclusive():
    finding = make_finding()
    stub = StubAI(["I think it's vulnerable. Trust me."])
    esc = AIEscalator(AI_CFG, client=stub)
    report = asyncio.run(esc.escalate([finding]))
    assert report["inconclusive"] == 1
    assert report["failed"] == 0
    assert finding.confidence == 0.6  # untouched


def test_escalator_model_error_keeps_finding():
    finding = make_finding()
    stub = StubAI(error=True)
    esc = AIEscalator(AI_CFG, client=stub)
    report = asyncio.run(esc.escalate([finding]))
    assert report["failed"] == 1
    assert finding.confidence == 0.6
    assert finding.metadata == {}


def test_escalator_respects_per_scan_cap_and_priorities():
    findings = [
        make_finding(confidence=0.5, severity=Severity.MEDIUM),   # not eligible
        make_finding(confidence=0.9),                              # not eligible (too confident)
        make_finding(confidence=0.7, severity=Severity.CRITICAL),  # eligible, first (highest sev)
        make_finding(confidence=0.4, severity=Severity.HIGH),      # eligible
        make_finding(confidence=0.6, severity=Severity.HIGH),      # eligible
    ]
    cfg = dict(AI_CFG)
    cfg["escalate"] = {**AI_CFG["escalate"], "max_per_scan": 2}
    # "inconclusive" responses never mutate confidence, so the assertion
    # below verifies pure selection order, not post-verdict mutation.
    stub = StubAI(['{"verdict": "inconclusive", "confidence": 0.5}'] * 5)
    esc = AIEscalator(cfg, client=stub)
    report = asyncio.run(esc.escalate(findings))
    assert report["eligible"] == 3
    assert report["sent"] == 2
    assert stub.calls and len(stub.calls) == 2
    escalated = [f for f in findings if f.metadata.get("ai_escalation")]
    assert len(escalated) == 2
    # Most severe first, then most ambiguous.
    assert escalated[0].severity == Severity.CRITICAL
    assert escalated[1].confidence == 0.4
    untouched = [f for f in findings if not f.metadata.get("ai_escalation")]
    assert len(untouched) == 3


def test_escalator_respects_overall_deadline():
    # 3 eligible findings, per-call delay 0.3s, overall budget 0.2s:
    # the first call is already in flight when the budget expires, the rest are
    # cut off and counted -- never sent, never applied.
    findings = [
        make_finding(confidence=0.4),
        make_finding(confidence=0.5),
        make_finding(confidence=0.6),
    ]
    cfg = dict(AI_CFG)
    cfg["escalate"] = {**AI_CFG["escalate"], "overall_deadline": 0.2, "max_per_scan": 5}
    stub = StubAI(['{"verdict": "inconclusive", "confidence": 0.5}'] * 5, delay=0.3)
    esc = AIEscalator(cfg, client=stub)
    report = asyncio.run(esc.escalate(findings))
    assert report["sent"] == 1
    assert report["cut_off"] == 2
    assert len([f for f in findings if f.metadata.get("ai_escalation")]) == 1


def test_escalation_prompt_contains_evidence_not_secrets():
    finding = make_finding()
    stub = StubAI()
    esc = AIEscalator(AI_CFG, client=stub)
    asyncio.run(esc.escalate([finding]))
    assert stub.calls
    prompt = stub.calls[0]
    assert "ATTACK HYPOTHESIS: LFI" in prompt
    assert "PAYLOAD: ../../../etc/passwd" in prompt
    assert "BASELINE RESPONSE:" in prompt
    assert "TEST RESPONSE:" in prompt
    assert '{"verdict": "confirmed|rejected|inconclusive"' in prompt
