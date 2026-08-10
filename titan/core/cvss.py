"""CVSS v3.1 scoring engine for Titan Scanner."""

from __future__ import annotations

from typing import Any, Dict, Optional

from titan.core.models import Severity, AttackType


class CVSSScorer:
    ATTACK_TYPE_BASE_SCORES: Dict[AttackType, float] = {
        AttackType.SQLI: 9.0,
        AttackType.XSS: 6.1,
        AttackType.SSRF: 9.0,
        AttackType.RCE: 10.0,
        AttackType.LFI: 7.5,
        AttackType.XXE: 7.5,
        AttackType.NO_SQLI: 9.0,
        AttackType.SSTI: 9.0,
        AttackType.UPLOAD: 9.0,
        AttackType.DESERIALIZATION: 9.0,
        AttackType.IDOR: 7.5,
        AttackType.AUTH_BYPASS: 9.0,
        AttackType.BUSINESS_LOGIC: 7.5,
        AttackType.RACE_CONDITION: 7.5,
        AttackType.CACHE_POISONING: 7.5,
        AttackType.REQUEST_SMUGGLING: 9.0,
        AttackType.CRYPTO_WEAKNESS: 7.5,
        AttackType.INFO_LEAK: 5.3,
        AttackType.BLIND_INJECTION: 7.5,
        AttackType.OOB: 7.5,
        AttackType.PROTO_POLLUTION: 7.5,
        AttackType.PRIVILEGE_ESCALATION: 9.0,
    }

    VERIFIED_BOOST = 1.5
    HIGH_CONFIDENCE_BOOST = 1.2
    UNVERIFIED_PENALTY = 0.7

    @classmethod
    def score(cls, finding) -> Dict[str, Any]:
        base = cls.ATTACK_TYPE_BASE_SCORES.get(finding.attack_type, 5.0)

        if finding.verified:
            base *= cls.VERIFIED_BOOST
        else:
            base *= cls.UNVERIFIED_PENALTY

        if finding.confidence >= 0.8:
            base *= cls.HIGH_CONFIDENCE_BOOST
        elif finding.confidence < 0.5:
            base *= 0.8

        severity_multiplier = {
            Severity.CRITICAL: 1.3,
            Severity.HIGH: 1.15,
            Severity.MEDIUM: 1.0,
            Severity.LOW: 0.9,
            Severity.UNCONFIRMED: 0.8,
        }
        multiplier = severity_multiplier.get(finding.severity, 1.0)
        base *= multiplier

        cvss = min(10.0, max(0.0, base))

        vector = cls._build_vector_string(finding, cvss)
        return {
            "cvss_score": round(cvss, 1),
            "cvss_vector": vector,
        }

    @classmethod
    def _build_vector_string(cls, finding, cvss_score: float) -> str:
        av = "N" if finding.location == "remote" else "A"
        ac = "L"
        pr = "H" if finding.attack_type in (AttackType.AUTH_BYPASS, AttackType.PRIVILEGE_ESCALATION) else "L"
        ui = "N" if finding.location in ("query", "body") else "R"
        s = "C"
        c = "H" if finding.verified else "L"
        i = "H" if finding.verified else "L"
        a = "H" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "L"

        return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    @classmethod
    def get_severity_from_cvss(cls, cvss_score: float) -> Severity:
        if cvss_score >= 9.0:
            return Severity.CRITICAL
        elif cvss_score >= 7.0:
            return Severity.HIGH
        elif cvss_score >= 4.0:
            return Severity.MEDIUM
        elif cvss_score > 0.0:
            return Severity.LOW
        return Severity.UNCONFIRMED
