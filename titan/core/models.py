"""Core types and models for Titan Scanner."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNCONFIRMED = "unconfirmed"


class AttackType(Enum):
    NO_SQLI = "NoSQLi"
    SQLI = "SQLi"
    XSS = "XSS"
    LFI = "LFI"
    RCE = "RCE"
    SSTI = "SSTI"
    SSRF = "SSRF"
    XXE = "XXE"
    OPEN_REDIRECT = "Open Redirect"
    INFO_LEAK = "Info Leak"
    AUTH_BYPASS = "Auth Bypass"
    BUSINESS_LOGIC = "Business Logic"
    BLIND_INJECTION = "Blind Injection"
    OOB = "OOB"
    DESERIALIZATION = "Deserialization"
    RACE_CONDITION = "Race Condition"
    CACHE_POISONING = "Cache Poisoning"
    REQUEST_SMUGGLING = "Request Smuggling"
    PROTO_POLLUTION = "Prototype Pollution"
    CRYPTO_WEAKNESS = "Crypto Weakness"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    IDOR = "IDOR"
    UPLOAD = "Upload"
    NO_ISSUE = "No Issue"


@dataclass
class Finding:
    target: str
    url: str
    method: str
    param: str
    location: str
    payload: str
    attack_type: Optional[AttackType] = None
    severity: Severity = Severity.UNCONFIRMED
    verified: bool = False
    confidence: float = 0.0
    status: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    diffs: List[str] = field(default_factory=list)
    baseline_body: str = ""
    baseline_status: Optional[int] = None
    verification_body: str = ""
    verification_status: Optional[int] = None
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    poc_curl: str = ""
    poc_python: str = ""
    screenshot_path: Optional[str] = None
    notes: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    chain: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "url": self.url,
            "method": self.method,
            "param": self.param,
            "location": self.location,
            "payload": self.payload,
            "attack_type": self.attack_type.value if self.attack_type else None,
            "severity": self.severity.value,
            "verified": self.verified,
            "confidence": self.confidence,
            "status": self.status,
            "headers": self.headers,
            "body": self.body,
            "diffs": self.diffs,
            "baseline_body": self.baseline_body,
            "baseline_status": self.baseline_status,
            "verification_body": self.verification_body,
            "verification_status": self.verification_status,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "poc_curl": self.poc_curl,
            "poc_python": self.poc_python,
            "screenshot_path": self.screenshot_path,
            "notes": self.notes,
            "metadata": self.metadata,
            "chain": self.chain,
            "tags": self.tags,
        }


@dataclass
class ScanResult:
    target: str
    started_at: float
    finished_at: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    fingerprint: Dict[str, Any] = field(default_factory=dict)
    config_snapshot: Dict[str, Any] = field(default_factory=dict)
    ai_escalation: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        if self.finished_at and self.started_at:
            return round(self.finished_at - self.started_at, 2)
        return 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def verified_count(self) -> int:
        return sum(1 for f in self.findings if f.verified)

    @property
    def chain_count(self) -> int:
        return sum(1 for f in self.findings if f.chain)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "fingerprint": self.fingerprint,
            "config_snapshot": self.config_snapshot,
            "ai_escalation": self.ai_escalation,
            "summary": {
                "total": len(self.findings),
                "verified": self.verified_count,
                "critical": self.critical_count,
                "high": self.high_count,
                "chains": self.chain_count,
            },
        }
