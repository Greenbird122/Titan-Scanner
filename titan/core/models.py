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
    DOM_XSS = "DOM XSS"
    POSTMESSAGE = "postMessage"
    SKIMMER = "Skimmer"
    CSP_WEAKNESS = "CSP Weakness"
    BOLA = "BOLA"
    MASS_ASSIGNMENT = "Mass Assignment"
    JWT_WEAKNESS = "JWT Weakness"
    SESSION_FIXATION = "Session Fixation"
    PROMPT_INJECTION = "Prompt Injection"
    SYSTEM_LEAK = "System Prompt Leak"
    LLM_EXFIL = "LLM Data Exfiltration"
    LLM_AGENCY = "LLM Tool Abuse"
    PUBLIC_STORAGE = "Public Cloud Storage"
    UPLOAD = "Upload"
    REDIRECT_HIJACK = "Redirect Hijack"
    # Track G — hostile & ad-monetized surface.
    HOSTILE_CLOAK = "Hostile Cloak"
    CLICKBAIT = "Clickbait"
    MINER_SCRIPT = "Miner Script"
    PUSH_NOTIFICATION_ABUSE = "Push-Notification Abuse"
    AD_MITM_CLEARTEXT = "Ad Supply-Chain Cleartext"
    AD_PHISHING_CHAIN = "Ad Redirect Chain"
    AD_REFERRER_GATE = "Ad Referrer Gate"
    SRI_ABSENT = "Third-Party Script Without SRI"
    AD_DOMAIN_FLUX = "Ad Domain Flux"
    # Source/bundle floor: hardcoded credentials in served code.
    HARDCODED_SECRET = "Hardcoded Secret"
    # PUSH-TO-100 B3 — novel-class detectors.
    FUZZ_DIFFERENTIAL = "Fuzz Differential"
    PARSER_DIFFERENTIAL = "Parser Differential"
    API_EXPOSURE = "API Exposure"
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
    # Track D (chain analysis) prerequisite: what this finding EXPOSES to an
    # attacker ("file_read", "creds", "url_fetch", "auth_bypass",
    # "code_exec", "data_leak", "oob", "client_exec"). Populated by
    # titan.verify.flows.apply_flows() at scan end.
    flows: List[str] = field(default_factory=list)
    # SCAN-QUALITY M1 evidence grade: "confirmed" (strong oracle marker in
    # the diffs), "corroborated" (verified but no named strong marker),
    # "indicative" (weak signals only), "none". Assigned by
    # titan.verify.oracles.enforce_evidence() at scan end, which also
    # AUTO-DEMOTES injection-family findings that are marked verified without
    # any strong marker (reflection-verifies storms). Serialized so reports
    # can sort by evidence strength.
    evidence: str = ""
    # PUSH-TO-100 A1 evidence TIER: "confirmed" (verified, names a strong
    # oracle marker — the finding is scored with CVSS/PoC and reported as
    # real) vs "suspicious" (behavioral signal only — triaged, never scored
    # as if proven). Derived from `evidence` by enforce_evidence(); "" means
    # no evidence at all. This is the tiered FP-policy contract (spec D4):
    # every finding is one of confirmed/suspicious/none, never mislabeled.
    tier: str = ""

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
            "flows": self.flows,
            "evidence": self.evidence,
            "tier": self.tier,
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
    # Track D — flow-typed attack chains (full path + per-hop evidence), each
    # an AttackChain.to_dict(). Populated by ChainAnalyzer after apply_flows.
    chains: List[Dict[str, Any]] = field(default_factory=list)
    # Track E — sessions auto-staged during the scan (rce-agent, webshell,
    # sqli-extraction channels). Each entry carries channel, session_id and the
    # session dir for attribution. Populated by _run_exploit_modules; empty
    # unless the operator enabled exploit and holds consent for the target.
    exploit_sessions: List[Dict[str, Any]] = field(default_factory=list)
    # Track G — hostile & ad-monetized surface profile (profile + observed
    # intel + serialized hostile findings). Populated by the engine's hostile
    # pass; empty unless crawl.profile == hostile.
    hostile: Dict[str, Any] = field(default_factory=dict)
    # PUSH-TO-100 A3 — coverage accounting. Populated by the engine at scan
    # end: `status` is "complete" when the scan provably covered the
    # discovered surface (queue drained, every discovered API ran the module
    # matrix, no checkpoint/driver/budget abort) or "partial" with a `reason`
    # naming WHY (crawl budget, max_pages cap, depth cap, checkpoint,
    # driver death, API cap). Carries the raw counters so the operator can
    # audit the claim.
    coverage: Dict[str, Any] = field(default_factory=dict)

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
    def confirmed_count(self) -> int:
        return sum(1 for f in self.findings if f.tier == "confirmed")

    @property
    def suspicious_count(self) -> int:
        return sum(1 for f in self.findings if f.tier == "suspicious")

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
            "chains": self.chains,
            "exploit_sessions": self.exploit_sessions,
            "hostile": self.hostile,
            "coverage": self.coverage,
            "summary": {
                "total": len(self.findings),
                "verified": self.verified_count,
                "confirmed": self.confirmed_count,
                "suspicious": self.suspicious_count,
                "critical": self.critical_count,
                "high": self.high_count,
                "chains": self.chain_count,
            },
        }
