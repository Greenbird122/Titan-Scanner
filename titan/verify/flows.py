"""Flow typing for Titan Scanner (Track D prerequisite).

Every verified finding declares what it EXPOSES to an attacker. The chain
analyzer (Track D) later joins findings whose *provides* feed another
finding's *consumes* (SSRF -> metadata creds -> storage). This module is the
single source of truth mapping attack evidence to capabilities.

Capability vocabulary (stable strings, stored in ``Finding.flows``):

- ``file_read``   : can read arbitrary files from the target (LFI)
- ``creds``       : leaks credentials / secrets (hardcoded keys, metadata creds)
- ``url_fetch``   : can make the server fetch attacker URLs (SSRF)
- ``auth_bypass`` : bypasses authentication or authorization checks (NoSQLi $ne,
                    JWT alg confusion, session fixation)
- ``code_exec``   : executes arbitrary code on the target (RCE, SSTI, XXE, deser)
- ``data_leak``   : leaks application data across tenants/records (IDOR, BOLA,
                    SQLi row exfil)
- ``oob``         : confirms out-of-band interaction (interactsh callback)
- ``client_exec`` : executes attacker script in a victim browser (XSS)
- ``model_control``: steers or extracts from the application's AI model
  (prompt injection, system-prompt leak, tool abuse, model exfiltration)
"""

from __future__ import annotations

from typing import Dict, List

from titan.core.models import AttackType, Finding

# Capability -> human description. Also serves as the vocabulary contract for
# the chain analyzer.
FLOW_DESCRIPTIONS: Dict[str, str] = {
    "file_read": "can read arbitrary files from the target",
    "creds": "leaks credentials or secrets",
    "url_fetch": "can make the server fetch attacker-controlled URLs",
    "auth_bypass": "bypasses authentication or authorization checks",
    "code_exec": "executes arbitrary code on the target",
    "data_leak": "leaks application data across records/tenants",
    "oob": "confirms out-of-band interaction",
    "client_exec": "executes attacker script in a victim browser",
    "model_control": "steers or extracts from the application's AI model",
}

# Flow inferred from *verified* evidence per attack class. Keep conservative:
# unverified / low-confidence findings get no flow (an unproven capability
# must not feed a chain).
_VERIFIED_FLOWS: Dict[AttackType, List[str]] = {
    AttackType.LFI: ["file_read"],
    AttackType.SSRF: ["url_fetch"],
    AttackType.RCE: ["code_exec"],
    AttackType.SSTI: ["code_exec"],
    AttackType.XXE: ["file_read", "url_fetch"],
    AttackType.DESERIALIZATION: ["code_exec"],
    AttackType.CRYPTO_WEAKNESS: ["creds"],
    AttackType.HARDCODED_SECRET: ["creds"],
    AttackType.NO_SQLI: ["auth_bypass", "data_leak"],
    AttackType.AUTH_BYPASS: ["auth_bypass"],
    AttackType.IDOR: ["data_leak"],
    AttackType.BOLA: ["data_leak", "auth_bypass"],
    AttackType.MASS_ASSIGNMENT: ["auth_bypass"],
    AttackType.JWT_WEAKNESS: ["auth_bypass"],
    AttackType.SESSION_FIXATION: ["auth_bypass"],
    AttackType.SQLI: ["data_leak"],
    AttackType.XSS: ["client_exec"],
    AttackType.DOM_XSS: ["client_exec"],
    AttackType.PROTO_POLLUTION: ["client_exec"],
    AttackType.POSTMESSAGE: ["data_leak"],
    AttackType.SKIMMER: ["creds", "data_leak"],
    # Track G — hostile & ad-monetized surface.
    AttackType.MINER_SCRIPT: ["data_leak"],
    AttackType.AD_MITM_CLEARTEXT: ["client_exec"],
    AttackType.AD_PHISHING_CHAIN: ["data_leak"],
    AttackType.SRI_ABSENT: ["client_exec"],
    AttackType.AD_DOMAIN_FLUX: ["client_exec"],
    AttackType.AD_REFERRER_GATE: [],
    AttackType.HOSTILE_CLOAK: [],
    AttackType.CLICKBAIT: [],
    AttackType.PUSH_NOTIFICATION_ABUSE: [],
    AttackType.RACE_CONDITION: ["data_leak"],
    AttackType.CACHE_POISONING: ["client_exec", "data_leak"],
    AttackType.OPEN_REDIRECT: ["url_fetch"],
    AttackType.PROMPT_INJECTION: ["model_control"],
    AttackType.SYSTEM_LEAK: ["model_control", "data_leak"],
    AttackType.LLM_EXFIL: ["model_control", "oob"],
    AttackType.LLM_AGENCY: ["model_control"],
    AttackType.PUBLIC_STORAGE: ["data_leak"],
}

# SSRF that reached the cloud metadata endpoint hands the attacker IAM
# credentials — a strictly stronger capability than url_fetch alone.
_METADATA_MARKERS = ("169.254.169.254", "metadata.google.internal", "169.254.170.2")


def infer_flows(finding: Finding) -> List[str]:
    """Return the capabilities a *verified* finding exposes.

    Unverified findings expose nothing (an unproven capability must not feed
    a chain). Evidence-specific refinements: SSRF to cloud metadata upgrades
    to credential exposure.
    """
    if not finding.verified or finding.attack_type is None:
        return []

    base = list(_VERIFIED_FLOWS.get(finding.attack_type, []))
    if finding.attack_type == AttackType.SSRF and any(
        m in (finding.payload or "") for m in _METADATA_MARKERS
    ):
        if "creds" not in base:
            base.append("creds")

    if finding.attack_type == AttackType.XXE and any(
        m in (finding.payload or "") for m in ("file://", "expect://")
    ):
        if "file_read" not in base:
            base.append("file_read")

    return base


def apply_flows(findings: List[Finding]) -> None:
    """Populate ``Finding.flows`` in place for every finding."""
    for f in findings:
        f.flows = infer_flows(f)
