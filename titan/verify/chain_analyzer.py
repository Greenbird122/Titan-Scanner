"""Flow-typed chain analyzer (Track D).

The old ``ChainDetector`` grouped findings by attack type and called every
SSRF a "chain" — that is not a chain, it is a category. This analyzer joins
findings on their FLOWS (the capabilities ``apply_flows`` tagged each
verified finding with): a chain exists when the capabilities of >= 2 distinct
findings COMBINE to reach a defined attack goal.

    SSRF to cloud metadata [url_fetch, creds]  +  hardcoded cloud key [creds]
        -> "Cloud Credential Exposure" (attacker has network reach AND creds)

    NoSQLi auth bypass [auth_bypass]  +  IDOR [data_leak]
        -> "Unauthorized Cross-Tenant Access"

Every goal requires a capability set; a hop set (size 2-3) qualifies when its
combined flows cover the set AND every hop contributes at least one required
flow (no passengers). One strongest chain per goal is reported (deterministic
tie-breaks), and the candidate pool is bounded so a 200-finding scan stays
fast. Unverified findings never chain — an unproven capability cannot feed a
path (same discipline as ``infer_flows``).
"""

from __future__ import annotations

import itertools
from typing import Any, Dict, List, Optional, Sequence

from titan.core.models import AttackType, Finding, Severity

_SEV_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
    Severity.UNCONFIRMED: 0,
}

# Attack goals reachable by combining finding capabilities. ``order`` is the
# hop ordering preference (enabler flows first), used only for a stable,
# readable path.
CHAIN_GOALS: List[Dict[str, Any]] = [
    {
        "name": "Cloud Credential Exposure",
        "requires": ("creds", "url_fetch"),
        "severity": Severity.CRITICAL,
        "description": (
            "The app can reach arbitrary URLs (SSRF) AND credentials are "
            "exposed — the combination hands an attacker cloud IAM/API "
            "credentials plus the network position to use them."
        ),
        "impact": "Critical — cloud credentials obtainable and usable from the target's network position.",
        "order": ("url_fetch", "creds"),
    },
    {
        "name": "Public Cloud Storage Exposure",
        "requires": ("data_leak", "url_fetch"),
        "severity": Severity.HIGH,
        "prefer_types": (AttackType.PUBLIC_STORAGE,),
        "description": (
            "A cloud storage bucket is publicly listable AND the app can "
            "reach arbitrary URLs — stored data plus the ability to pull it "
            "into the application."
        ),
        "impact": "High — attacker can read and ingest publicly exposed cloud storage.",
        "order": ("url_fetch", "data_leak"),
    },
    {
        "name": "Unauthorized Cross-Tenant Access",
        "requires": ("auth_bypass", "data_leak"),
        "severity": Severity.CRITICAL,
        "description": (
            "Authorization is bypassable AND record data leaks — the "
            "combination gives full cross-tenant read of application data."
        ),
        "impact": "Critical — attacker reads every tenant's records.",
        "order": ("auth_bypass", "data_leak"),
    },
    {
        "name": "Session Hijack via Stored Script",
        "requires": ("client_exec", "data_leak"),
        "severity": Severity.CRITICAL,
        "description": (
            "Attacker script executes in a victim browser (XSS/DOM XSS) AND "
            "application data leaks — the script can steal the leaked data "
            "or the sessions that reach it."
        ),
        "impact": "Critical — full account/session takeover from a stored script.",
        "order": ("client_exec", "data_leak"),
    },
    {
        "name": "Secret Theft to Lateral Movement",
        "requires": ("file_read", "creds"),
        "severity": Severity.HIGH,
        "description": (
            "Arbitrary file read AND exposed credentials — config and secret "
            "files can be exfiltrated and the credentials reused elsewhere."
        ),
        "impact": "High — attacker harvests secrets and moves laterally.",
        "order": ("file_read", "creds"),
    },
    {
        "name": "Remote Code Execution Pivot",
        "requires": ("code_exec", "url_fetch"),
        "severity": Severity.CRITICAL,
        "description": (
            "Arbitrary code execution AND server-side URL fetch — the "
            "attacker pivots from the compromised host into internal "
            "networks and services."
        ),
        "impact": "Critical — full internal-network compromise from RCE.",
        "order": ("code_exec", "url_fetch"),
    },
    {
        "name": "Confirmed Data Exfiltration",
        "requires": ("oob", "data_leak"),
        "severity": Severity.CRITICAL,
        "description": (
            "Out-of-band interaction is confirmed AND record data leaks — "
            "the leaked data can be exfiltrated to an attacker-controlled "
            "server."
        ),
        "impact": "Critical — confirmed data exfiltration channel.",
        "order": ("oob", "data_leak"),
    },
    {
        "name": "Model Takeover Path",
        "requires": ("model_control", "oob"),
        "severity": Severity.HIGH,
        "description": (
            "The application's AI model is attacker-steerable AND OOB "
            "interaction is confirmed — model-mediated exfiltration is "
            "possible."
        ),
        "impact": "High — attacker exfiltrates data through the AI model.",
        "order": ("model_control", "oob"),
    },
]

# Cap the per-goal candidate pool; the analyzer is O(pool^3) per goal.
_MAX_POOL = 10
_PER_FLOW_PROVIDERS = 2


class AttackChain:
    """A multi-hop attack path: >= 2 findings whose capabilities combine."""

    def __init__(self, goal: Dict[str, Any], hops: List[Finding]):
        self.name = goal["name"]
        self.description = goal["description"]
        self.impact = goal["impact"]
        self.severity = goal["severity"]
        self.hops = hops

    @property
    def capabilities(self) -> List[str]:
        return sorted({c for f in self.hops for c in f.flows})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "impact": self.impact,
            "severity": self.severity.value,
            "capabilities": self.capabilities,
            "hop_urls": [f.url for f in self.hops],
            "hops": [f.to_dict() for f in self.hops],
        }


def _sev_rank(severity: Severity) -> int:
    return _SEV_RANK.get(severity, 0)


def _order_hops(hops: List[Finding], order: Sequence[str]) -> List[Finding]:
    """Stable ordering: findings providing an earlier ``order`` flow first,
    then severity (desc), then URL for determinism."""

    def flow_pos(f: Finding) -> int:
        for i, flow in enumerate(order):
            if flow in f.flows:
                return i
        return len(order)

    return sorted(
        hops,
        key=lambda f: (flow_pos(f), -_sev_rank(f.severity), f.url),
    )


def _candidate_pool(verified: List[Finding], required: set) -> List[Finding]:
    """Bounded, coverage-guaranteed candidate set for a goal.

    The top ``_PER_FLOW_PROVIDERS`` findings for each required flow are always
    included (so a low-severity sole provider can never be starved out), then
    the pool is filled with the strongest remaining providers up to
    ``_MAX_POOL``.
    """
    pool: List[Finding] = []
    seen = set()
    for flow in required:
        providers = sorted(
            (f for f in verified if flow in f.flows),
            key=lambda f: (-_sev_rank(f.severity), f.url),
        )[:_PER_FLOW_PROVIDERS]
        for f in providers:
            if id(f) not in seen:
                seen.add(id(f))
                pool.append(f)
    rest = sorted(
        (f for f in verified if required.intersection(f.flows) and id(f) not in seen),
        key=lambda f: (-_sev_rank(f.severity), f.url),
    )[:_MAX_POOL - len(pool)]
    pool.extend(rest)
    return pool


def _combo_severity(hops: List[Finding]) -> int:
    return sum(_sev_rank(f.severity) for f in hops)


def _combo_key(chain: "AttackChain", prefer_types=()) -> tuple:
    """Chain quality key. The FEWEST hops wins first (a minimal covering set
    is the more precise statement of the goal — a 2-hop SSRF+bucket chain
    beats a 3-hop that drags in unrelated data_leak findings); then combined
    severity; then how many hops match the goal's thematic attack types (so
    the storage chain names the bucket finding, not an unrelated NoSQLi)."""
    thematic = sum(1 for f in chain.hops if f.attack_type in prefer_types)
    return (-len(chain.hops), _combo_severity(chain.hops), thematic)


class ChainAnalyzer:
    """Flow-typed chain detector. ``detect`` MUST run after ``apply_flows`` —
    it reads ``Finding.flows``, which is empty until then."""

    def detect(self, findings: List[Finding]) -> List[AttackChain]:
        verified = [f for f in findings if f.verified and f.flows]
        chains: List[AttackChain] = []

        for goal in CHAIN_GOALS:
            required = set(goal["requires"])
            pool = _candidate_pool(verified, required)
            if len(pool) < 2:
                continue

            best: Optional[AttackChain] = None
            for size in (2, 3):
                if len(pool) < size:
                    break
                for combo in itertools.combinations(pool, size):
                    combined = {c for f in combo for c in f.flows}
                    if not required.issubset(combined):
                        continue
                    # No passengers: every hop must contribute a required flow.
                    if not all(required.intersection(f.flows) for f in combo):
                        continue
                    chain = AttackChain(goal, _order_hops(list(combo), goal["order"]))
                    if best is None or _combo_key(chain, goal.get("prefer_types", ())) > _combo_key(best, goal.get("prefer_types", ())):
                        best = chain
            if best is not None:
                chains.append(best)

        return chains
