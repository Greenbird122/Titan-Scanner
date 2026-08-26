"""Track G — Hostile & Ad-Monetized Surface.

Profiles the ad/monetization stack of ad-heavy sites (ad networks, popunders,
push abuse, miners, anti-debug cloaks, clickbait), hardens the picture with
deterministic supply-chain findings (cleartext ad scripts, missing SRI,
domain flux) and, under signed consent, runs the bounded active probes
(redirect-chain mapping, referrer-gate detection).

Use:
    from titan.hostile import run_pass
    payload = await run_pass(html_samples, base_url, session=aiohttp_session,
                             consented=True, target=target)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from titan.core.models import Finding
from titan.hostile import offense, profiler
from titan.hostile.intel import IntelDB, ObservedIntel
from titan.hostile.profiler import analyze

__all__ = ["run_pass", "IntelDB", "ObservedIntel", "analyze", "offense", "profiler"]


async def run_pass(
    html_samples: List[Dict[str, str]],
    base_url: str,
    target: str = "",
    session=None,
    consented: bool = False,
    prior_observed: Optional[Dict[str, Any]] = None,
    block_private: bool = True,
) -> Dict[str, Any]:
    """Run the full hostile-surface pass over one or more page samples.

    Args:
        html_samples: [{"url": ..., "html": ...}, ...]
        base_url:     canonical target URL
        target:       finding target string (defaults to base_url)
        session:      aiohttp ClientSession for the ACTIVE probes (redirect
                      chains / referrer gates); must be provided for them to run
        consented:    signed consent held for the target — gates the active
                      probes (Track E model). Read-only analysis always runs.
        prior_observed: previous scan's intel.json dict (domain-flux diff, M6)
        block_private: refuse active-probe hops that resolve into private /
                      loopback / link-local space (True). Local-fixture tests
                      pass False explicitly.

    Returns a dict with: profile (merged), observed, findings (serialized),
    consented (bool) and active_probes (bool).
    """
    target = target or base_url
    intel = IntelDB()
    observed = ObservedIntel()

    pages: List[Dict[str, Any]] = []
    merged_origins: Dict[str, Dict[str, Any]] = {}
    merged_counts: Dict[str, int] = {}
    merged_clickbait: Optional[Dict[str, Any]] = None
    all_cloaks: List[Dict[str, Any]] = []
    all_miners: List[Dict[str, Any]] = []
    all_push: List[Dict[str, Any]] = []
    all_mechanics: List[Dict[str, Any]] = []

    for sample in html_samples or []:
        html = sample.get("html", "")
        page_url = sample.get("url") or base_url
        if not html:
            continue
        prof = analyze(html, page_url, intel=intel, observed=observed)
        pages.append(prof)
        for r in prof["origins"]:
            key = r["host"]
            if key in merged_origins:
                prev = merged_origins[key]
                prev["kinds"] = sorted(set(prev["kinds"]) | set(r["kinds"]))
                prev["count"] += r["count"]
                prev["cleartext"] = prev["cleartext"] or r["cleartext"]
                prev["sri_missing"] = prev["sri_missing"] or r["sri_missing"]
                prev["risk_score"] = max(prev["risk_score"], r["risk_score"])
                prev["urls"] = list(dict.fromkeys(prev["urls"] + r["urls"]))[:8]
            else:
                merged_origins[key] = dict(r)
        for cat, n in prof["counts"].items():
            merged_counts[cat] = merged_counts.get(cat, 0) + n
        if merged_clickbait is None:
            merged_clickbait = prof["clickbait"]
        all_cloaks.extend(prof["cloaks"])
        all_miners.extend(prof["miners"])
        all_push.extend(prof["push"])
        all_mechanics.extend(prof["mechanics"])

    all_cloaks = _dedupe_signals(all_cloaks)
    all_miners = _dedupe_signals(all_miners)
    all_push = _dedupe_signals(all_push)
    all_mechanics = _dedupe_signals(all_mechanics)

    origin_rows = sorted(merged_origins.values(), key=lambda r: (-r["risk_score"], r["host"]))
    monetization_score = min(
        100,
        sum(({"miner": 50, "risky_ad": 30, "popunder": 20, "push_notif": 12,
              "ad_network": 6, "tracker": 3}.get(r.get("category"), 3)) for r in origin_rows) // 2
        + len(all_cloaks) * 6 + (merged_clickbait or {}).get("score", 0) // 5
        + len(all_miners) * 15,
    )

    profile = {
        "page_url": base_url,
        "monetization_score": monetization_score,
        "origins": origin_rows,
        "counts": merged_counts,
        "clickbait": merged_clickbait or {"score": 0, "signals": [], "mechanics": [], "grade": "low"},
        "cloaks": all_cloaks,
        "miners": all_miners,
        "push": all_push,
        "mechanics": all_mechanics,
    }

    findings: List[Finding] = []
    findings.extend(offense.cleartext_findings(profile, target))
    findings.extend(offense.sri_findings(profile, target))
    findings.extend(offense._category_findings(profile, target))
    findings.extend(offense.flux_findings(profile, prior_observed, target))

    active_probes = bool(session) and bool(consented)
    if active_probes:
        findings.extend(await offense.map_redirect_chains(
            session, profile, target, block_private=block_private))
        findings.extend(await offense.probe_referrer_gate(
            session, profile, target, block_private=block_private))

    return {
        "profile": profile,
        "observed": observed.to_dict(),
        "findings": [f.to_dict() for f in findings],
        "consented": bool(consented),
        "active_probes": active_probes,
    }


def _dedupe_signals(signals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for s in signals:
        key = s.get("oracle", "")
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def findings_from_dicts(rows: List[Dict[str, Any]]) -> List[Finding]:
    """Rebuild Finding objects from serialized dicts (engine + CLI use this)."""
    from titan.core.models import AttackType, Severity
    out: List[Finding] = []
    for d in rows:
        f = Finding(
            target=d.get("target", ""),
            url=d.get("url", ""),
            method=d.get("method", "GET"),
            param=d.get("param", ""),
            location=d.get("location", "client"),
            payload=d.get("payload", ""),
        )
        try:
            f.attack_type = AttackType(d["attack_type"]) if d.get("attack_type") else None
        except Exception:
            f.attack_type = None
        try:
            f.severity = Severity(d.get("severity", "unconfirmed"))
        except Exception:
            f.severity = None
        f.verified = bool(d.get("verified"))
        f.confidence = float(d.get("confidence") or 0.0)
        f.diffs = list(d.get("diffs") or [])
        f.metadata = d.get("metadata") or {}
        f.evidence = str(d.get("evidence") or "")
        out.append(f)
    return out
