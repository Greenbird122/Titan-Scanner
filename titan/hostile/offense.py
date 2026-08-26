"""Track G offensive probes (M5/M6) — consent-gated, aiohttp-based.

Read-only by construction (GET-only, bounded hops, own session): the active
probes here — following a third-party redirect chain and probing a
referrer/geo ad-delivery gate — are gated behind a signed consent file for the
target by the caller (``titan.hostile.run_pass``). The deterministic
findings (cleartext ad scripts, SRI-absent ad scripts, domain flux) are
computed from the profile and need no extra traffic.

Active probes refuse to fetch destinations that resolve into private /
loopback / link-local address space (``_hop_allowed``): the ad chain is
attacker-influenced, and the scanner must never become a fetch oracle for the
operator's own network (metadata endpoints, internal hosts).
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from titan.core.models import AttackType, Finding, Severity
from titan.hostile.detectors import classify_terminal
from titan.hostile.profiler import body_fingerprint

MAX_HOPS = 3
MAX_CHAINS = 6
MAX_GATE_REFERERS = 3


def _ip_blocked(ip_str: str) -> bool:
    """True when an IP literal is private / loopback / link-local / reserved."""
    try:
        ip = ipaddress.ip_address(ip_str.split("%")[0])
    except ValueError:
        return False
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def _hop_allowed(url: str) -> bool:
    """Refuse to follow a probe hop that resolves into non-public space.

    Literal IPs are checked directly; hostnames are resolved and require
    EVERY A/AAAA record to be public (guards DNS rebinding). Unresolvable
    hosts are refused — if the destination can't be verified as public it
    isn't fetched.
    """
    try:
        host = (urlparse(url).hostname or "").lower().rstrip(".")
    except Exception:
        return False
    if not host:
        return False
    if host == "localhost" or host.endswith((".local", ".internal", ".lan", ".home")):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return not _ip_blocked(host)
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return False
    if not infos:
        return False
    return all(not _ip_blocked(i[4][0]) for i in infos)


def _origin_attr(profile: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The page origin for finding URLs (first profile page, fallback '')."""
    return profile.get("page_url") or ""


def cleartext_findings(profile: Dict[str, Any], target: str) -> List[Finding]:
    """Deterministic: ad/third-party script loaded over http:// on an https page."""
    findings: List[Finding] = []
    page_url = _origin_attr(profile)
    for row in profile.get("origins", []):
        if not row.get("cleartext"):
            continue
        for url in row.get("urls", [])[:3]:
            findings.append(Finding(
                target=target,
                url=url,
                method="GET",
                param="script[src]",
                location="client",
                payload=f"Cleartext third-party resource on an https page: {url}",
                attack_type=AttackType.AD_MITM_CLEARTEXT,
                severity=Severity.MEDIUM,
                verified=True,
                confidence=0.95,
                diffs=["adtech:tls", f"adtech:cleartext:{row['host']}"],
                metadata={"host": row["host"], "category": row.get("category")},
                evidence="confirmed",
            ))
    return findings


def sri_findings(profile: Dict[str, Any], target: str) -> List[Finding]:
    """SRI-absent classified ad/popunder scripts — supply-chain surface (M6)."""
    findings: List[Finding] = []
    page_url = _origin_attr(profile)
    for row in profile.get("origins", []):
        if not row.get("sri_missing"):
            continue
        if row.get("category") not in ("ad_network", "popunder", "push_notif", "risky_ad", "miner"):
            continue
        for url in row.get("urls", [])[:3]:
            findings.append(Finding(
                target=target,
                url=url,
                method="GET",
                param="script[integrity]",
                location="client",
                payload=f"Ad script loaded without Subresource Integrity (tamperable supply chain): {url}",
                attack_type=AttackType.SRI_ABSENT,
                severity=Severity.LOW,
                verified=True,
                confidence=0.9,
                diffs=["adtech:sri", f"adtech:sri-absent:{row['host']}"],
                metadata={"host": row["host"], "category": row.get("category")},
                evidence="confirmed",
            ))
    return findings


def _category_findings(profile: Dict[str, Any], target: str) -> List[Finding]:
    """Signal findings for miners, cloaks, push abuse, clickbait mechanics."""
    findings: List[Finding] = []
    page_url = _origin_attr(profile)

    def _make(attack: AttackType, severity: Severity, payload: str, oracle: str,
              confidence: float, metadata: Dict[str, Any], verified: bool = True) -> Finding:
        return Finding(
            target=target,
            url=page_url,
            method="GET",
            param="page[content]",
            location="client",
            payload=payload,
            attack_type=attack,
            severity=severity,
            verified=verified,
            confidence=confidence,
            diffs=[oracle],
            metadata=metadata,
            evidence="confirmed" if verified else "indicative",
        )

    for m in profile.get("miners", []):
        findings.append(_make(
            AttackType.MINER_SCRIPT, Severity.HIGH,
            f"Browser miner signature: {m['signal']}", m["oracle"], m["confidence"],
            {"signal": m["signal"]},
        ))
    for c in profile.get("cloaks", []):
        findings.append(_make(
            AttackType.HOSTILE_CLOAK, Severity.LOW if c["severity"] == "low" else Severity.INFO,
            f"Anti-debug cloak: {c['signal']}", c["oracle"], c["confidence"],
            {"signal": c["signal"]},
        ))
    for p in profile.get("push", []):
        findings.append(_make(
            AttackType.PUSH_NOTIFICATION_ABUSE, Severity.LOW,
            f"Push-notification pattern: {p['signal']}", p["oracle"], p["confidence"],
            {"signal": p["signal"]},
        ))
    for m in profile.get("mechanics", []):
        findings.append(_make(
            AttackType.CLICKBAIT, Severity.LOW,
            f"Clickbait mechanics: {m['signal']}", m["oracle"], m["confidence"],
            {"signal": m["signal"]},
        ))
    return findings


async def map_redirect_chains(session, profile: Dict[str, Any], target: str,
                              max_hops: int = MAX_HOPS,
                              block_private: bool = True) -> List[Finding]:
    """Follow each third-party load origin's URL chain (bounded) and classify
    the terminal (M5).

    Active probe — caller must gate on consent. Navigation is GET-only with
    no cookies. Every hop is subject to ``_hop_allowed`` unless
    ``block_private`` is False (the explicit local-fixture test escape
    hatch); a chain that steps into private/loopback space is refused.
    """
    findings: List[Finding] = []
    page_url = _origin_attr(profile)
    seen: set = set()
    count = 0
    for row in profile.get("origins", []):
        if count >= MAX_CHAINS:
            break
        # Consent already gates this function; follow any third-party load
        # origin the page pulls in (the terminal classifier decides whether
        # the chain ends somewhere meaningful — unknown/benign terminals are
        # never findings).
        for start_url in row.get("urls", []):
            if start_url in seen or count >= MAX_CHAINS:
                break
            seen.add(start_url)
            hops = []
            current = start_url
            try:
                for _ in range(max_hops):
                    if block_private and not _hop_allowed(current):
                        break
                    if current in seen and hops:
                        break
                    seen.add(current)
                    resp = await asyncio.wait_for(
                        session.get(current, timeout=8, ssl=False,
                                    allow_redirects=False),
                        timeout=10,
                    )
                    hops.append({
                        "url": current,
                        "status": resp.status,
                        "location": resp.headers.get("location", ""),
                    })
                    if resp.status in (301, 302, 303, 307, 308) and resp.headers.get("location"):
                        from urllib.parse import urljoin
                        current = urljoin(current, resp.headers["location"])
                    else:
                        break
                if not hops:
                    # Refused (private hop) or unresolvable — never a finding.
                    continue
                terminal = classify_terminal(current)
                if terminal["category"] != "unknown" and terminal["confidence"] >= 0.65:
                    count += 1
                    findings.append(Finding(
                        target=target,
                        url=start_url,
                        method="GET",
                        param="redirect",
                        location="client",
                        payload=f"Ad redirect chain terminates in {terminal['category']}: {current}",
                        attack_type=AttackType.AD_PHISHING_CHAIN,
                        severity=Severity.HIGH if terminal["category"] == "phishing" else Severity.MEDIUM,
                        verified=True,
                        confidence=terminal["confidence"],
                        diffs=[f"adtech:redirect_chain:{terminal['category']}",
                               f"adtech:terminal:{terminal['confidence']:.2f}"],
                        metadata={"chain": hops, "terminal": terminal, "host": row["host"]},
                        evidence="confirmed",
                    ))
            except Exception:
                continue
    return findings


async def probe_referrer_gate(session, profile: Dict[str, Any], target: str,
                              block_private: bool = True) -> List[Finding]:
    """Detect referrer-gated ad delivery: same URL, different Referer, diff (M5).

    Active probe — caller must gate on consent. To avoid the rotating-ad
    false positive (ad content varies between ANY two requests), every Referer
    is fetched TWICE and must be STABLE under that referer (both fetches
    identical); the no-referer control must also be stable. Only a referer
    whose stable fingerprint differs from the stable control is a gate.
    """
    findings: List[Finding] = []
    page_url = _origin_attr(profile)
    referers = ["", "https://google.com/", "https://facebook.com/"]
    for row in profile.get("origins", []):
        if row.get("category") not in ("ad_network", "popunder", "risky_ad"):
            continue
        for url in row.get("urls", []):
            if block_private and not _hop_allowed(url):
                continue
            samples: Dict[str, Optional[str]] = {}
            try:
                for ref in referers[:MAX_GATE_REFERERS]:
                    fps = []
                    for _ in range(2):
                        headers = {"Referer": ref} if ref else {}
                        resp = await asyncio.wait_for(session.get(url, timeout=8, ssl=False,
                                                                  headers=headers), timeout=10)
                        text = await resp.text(errors="replace")
                        fps.append(body_fingerprint(text[:4000]))
                    # Stable under this referer -> its fingerprint; else None.
                    samples[ref or "none"] = fps[0] if len(set(fps)) == 1 else None
            except Exception:
                continue
            baseline = samples.get("none")
            if not baseline:
                # No stable control (content rotates) — don't guess.
                continue
            gated = sorted(
                ref for ref, fp in samples.items()
                if ref != "none" and fp and fp != baseline
            )
            if gated:
                findings.append(Finding(
                    target=target,
                    url=url,
                    method="GET",
                    param="Referer",
                    location="client",
                    payload=f"Ad delivery varies by Referer header (referrer-gated content: {', '.join(gated)})",
                    attack_type=AttackType.AD_REFERRER_GATE,
                    severity=Severity.LOW,
                    verified=True,
                    confidence=0.8,
                    diffs=[f"adtech:referrer_gate:{','.join(gated)}"],
                    metadata={"variants": samples, "host": row["host"]},
                    evidence="confirmed",
                ))
            break
        if findings:
            break
    return findings


def flux_findings(profile: Dict[str, Any], prior_observed: Optional[Dict[str, Any]],
                  target: str) -> List[Finding]:
    """Ad-domain rotation between scans (M6). Deterministic from stored intel."""
    from titan.hostile.intel import domain_flux
    if not prior_observed:
        return []
    current = {r["host"]: {"category": r.get("category")} for r in profile.get("origins", [])}
    flux = domain_flux(prior_observed, current)
    findings: List[Finding] = []
    for host in flux.get("removed", []):
        findings.append(Finding(
            target=target,
            url=profile.get("page_url") or target,
            method="GET",
            param="domain",
            location="client",
            payload=f"Ad/monetization origin {host} present last scan, absent now (domain rotation)",
            attack_type=AttackType.AD_DOMAIN_FLUX,
            severity=Severity.LOW,
            verified=True,
            confidence=0.85,
            diffs=[f"adtech:domain_flux:removed:{host}"],
            metadata={"host": host, "flux": "removed"},
            evidence="confirmed",
        ))
    return findings[:5]
