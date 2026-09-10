"""Markdown report rendering for SiteReportWriter.

The renderer is a module function taking the writer as a collaborator so
titan/reporting/__init__.py stays focused on the persistence layer.
Moved from titan/reporting/__init__.py; SiteReportWriter._markdown
delegates here.
"""

from __future__ import annotations

from typing import Any

from titan.core.models import ScanResult

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unconfirmed"]



def render_markdown_report(result: ScanResult, writer) -> str:
    lines: list[str] = [
        f"# Scan Report — {result.target}",
        "",
        "| | |",
        "|---|---|",
        f"| **Site slug** | `{writer.slug_for(result.target)}` |",
        f"| **Scanned** | {writer._iso(result.started_at) or 'n/a'} |",
        f"| **Duration** | {result.duration_seconds}s |",
        f"| **Technologies** | {', '.join((result.fingerprint or {}).get('technologies', [])[:8]) or 'unknown'} |",
    ]
    consent_line = writer._consent_line(result.target)
    if consent_line:
        lines.append(f"| **Consent** | {consent_line} |")
    lines += [
        "",
        "## Summary",
        "",
        "| Total | Verified | Critical | High | Medium | Low | Unconfirmed | Chains |",
        "|---|---|---|---|---|---|---|---|",
        f"| {len(result.findings)} | {result.verified_count} | {result.critical_count} "
        f"| {result.high_count} | "
        f"{sum(1 for f in result.findings if f.severity.value == 'medium')} | "
        f"{sum(1 for f in result.findings if f.severity.value == 'low')} | "
        f"{sum(1 for f in result.findings if f.severity.value == 'unconfirmed')} | "
        f"{result.chain_count} |",
        "",
    ]

    # Executive summary: risk posture, top 3 risks, remediation estimate, estate comparison.
    from titan.core.models import Severity
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    high = [f for f in result.findings if f.severity == Severity.HIGH]
    medium = [f for f in result.findings if f.severity == Severity.MEDIUM]
    demoted = [f for f in result.findings if "evidence_demotion" in f.metadata]
    if critical:
        posture = "Critical exposure — immediate remediation advised."
    elif high:
        posture = "High-risk exposure — prioritize remediation."
    elif result.findings:
        posture = "Moderate / low risk — harden opportunistically."
    else:
        posture = "No findings recorded for this site."
    lines += [
        "## Executive summary",
        "",
        f"- **Risk posture** {posture}",
    ]
    # Top 3 risks
    top3 = sorted(
        [f for f in result.findings if f.verified or f.confidence >= 0.7],
        key=lambda f: (f.severity == Severity.CRITICAL, f.severity == Severity.HIGH, f.confidence),
        reverse=True,
    )[:3]
    if top3:
        lines.append("- **Top risks:**")
        for i, f in enumerate(top3, 1):
            label = f.attack_type.value if f.attack_type else "Unknown"
            lines.append(
                f"  {i}. [{f.severity.value.upper()}] {label} — "
                f"`{f.method} {f.url}` param=`{f.param}` (conf {f.confidence:.2f})"
            )
    # Remediation time estimate
    est_minutes = (
        len(critical) * 120 + len(high) * 60 + len(medium) * 15
        + sum(1 for f in result.findings if f.severity == Severity.LOW) * 5
    )
    if est_minutes >= 60:
        est_str = f"~{est_minutes // 60}h {est_minutes % 60}m"
    else:
        est_str = f"~{est_minutes}m"
    lines.append(f"- **Est. remediation** {est_str} (critical=2h, high=1h, medium=15m, low=5m)")
    # Estate comparison
    estate_avg = writer._estate_average()
    if estate_avg is not None:
        my_total = len(result.findings)
        if my_total > estate_avg * 1.5:
            lines.append(f"- **Estate comparison** ⚠️ above average ({my_total} vs avg {estate_avg:.0f})")
        elif my_total < estate_avg * 0.5:
            lines.append(f"- **Estate comparison** ✅ below average ({my_total} vs avg {estate_avg:.0f})")
        else:
            lines.append(f"- **Estate comparison** ≈ average ({my_total} vs avg {estate_avg:.0f})")
    lines += [
        f"- **Counts** {len(result.findings)} findings · "
        f"{result.verified_count} verified · "
        f"{result.confirmed_count} confirmed · "
        f"{result.suspicious_count} suspicious · "
        f"{len(critical)} critical · {len(high)} high · "
        f"{result.chain_count} chains · "
        f"{sum(1 for f in result.findings if f.metadata.get('repro'))} repro scripts",
    ]
    if result.coverage:
        cov = result.coverage
        lines += [
            f"- **Coverage** `{cov.get('status', 'unknown')}` — "
            f"{cov.get('reason', '')} · {cov.get('urls_crawled', 0)} URLs crawled · "
            f"{cov.get('endpoint_groups_run', 0)} endpoint groups × module matrix · "
            f"{cov.get('params_discovered', 0)} params · "
            f"{cov.get('duplicate_bodies_skipped', 0)} duplicate bodies skipped",
        ]
    lines += [
        f"- **Evidence gate** {len(demoted)} finding(s) auto-demoted for "
        "lacking a strong oracle marker (reflection never verifies)",
        "",
    ]

    if not result.findings:
        lines += ["No findings recorded for this site.", ""]
    else:
        lines += ["## Findings", ""]
        by_severity: dict[str, list[Any]] = {}
        for f in result.findings:
            by_severity.setdefault(f.severity.value, []).append(f)

        ordinal = 0
        for sev in _SEVERITY_ORDER:
            for f in by_severity.get(sev, []):
                ordinal += 1
                lines += finding_section(ordinal, f)
                lines += ["---", ""]

    # Low-confidence section (M4): weak-evidence findings surfaced apart so
    # the verified list reads clean and the FP candidates are auditable.
    low_confidence = [
        f for f in result.findings
        if not f.verified and (f.evidence == "indicative" or f.confidence < 0.6)
    ]
    if low_confidence:
        lines += ["## Low-confidence findings", ""]
        lines += [
            "> Weak evidence only (reflection/noise — not verified). Review "
            "manually before acting.",
            "",
        ]
        for f in low_confidence:
            atk = f.attack_type.value if f.attack_type else "Unknown"
            lines.append(
                f"- `{atk}` ({f.evidence or 'no-grade'}) — "
                f"{f.method} {f.url} param=`{f.param}` conf={f.confidence:.2f}"
            )
        lines += [""]

    # Gate 5 — disclosure tracking. Critical/high findings must be
    # disclosed to the owner (technical finding only, no victim PII), and
    # the report records whether that happened. This is the piece that
    # keeps "polished report" from being the only output of an audit.
    from titan.core.models import Severity as _Sev
    critical = [f for f in result.findings if f.severity == _Sev.CRITICAL]
    high = [f for f in result.findings if f.severity == _Sev.HIGH]
    if critical or high:
        lines += ["## Disclosure status", ""]
        lines += [
            "> Gate 5: every Critical/High finding must be disclosed to the "
            "owner (technical finding only — no victim PII). Mark each when done.",
            "",
        ]
        for i, f in enumerate(critical + high, 1):
            label = f.attack_type.value if f.attack_type else "Unknown"
            lines.append(
                f"- [ ] **[{f.severity.value.upper()}] {label}** — "
                f"{f.method} {f.url} — disclosed to owner: ____ (date)"
            )
        lines += [""]

    # Business logic impact section: translate technical findings into
    # business consequences for non-technical stakeholders.
    lines += business_logic_section(result)
    if result.chains:
        lines += ["## Attack Chains", ""]
        for i, chain in enumerate(result.chains, 1):
            sev = chain.get("severity", "unknown")
            lines += [
                f"### Chain {i}: {chain.get('name', 'Unknown')} [{sev.upper()}]",
                "",
                f"- **Impact** {chain.get('impact', '')}",
                f"- **Capabilities** `{'` + `'.join(chain.get('capabilities', []))}`",
                "",
                "- **Hops**",
                "",
            ]
            for hop in chain.get("hops", []):
                atk = (hop.get("attack_type") or "Unknown").replace("`", "`` `")
                lines.append(
                    f"  - `{atk}` — {hop.get('method', 'GET')} {hop.get('url', '')} "
                    f"(flows: {', '.join(hop.get('flows', []))})"
                )
            lines += [""]

    if result.exploit_sessions:
        lines += ["## Exploitation sessions", ""]
        lines += [
            "> Consent-gated (Track E): sessions were only staged against findings"
            " backed by a signed, unexpired consent file for this target.",
            "",
        ]
        for s in result.exploit_sessions:
            lines += [f"- **{s.get('channel', '?')}** — session `{s.get('session_id', '?')}`", ""]
            if s.get("webshell_url"):
                lines += [f"  - Webshell: `{s['webshell_url']}`", ""]
            if s.get("finding_url"):
                lines += [f"  - Finding: `{s['finding_url']}`", ""]
            if s.get("dir"):
                lines += [f"  - Session dir: `{s['dir']}`", ""]
        lines += [""]

    if result.hostile:
        h = result.hostile
        prof = h.get("profile", {})
        lines += ["## Monetization & Hostile Surface (Track G)", ""]
        clickbait = prof.get("clickbait", {}) or {}
        counts = prof.get("counts", {}) or {}
        lines += [
            f"- **Monetization score** {prof.get('monetization_score', 0)}/100",
            f"- **Third-party origins** {len(prof.get('origins', []))} · "
            f"**Categories** {', '.join(f'{k}: {v}' for k, v in counts.items()) or 'none'}",
            f"- **Clickbait index** {clickbait.get('score', 0)}/100 "
            f"({clickbait.get('grade', 'low')}) · "
            f"**Cloaks** {len(prof.get('cloaks', []))} · "
            f"**Miners** {len(prof.get('miners', []))} · "
            f"**Push-abuse** {len(prof.get('push', []))} · "
            f"**Clickbait mechanics** {len(prof.get('mechanics', []))}",
            f"- **Active probes** "
            f"{'enabled (consent held)' if h.get('active_probes') else 'off — read-only (no consent)'}",
            "",
        ]
        if prof.get("origins"):
            lines += [
                "### Third-party origins",
                "",
                "| Host | Category | Kinds | Count | Cleartext | SRI | Risk |",
                "|---|---|---|---|---|---|---|",
            ]
            for r in prof["origins"][:20]:
                lines.append(
                    f"| `{r['host']}` | {r.get('category') or 'unknown'} | "
                    f"{', '.join(r.get('kinds', []))} | {r['count']} | "
                    f"{'cleartext!' if r.get('cleartext') else 'ok'} | "
                    f"{'missing' if r.get('sri_missing') else 'ok'} | "
                    f"{r.get('risk_score')} |"
                )
            lines += [""]
        if h.get("redirect_chain"):
            lines += ["### Redirect chain (observed)", ""]
            for hop in h["redirect_chain"][-10:]:
                lines.append(
                    f"- `{hop.get('status')}` {hop.get('from', '')} -> {hop.get('to', '')}"
                )
            lines += [""]

    if result.errors:
        lines += ["## Scan errors", ""]
        for err in result.errors:
            lines += [f"- {err}"]
        lines += [""]

    if getattr(result, "manual_verification", None):
        lines += ["## Manual verification", ""]
        for mv in result.manual_verification:
            status = mv.get("status", "info")
            icon = {"confirmed": "[CONFIRMED]", "debunked": "[DEBUNKED]", "info": "[INFO]"}.get(status, "[INFO]")
            lines += [
                f"- {icon} **{mv.get('check', 'Unknown check')}**",
                f"  - Result: {mv.get('result', '')}",
                f"  - Status: {status}",
            ]
        lines += [""]

    if result.ai_escalation:
        esc = result.ai_escalation
        lines += [
            "## AI escalation",
            "",
            f"- Sent: {esc.get('sent', 0)} · Confirmed: {esc.get('confirmed', 0)} "
            f"· Rejected: {esc.get('rejected', 0)} · Failed: {esc.get('failed', 0)}",
            "",
        ]

    return "\n".join(lines)




def finding_section(ordinal: int, f) -> list[str]:
    label = f.attack_type.value if f.attack_type else "Unknown"
    if f.verified:
        mark = " — verified"
    else:
        mark = " — SUSPICION (not proven; review manually)"
    lines = [
        f"### {ordinal}. [{f.severity.value.upper()}] {label}{mark}",
        "",
        f"- **URL** `{f.method.upper()} {f.url}`",
        f"- **Param** `{f.param}` ({f.location}) · **Confidence** {f.confidence:.2f} "
        f"· **Status** {f.status or 'n/a'}",
    ]
    if f.cvss_score is not None:
        lines.append(
            f"- **CVSS** {f.cvss_score} — `{f.cvss_vector}`"
        )
    if f.payload:
        # Guard the code fence: a payload containing ``` would break out
        # and inject raw markdown into the report.
        payload = f.payload.replace("```", "`` `")
        lines += ["- **Payload**", "", "```text", payload, "```", ""]
    if f.tier:
        tier_note = ""
        if f.tier == "suspicious":
            tier_note = " — behavioral signal, NOT confirmed; triage but do not treat as proven"
        lines.append(f"- **Tier** `{f.tier}`{tier_note}")
    if f.evidence:
        demotion = " (auto-demoted)" if "evidence_demotion" in f.metadata else ""
        lines.append(f"- **Evidence grade** `{f.evidence}`{demotion}")
    if f.metadata.get("repro"):
        lines.append(
            f"- **Repro** `{f.metadata['repro']}` — executable Ground-Truth "
            "check (PASS = flaw still present, FAIL = fixed)"
        )
    if "affected_urls" in f.metadata:
        lines += ["- **Affected URLs** (root-cause merged)", ""]
        for u in f.metadata["affected_urls"]:
            lines.append(f"  - `{u}`")
        lines += [""]
    if f.diffs:
        lines += ["- **Evidence**", ""]
        for d in f.diffs:
            lines.append(f"  - `{d}`")
        lines += [""]
    if f.chain:
        lines += [f"- **Chain** `{'` -> `'.join(f.chain)}`", ""]
    if f.tags:
        lines += [f"- **Tags** {', '.join(f.tags)}", ""]
    if f.poc_curl:
        lines += ["- **PoC (curl)**", "", "```bash", f.poc_curl, "```", ""]
    if f.poc_python:
        lines += ["- **PoC (python)**", "", "```python", f.poc_python, "```", ""]
    return lines




def business_logic_section(result: ScanResult) -> list[str]:
    """Translate technical findings into business-impact language."""
    findings = result.findings
    if not findings:
        return []

    impact_groups: dict[str, list[Any]] = {
        "Data breach / privacy": [],
        "Account takeover / auth": [],
        "Financial fraud": [],
        "Service disruption": [],
        "Reputation damage": [],
        "Compliance violation": [],
        "Infrastructure compromise": [],
    }

    for f in findings:
        atk = (f.attack_type.value if f.attack_type else "").lower()
        tags = [t.lower() for t in (f.tags or [])]
        if any(k in atk for k in ("sql", "nosql", "idor", "bola", "lfi", "xxe", "deser")):
            impact_groups["Data breach / privacy"].append(f)
        if any(k in atk for k in ("xss", "auth", "jwt", "session", "redirect")):
            impact_groups["Account takeover / auth"].append(f)
        if any(k in atk for k in ("ssrf", "rce", "upload", "smuggling")):
            impact_groups["Infrastructure compromise"].append(f)
        if any(k in atk for k in ("race", "cache", "logic")):
            impact_groups["Financial fraud"].append(f)
        if "platform:moodle" in tags:
            impact_groups["Compliance violation"].append(f)
        if any(k in atk for k in ("headers", "cors", "csp")):
            impact_groups["Reputation damage"].append(f)

    lines = ["## Business Logic Impact", ""]
    has_impact = False
    for group, group_findings in impact_groups.items():
        if not group_findings:
            continue
        has_impact = True
        lines += [f"### {group}", ""]
        for f in group_findings[:5]:
            label = f.attack_type.value if f.attack_type else "Unknown"
            lines.append(
                f"- [{f.severity.value.upper()}] {label} — "
                f"`{f.method} {f.url}` param=`{f.param}` (conf {f.confidence:.2f})"
            )
        if len(group_findings) > 5:
            lines.append(f"- ... and {len(group_findings) - 5} more")
        lines += [""]

    if not has_impact:
        lines += ["No significant business-impact findings identified.", ""]

    return lines

