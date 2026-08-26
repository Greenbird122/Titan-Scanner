"""Titan reporting subsystem — per-site findings documentation.

Every scanned site gets its own directory under ``output_dir`` (default
``findings/``) so findings are always documented under the site they came
from:

    findings/
      sites.json                 index of every scanned site
      <site-slug>/               e.g. localhost-5000, repairai-co-ke
        report.md                human-readable documentation (the report)
        findings.json            full machine-readable results
        scan_meta.json           target, timing, counts, errors, fingerprint
"""

from __future__ import annotations

import copy
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from titan.core.models import ScanResult


# Keys redacted from the persisted config snapshot: credentials must never
# land on disk inside per-site finding docs.
_REDACT_KEYS = ("password", "token", "secret", "api_key", "apikey")


def site_slug(target: str) -> str:
    """Deterministic, filesystem-safe slug for a target URL.

    ``http://localhost:8080/login.php`` -> ``localhost-8080``
    ``https://repairai.co.ke/``        -> ``repairai-co-ke``
    """
    raw = target if "://" in (target or "") else f"http://{target}"
    try:
        parsed = urlparse(raw)
        host = parsed.hostname or "unknown"
    except Exception:
        host, parsed = "unknown", None
    slug = re.sub(r"[^a-z0-9]+", "-", host.lower()).strip("-") or "unknown"
    if parsed is not None and parsed.port is not None:
        is_default = (parsed.scheme == "http" and parsed.port == 80) or (
            parsed.scheme == "https" and parsed.port == 443
        )
        if not is_default:
            slug += f"-{parsed.port}"
    return slug


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unconfirmed"]


class SiteReportWriter:
    """Writes a scan's findings under a per-site directory.

    Usage::

        writer = SiteReportWriter(output_dir="findings")
        writer.write(result)          # writes all docs, returns site directory
    """

    def __init__(self, output_dir: str = "findings"):
        self.output_dir = Path(output_dir)

    def slug_for(self, target: str) -> str:
        return site_slug(target)

    def write(self, result: ScanResult) -> Path:
        """Persist the per-site documentation for this scan.

        Returns the site directory that was written.
        """
        slug = self.slug_for(result.target)
        site_dir = self.output_dir / slug
        site_dir.mkdir(parents=True, exist_ok=True)

        # PUSH-TO-100 A2 — per-finding repro proof. Every CONFIRMED finding
        # ships an executable repro script (the Ground-Truth receipt): run it
        # against the still-vulnerable site and it asserts the flaw (PASS,
        # exit 0); after the fix lands it flips FAIL (exit 1). Suspicious /
        # no-evidence findings get no repro — their contract is "triaged, not
        # proven". The relative path lands in the finding's metadata BEFORE
        # findings.json is serialized, so the machine record carries the
        # receipt.
        from titan.verify.repro import generate_repro

        repro_dir = site_dir / "repros"
        repro_count = 0
        for f in result.findings:
            if f.tier == "confirmed":
                repro_count += 1
                repro_dir.mkdir(parents=True, exist_ok=True)
                name = f"repro_{repro_count:02d}.py"
                (repro_dir / name).write_text(
                    generate_repro(f, ordinal=repro_count), encoding="utf-8"
                )
                f.metadata["repro"] = f"repros/{name}"

        (site_dir / "findings.json").write_text(
            json.dumps(self._redacted_to_dict(result), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        (site_dir / "scan_meta.json").write_text(
            json.dumps(self._meta(result, slug), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        (site_dir / "report.md").write_text(self._markdown(result), encoding="utf-8")
        # Track G — persist the hostile-surface profile + observed intel so
        # the S5 dashboard can render them and the next scan can diff flux.
        hostile = result.hostile or {}
        if hostile:
            (site_dir / "hostile.json").write_text(
                json.dumps(hostile, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            observed = hostile.get("observed") or {}
            if observed:
                (site_dir / "intel.json").write_text(
                    json.dumps(observed, indent=2, ensure_ascii=False), encoding="utf-8"
                )
        self._update_index(slug, result)
        return site_dir

    @staticmethod
    def _redacted_to_dict(result: ScanResult) -> Dict[str, Any]:
        """result.to_dict() with credentials scrubbed from config_snapshot.

        The snapshot carries the live config (including auth.username/password)
        — a deep copy is redacted so the in-memory config object is untouched.
        """
        data = result.to_dict()
        # SCAN-QUALITY M4: consumers can check schema_version to know whether
        # evidence grades / demotion metadata are present.
        data["schema_version"] = 2
        snap = data.get("config_snapshot")
        if isinstance(snap, dict):
            cleaned = copy.deepcopy(snap)

            def _scrub(obj: Any) -> Any:
                if isinstance(obj, dict):
                    return {
                        k: ("[REDACTED]" if k in _REDACT_KEYS else _scrub(v))
                        for k, v in obj.items()
                    }
                if isinstance(obj, list):
                    return [_scrub(v) for v in obj]
                return obj

            data["config_snapshot"] = _scrub(cleaned)
        return data

    # ------------------------------------------------------------------ meta

    @staticmethod
    def _iso(epoch: float) -> Optional[str]:
        if not epoch:
            return None
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()

    def _meta(self, result: ScanResult, slug: str) -> Dict[str, Any]:
        meta = {
            "target": result.target,
            "slug": slug,
            "started_at": result.started_at,
            "started_at_iso": self._iso(result.started_at),
            "finished_at": result.finished_at,
            "finished_at_iso": self._iso(result.finished_at),
            "duration_seconds": result.duration_seconds,
            "findings": len(result.findings),
            "verified": result.verified_count,
            "critical": result.critical_count,
            "high": result.high_count,
            "chains": result.chain_count,
            "errors": result.errors,
            "technologies": (result.fingerprint or {}).get("technologies", []),
            "ai_escalation": result.ai_escalation or {},
            "exploit_sessions": len(result.exploit_sessions or []),
            "repros": sum(1 for f in result.findings if f.metadata.get("repro")),
            "coverage": result.coverage,
        }
        hostile = result.hostile or {}
        if hostile:
            meta["hostile"] = {
                "monetization_score": hostile.get("profile", {}).get("monetization_score"),
                "origins": len(hostile.get("profile", {}).get("origins", [])),
                "hostile_findings": len(hostile.get("findings", [])),
                "active_probes": hostile.get("active_probes", False),
            }
        return meta

    # --------------------------------------------------------------- markdown

    def _markdown(self, result: ScanResult) -> str:
        lines: List[str] = [
            f"# Scan Report — {result.target}",
            "",
            "| | |",
            "|---|---|",
            f"| **Site slug** | `{self.slug_for(result.target)}` |",
            f"| **Scanned** | {self._iso(result.started_at) or 'n/a'} |",
            f"| **Duration** | {result.duration_seconds}s |",
            f"| **Technologies** | {', '.join((result.fingerprint or {}).get('technologies', [])[:8]) or 'unknown'} |",
        ]
        consent_line = self._consent_line(result.target)
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
        estate_avg = self._estate_average()
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
            by_severity: Dict[str, List[Any]] = {}
            for f in result.findings:
                by_severity.setdefault(f.severity.value, []).append(f)

            ordinal = 0
            for sev in _SEVERITY_ORDER:
                for f in by_severity.get(sev, []):
                    ordinal += 1
                    lines += self._finding_section(ordinal, f)
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

    def _finding_section(self, ordinal: int, f) -> List[str]:
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

    # ------------------------------------------------------------ estate avg

    def _estate_average(self) -> Optional[float]:
        """Average finding count across all scanned sites in the estate."""
        index_path = self.output_dir / "sites.json"
        if not index_path.exists():
            return None
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
            sites = index.get("sites", [])
            if not sites:
                return None
            totals = [s.get("findings", 0) for s in sites]
            return sum(totals) / len(totals)
        except Exception:
            return None

    # --------------------------------------------------------------- consent

    def _consent_line(self, target: str, key_path=None, consent_dir=None) -> Optional[str]:
        """Authorization story for the target, if a consent file exists.

        Reads the consent ledger and returns a one-line summary: basis + flags
        + expiry. Returns None when no consent covers the target (read-only
        path may still be authorized by the practice manifest — the report
        simply omits the consent row in that case).
        """
        try:
            from titan.exploit.consent import (
                DEFAULT_CONSENT_DIR,
                verify_consent,
            )
            from titan.exploit.consent import consent_filename

            cdir = consent_dir if consent_dir is not None else DEFAULT_CONSENT_DIR
            file = cdir / f"{consent_filename(target)}.json"
            if not file.exists():
                return None
            doc = verify_consent(target, consent_dir=cdir, key_path=key_path)
            basis = doc.get("basis") or "undeclared"
            flags = doc.get("flags", []) or []
            expiry = doc.get("expires_at")
            exp = self._iso(expiry) if expiry else "n/a"
            flag_txt = ", ".join(flags) if flags else "read-only"
            return f"basis={basis} · flags={flag_txt} · expires {exp}"
        except Exception:
            # Consent missing, expired, or invalid — the report shouldn't
            # crash over the authorization row; it just omits it.
            return None

    # ------------------------------------------------------------------ index

    def _update_index(self, slug: str, result: ScanResult) -> None:
        index_path = self.output_dir / "sites.json"
        index: Dict[str, Any] = {"sites": []}
        if index_path.exists():
            try:
                index = json.loads(index_path.read_text(encoding="utf-8"))
            except Exception:
                index = {"sites": []}

        entry = {
            "slug": slug,
            "target": result.target,
            "last_scan": self._iso(result.started_at) or time.ctime(result.started_at),
            "findings": len(result.findings),
            "verified": result.verified_count,
            "critical": result.critical_count,
            "high": result.high_count,
            "report": f"{slug}/report.md",
        }
        sites = [s for s in index.get("sites", []) if s.get("slug") != slug]
        sites.append(entry)
        sites.sort(key=lambda s: s.get("target", ""))
        index["sites"] = sites

        # Atomic write (temp + rename) so a crash mid-write can't corrupt the
        # site index.
        tmp = index_path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        tmp.replace(index_path)


# ────────────────────────────────────────────────────────────────────────────
# Phase 8b — Estate-wide rollup
# ────────────────────────────────────────────────────────────────────────────


def estate_rollup(output_dir: str = "findings") -> str:
    """Generate a cross-site estate report from all scanned sites.

    Reads sites.json and per-site scan_meta.json / findings.json to produce
    a single markdown document covering every audited site, ranked by severity,
    with cross-site patterns highlighted.
    """
    out = Path(output_dir)
    index_path = out / "sites.json"
    if not index_path.exists():
        return "# Estate Rollup\n\nNo sites scanned yet.\n"

    index = json.loads(index_path.read_text(encoding="utf-8"))
    sites = index.get("sites", [])
    if not sites:
        return "# Estate Rollup\n\nNo sites scanned yet.\n"

    lines: List[str] = [
        "# Estate Rollup",
        "",
        f"> Generated {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"> {len(sites)} sites scanned",
        "",
    ]

    # ── Severity distribution across estate ──
    total_findings = 0
    total_verified = 0
    total_critical = 0
    total_high = 0
    total_chains = 0
    all_findings: List[Dict[str, Any]] = []
    attack_type_counts: Dict[str, int] = {}

    for site in sites:
        slug = site.get("slug", "")
        meta_path = out / slug / "scan_meta.json"
        findings_path = out / slug / "findings.json"

        meta = {}
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                pass

        site_findings = []
        if findings_path.exists():
            try:
                site_findings = json.loads(findings_path.read_text(encoding="utf-8"))
                if isinstance(site_findings, dict):
                    site_findings = site_findings.get("findings", [])
            except Exception:
                pass

        f_count = meta.get("findings", len(site_findings))
        v_count = meta.get("verified", 0)
        c_count = meta.get("critical", 0)
        h_count = meta.get("high", 0)
        ch_count = meta.get("chains", 0)

        total_findings += f_count
        total_verified += v_count
        total_critical += c_count
        total_high += h_count
        total_chains += ch_count

        for f in site_findings:
            atk = f.get("attack_type", "unknown")
            attack_type_counts[atk] = attack_type_counts.get(atk, 0) + 1
            sev = f.get("severity", "info")
            if sev in ("critical", "high"):
                all_findings.append({
                    "site": site.get("target", slug),
                    "slug": slug,
                    "severity": sev,
                    "attack_type": atk,
                    "url": f.get("url", ""),
                    "param": f.get("param", ""),
                    "verified": f.get("verified", False),
                    "confidence": f.get("confidence", 0),
                })

    lines += [
        "## Estate overview",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Sites scanned | {len(sites)} |",
        f"| Total findings | {total_findings} |",
        f"| Verified findings | {total_verified} |",
        f"| Critical | {total_critical} |",
        f"| High | {total_high} |",
        f"| Attack chains | {total_chains} |",
        f"| Avg findings/site | {total_findings / len(sites):.1f} |",
        "",
    ]

    # ── Top attack types ──
    if attack_type_counts:
        sorted_types = sorted(attack_type_counts.items(), key=lambda x: x[1], reverse=True)
        lines += ["## Most common attack types", ""]
        lines += ["| Attack type | Count |", "|---|---|"]
        for atk, count in sorted_types[:10]:
            lines.append(f"| {atk} | {count} |")
        lines += [""]

    # ── Cross-site patterns ──
    # Find attack types that appear on 3+ sites
    atk_sites: Dict[str, set] = {}
    for site in sites:
        slug = site.get("slug", "")
        findings_path = out / slug / "findings.json"
        if not findings_path.exists():
            continue
        try:
            site_findings = json.loads(findings_path.read_text(encoding="utf-8"))
            if isinstance(site_findings, dict):
                site_findings = site_findings.get("findings", [])
            for f in site_findings:
                atk = f.get("attack_type", "unknown")
                atk_sites.setdefault(atk, set()).add(site.get("target", slug))
        except Exception:
            continue

    patterns = {atk: s for atk, s in atk_sites.items() if len(s) >= 3}
    if patterns:
        lines += ["## Cross-site patterns (3+ sites)", ""]
        lines += ["| Pattern | Sites affected |", "|---|---|"]
        for atk, site_set in sorted(patterns.items(), key=lambda x: len(x[1]), reverse=True):
            lines.append(f"| {atk} | {len(site_set)} sites |")
        lines += [""]

    # ── Ranked critical/high findings ──
    all_findings.sort(key=lambda f: (f["severity"] == "critical", f["confidence"]), reverse=True)
    if all_findings:
        lines += ["## Top findings across estate", ""]
        lines += [
            "| # | Severity | Type | Site | URL | Param | Verified |",
            "|---|---|---|---|---|---|---|",
        ]
        for i, f in enumerate(all_findings[:20], 1):
            v_mark = "✅" if f["verified"] else "⚠️"
            lines.append(
                f"| {i} | {f['severity'].upper()} | {f['attack_type']} | "
                f"`{f['slug']}` | `{f['url']}` | `{f['param']}` | {v_mark} |"
            )
        lines += [""]

    # ── Per-site summary ──
    lines += ["## Per-site summary", ""]
    lines += [
        "| Site | Findings | Verified | Critical | High | Chains |",
        "|---|---|---|---|---|---|",
    ]
    for site in sorted(sites, key=lambda s: s.get("critical", 0), reverse=True):
        lines.append(
            f"| `{site.get('slug', '?')}` | {site.get('findings', 0)} | "
            f"{site.get('verified', 0)} | {site.get('critical', 0)} | "
            f"{site.get('high', 0)} | {site.get('chains', 0)} |"
        )
    lines += [""]

    return "\n".join(lines)


# ────────────────────────────────────────────────────────────────────────────
# Phase 8c — Auto-generated remediation patches
# ────────────────────────────────────────────────────────────────────────────

REMEDIATION_MAP = {
    "headers": {
        "title": "Missing Security Headers",
        "fix": """# Nginx
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Apache
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

# Cloudflare (Page Rules → Transform Rules → Modify Response Header)
# Add each header via the dashboard: Security → Settings → Security Headers""",
    },
    "cors": {
        "title": "Overly Permissive CORS",
        "fix": """# Restrict CORS to specific origins
# Nginx
add_header Access-Control-Allow-Origin "https://yourdomain.com" always;
add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;
add_header Access-Control-Allow-Credentials "true" always;

# Never use: Access-Control-Allow-Origin: * with credentials""",
    },
    "sqli": {
        "title": "SQL Injection",
        "fix": """# 1. Use parameterized queries (prepared statements)
# Python (psycopg2)
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Python (sqlite3)
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Node.js (pg)
client.query('SELECT * FROM users WHERE id = $1', [userId])

# 2. Use an ORM (SQLAlchemy, Django ORM, Prisma)
# 3. Input validation: whitelist allowed characters
# 4. Apply least-privilege DB user (no DROP, ALTER, GRANT)""",
    },
    "xss": {
        "title": "Cross-Site Scripting (XSS)",
        "fix": """# 1. Output encoding (context-aware)
# HTML context: HTML-encode <, >, &, ", '
# JS context: JS-encode
# URL context: URL-encode

# 2. Content Security Policy (CSP)
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'

# 3. Use framework auto-escaping (React, Vue, Jinja2 autoescape)
# 4. Never use innerHTML — use textContent or framework templates
# 5. HttpOnly cookies for session tokens""",
    },
    "ssrf": {
        "title": "Server-Side Request Forgery (SSRF)",
        "fix": """# 1. Validate and whitelist URLs before fetching
allowed_hosts = ['api.example.com', 'cdn.example.com']
if parsed.hostname not in allowed_hosts:
    raise ValueError("Host not allowed")

# 2. Block internal IPs
import ipaddress
def is_internal(url):
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    return ip.is_private or ip.is_loopback

# 3. Use a network policy / firewall to block outbound to metadata IPs
# 4. Disable unnecessary URL schemes (file://, gopher://, dict://)""",
    },
    "lfi": {
        "title": "Local File Inclusion (LFI)",
        "fix": """# 1. Never use user input in file paths
# BAD: open(f'/data/{user_input}.txt')
# GOOD: use a whitelist of allowed files

# 2. Sanitize path traversal
import os
def safe_path(base, user_input):
    resolved = os.path.normpath(os.path.join(base, user_input))
    if not resolved.startswith(base):
        raise ValueError("Path traversal blocked")
    return resolved

# 3. chroot / containerize the file-serving process""",
    },
    "ssti": {
        "title": "Server-Side Template Injection (SSTI)",
        "fix": """# 1. Never render user input in templates
# BAD: template.render(user_input)
# GOOD: template.render(safe_var=user_input)

# 2. Use sandboxed template environments
# Jinja2: SandboxedEnvironment
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()

# 3. Auto-escape all output (enabled by default in Jinja2, Django, etc.)""",
    },
    "idor": {
        "title": "Insecure Direct Object Reference (IDOR)",
        "fix": """# 1. Always check authorization, not just authentication
# BAD: if user.is_authenticated: return get_object(id)
# GOOD: if user.is_authenticated and ownership(user, id): return get_object(id)

# 2. Use indirect references (UUIDs instead of sequential IDs)
# 3. Implement row-level security (RLS) in the database
# 4. Use permission classes (Django REST Framework)
class IsOwner(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user""",
    },
    "open_redirect": {
        "title": "Open Redirect",
        "fix": """# 1. Validate redirect targets against a whitelist
ALLOWED_REDIRECTS = ['/dashboard', '/profile', '/settings']
if redirect_url not in ALLOWED_REDIRECTS:
    redirect_url = '/dashboard'  # fallback

# 2. Never redirect to user-controlled URLs
# 3. Use relative redirects: return redirect('/safe/path')""",
    },
    "info_leak": {
        "title": "Information Disclosure",
        "fix": """# 1. Remove server version headers
# Nginx: server_tokens off;
# Apache: ServerSignature Off, ServerTokens Prod

# 2. Disable debug mode in production
# Flask: app.debug = False
# Django: DEBUG = False
# Node: NODE_ENV=production

# 3. Remove stack traces from error pages
# 4. Don't expose API keys in client-side code""",
    },
    "crypto": {
        "title": "Cryptographic Weakness",
        "fix": """# 1. Use modern algorithms (AES-256-GCM, SHA-256+)
# 2. Never roll your own crypto
# 3. Use established libraries (cryptography, bcrypt, argon2)
# 4. Enforce TLS 1.2+ and strong cipher suites""",
    },
}


def generate_remediation(finding) -> str:
    """Generate a concrete remediation patch for a finding.

    Returns a markdown-formatted remediation block, or a generic message
    if the finding type is not in the remediation map.
    """
    atk = (finding.attack_type.value if hasattr(finding, 'attack_type') and finding.attack_type
           else finding.get("attack_type", "unknown") if isinstance(finding, dict) else "unknown")

    # Try exact match first, then partial match
    patch = REMEDIATION_MAP.get(atk)
    if not patch:
        for key in REMEDIATION_MAP:
            if key in str(atk).lower():
                patch = REMEDIATION_MAP[key]
                break

    if not patch:
        return (
            f"### Remediation for {atk}\n\n"
            f"No automated patch available for this finding type.\n"
            f"Review the finding details and apply manual remediation.\n"
        )

    url = finding.url if hasattr(finding, 'url') else finding.get("url", "")
    param = finding.param if hasattr(finding, 'param') else finding.get("param", "")

    return (
        f"### Remediation: {patch['title']}\n\n"
        f"**Finding:** `{param}` at `{url}`\n\n"
        f"```\n{patch['fix']}\n```\n"
    )


def remediation_rollup(output_dir: str = "findings") -> str:
    """Generate a remediation-focused report across all sites."""
    out = Path(output_dir)
    index_path = out / "sites.json"
    if not index_path.exists():
        return "# Remediation Rollup\n\nNo sites scanned yet.\n"

    index = json.loads(index_path.read_text(encoding="utf-8"))
    sites = index.get("sites", [])
    if not sites:
        return "# Remediation Rollup\n\nNo sites scanned yet.\n"

    lines: List[str] = [
        "# Remediation Rollup",
        "",
        f"> Generated {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"> {len(sites)} sites · actionable patches per finding type",
        "",
    ]

    # Collect all unique finding types with their patches
    seen_patches: Dict[str, str] = {}  # atk_type -> remediation text
    finding_count_by_type: Dict[str, int] = {}

    for site in sites:
        slug = site.get("slug", "")
        findings_path = out / slug / "findings.json"
        if not findings_path.exists():
            continue
        try:
            site_findings = json.loads(findings_path.read_text(encoding="utf-8"))
            if isinstance(site_findings, dict):
                site_findings = site_findings.get("findings", [])
            for f in site_findings:
                atk = f.get("attack_type", "unknown")
                finding_count_by_type[atk] = finding_count_by_type.get(atk, 0) + 1
                if atk not in seen_patches:
                    seen_patches[atk] = generate_remediation(f)
        except Exception:
            continue

    # Sort by frequency
    sorted_types = sorted(finding_count_by_type.items(), key=lambda x: x[1], reverse=True)

    lines += ["## Priority remediation (by frequency)", ""]
    for atk, count in sorted_types:
        if count >= 2:  # Only types appearing 2+ times
            lines.append(f"### {atk} ({count} instances across estate)")
            lines.append("")
            # Extract just the code block from the remediation
            patch = REMEDIATION_MAP.get(atk)
            if patch:
                lines.append(f"**{patch['title']}**")
                lines.append("")
                lines.append("```")
                lines.append(patch["fix"])
                lines.append("```")
                lines.append("")

    # One-off patches
    one_offs = [(atk, count) for atk, count in sorted_types if count < 2]
    if one_offs:
        lines += ["## One-off remediation", ""]
        for atk, count in one_offs:
            patch = REMEDIATION_MAP.get(atk)
            if patch:
                lines.append(f"### {atk}")
                lines.append("")
                lines.append(f"```\n{patch['fix']}\n```")
                lines.append("")

    return "\n".join(lines)
