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
from typing import Any
from urllib.parse import urlparse

from titan.core.logger import get_logger
from titan.core.models import ScanResult

logger = get_logger("__init__")


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
    def _redacted_to_dict(result: ScanResult) -> dict[str, Any]:
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
    def _iso(epoch: float) -> str | None:
        if not epoch:
            return None
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()

    def _meta(self, result: ScanResult, slug: str) -> dict[str, Any]:
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
        lines: list[str] = [
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
            by_severity: dict[str, list[Any]] = {}
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

        # Business logic impact section: translate technical findings into
        # business consequences for non-technical stakeholders.
        lines += self._business_logic_section(result)
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

    def _finding_section(self, ordinal: int, f) -> list[str]:
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

    def _business_logic_section(self, result: ScanResult) -> list[str]:
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

    # ------------------------------------------------------------ estate avg

    def _estate_average(self) -> float | None:
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

    def _consent_line(self, target: str, key_path=None, consent_dir=None) -> str | None:
        """Authorization story for the target, if a consent file exists.

        Reads the consent ledger and returns a one-line summary: basis + flags
        + expiry. Returns None when no consent covers the target (read-only
        path may still be authorized by the practice manifest — the report
        simply omits the consent row in that case).
        """
        try:
            from titan.exploit.consent import (
                DEFAULT_CONSENT_DIR,
                consent_filename,
                verify_consent,
            )

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
        index: dict[str, Any] = {"sites": []}
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


from titan.reporting.estate import estate_rollup
from titan.reporting.remediation import REMEDIATION_MAP, generate_remediation, remediation_rollup

__all__ = [
    "REMEDIATION_MAP",
    "SiteReportWriter",
    "estate_rollup",
    "generate_remediation",
    "remediation_rollup",
    "site_slug",
]
