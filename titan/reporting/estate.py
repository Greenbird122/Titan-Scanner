"""Estate-wide rollup — Phase 8b.

Cross-site report generated from every per-site directory written by
SiteReportWriter. Moved from titan/reporting/__init__.py; re-exported
there for compatibility.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from titan.core.logger import get_logger

logger = get_logger("estate")


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

    lines: list[str] = [
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
    all_findings: list[dict[str, Any]] = []
    attack_type_counts: dict[str, int] = {}

    for site in sites:
        slug = site.get("slug", "")
        meta_path = out / slug / "scan_meta.json"
        findings_path = out / slug / "findings.json"

        meta = {}
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.debug(f"suppressed exception: {exc}")
                pass

        site_findings = []
        if findings_path.exists():
            try:
                site_findings = json.loads(findings_path.read_text(encoding="utf-8"))
                if isinstance(site_findings, dict):
                    site_findings = site_findings.get("findings", [])
            except Exception as exc:
                logger.debug(f"suppressed exception: {exc}")
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
                all_findings.append(
                    {
                        "site": site.get("target", slug),
                        "slug": slug,
                        "severity": sev,
                        "attack_type": atk,
                        "url": f.get("url", ""),
                        "param": f.get("param", ""),
                        "verified": f.get("verified", False),
                        "confidence": f.get("confidence", 0),
                    }
                )

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
    atk_sites: dict[str, set] = {}
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
        except Exception as exc:
            logger.debug(f"variant failed, continuing: {exc}")
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
