"""Trend & anomaly analyzer — the estate learns from its own ledger.

Reads the findings/ ledger (scan_meta + findings.json + FINDINGS.md notes)
plus the purple scoreboard's round notes, builds a per-site profile of
*trend signals* (deterministic: computed from attack types, evidence diffs,
and note text — no LLM), then:

* **Shared trends** — signals co-occurring across >= 2 sites ("Vercel SPAs
  that ship a Firebase key", "static pages with no CSP"). These are the
  patterns the estate repeats; a new site matching one inherits its peers'
  remediation playbook.
* **Anomalies** — three classes, all computed, all explainable:
  ``unique``    a signal present on exactly one site (novel exposure),
  ``platform``  a site deviating from its platform peers on a security
                control (e.g. the only Vercel SPA without CSP),
  ``severity``  a site carrying critical/high findings where its platform
                cluster has none.

Everything is pure and deterministic — the tests pin the exact shapes. The
CLI (``titan_learn_cli.py trends``) writes findings/TRENDS.md + TRENDS.json.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from titan.learn.notes import mine_findings_md_file

# ---------------------------------------------------------------------------
# signal extraction
# ---------------------------------------------------------------------------

HEADER_MISS_RE = re.compile(r"missing:([A-Za-z-]+)", re.I)


def _notes_text(slug: str, root: Path) -> str:
    """Concatenate the human notes an auditor left about a site: scan_meta
    recheck notes + the deep-audit FINDINGS.md if present."""
    parts: List[str] = []
    meta = root / slug / "scan_meta.json"
    if meta.exists():
        try:
            m = json.loads(meta.read_text(encoding="utf-8"))
            if m.get("recheck_notes"):
                parts.append(str(m["recheck_notes"]))
        except Exception:
            pass
    fmd = root / slug / "FINDINGS.md"
    if fmd.exists():
        try:
            parts.append(fmd.read_text(encoding="utf-8")[:4000])
        except Exception:
            pass
    return "\n".join(parts)


def _platform(target: str, slug: str) -> str:
    t = target.lower()
    for suffix in (".vercel.app", ".lovable.app", ".github.io", "localhost", "127.0.0.1"):
        if suffix in t:
            return suffix.lstrip(".")
    m = re.search(r"\.([a-z0-9-]+\.(?:co\.ke|com|ke|app|dev|rest))$", t)
    if m:
        return m.group(1)
    return slug.split("-")[0] if slug else "other"


def build_profile(slug: str, root: Path, scoreboard_rounds: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Pure: one site's trend profile from its ledger entries."""
    fpath = root / slug / "findings.json"
    data: Dict[str, Any] = {}
    if fpath.exists():
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    meta: Dict[str, Any] = {}
    mpath = root / slug / "scan_meta.json"
    if mpath.exists():
        try:
            meta = json.loads(mpath.read_text(encoding="utf-8"))
        except Exception:
            meta = {}

    findings = data.get("findings", [])
    target = meta.get("target") or data.get("target") or f"https://{slug}"
    notes = _notes_text(slug, root)

    attack_types = {f.get("attack_type", "") for f in findings}
    diffs_joined = " ".join(d for f in findings for d in (f.get("diffs") or [])).lower()
    severities = {f.get("severity", "") for f in findings}
    verified = sum(1 for f in findings if f.get("verified"))
    notes_l = notes.lower()

    # Deep-audit sites documented in FINDINGS.md but not findings.json — mine
    # the note headings so their attack types and severities enter the profile.
    mined = mine_findings_md_file(root / slug / "FINDINGS.md")
    for row in mined:
        if row.get("attack_type"):
            attack_types.add(row["attack_type"])
        if row.get("severity"):
            severities.add(row["severity"])

    # scoreboard round notes for this site (host match on the test URL)
    sb_notes = ""
    host = re.sub(r"^https?://", "", target).split("/")[0]
    for r in scoreboard_rounds or []:
        test = (r.get("test") or "").lower()
        if host and host in test:
            tech = r.get("technique") or ""
            if tech:
                sb_notes += " " + tech
    notes_l += " " + sb_notes.lower()

    missing_headers = {m.group(1).lower() for m in HEADER_MISS_RE.finditer(diffs_joined)}

    signals = {
        "exposed_bundle_secret": "Hardcoded Secret" in attack_types
        or "hardcoded secret" in notes_l,
        "firebase_key": "AIza" in notes_l
        or any("AIza" in (f.get("payload") or "") for f in findings),
        "missing_csp": "CSP Weakness" in attack_types
        or "content-security-policy" in missing_headers,
        "clickjackable": "x-frame-options" in missing_headers
        or "clickjack" in notes_l or "frameable" in notes_l,
        "hsts_present": "strict-transport-security" not in missing_headers
        and "hsts" in notes_l or "strict-transport-security" in notes_l,
        # Note-text signals are guarded against discussion-of-a-control reading
        # as a finding: "bucket not listable" is not public storage, "client-side
        # auth shell" describing a hosting platform is not the site's bypass,
        # and "Stored XSS via innerHTML" is not the DOM-XSS class.
        "localstorage_gate": "localstorage" in notes_l
        and ("architect_access" in notes_l or re.search(r"\bgate\b", notes_l)),
        "api_dom_sink": "DOM XSS" in attack_types or "dom xss" in notes_l,
        "fk_idor": "IDOR" in attack_types or "idor" in notes_l,
        "sqli": "SQLi" in attack_types,
        "exposed_db_admin": "phpmyadmin" in notes_l or "dbadmin" in notes_l,
        "public_storage": "Public Cloud Storage" in attack_types
        or ("firestore" in notes_l and ("exposed" in notes_l or "open" in notes_l))
        or ("bucket" in notes_l and "listable" in notes_l and "not listable" not in notes_l),
        "write_verified_chain": "write-verified" in notes_l or ("write" in notes_l and "tamper" in notes_l),
        "client_auth_bypass": "Auth Bypass" in attack_types
        or "architect_access" in notes_l
        or ("localstorage" in notes_l and re.search(r"\bgate\b", notes_l)),
        "static_no_backend": (not findings and not mined)
        or ("static" in notes_l and "no backend" in notes_l),
        "missing_headers": "Info Leak" in attack_types or "headers:missing" in diffs_joined,
    }

    return {
        "slug": slug,
        "target": target,
        "platform": _platform(target, slug),
        "technologies": meta.get("technologies", []),
        "findings": len(findings),
        "verified": verified,
        "critical": max(sum(1 for f in findings if f.get("severity") == "critical"),
                        sum(1 for r in mined if r.get("severity") == "critical")),
        "high": max(sum(1 for f in findings if f.get("severity") == "high"),
                     sum(1 for r in mined if r.get("severity") == "high")),
        "mined_findings": len(mined),
        "attack_types": sorted(a for a in attack_types if a),
        "severities": sorted(s for s in severities if s),
        "missing_headers": sorted(missing_headers),
        "signals": {k: bool(v) for k, v in signals.items()},
        "deep_audit": bool(meta.get("reverification_round")),
    }


def build_profiles(findings_root: str = "findings", scoreboard_path: str = "purple/scoreboard.json") -> List[Dict[str, Any]]:
    """Pure: profiles for every site in the ledger."""
    root = Path(findings_root)
    rounds: List[Dict[str, Any]] = []
    sp = Path(scoreboard_path)
    if sp.exists():
        try:
            data = json.loads(sp.read_text(encoding="utf-8"))
            # scoreboard.json is a bare round list; warroom bundles it under "rounds".
            rounds = data if isinstance(data, list) else data.get("rounds", [])
        except Exception:
            rounds = []
    profiles = []
    for slug in sorted(p.name for p in root.iterdir() if p.is_dir()):
        sdir = root / slug
        # any record counts — deep audits live in FINDINGS.md/scan_meta only.
        if not any((sdir / n).exists() for n in ("findings.json", "FINDINGS.md", "scan_meta.json")):
            continue
        profiles.append(build_profile(slug, root, rounds))
    return profiles


# ---------------------------------------------------------------------------
# grouping + anomalies
# ---------------------------------------------------------------------------

def find_trend_groups(profiles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Signals shared by >= 2 sites — the trends the estate repeats."""
    groups: List[Dict[str, Any]] = []
    signal_names = sorted({s for p in profiles for s in p["signals"] if p["signals"][s]})
    for sig in signal_names:
        members = [p["slug"] for p in profiles if p["signals"].get(sig)]
        if len(members) >= 2:
            platforms = sorted({p["platform"] for p in profiles if p["signals"].get(sig)})
            groups.append({
                "signal": sig,
                "members": members,
                "count": len(members),
                "platforms": platforms,
            })
    groups.sort(key=lambda g: -g["count"])
    return groups


def flag_anomalies(profiles: List[Dict[str, Any]], groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pure: the three anomaly classes."""
    anomalies: List[Dict[str, Any]] = []
    by_slug = {p["slug"]: p for p in profiles}
    group_sigs = {g["signal"] for g in groups}

    # unique — a signal carried by exactly one site
    for p in profiles:
        for sig, present in p["signals"].items():
            if present and sig not in group_sigs:
                anomalies.append({
                    "slug": p["slug"],
                    "kind": "unique",
                    "signal": sig,
                    "message": f"only site with {sig.replace('_', ' ')}",
                })

    # platform — a site deviating from its platform peers on a control
    controls = ("missing_csp", "clickjackable", "hsts_present")
    platforms: Dict[str, List[Dict[str, Any]]] = {}
    for p in profiles:
        platforms.setdefault(p["platform"], []).append(p)
    for plat, members in platforms.items():
        if len(members) < 2:
            continue
        for control in controls:
            values = [m["signals"].get(control, False) for m in members]
            majority = sum(1 for v in values if v) >= (len(values) + 1) // 2
            for m in members:
                if m["signals"].get(control, False) != majority:
                    anomalies.append({
                        "slug": m["slug"],
                        "kind": "platform",
                        "signal": control,
                        "message": (
                            f"{control.replace('_', ' ')} deviates from {len(members)} "
                            f"{plat} platform peers"
                        ),
                    })

    # severity — critical/high findings where the platform cluster has none
    for plat, members in platforms.items():
        if len(members) < 2:
            continue
        cluster_has_severe = any(m["critical"] or m["high"] for m in members)
        for m in members:
            if cluster_has_severe and not (m["critical"] or m["high"]):
                continue
            if not cluster_has_severe and (m["critical"] or m["high"]):
                anomalies.append({
                    "slug": m["slug"],
                    "kind": "severity",
                    "signal": "severe_findings",
                    "message": (
                        f"critical/high findings ({m['critical']}c/{m['high']}h) while "
                        f"all {plat} peers have none"
                    ),
                })

    anomalies.sort(key=lambda a: (a["slug"], a["kind"]))
    return anomalies


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def render_profiles_table(profiles: List[Dict[str, Any]]) -> str:
    lines = [
        "| Site | Platform | Findings | Verified | Crit | High | Signals |",
        "|---|---|---|---|---|---|---|",
    ]
    for p in profiles:
        sigs = ",".join(s for s in sorted(p["signals"]) if p["signals"][s])
        lines.append(
            f"| {p['slug']} | {p['platform']} | {p['findings']} | {p['verified']} | "
            f"{p['critical']} | {p['high']} | {sigs} |"
        )
    return "\n".join(lines)


def render_trends(profiles: List[Dict[str, Any]], groups: List[Dict[str, Any]], anomalies: List[Dict[str, Any]]) -> str:
    lines = [
        "# Estate trends & anomalies",
        "",
        f"Profiles: {len(profiles)} sites · Shared trends: {len(groups)} · Anomalies: {len(anomalies)}",
        "",
        "## Shared trends (signals across ≥ 2 sites)",
        "",
    ]
    if groups:
        for g in groups:
            lines.append(
                f"- **{g['signal'].replace('_', ' ')}** — {g['count']} sites "
                f"({', '.join(g['members'])})"
            )
    else:
        lines.append("- none")
    lines += ["", "## Anomalies", ""]
    if anomalies:
        lines.append("| Site | Kind | Signal | Detail |")
        lines.append("|---|---|---|---|")
        for a in anomalies:
            lines.append(
                f"| {a['slug']} | {a['kind']} | {a['signal']} | {a['message']} |"
            )
    else:
        lines.append("- none")
    lines += ["", "## Per-site profiles", "", render_profiles_table(profiles), ""]
    lines += [
        "*Methodology: signals are computed deterministically from the findings "
        "ledger (attack types, evidence diffs, scan notes, scoreboard round "
        "techniques). A shared trend means the same exposure class recurs "
        "across the estate — new sites matching a trend inherit its peers' "
        "remediation playbook. Anomalies are unique/platform/severity classes, "
        "each explainable from the profile above.*",
        "",
    ]
    return "\n".join(lines)


def write_trends(profiles, groups, anomalies, out_dir: str = "findings") -> Tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    md = out / "TRENDS.md"
    md.write_text(render_trends(profiles, groups, anomalies), encoding="utf-8")
    js = out / "TRENDS.json"
    payload = {
        "generated_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S"),
        "profiles": profiles,
        "groups": groups,
        "anomalies": anomalies,
    }
    tmp = js.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(js)
    return md, js
