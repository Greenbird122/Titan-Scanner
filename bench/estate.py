"""Estate benchmark corpus — every audited site as a benchmark target.

Builds ``bench/manifests/estate.json`` from the findings ledger: one entry per
audited site, each carrying the expected attack types (the verified findings
on record) as benchmark challenges. Scoring is the standard Phase C rig
(``bench.benchmark.score_challenge``): HIT when the engine reports the
expected attack type verified on that site, MISS when it scanned and did not,
N/A when the site was never reached.

The corpus is regenerated from the ledger, so it always reflects reality —
re-auditing a site and writing verified findings automatically updates its
challenges on the next build.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List

from titan.learn.notes import mine_findings_md_file

MAX_ATTACK_TYPES_PER_SITE = 3


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _consent_roster(consent_dir: str) -> set:
    """Hosts with a signed consent file — the authoritative owned-estate list.
    Consent filenames are ``<host>.json`` (``git-vizor.vercel.app.json``)."""
    roster: set = set()
    d = Path(consent_dir)
    if not d.is_dir():
        return roster
    for p in d.glob("*.json"):
        roster.add(p.stem.strip())
    return roster


def _host_norm(host: str) -> str:
    host = host.split("://")[-1]  # strip scheme
    host = host.split("/")[0]     # strip path
    host = host.split(":")[0]     # strip port
    return host.replace(".", "-").replace("_", "-")


def _is_estate_site(slug: str, target: str, meta: Dict[str, Any], index: Dict[str, Any], roster: set) -> bool:
    """A site belongs to the owned estate when consent is on file for its host
    (the authoritative roster), or it was deep-audited (sites.json ``deep_audit``
    or a reverification round on its scan_meta). Local lab hosts count as
    owned. Practice/third-party hosts are excluded from the estate benchmark
    scan but stay in the ledger the trend analyzer reads."""
    host = _host_norm(target)
    if host and any(host == _host_norm(r) or r.startswith(host + "-") or host.startswith(r + "-") for r in roster):
        return True
    entry = index.get(slug, {})
    if entry.get("deep_audit"):
        return True
    if meta.get("reverification_round"):
        return True
    if slug.startswith(("127-0-0-1-", "localhost-")):
        return True
    return False


def build_estate_manifest(findings_root: str = "findings", include_practice: bool = False,
                          consent_dir: str = "consent") -> Dict[str, Any]:
    """Pure: build the estate corpus from the findings/ ledger.

    Returns ``{"manifest", "generated_at", "sites": [{slug, target, estate,
    challenges: [{id, name, endpoint, attack_type, method}], source}]}``.
    A site dir counts when it carries ANY record — findings.json, FINDINGS.md
    (deep audits are documented in notes only), or scan_meta.json.
    """
    root = Path(findings_root)
    index = _load_json(root / "sites.json").get("sites", [])
    index_by_slug = {s.get("slug", ""): s for s in index if s.get("slug")}
    roster = _consent_roster(consent_dir)
    # slug -> consent host, so notes-only sites (no scan_meta/findings.json)
    # still get a target from the consent roster.
    slug_to_host = {_host_norm(r): r for r in roster}
    sites: List[Dict[str, Any]] = []

    for slug in sorted(p.name for p in root.iterdir() if p.is_dir()):
        sdir = root / slug
        fpath = sdir / "findings.json"
        if not fpath.exists() and not (sdir / "FINDINGS.md").exists() and not (sdir / "scan_meta.json").exists():
            continue
        data = _load_json(fpath) if fpath.exists() else {}
        raw_findings = data.get("findings", [])
        meta = _load_json(sdir / "scan_meta.json")
        target = meta.get("target") or data.get("target") or ""
        if not target:
            target = index_by_slug.get(slug, {}).get("target", "")
        if not target and slug in slug_to_host:
            target = "https://" + slug_to_host[slug]
        if not target:
            continue

        estate = _is_estate_site(slug, target, meta, index_by_slug, roster)
        if not estate and not include_practice:
            continue

        # Expected attack types = verified attack types on record (findings.json),
        # merged with FINDINGS.md-mined attack types so deep-audit sites whose
        # machine ledger is empty (documented in notes only) still get
        # benchmark challenges. Ranked by how many records carry them.
        counts: Dict[str, int] = {}
        methods: Dict[str, str] = {}
        mined: Dict[str, int] = {}
        for f in raw_findings:
            atk = (f.get("attack_type") or "").strip()
            if not atk or not f.get("verified"):
                continue
            counts[atk] = counts.get(atk, 0) + 1
            methods.setdefault(atk, f.get("method", "GET"))
        fmd_path = root / slug / "FINDINGS.md"
        for row in mine_findings_md_file(fmd_path):
            atk = row.get("attack_type") or ""
            if atk:
                mined[atk] = mined.get(atk, 0) + 1
        merged: Dict[str, int] = {k: counts.get(k, 0) + mined.get(k, 0) for k in set(counts) | set(mined)}
        top = sorted(merged.items(), key=lambda kv: -kv[1])[:MAX_ATTACK_TYPES_PER_SITE]

        challenges = []
        for atk, n in top:
            cid = f"{slug}-{atk.lower().replace(' ', '-')}"
            challenges.append({
                "id": cid,
                "name": f"{atk} ({n} records: {counts.get(atk, 0)} scan + {mined.get(atk, 0)} mined)",
                "endpoint": target,
                "attack_type": atk,
                "method": methods.get(atk, "GET"),
                "mined": atk in mined,
            })

        sites.append({
            "slug": slug,
            "target": target,
            "estate": estate,
            "challenges": challenges,
            "source": {
                "findings": len(raw_findings),
                "verified": sum(1 for f in raw_findings if f.get("verified")),
                "critical": sum(1 for f in raw_findings if f.get("severity") == "critical"),
                "high": sum(1 for f in raw_findings if f.get("severity") == "high"),
                "deep_audit": index_by_slug.get(slug, {}).get("deep_audit", False),
                "mined_findings": len(mined),
            },
        })

    return {
        "manifest": "estate-corpus",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "policy": (
            "Benchmark corpus generated from the findings ledger. estate=true "
            "sites are the owned estate (deep-audited or reverified); the "
            "estate scan path is consent-gated like any other scan."
        ),
        "sites": sites,
    }


def write_estate_manifest(manifest: Dict[str, Any], out_path: str = "bench/manifests/estate.json") -> Path:
    """Atomically persist the estate corpus. Returns the written path."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    tmp.replace(out)
    return out
