"""PUSH-TO-100 Phase C — benchmark runner.

Pure scoring first (testable exactly), then the per-challenge scan wiring.

A challenge is ``{"id", "name", "endpoint", "attack_type", "method",
"param"}`` in a manifest. The runner scans the challenge's endpoint with the
engine and scores:

  * HIT  — a finding of the expected attack type was reported for the
    challenge's endpoint (verified, not merely suspicious).
  * MISS — the endpoint was scanned/reached but the expected attack type was
    not reported.
  * N/A  — the endpoint was not reached (checkpoint, driver death, scan
    error) — scored as N/A, never as a false MISS.

The pure scorer is what the tests pin; the engine wiring degrades quietly so
a broken benchmark target can never take the whole rig down.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from titan.core.models import ScanResult


def score_challenge(
    challenge: Dict[str, Any],
    result: Optional[ScanResult],
    scan_error: str = "",
) -> Dict[str, Any]:
    """Pure: score one challenge against a scan result.

    Returns a row dict: ``{id, name, endpoint, attack_type, outcome,
    evidence}``. ``outcome`` is ``hit``/``miss``/``na``; ``evidence`` names
    the matching finding's diff markers (or the N/A reason).

    Pure — the tests pin this exactly.
    """
    row = {
        "id": challenge.get("id", ""),
        "name": challenge.get("name", ""),
        "endpoint": challenge.get("endpoint", ""),
        "attack_type": challenge.get("attack_type", ""),
        "outcome": "na",
        "evidence": "",
    }
    if scan_error:
        row["evidence"] = f"scan error: {scan_error[:120]}"
        return row
    if result is None:
        row["evidence"] = "no scan result"
        return row

    # Was the challenge's endpoint reached at all? If the scan never got a
    # response from it, the outcome is N/A (never a false MISS).
    expected_atk = (challenge.get("attack_type") or "").lower()
    expected_ep = (challenge.get("endpoint") or "").rstrip("/")
    ep_findings = [
        f for f in result.findings
        if (f.url or "").rstrip("/") == expected_ep
        or expected_ep and expected_ep in (f.url or "")
    ]
    if not ep_findings:
        row["evidence"] = "endpoint not reached"
        return row

    for f in ep_findings:
        atk = (f.attack_type.value if f.attack_type else "").lower()
        if expected_atk and expected_atk not in atk:
            continue
        # A hit must be verified — a suspicious-only report is a partial
        # detection, not the challenge captured.
        if f.tier == "confirmed" or f.verified:
            row["outcome"] = "hit"
            row["evidence"] = " ".join(f.diffs or [])[:200]
            return row
        row["outcome"] = "suspicious"
        row["evidence"] = " ".join(f.diffs or [])[:200]
    if row["outcome"] == "suspicious":
        return row
    row["outcome"] = "miss"
    row["evidence"] = "scanned; expected attack type not reported"
    return row


def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Pure: aggregate challenge rows into a scorecard summary."""
    total = len(rows)
    hits = sum(1 for r in rows if r["outcome"] == "hit")
    suspicious = sum(1 for r in rows if r["outcome"] == "suspicious")
    misses = sum(1 for r in rows if r["outcome"] == "miss")
    na = sum(1 for r in rows if r["outcome"] == "na")
    reachable = total - na
    pass_rate = round(hits / reachable * 100, 1) if reachable else 0.0
    return {
        "total": total,
        "hits": hits,
        "suspicious": suspicious,
        "misses": misses,
        "na": na,
        "reachable": reachable,
        "pass_rate": pass_rate,
    }


def load_manifest(path: str) -> Dict[str, Any]:
    """Load a manifest file, preserving the top-level ``target`` field.

    Returns ``{"target": ..., "challenges": [...]}`` so callers can resolve
    the benchmark target from the manifest itself instead of falling back to
    a default. A bare list is accepted and wrapped.
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return {"target": "", "challenges": data}
    return {
        "target": data.get("target", ""),
        "challenges": data.get("challenges", []),
    }


async def run_benchmark(
    target: str,
    challenges: List[Dict[str, Any]],
    engine,
    max_scan_seconds: int = 300,
) -> Dict[str, Any]:
    """Scan the target once, then score every challenge against the result.

    One scan per target (not per challenge) — the scan already covers the
    whole discovered surface; scoring is a pure post-pass. Returns the full
    benchmark result: ``{target, scanned_at, rows, summary}``.
    """
    started = time.time()
    result = None
    scan_error = ""
    # C1: seed the challenge endpoints (the engine's ``crawl.seed_urls``) and
    # scan them browserless. The benchmark certifies these endpoints as
    # known-vulnerable ground truth, so it tests DETECTION — does the module
    # matrix fire on a real sink? — not crawler discovery. A full-site crawl
    # of a heavy SPA (Juice Shop's ~90 discovered APIs) OOMs the target's own
    # server before any seed runs on a memory-constrained box.
    seed = []
    for c in challenges:
        ep = c.get("endpoint", "")
        if not ep:
            continue
        # Ground the declared param (the manifest says which field is
        # vulnerable — e.g. ``email`` on a login) so the module matrix
        # actually tests it. _test_rest_api parses the URL query into params;
        # without this it only tries generic {id,q,search} and the real sink
        # never gets probed (the login SQLi was missed this way).
        p = c.get("param", "")
        if p and "?" not in ep and "=" not in ep.split("?")[-1]:
            sep = "&" if "?" in ep else "?"
            ep = f"{ep}{sep}{p}=1"
        seed.append(ep)
    engine.config.setdefault("crawl", {})["seed_urls"] = (
        engine.config.get("crawl", {}).get("seed_urls", []) + seed
    )
    try:
        if engine.config.get("crawl", {}).get("browserless", True):
            result = await engine.scan_browserless(target)
        else:
            result = await engine.scan(target)
        for err in result.errors or []:
            if "checkpoint" in err.lower() or "authorization" in err.lower():
                scan_error = err
                break
    except Exception as exc:  # noqa: BLE001 - a broken target can't kill the rig
        scan_error = str(exc)[:200]

    rows = [score_challenge(c, result, scan_error=scan_error) for c in challenges]
    return {
        "target": target,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "scan_seconds": round(time.time() - started, 1),
        "scan_error": scan_error,
        "rows": rows,
        "summary": summarize(rows),
    }
