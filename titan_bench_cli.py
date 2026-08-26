#!/usr/bin/env python
"""Titan Bench CLI - PUSH-TO-100 Phase C benchmark rig.

Scans a benchmark manifest's known-vulnerable targets and produces the
public scorecard: per-challenge pass rates anyone can check.

Usage:
    python titan_bench_cli.py run [--manifest bench/manifests/local_lab.json]
                                  [--target http://127.0.0.1:5000]
                                  [--output bench/results]
                                  [--auth-cookies 'JSESSIONID=abc']
    python titan_bench_cli.py score [--output bench/results]

The pilot benchmark is the local lab (no installs). Juice Shop / WebGoat
manifests plug in the same way once the operator approves the installs.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from bench.benchmark import load_manifest, run_benchmark  # noqa: E402
from bench.scorecard import merge_runs, write_scorecard  # noqa: E402
from titan.core.engine import TitanEngine  # noqa: E402

DEFAULT_CONFIG = {
    # max_apis: scan the full discovered API surface in benchmark runs — a
    # hardcoded cap silently drops challenge endpoints and reports N/A.
    # module_concurrency 2: the module matrix hammers the target; 8 killed
    # Juice Shop's Node heap (OOM) mid-benchmark on a 7.8 GB box.
    # timeout 900: the homepage of a real SPA (Juice Shop) exposes ~90 APIs
    # and the module matrix on all of them exceeds 180s — the crawl must not
    # die before the seeded challenge endpoints ever run.
    "crawl": {"profile": "deep", "max_pages": 10, "timeout": 900,
              "module_concurrency": 2, "max_apis": 500},
    "modules": {},
    "clientside": {"enabled": False},
    "llm": {"enabled": False},
    "cloud": {"storage": {"enabled": False}},
    "headless": True,
    "reporting": {"enabled": True, "output_dir": "findings"},
    "exploit": {"consent_dir": "consent"},
    "authorization": {"practice_manifest": "findings/AUTHORIZED-PRACTICE.json"},
    "ai": {},
}


async def _run(
    manifest_path: str,
    target: str | None,
    out_dir: str,
    auth_cookies: str | None = None,
) -> Path:
    manifest = load_manifest(manifest_path)
    challenges = manifest["challenges"]
    if not challenges:
        print(f"[!] No challenges in {manifest_path}")
        return Path(out_dir)

    target = target or manifest.get("target") or challenges[0].get("target") or "http://127.0.0.1:5000"
    cfg = dict(DEFAULT_CONFIG)
    cfg["output_dir"] = out_dir
    if auth_cookies:
        cookies = {}
        for pair in auth_cookies.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
        if cookies:
            cfg["auth"] = {"cookies": cookies}

    from titan.core.engine import TitanEngine
    engine = TitanEngine(cfg)
    print(f"[+] Benchmark scan: {target} ({len(challenges)} challenges)")
    result = await run_benchmark(target, challenges, engine)

    out = Path(out_dir)
    prev = {}
    score_path = out / "scorecard.json"
    if score_path.exists():
        try:
            prev = json.loads(score_path.read_text(encoding="utf-8"))
        except Exception:
            prev = {}
    merged = merge_runs(prev, result) if prev else {
        "target": target,
        "last_scan": result["scanned_at"],
        "runs": 1,
        "rows": result["rows"],
        "summary": result["summary"],
    }
    write_scorecard(merged, out_dir=out_dir)

    s = merged["summary"]
    print(f"[+] Pass rate: {s['pass_rate']}% ({s['hits']}/{s['reachable']} reachable)")
    print(f"[+] Hits {s['hits']} · Suspicious {s['suspicious']} · "
          f"Misses {s['misses']} · N/A {s['na']}")
    print(f"[+] Scorecard written to {out / 'scorecard.md'}")
    return out


async def _estate(out_dir: str, limit: int, rebuild_only: bool, auth_cookies: str | None) -> None:
    """Rebuild the estate corpus from the ledger, then scan each estate site.

    The corpus is regenerated first so the benchmark always reflects the
    latest recorded findings (a re-audit that adds verified findings
    automatically adds challenges). Sites are scanned one at a time with the
    Phase C engine config; per-site scorecards accumulate in out_dir.
    """
    from bench.estate import build_estate_manifest, write_estate_manifest
    from bench.scorecard import render_scorecard, write_scorecard

    manifest = build_estate_manifest("findings", include_practice=False)
    manifest_path = write_estate_manifest(manifest)
    print(f"[+] Estate corpus regenerated: {manifest_path}")
    print(f"[+] {len(manifest['sites'])} estate sites · "
          f"{sum(len(s['challenges']) for s in manifest['sites'])} challenges")
    if rebuild_only:
        return

    cfg = dict(DEFAULT_CONFIG)
    if auth_cookies:
        cookies = {}
        for pair in auth_cookies.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
        if cookies:
            cfg["auth"] = {"cookies": cookies}

    from titan.core.engine import TitanEngine
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    score_path = out / "scorecard.json"
    prev = {}
    if score_path.exists():
        try:
            prev = json.loads(score_path.read_text(encoding="utf-8"))
        except Exception:
            prev = {}

    sites = [s for s in manifest["sites"] if s["estate"] and s["challenges"]]
    if limit:
        sites = sites[:limit]
    for i, site in enumerate(sites, 1):
        print(f"[+] [{i}/{len(sites)}] scanning {site['slug']} "
              f"({len(site['challenges'])} challenges)")
        engine = TitanEngine(cfg)
        try:
            result = await run_benchmark(site["target"], site["challenges"], engine)
        except Exception as exc:  # noqa: BLE001 - a broken site can't kill the estate run
            result = {
                "target": site["target"],
                "scanned_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S"),
                "scan_seconds": 0,
                "scan_error": str(exc)[:200],
                "rows": [{
                    "id": c["id"], "name": c["name"], "endpoint": c["endpoint"],
                    "attack_type": c["attack_type"], "outcome": "na",
                    "evidence": f"scan error: {str(exc)[:120]}",
                } for c in site["challenges"]],
                "summary": {"total": len(site["challenges"]), "hits": 0,
                            "suspicious": 0, "misses": 0, "na": len(site["challenges"]),
                            "reachable": 0, "pass_rate": 0.0},
            }
        prev[site["slug"]] = result
        s = result["summary"]
        print(f"    pass {s['pass_rate']}% ({s['hits']}/{s['reachable']}) "
              f"miss {s['misses']} na {s['na']}")

    tmp = out / "scorecard.json.tmp"
    tmp.write_text(json.dumps(prev, indent=2), encoding="utf-8")
    tmp.replace(score_path)

    # estate summary table
    lines = ["# Estate benchmark — owned sites vs their recorded findings", "",
             "| Site | Pass | Hits | Misses | N/A |", "|---|---|---|---|---|"]
    for slug, res in prev.items():
        s = res.get("summary", {})
        lines.append(f"| {slug} | {s.get('pass_rate', 0)}% | {s.get('hits', 0)} | "
                     f"{s.get('misses', 0)} | {s.get('na', 0)} |")
    (out / "SCORECARD.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] Estate scorecard written to {out / 'SCORECARD.md'}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Titan Bench CLI (Phase C)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="scan a manifest and score it")
    run_p.add_argument("--manifest", default="bench/manifests/local_lab.json")
    run_p.add_argument("--target", default=None)
    run_p.add_argument("--output", default="bench/results")
    run_p.add_argument("--auth-cookies", default=None,
                       help="session cookies to inject, e.g. 'JSESSIONID=abc; foo=bar'")

    estate_p = sub.add_parser(
        "estate",
        help="rebuild the estate corpus from the findings ledger, then scan "
             "each owned-estate site and score it against its recorded findings",
    )
    estate_p.add_argument("--output", default="bench/results/estate")
    estate_p.add_argument("--limit", type=int, default=0,
                          help="cap the number of estate sites scanned (0 = all)")
    estate_p.add_argument("--rebuild-only", action="store_true",
                          help="only regenerate bench/manifests/estate.json, don't scan")
    estate_p.add_argument("--auth-cookies", default=None)

    args = parser.parse_args()

    if args.cmd == "run":
        asyncio.run(_run(args.manifest, args.target, args.output, args.auth_cookies))
        return 0

    if args.cmd == "estate":
        asyncio.run(_estate(args.output, args.limit, args.rebuild_only, args.auth_cookies))
        return 0

    if args.cmd == "score":
        from bench.scorecard import render_scorecard
        p = Path(args.output) / "scorecard.json"
        if not p.exists():
            print(f"[!] No scorecard at {p} — run `bench run` first")
            return 1
        data = json.loads(p.read_text(encoding="utf-8"))
        print(render_scorecard(data))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
