#!/usr/bin/env python
"""Titan Learn CLI — the estate learns from its own ledger.

Usage:
    python titan_learn_cli.py trends [--output findings]
    python titan_learn_cli.py estate-manifest [--output bench/manifests/estate.json]
                                        [--include-practice]

`trends` rebuilds the per-site profiles from the findings ledger + scoreboard
notes and writes findings/TRENDS.md + TRENDS.json — the shared trends across
the estate and the anomalies (unique / platform-deviation / severity-outlier)
the system flags so similar sites get compared.

`estate-manifest` regenerates the estate benchmark corpus
(bench/manifests/estate.json) from the ledger — every audited site with its
expected attack types as benchmark challenges.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from bench.estate import build_estate_manifest, write_estate_manifest  # noqa: E402
from titan.learn.trends import (  # noqa: E402
    build_profiles,
    find_trend_groups,
    flag_anomalies,
    render_trends,
    write_trends,
)


def _cmd_trends(args) -> int:
    profiles = build_profiles(args.findings, args.scoreboard)
    groups = find_trend_groups(profiles)
    anomalies = flag_anomalies(profiles, groups)
    md, js = write_trends(profiles, groups, anomalies, out_dir=args.output)
    print(f"[+] Profiles: {len(profiles)} sites")
    print(f"[+] Shared trends: {len(groups)}")
    for g in groups:
        print(f"    - {g['signal']}: {g['count']} sites ({', '.join(g['members'])})")
    print(f"[+] Anomalies: {len(anomalies)}")
    for a in anomalies:
        print(f"    - [{a['kind']}] {a['slug']}: {a['message']}")
    print(f"[+] Wrote {md} + {js}")
    return 0


def _cmd_estate_manifest(args) -> int:
    manifest = build_estate_manifest(args.findings, include_practice=args.include_practice)
    p = write_estate_manifest(manifest, out_path=args.output)
    estate = sum(1 for s in manifest["sites"] if s["estate"])
    challenges = sum(len(s["challenges"]) for s in manifest["sites"])
    print(f"[+] Estate corpus: {len(manifest['sites'])} sites "
          f"({estate} owned estate) · {challenges} expected-finding challenges")
    print(f"[+] Wrote {p}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Titan Learn CLI — trend/anomaly learning")
    sub = parser.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("trends", help="rebuild profiles + trends + anomalies from the ledger")
    t.add_argument("--output", default="findings")
    t.add_argument("--findings", default="findings")
    t.add_argument("--scoreboard", default="purple/scoreboard.json")
    t.set_defaults(fn=_cmd_trends)

    e = sub.add_parser("estate-manifest", help="regenerate the estate benchmark corpus")
    e.add_argument("--output", default="bench/manifests/estate.json")
    e.add_argument("--findings", default="findings")
    e.add_argument("--include-practice", action="store_true",
                   help="also include practice/third-party hosts from the ledger")
    e.set_defaults(fn=_cmd_estate_manifest)

    args = parser.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
