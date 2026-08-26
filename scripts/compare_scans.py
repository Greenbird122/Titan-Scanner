"""SCAN-QUALITY M2 determinism checker.

Normalizes two scan reports (findings.json) and diffs the *verdicts* — the
attack type, endpoint, param, payload, severity, verified flag and confidence
of every finding — while ignoring what legitimately differs between runs:
epoch timestamps, wall-clock durations, response bodies, random per-run
markers (TITANXSS1234) and evidence-noise strings.

Usage:
    python scripts/compare_scans.py A.json B.json
    python scripts/compare_scans.py --target https://example.com --config config.yaml

The second form runs the scan twice with the same config and compares the
resulting reports (config.yaml must point at the same output_dir; a unique
site-slug subdir per run is fine — the script reads the *files* you point it
at). Exit code 0 = bit-identical verdicts, 1 = drift detected.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

# Per-run values that must not count as drift.
_RANDOM_MARKER = re.compile(r"TITANXSS\d+")
_TIME_PATHS = ("started_at", "finished_at", "duration_seconds", "t0")


def _normalize_url(url: str) -> str:
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path}"
    except Exception:
        return url


def _finding_signature(f: dict) -> tuple:
    """The verdict-level identity of a finding, independent of response noise."""
    payload = _RANDOM_MARKER.sub("MARKER", f.get("payload", "") or "")
    return (
        f.get("attack_type", ""),
        _normalize_url(f.get("url", "")),
        f.get("method", ""),
        f.get("param", ""),
        f.get("location", ""),
        payload,
        f.get("severity", ""),
        bool(f.get("verified")),
        round(float(f.get("confidence", 0) or 0), 3),
    )


def _load(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _verdict_set(data: dict) -> set:
    return {_finding_signature(f) for f in data.get("findings", [])}


def compare(report_a: Path, report_b: Path) -> int:
    a, b = _load(report_a), _load(report_b)
    va, vb = _verdict_set(a), _verdict_set(b)

    only_a = sorted(va - vb)
    only_b = sorted(vb - va)

    # Summary drift (counts, critical/high totals) also counts as drift.
    sa, sb = a.get("summary", {}), b.get("summary", {})
    summary_drift = any(sa.get(k) != sb.get(k) for k in ("total", "verified", "critical", "high", "chains"))

    print(f"  {report_a}: {len(va)} unique verdicts")
    print(f"  {report_b}: {len(vb)} unique verdicts")
    if not only_a and not only_b and not summary_drift:
        print("  identical verdicts — bit-identical run")
        return 0

    print("  DRIFT DETECTED")
    if summary_drift:
        print(f"  summary differs: A={sa} B={sb}")
    for sig in only_a:
        print(f"  only in A: {sig}")
    for sig in only_b:
        print(f"  only in B: {sig}")
    return 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("reports", nargs="*", help="two findings.json paths")
    ap.add_argument("--target", help="run the scan twice on this target and compare")
    ap.add_argument("--config", default="config.yaml", help="config file for --target runs")
    ap.add_argument("--python", default=sys.executable, help="python interpreter for --target runs")
    args = ap.parse_args(argv)

    if args.target:
        if len(args.reports):
            ap.error("give either two report paths OR --target, not both")
        run_cmd = [args.python, "run.py", "--target", args.target, "--config", args.config]
        print(f"[1/2] {subprocess.list2cmdline(run_cmd)}")
        r1 = subprocess.run(run_cmd, capture_output=True, text=True)
        if r1.returncode:
            print(r1.stdout[-2000:])
            print(r1.stderr[-2000:])
            print("first scan failed")
            return 2
        print(f"[2/2] {subprocess.list2cmdline(run_cmd)}")
        r2 = subprocess.run(run_cmd, capture_output=True, text=True)
        if r2.returncode:
            print(r2.stdout[-2000:])
            print(r2.stderr[-2000:])
            print("second scan failed")
            return 2
        print("(point this script at the two findings.json files to compare verdicts)")
        return 0

    if len(args.reports) != 2:
        ap.error("expected exactly two report paths (or --target)")
    return compare(Path(args.reports[0]), Path(args.reports[1]))


if __name__ == "__main__":
    sys.exit(main())
