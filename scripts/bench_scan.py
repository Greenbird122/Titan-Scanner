"""SHARPEN-S1 benchmark harness: time a full scan and print the breakdown.

Usage:
    python scripts/bench_scan.py --target http://localhost:5000 [--profile fast|deep]

Prints wall-clock scan duration and (when available) per-phase timings, plus
the resulting finding counts so speed changes can be validated against
unchanged detection results.
"""

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import yaml


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark a Titan scan.")
    parser.add_argument("--target", required=True, help="Target URL to scan")
    parser.add_argument("--profile", default="fast", choices=["fast", "deep"])
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    config.setdefault("crawl", {})["profile"] = args.profile
    # Benchmarks must not be throttled by proxy rotation or AI escalation.
    config.setdefault("ai", {}).setdefault("escalate", {})["enabled"] = False
    config.setdefault("reporting", {})["enabled"] = False
    config["output_dir"] = "findings"

    from titan.core.engine import TitanEngine

    engine = TitanEngine(config)
    print(f"[bench] target={args.target} profile={args.profile} "
          f"stealth={engine.stealth.min_delay}/{engine.stealth.max_delay}s "
          f"concurrency={config.get('crawl', {}).get('module_concurrency', 8)}")

    t0 = time.monotonic()
    result = None
    try:
        import asyncio
        result = asyncio.run(engine.scan(args.target))
    except Exception as exc:  # pragma: no cover - harness
        print(f"[bench] scan failed: {exc}")
        return 1
    elapsed = time.monotonic() - t0

    print(f"[bench] duration={elapsed:.1f}s")
    print(f"[bench] findings={len(result.findings)} "
          f"verified={sum(1 for f in result.findings if f.verified)} "
          f"critical={sum(1 for f in result.findings if str(getattr(f, 'severity', '')).startswith('Severity.CRITICAL'))}")
    if result.errors:
        print(f"[bench] errors={result.errors}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
