"""Titan Scanner — quick launcher.

Usage:
    python run.py                          # scan config.yaml's target
    python run.py --target <url>           # scan a specific site
    python run.py --target <url> --config <path>

Every scan is documented under findings/<site-slug>/ (report.md, findings.json,
scan_meta.json) plus the sites.json index.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from titan.core.engine import TitanEngine


def load_config(path: str = "config.yaml") -> dict:
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _arg_value(flag: str, default: str) -> str:
    if flag in sys.argv:
        idx = sys.argv.index(flag)
        if idx + 1 < len(sys.argv):
            return sys.argv[idx + 1]
    return default


async def main():
    config_path = _arg_value("--config", "config.yaml")
    config = load_config(config_path)
    target = _arg_value("--target", config.get("target", ""))
    if not target:
        print("[!] No target. Set 'target' in config.yaml or pass --target <url>")
        sys.exit(1)

    engine = TitanEngine(config)
    result = await engine.scan(target)

    print(f"\n[+] Scan complete: {len(result.findings)} findings ({result.verified_count} verified)")
    print(f"    Critical: {result.critical_count}, High: {result.high_count}, Chains: {result.chain_count}")
    print(f"    Duration: {result.duration_seconds}s")

    for f in result.findings:
        print(f"  [{f.severity.value.upper()}] {f.attack_type.value} conf={f.confidence:.2f} "
              f"verified={'Y' if f.verified else 'N'}")
        print(f"    {f.method} {f.url}  param={f.param} ({f.location})")
        print(f"    payload: {f.payload[:100]}")
        print()

    if result.errors:
        print(f"\n[!] Errors: {len(result.errors)}")
        for err in result.errors:
            print(f"    - {err}")

    from titan.reporting import site_slug
    print(f"[+] Findings documented under findings/{site_slug(target)}/")


if __name__ == "__main__":
    asyncio.run(main())
