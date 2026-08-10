"""Titan Scanner — canonical entry point."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from titan.core.engine import TitanEngine


def load_config(path: str = "config.yaml") -> dict:
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


async def main():
    config = load_config()
    target = config.get("target", "https://sales-ten-xi.vercel.app/")
    engine = TitanEngine(config)
    result = await engine.scan(target)

    print(f"\n[+] Scan complete: {len(result.findings)} findings ({result.verified_count} verified)")
    print(f"    Critical: {result.critical_count}, High: {result.high_count}, Chains: {result.chain_count}")
    print(f"    Duration: {result.duration_seconds}s")

    # The engine persists per-site docs to <output_dir>/<site-slug>/.
    from titan.reporting import site_slug
    print(f"\n[+] Findings documented under {config.get('output_dir', 'findings')}/{site_slug(target)}/")


if __name__ == "__main__":
    asyncio.run(main())
