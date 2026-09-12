"""Full-engine scan of the adversarial honeypot (whole module matrix).

Loads config.yaml unchanged except repointing target + auth so nothing
touches the default config target. Consent for
acme-store-adversarial.vercel.app is on record (ownership, full flags).
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from run import load_config
from titan.core.engine import TitanEngine

TARGET = "https://acme-store-adversarial.vercel.app"


async def main() -> int:
    config = load_config("config.yaml")
    config["target"] = TARGET
    # Repoint any auth/login scaffolding to the honeypot so nothing ever
    # drifts to the default config target.
    config.setdefault("auth", {})["url"] = TARGET
    # Full module matrix, no LLM/brain/deep-audit escalation layers:
    # deterministic and faster for the negative-control calibration.
    config["brain"] = {"enabled": False}
    config["ai"] = {"enabled": False}
    config["deep_audit"] = {"enabled": False}

    engine = TitanEngine(config)
    result = await engine.scan(TARGET)

    print(f"\n[+] Scan complete: {len(result.findings)} findings ({result.verified_count} verified)")
    print(
        f"    Critical: {result.critical_count}, High: {result.high_count}, "
        f"Chains: {result.chain_count}, Duration: {result.duration_seconds}s"
    )

    for f in sorted(result.findings, key=lambda x: (x.severity.value, x.attack_type.value)):
        print(
            f"  [{f.severity.value.upper()}] {f.attack_type.value} "
            f"conf={f.confidence:.2f} verified={'Y' if f.verified else 'N'} tier={f.tier}"
        )
        print(f"    {f.method} {f.url}  param={f.param} ({f.location})")
        note = (f.notes or "")[:120]
        if note:
            print(f"    note: {note}")

    if result.errors:
        print(f"\n[!] Errors ({len(result.errors)}):")
        for err in result.errors[:20]:
            print(f"    - {err}")

    print(
        f"\n[+] BaaS on-origin sweep cache size: "
        f"{len(__import__('titan.modules.baas.detector', fromlist=['BaasDetector']).BaasDetector._SWEPT_ORIGINS)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
