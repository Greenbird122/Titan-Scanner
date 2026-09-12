"""Instrumented full-engine honeypot scan: prove the module matrix fires.

Counters wrap the two dispatch points the regression killed (_run_modules
on the engine and the API-only runner) so we can see the matrix actually
run against crawl-discovered endpoints, and confirm the BaaS on-origin
sweep reaches its origin-level dedupe cache.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from run import load_config
from titan.core.engine import TitanEngine

TARGET = "https://acme-store-adversarial.vercel.app"
COUNTERS = {"modules": 0, "api_modules": 0, "module_calls": 0}


async def main() -> int:
    config = load_config("config.yaml")
    config["target"] = TARGET
    config.setdefault("auth", {})["url"] = TARGET
    config["brain"] = {"enabled": False}
    config["ai"] = {"enabled": False}
    config["deep_audit"] = {"enabled": False}
    # The honeypot is a SPA: the homepage alone references every endpoint,
    # so a tiny crawl budget still exercises the full crawl -> module-matrix
    # wiring while keeping the run bounded.
    config.setdefault("crawl", {})["max_pages"] = 2
    config["crawl"]["max_depth"] = 1

    engine = TitanEngine(config)

    # ---- instrument the two dispatch points --------------------------
    _orig_modules = engine._run_modules
    _orig_api = engine._run_api_modules

    async def wrapped_modules(context, target, forms, links, apis, fingerprint, result=None, route_score=5):
        COUNTERS["modules"] += 1
        COUNTERS["module_calls"] += len(forms) + len(links) + len(apis)
        return await _orig_modules(context, target, forms, links, apis, fingerprint, result, route_score)

    async def wrapped_api(context, target, api_url, fingerprint):
        COUNTERS["api_modules"] += 1
        return await _orig_api(context, target, api_url, fingerprint)

    engine._run_modules = wrapped_modules
    engine._run_api_modules = wrapped_api
    # ---- run ---------------------------------------------------------

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

    from titan.modules.baas.detector import BaasDetector

    print(
        f"\n[+] Module matrix dispatch: _run_modules={COUNTERS['modules']} "
        f"runs over {COUNTERS['module_calls']} endpoints, "
        f"_run_api_modules={COUNTERS['api_modules']}"
    )
    print(f"[+] BaaS on-origin sweep cache size: {len(BaasDetector._SWEPT_ORIGINS)}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
