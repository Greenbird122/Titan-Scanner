"""Fast real-engine honeypot run: only headers + baas modules enabled.

Traces BaasDetector.scan/_sweep_on_origin to find why the on-origin sweep
cache stays empty inside the real engine flow (the module matrix fires,
other modules run, but the sweep never populates its dedupe cache).
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from run import load_config
from titan.core.engine import TitanEngine
from titan.modules.baas.detector import BaasDetector

TARGET = "https://acme-store-adversarial.vercel.app"

# Names of every module in ModuleRunner.run_attack_modules' matrix
MODULES = ["sqli", "xss", "ssrf", "auth", "idor", "lfi", "rce", "nosqli",
           "ssti", "xxe", "upload", "logic", "cors", "headers", "crypto",
           "deser", "race", "cache", "smuggling", "fuzzer", "parserdiff",
           "sourcesecret", "apixss", "baas"]


async def main() -> int:
    config = load_config("config.yaml")
    config["target"] = TARGET
    config.setdefault("auth", {})["url"] = TARGET
    config["brain"] = {"enabled": False}
    config["ai"] = {"enabled": False}
    config["deep_audit"] = {"enabled": False}
    config["clientside"] = {"enabled": False}
    config["reporting"] = {"enabled": False}
    config.setdefault("crawl", {})["max_pages"] = 2
    config["crawl"]["max_depth"] = 1
    config["crawl"]["timeout"] = 60
    # Only headers (cheap, keeps the matrix alive) + baas (the module under test)
    mods = {}
    for m in MODULES:
        mods[m] = {"enabled": m in ("headers", "baas"), "timeout": 20}
    config["modules"] = mods

    BaasDetector.reset_sweep_cache()

    # ---- trace baas scan + sweep entry ------------------------------
    orig_scan = BaasDetector.scan

    async def traced_scan(self, context, target, method, url, params):
        print(f"[trace] scan enter url={url!r} platform={self._detected_platform}", flush=True)
        try:
            out = await orig_scan(self, context, target, method, url, params)
            print(f"[trace] scan exit -> {len(out)} findings", flush=True)
            return out
        except Exception as exc:
            import traceback
            print(f"[trace] scan RAISED {type(exc).__name__}: {exc}", flush=True)
            traceback.print_exc()
            return []

    BaasDetector.scan = traced_scan

    engine = TitanEngine(config)
    result = await engine.scan(TARGET)

    print(f"\n[+] Scan complete: {len(result.findings)} findings", flush=True)
    print(f"[+] BaaS on-origin sweep cache size: {len(BaasDetector._SWEPT_ORIGINS)}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
