"""Attack-module bindings: one lazy-import wrapper per detector.

Split out of ``modules_runner.py`` (which held 24 near-identical
wrappers among its 787 lines). ``ModuleRunner`` inherits this class,
so ``self._run_sqli`` etc. resolve exactly as before — including
tests that monkey-patch them on a runner instance.
"""

from __future__ import annotations

from typing import Any


class AttackModuleBindings:
    """Lazy-import dispatch table; engine handle comes from ModuleRunner."""

    # State supplied by the host runner before any mixin method runs.
    engine: Any

    # Individual attack module wrappers
    # ------------------------------------------------------------------

    async def _run_sqli(self, ctx, t, m, u, p, fp):
        from titan.modules.sqli.detector import SQLiDetector

        return await SQLiDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_xss(self, ctx, t, m, u, p, fp):
        from titan.modules.xss.detector import XSSDetector

        return await XSSDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_ssrf(self, ctx, t, m, u, p, fp):
        from titan.modules.ssrf.detector import SSRFDetector

        e = self.engine
        internal_paths = [
            v for v in sorted(e._discovered_urls) if v.startswith("http") and e._is_in_scope(v) and "#" not in v
        ][:8]
        return await SSRFDetector(e.payload_smith, fp).scan(ctx, t, m, u, p, internal_paths=internal_paths)

    async def _run_auth(self, ctx, t, m, u, p, fp):
        from titan.modules.auth.detector import AuthDetector

        return await AuthDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_idor(self, ctx, t, m, u, p, fp):
        from titan.modules.idor.detector import IDORDetector

        return await IDORDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_lfi(self, ctx, t, m, u, p, fp):
        from titan.modules.lfi.detector import LFIDetector

        return await LFIDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_rce(self, ctx, t, m, u, p, fp):
        from titan.modules.rce.detector import RCEDetector

        return await RCEDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_nosqli(self, ctx, t, m, u, p, fp):
        from titan.modules.nosqli.detector import NoSQLiDetector

        return await NoSQLiDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_ssti(self, ctx, t, m, u, p, fp):
        from titan.modules.ssti.detector import SSTIDetector

        return await SSTIDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_xxe(self, ctx, t, m, u, p, fp):
        from titan.modules.xxe.detector import XXEDetector

        return await XXEDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_upload(self, ctx, t, m, u, p, fp):
        from titan.modules.upload.detector import UploadDetector

        return await UploadDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_logic(self, ctx, t, m, u, p, fp):
        from titan.core.scan_params import validate_scan_params
        from titan.modules.logic.detector import LogicDetector

        validate_scan_params(target=t, method=m, url=u, params=p)
        return await LogicDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_cors(self, ctx, t, m, u, p, fp):
        from titan.modules.cors.detector import CORSDetector

        return await CORSDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_headers(self, ctx, t, m, u, p, fp):
        from titan.modules.headers.detector import HeadersDetector

        return await HeadersDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_crypto(self, ctx, t, m, u, p, fp):
        from titan.modules.crypto.detector import CryptoDetector

        return await CryptoDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_deser(self, ctx, t, m, u, p, fp):
        from titan.modules.deser.detector import DeserDetector

        return await DeserDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_race(self, ctx, t, m, u, p, fp):
        from titan.modules.race.detector import RaceDetector

        return await RaceDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_cache(self, ctx, t, m, u, p, fp):
        from titan.modules.cache.detector import CacheDetector

        return await CacheDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_smuggling(self, ctx, t, m, u, p, fp):
        from titan.modules.smuggling.detector import SmugglingDetector

        return await SmugglingDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_baas(self, ctx, t, m, u, p, fp):
        from titan.modules.baas.detector import BaasDetector

        return await BaasDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_fuzzer(self, ctx, t, m, u, p, fp):
        from titan.modules.fuzzer.detector import FuzzerDetector

        return await FuzzerDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_parserdiff(self, ctx, t, m, u, p, fp):
        from titan.modules.parserdiff.detector import ParserDiffDetector

        return await ParserDiffDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_sourcesecret(self, ctx, t, m, u, p, fp):
        from titan.modules.sourcesecret.detector import SourceSecretDetector

        return await SourceSecretDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)

    async def _run_apixss(self, ctx, t, m, u, p, fp):
        from titan.modules.apixss.detector import ApiXssDetector

        return await ApiXssDetector(self.engine.payload_smith, fp).scan(ctx, t, m, u, p)
