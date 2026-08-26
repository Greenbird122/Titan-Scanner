"""Track G — hostile & ad-monetized surface tests (M1-M6).

Hermetic by design: the profiler/detectors/intel operate on HTML strings, and
the active probes run against a local aiohttp fixture server — CI never
touches live third-party ad origins. The zairaku.rest cloak and the
ad-heavy-stack patterns are the reference fixtures.
"""

import asyncio
import json
from pathlib import Path

import pytest

from titan.core.models import AttackType, ScanResult
from titan.hostile import offense, profiler, run_pass
from titan.hostile.detectors import (
    classify_terminal,
    clickbait_index,
    detect_cloaks,
    detect_miners,
    detect_push_notif,
)
from titan.hostile.intel import IntelDB, ObservedIntel, domain_flux


def _ad_heavy_html() -> str:
    return """<!DOCTYPE html>
<html><head><title>Stream Now — Watch Free</title>
<script>document.addEventListener('contextmenu',e=>e.preventDefault(),true);
document.addEventListener('keydown',function(e){if(e.key==='F12'||(e.ctrlKey&&e.shiftKey&&'IJC'.indexOf(e.key.toUpperCase())>=0)||(e.ctrlKey&&e.key.toUpperCase()==='U')){e.preventDefault();e.stopPropagation()}},true);
setInterval(function(){try{(function(){}).constructor('debugger')()}catch(e){}},500);
setInterval(function(){if(window.outerWidth-window.innerWidth>160){document.documentElement.style.display='none'}},1000);
['log','warn','error'].forEach(function(m){try{console[m]=function(){}}catch(e){}});
window.onload=function(){window.open('http://pop.example/land','','width=400,height=300,left=10,top=10');};
</script>
<script src="https://effectivecpmnetwork.com/ads.js"></script>
<script src="http://adsterra.com/banner.js"></script>
<script src="https://cdn.jsdelivr.net/npm/lib@1.0.0/lib.min.js" integrity="sha384-abc"></script>
<img src="https://popads.net/pixel.png">
<iframe src="https://propellerads.com/frame.html"></iframe>
<script>if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js');}</script>
<script>Notification.requestPermission();</script>
<p>You are the 1,000,000th visitor! Claim your prize now. Your download will begin in 10 seconds.</p>
<a href="https://example.com/watch?v=1" onclick="window.open('https://casino.example/slots')">Play now</a>
</body></html>"""


class TestIntel:
    def test_classify_known_suffix(self):
        db = IntelDB()
        assert db.classify("effectivecpmnetwork.com") == "risky_ad"
        assert db.classify("cdn.effectivecpmnetwork.com") == "risky_ad"
        assert db.classify("popads.net") == "popunder"
        assert db.classify("coinhive.com") == "miner"

    def test_unknown_and_benign(self):
        db = IntelDB()
        assert db.classify("example.org") is None
        assert db.is_benign("cdn.jsdelivr.net") is True
        assert db.is_benign("effectivecpmnetwork.com") is False

    def test_promote_roundtrip(self, tmp_path):
        db = IntelDB(user_db_path=tmp_path / "user.json")
        assert db.promote("myad.shop", "ad_network", source="test", url="https://myad.shop/a.js")
        reloaded = IntelDB(user_db_path=tmp_path / "user.json")
        assert reloaded.classify("myad.shop") == "ad_network"
        # Collision with a different bundled category is rejected.
        assert db.promote("popads.net", "ad_network") is False
        # Garbage is rejected.
        assert db.promote("http://bad/x", "ad_network") is False

    def test_domain_flux(self):
        flux = domain_flux({"a.com": {}, "b.com": {}}, {"b.com": {}, "c.com": {}})
        assert flux["added"] == ["c.com"]
        assert flux["removed"] == ["a.com"]


class TestProfiler:
    def test_analyze_taxonomy(self):
        prof = profiler.analyze(_ad_heavy_html(), "https://example.com/")
        origins = {r["host"]: r for r in prof["origins"]}
        assert origins["effectivecpmnetwork.com"]["category"] == "risky_ad"
        adsterra = origins["adsterra.com"]
        assert adsterra["category"] == "risky_ad"
        assert adsterra["cleartext"] is True  # http:// script on https page
        assert adsterra["sri_missing"] is True
        assert origins["popads.net"]["category"] == "popunder"
        assert "cdn.jsdelivr.net" not in origins  # benign CDN filtered
        assert prof["counts"].get("risky_ad", 0) >= 2
        assert prof["monetization_score"] > 0

    def test_analyze_tls_ok_on_http_page(self):
        # A cleartext script on an http:// page is NOT a downgrade signal.
        prof = profiler.analyze(
            '<script src="http://adsterra.com/a.js"></script>', "http://example.com/"
        )
        origins = {r["host"]: r for r in prof["origins"]}
        assert origins["adsterra.com"]["cleartext"] is False

    def test_sri_present_ok(self):
        prof = profiler.analyze(
            '<script src="https://popads.net/a.js" integrity="sha384-x"></script>',
            "https://example.com/",
        )
        assert prof["origins"][0]["sri_missing"] is False

    def test_observed_intel_recording(self):
        obs = ObservedIntel()
        profiler.analyze(_ad_heavy_html(), "https://example.com/", observed=obs)
        d = obs.to_dict()
        assert "effectivecpmnetwork.com" in d
        assert d["adsterra.com"]["cleartext"] is True
        assert d["adsterra.com"]["sri_missing"] is True


class TestDetectors:
    def test_cloaks(self):
        sigs = detect_cloaks(_ad_heavy_html())
        oracles = {s["oracle"] for s in sigs}
        assert "cloak:keyboard-block" in oracles
        assert "cloak:debugger-loop" in oracles
        assert "cloak:devtools-size-detect" in oracles
        assert "cloak:context-menu-block" in oracles

    def test_clean_page_no_cloaks(self):
        assert detect_cloaks("<html><body>hi</body></html>") == []

    def test_miners(self):
        sigs = detect_miners('<script src="https://coinhive.com/lib/coinhive.min.js"></script>')
        assert any(s["oracle"] == "miner:host:coinhive.com" for s in sigs)
        sigs2 = detect_miners("var miner = new CoinHive.Anonymous('key'); miner.startMining();")
        assert any("miner:js-api" in s["oracle"] for s in sigs2)

    def test_push(self):
        sigs = detect_push_notif(_ad_heavy_html())
        oracles = {s["oracle"] for s in sigs}
        assert "push:service-worker" in oracles
        assert "push:request-permission" in oracles

    def test_clickbait_index(self):
        idx = clickbait_index(_ad_heavy_html())
        assert idx["score"] >= 25
        assert idx["grade"] in ("medium", "high")
        assert any("visitor" in s for s in idx["signals"])
        assert any("countdown" in m for m in idx["mechanics"])

    def test_classify_terminal(self):
        assert classify_terminal("https://x/free-setup.exe")["category"] == "fake_download"
        assert classify_terminal("https://x/account/verify-email")["category"] == "phishing"
        assert classify_terminal("https://x/")["category"] == "unknown"


class TestOffenseStatic:
    def test_cleartext_findings(self):
        prof = profiler.analyze(_ad_heavy_html(), "https://example.com/")
        finds = offense.cleartext_findings(prof, "https://example.com")
        assert finds
        assert all(f.attack_type == AttackType.AD_MITM_CLEARTEXT for f in finds)
        assert all(f.verified for f in finds)
        assert any("adsterra.com" in f.url for f in finds)

    def test_sri_findings(self):
        prof = profiler.analyze(_ad_heavy_html(), "https://example.com/")
        finds = offense.sri_findings(prof, "https://example.com")
        assert finds
        assert all(f.attack_type == AttackType.SRI_ABSENT for f in finds)

    def test_flux_findings(self):
        prof = profiler.analyze(_ad_heavy_html(), "https://example.com/")
        prior = {"effectivecpmnetwork.com": {}, "oldflux.shop": {}}
        finds = offense.flux_findings(prof, prior, "https://example.com")
        assert finds
        assert finds[0].attack_type == AttackType.AD_DOMAIN_FLUX
        assert "oldflux.shop" in finds[0].payload


class TestOffenseLive:
    async def _serve(self, app):
        runner = None
        try:
            runner = __import__("aiohttp").web.AppRunner(app)
            await runner.setup()
            site = __import__("aiohttp").web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            yield runner, site
        finally:
            if runner:
                await runner.cleanup()

    async def test_redirect_chain_maps_to_phishing(self):
        import aiohttp
        from aiohttp import web

        async def ad_land(request):
            return web.Response(status=302, headers={"Location": "/account/verify-payment"})

        async def phish(request):
            return web.Response(text="<html>Verify your account</html>")

        app = web.Application()
        app.router.add_get("/ad.js", ad_land)
        app.router.add_get("/account/verify-payment", phish)
        async for _runner, site in self._serve(app):
            port = site._server.sockets[0].getsockname()[1]
            prof = {
                "page_url": f"http://127.0.0.1:{port}/",
                "origins": [{
                    "host": "127.0.0.1", "category": "ad_network",
                    "urls": [f"http://127.0.0.1:{port}/ad.js"],
                }],
            }
            async with aiohttp.ClientSession() as session:
                finds = await offense.map_redirect_chains(
                    session, prof, f"http://127.0.0.1:{port}", block_private=False)
            assert finds
            assert finds[0].attack_type == AttackType.AD_PHISHING_CHAIN
            assert finds[0].verified

    async def test_private_hop_blocked_by_default(self):
        """The active probes must refuse hops into private/loopback space even
        when the chain would otherwise classify — the scanner never becomes a
        fetch oracle for the operator's own network."""
        import aiohttp
        from aiohttp import web

        async def land(request):
            return web.Response(status=302, headers={"Location": "/setup.exe"})

        app = web.Application()
        app.router.add_get("/a.js", land)
        app.router.add_get("/setup.exe", lambda r: web.Response(text="installer"))
        async for _runner, site in self._serve(app):
            port = site._server.sockets[0].getsockname()[1]
            prof = {
                "page_url": f"http://127.0.0.1:{port}/",
                "origins": [{
                    "host": "127.0.0.1", "category": "ad_network",
                    "urls": [f"http://127.0.0.1:{port}/a.js"],
                }],
            }
            async with aiohttp.ClientSession() as session:
                finds = await offense.map_redirect_chains(session, prof, f"http://127.0.0.1:{port}")
            # Loopback ad origin refused — the /setup.exe terminal exists and
            # would classify as fake_download, but the hop is never followed.
            assert finds == []

    async def test_referrer_gate_detected(self):
        import aiohttp
        from aiohttp import web

        async def gated(request):
            if request.headers.get("Referer") == "https://facebook.com/":
                return web.Response(text="<div>social offer</div>")
            return web.Response(text="<div>generic ad</div>")

        app = web.Application()
        app.router.add_get("/ads.js", gated)
        async for _runner, site in self._serve(app):
            port = site._server.sockets[0].getsockname()[1]
            prof = {
                "page_url": f"http://127.0.0.1:{port}/",
                "origins": [{
                    "host": "127.0.0.1", "category": "risky_ad",
                    "urls": [f"http://127.0.0.1:{port}/ads.js"],
                }],
            }
            async with aiohttp.ClientSession() as session:
                finds = await offense.probe_referrer_gate(
                    session, prof, f"http://127.0.0.1:{port}", block_private=False)
            assert finds
            assert finds[0].attack_type == AttackType.AD_REFERRER_GATE


class TestRunPass:
    async def test_read_only_pass(self):
        payload = await run_pass(
            [{"url": "https://example.com/", "html": _ad_heavy_html()}],
            "https://example.com/",
            target="https://example.com",
            session=None,
            consented=False,
        )
        prof = payload["profile"]
        assert prof["monetization_score"] > 0
        assert any(r["host"] == "effectivecpmnetwork.com" for r in prof["origins"])
        assert payload["observed"]
        assert payload["active_probes"] is False
        # Read-only pass still yields the deterministic findings.
        kinds = {f["attack_type"] for f in payload["findings"]}
        assert AttackType.AD_MITM_CLEARTEXT.value in kinds
        assert AttackType.HOSTILE_CLOAK.value in kinds
        assert AttackType.SRI_ABSENT.value in kinds

    async def test_active_probes_require_consent(self):
        import aiohttp
        from aiohttp import web

        async def land(request):
            return web.Response(status=302, headers={"Location": "/setup.exe"})

        app = web.Application()
        app.router.add_get("/a.js", land)
        app.router.add_get("/setup.exe", lambda r: web.Response(text="installer"))
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        try:
            port = site._server.sockets[0].getsockname()[1]
            # The page origin and the ad-script origin must differ or the
            # profiler filters the script as same-host. ``localhost`` vs
            # ``127.0.0.1`` keeps them distinct while resolving to the same
            # bound socket.
            page_url = f"http://127.0.0.1:{port}/"
            html = f'<script src="http://localhost:{port}/a.js"></script>'
            async with aiohttp.ClientSession() as session:
                off = await run_pass([{"url": page_url, "html": html}], page_url,
                                     target=page_url, session=session, consented=False,
                                     block_private=False)
                on = await run_pass([{"url": page_url, "html": html}], page_url,
                                    target=page_url, session=session, consented=True,
                                    block_private=False)
            off_kinds = {f["attack_type"] for f in off["findings"]}
            on_kinds = {f["attack_type"] for f in on["findings"]}
            # Without consent the redirect chain was NOT followed.
            assert AttackType.AD_PHISHING_CHAIN.value not in off_kinds
            assert AttackType.AD_PHISHING_CHAIN.value in on_kinds
        finally:
            await runner.cleanup()


class TestReporting:
    def test_writer_persists_hostile_artifacts(self, tmp_path):
        result = ScanResult(target="https://example.com", started_at=1.0, finished_at=2.0)
        result.hostile = {
            "profile": {
                "monetization_score": 42,
                "origins": [{
                    "host": "popads.net", "category": "popunder", "kinds": ["img"],
                    "count": 1, "cleartext": False, "sri_missing": False,
                    "urls": ["https://popads.net/pixel.png"], "risk_score": 20,
                }],
                "counts": {"popunder": 1},
                "clickbait": {"score": 30, "signals": ["click here"], "mechanics": [], "grade": "medium"},
                "cloaks": [], "miners": [], "push": [], "mechanics": [],
            },
            "observed": {"popads.net": {"host": "popads.net", "kinds": ["img"], "count": 1}},
            "findings": [],
            "consented": False,
            "active_probes": False,
        }
        from titan.reporting import SiteReportWriter
        site_dir = SiteReportWriter(str(tmp_path)).write(result)
        assert (site_dir / "hostile.json").exists()
        assert (site_dir / "intel.json").exists()
        report = (site_dir / "report.md").read_text(encoding="utf-8")
        assert "Monetization & Hostile Surface" in report
        assert "popads.net" in report
        meta = json.loads((site_dir / "scan_meta.json").read_text(encoding="utf-8"))
        assert meta["hostile"]["monetization_score"] == 42


class TestSupplyChainB4:
    """PUSH-TO-100 B4 — the read-only supply-chain surface runs in the
    DEFAULT scan, not hostile-profile-only."""

    def _page_with_supply_chain_issues(self) -> str:
        return """<!DOCTYPE html>
<html><head><title>Clean store</title>
<script src="https://effectivecpmnetwork.com/ads.js"></script>
<script src="http://tracker.example.net/pixel.js"></script>
</head><body><h1>Welcome</h1></body></html>
"""

    def test_supplychain_enabled_by_default_in_config(self):
        """A default config must run the read-only supply-chain pass (the
        gate defaults to on when crawl.supplychain is absent)."""
        from titan.core.engine import TitanEngine

        cfg = {
            "crawl": {"profile": "fast"},
            "modules": {}, "ai": {}, "stealth": {}, "auth": {},
            "proxy": {}, "exploit": {},
        }
        eng = TitanEngine(cfg)
        sc = eng.config.get("crawl", {}).get("supplychain", {})
        assert sc.get("enabled", True) is True

    def test_plain_page_sri_missing_is_a_supply_chain_finding(self):
        """A plain (non-hostile) page loading a CLASSIFIED third-party script
        WITHOUT SRI yields the supply-chain finding — the default scan must
        cover this surface, not only hostile profiles. (Unclassified origins
        correctly produce nothing — the adsbygoogle-on-a-clean-page FP
        lesson.)"""
        html = self._page_with_supply_chain_issues()
        prof = profiler.analyze(html, "https://clean.example.com/")
        finds = offense.sri_findings(prof, "https://clean.example.com/")
        assert finds, "a classified ad script without SRI must produce a finding"
        f = finds[0]
        assert f.attack_type == AttackType.SRI_ABSENT
        assert "effectivecpmnetwork.com" in f.payload

    def test_cleartext_load_on_https_is_supply_chain_finding(self):
        html = self._page_with_supply_chain_issues()
        prof = profiler.analyze(html, "https://clean.example.com/")
        finds = offense.cleartext_findings(prof, "https://clean.example.com/")
        assert finds
        assert any("tracker.example.net" in (f.payload or "") for f in finds)

    def test_run_pass_without_session_is_read_only(self):
        """run_pass with no aiohttp session and no consent must not fire
        active probes — the default-scan pass stays read-only."""
        page_url = "https://clean.example.com/"
        payload = asyncio.run(run_pass(
            [{"url": page_url, "html": self._page_with_supply_chain_issues()}],
            page_url,
        ))
        assert payload["active_probes"] is False
        assert payload["consented"] is False
        # read-only supply-chain findings still produced
        assert payload["findings"], "read-only pass must still yield SRI/cleartext findings"


class TestModel:
    def test_new_attack_types_exist(self):
        for name in ("HOSTILE_CLOAK", "CLICKBAIT", "MINER_SCRIPT",
                     "PUSH_NOTIFICATION_ABUSE", "AD_MITM_CLEARTEXT",
                     "AD_PHISHING_CHAIN", "AD_REFERRER_GATE", "SRI_ABSENT",
                     "AD_DOMAIN_FLUX"):
            assert hasattr(AttackType, name), name
