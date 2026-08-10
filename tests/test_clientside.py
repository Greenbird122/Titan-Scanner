"""Track A — client-side browser security tests.

Each detector's oracle lives inside a real browser: JS sink reports,
postMessage handler behaviour, prototype-chain inheritance, external-script
enumeration, CSP policy text. These tests drive the real detectors against a
scripted FAKE page (the client-side analogue of FakeLabContext): the fake
page records which hooks were installed and returns canned JS state that
either contains the attacker marker or not, exactly as a vulnerable or a
clean page would behave.

Assertions enforce the oracle semantics: a finding only fires when the
marker reached a dangerous sink / a handler ran without an origin check /
a fresh object inherited the probe / the CSP text is weak. A marker that
stays inert, or a validating handler, or a strong CSP, never fires.
"""

import asyncio
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from titan.core.models import AttackType
from titan.ai.payloadforge import PayloadForge


class StubSmith:
    def __init__(self):
        self.forge = PayloadForge()

    def get_base_payloads(self, attack_type, context):
        return self.forge.get_context_payloads(attack_type, context)

    def get_waf_bypass_payloads(self, base_payloads, waf):
        return base_payloads

    def detect_waf(self, headers, body, status):
        return None

    async def mutate(self, base_payloads, context):
        return []


class FakePage:
    """A scripted Playwright page double.

    ``evaluate_results`` maps JS substrings to canned results (the fake's
    \"DOM state\"). ``page_url`` is what ``page.url`` returns after goto.
    ``navigated`` records the URLs passed to goto so tests can assert the
    marker was actually injected.
    """

    def __init__(self, evaluate_results=None, page_url="http://localhost:5000/", headers=None):
        self.evaluate_results = evaluate_results or {}
        self.page_url = page_url
        self.headers = headers or {}
        self.navigated = []
        self.hooks_installed = []
        self._requests = []
        # Playwright's page.request is a synchronous attribute whose .get()/
        # .post() are async — mirror that shape.
        self.request = SimpleNamespace(get=self._get)

    async def _get(self, url, **kwargs):
        self._requests.append(url)
        return SimpleNamespace(status=200, headers=self.headers)

    async def add_init_script(self, script):
        self.hooks_installed.append(script)

    async def goto(self, url, **kwargs):
        self.navigated.append(url)
        self.page_url = url
        return SimpleNamespace(status=200)

    async def wait_for_load_state(self, *a, **k):
        return None

    async def wait_for_timeout(self, *a, **k):
        return None

    async def evaluate(self, js, *args):
        # Route: match by distinctive marker substring in the JS.
        for key, value in self.evaluate_results.items():
            if key in js:
                return value
        return None

    @property
    def url(self):
        return self.page_url


class SimpleNamespace:
    def __init__(self, **kw):
        self.__dict__.update(kw)


# ─── DOM XSS ────────────────────────────────────────────────────────────────


class TestDomXSS:
    async def test_marker_reaching_innerhtml_is_verified(self):
        from titan.modules.clientside.domxss.detector import DomXSSDetector
        # The page reads ?q= into innerHTML (a vulnerable app). The marker
        # is passed explicitly so the fake page's canned DOM state matches.
        page = FakePage(
            evaluate_results={"window.__titan_sinks__": [
                {"sink": "innerHTML", "value": "<img src=x onerror=alert('titanmxdeadbeef')>"},
            ]},
        )
        findings = await DomXSSDetector(StubSmith(), {}).scan(
            page, "http://localhost:5000", "http://localhost:5000/page", {"q": "test"}, marker="titanmxdeadbeef")
        assert findings, "marker reaching innerHTML must be found"
        f = findings[0]
        assert f.attack_type == AttackType.DOM_XSS
        assert f.verified is True, f"expected verified DOM XSS, got diffs={f.diffs}"
        assert f.severity.value == "critical"

    async def test_site_own_content_in_sink_is_not_domxss(self):
        """A sink write containing the SITE's own content (no marker) is not
        attacker-controlled — must not fire."""
        from titan.modules.clientside.domxss.detector import DomXSSDetector
        page = FakePage(
            evaluate_results={"window.__titan_sinks__": [
                {"sink": "innerHTML", "value": "<p>legitimate page content</p>"},
            ]},
        )
        findings = await DomXSSDetector(StubSmith(), {}).scan(page, "http://localhost:5000", "http://localhost:5000/page", {"q": "test"})
        assert findings == [], f"site content in sink must not be DOM XSS, got {findings}"

    async def test_no_sinks_is_not_domxss(self):
        from titan.modules.clientside.domxss.detector import DomXSSDetector
        page = FakePage(evaluate_results={"window.__titan_sinks__": []})
        findings = await DomXSSDetector(StubSmith(), {}).scan(page, "http://localhost:5000", "http://localhost:5000/page", {"q": "test"})
        assert findings == [], f"no sink hits must not be DOM XSS, got {findings}"

    async def test_non_dangerous_sink_is_not_domxss(self):
        """A marker landing in a SAFE sink (textContent) proves nothing."""
        from titan.modules.clientside.domxss.detector import DomXSSDetector
        page = FakePage(
            evaluate_results={"window.__titan_sinks__": [
                {"sink": "textContent", "value": "titanmxdeadbeef"},
            ]},
        )
        findings = await DomXSSDetector(StubSmith(), {}).scan(page, "http://localhost:5000", "http://localhost:5000/page", {"q": "test"})
        assert findings == [], f"marker in safe sink must not be DOM XSS, got {findings}"


# ─── postMessage ─────────────────────────────────────────────────────────────


class TestPostMessage:
    async def test_unvalidated_handler_with_attacker_message_is_verified(self):
        from titan.modules.clientside.postmessage.detector import PostMessageDetector
        page = FakePage(
            evaluate_results={
                "window.__titan_messages__": {
                    "handlers": [{"checksOrigin": False, "source": "function(e){ location.href = e.data; }"}],
                    "received": [{"origin": "https://attacker-controlled.example", "data": "titanmsgprobe"}],
                },
            },
        )
        findings = await PostMessageDetector(StubSmith(), {}).scan(page, "http://localhost:5000", "http://localhost:5000/page", {})
        assert findings, "unvalidated handler receiving attacker message must be found"
        f = findings[0]
        assert f.attack_type == AttackType.POSTMESSAGE
        assert f.verified is True, f"expected verified postMessage flaw, got diffs={f.diffs}"

    async def test_origin_validating_handler_is_not_found(self):
        """Handler compares event.origin against an allowlist — the flaw is
        absent (this is the secure pattern)."""
        from titan.modules.clientside.postmessage.detector import PostMessageDetector
        page = FakePage(
            evaluate_results={
                "window.__titan_messages__": {
                    "handlers": [{"checksOrigin": True, "source": "function(e){ if (e.origin !== 'https://trusted.com') return; ... }"}],
                    "received": [{"origin": "https://attacker-controlled.example", "data": "titanmsgprobe"}],
                },
            },
        )
        findings = await PostMessageDetector(StubSmith(), {}).scan(page, "http://localhost:5000", "http://localhost:5000/page", {})
        assert findings == [], f"origin-validating handler must not be flagged, got {findings}"

    async def test_no_handlers_is_not_found(self):
        from titan.modules.clientside.postmessage.detector import PostMessageDetector
        page = FakePage(
            evaluate_results={"window.__titan_messages__": {"handlers": [], "received": []}},
        )
        findings = await PostMessageDetector(StubSmith(), {}).scan(page, "http://localhost:5000", "http://localhost:5000/page", {})
        assert findings == [], f"no handlers must not be flagged, got {findings}"

    async def test_hook_own_capture_listener_is_not_an_app_handler(self):
        """The hook's own capture plumbing (source referencing
        __titan_messages__) must never be treated as an app handler — a page
        with NO app message handlers at all must produce no finding, even
        though the probe is always received by the hook's own listener.
        This pins the systematic self-FP regression."""
        from titan.modules.clientside.postmessage.detector import PostMessageDetector
        page = FakePage(
            evaluate_results={
                "window.__titan_messages__": {
                    "handlers": [{"checksOrigin": False, "source": "(ev) => { window.__titan_messages__.received.push({origin: ev.origin}); }"}],
                    "received": [{"origin": "https://attacker-controlled.example", "data": "titanmsgprobe"}],
                },
            },
        )
        findings = await PostMessageDetector(StubSmith(), {}).scan(page, "http://localhost:5000", "http://localhost:5000/page", {})
        assert findings == [], f"hook's own capture listener must not be flagged, got {findings}"

    async def test_unvalidated_handler_without_received_message_is_not_found(self):
        """An unvalidated handler alone is NOT the flaw — the probe must
        actually have been received (the handler ran for the attacker
        origin). A handler that never executed for our origin proves
        nothing."""
        from titan.modules.clientside.postmessage.detector import PostMessageDetector
        page = FakePage(
            evaluate_results={
                "window.__titan_messages__": {
                    "handlers": [{"checksOrigin": False, "source": "function(e){ location.href = e.data; }"}],
                    "received": [],
                },
            },
        )
        findings = await PostMessageDetector(StubSmith(), {}).scan(page, "http://localhost:5000", "http://localhost:5000/page", {})
        assert findings == [], f"handler that never ran for the attacker origin must not be flagged, got {findings}"


# ─── Prototype pollution ─────────────────────────────────────────────────────


class TestPrototypePollution:
    async def test_marker_inherited_by_fresh_object_is_verified(self):
        from titan.modules.clientside.prototype.detector import PrototypePollutionDetector
        # A vulnerable app merges the query __proto__[marker] into a deep
        # object, so a fresh {} inherits the marker.
        page = FakePage(evaluate_results={"fresh[marker]": "polluted_titanppdeadbeef"})
        findings = await PrototypePollutionDetector(StubSmith(), {}).scan(page, "http://localhost:5000", "http://localhost:5000/page", {"q": "test"})
        assert findings, "marker inherited by fresh object must be found"
        f = findings[0]
        assert f.attack_type == AttackType.PROTO_POLLUTION
        assert f.verified is True, f"expected verified prototype pollution, got diffs={f.diffs}"

    async def test_clean_page_is_not_polluted(self):
        from titan.modules.clientside.prototype.detector import PrototypePollutionDetector
        # A sanitizing app never merges __proto__ — fresh objects stay clean.
        page = FakePage(evaluate_results={"fresh[marker]": None})
        findings = await PrototypePollutionDetector(StubSmith(), {}).scan(page, "http://localhost:5000", "http://localhost:5000/page", {"q": "test"})
        assert findings == [], f"clean page must not be polluted, got {findings}"


# ─── Third-party / skimmer heuristic ─────────────────────────────────────────


class TestThirdParty:
    async def test_external_script_with_sensitive_inputs_is_flagged(self):
        from titan.modules.clientside.thirdparty.detector import ThirdPartyDetector, KNOWN_GOOD_ORIGINS
        page = FakePage(
            evaluate_results={"document.querySelectorAll('script[src]')": {
                "scripts": [{"src": "https://skimmer-evil.example/analytics.js"}],
                "sensitive_inputs": ["cardnumber", "cvv"],
                "origin": "https://shop.example",
            }},
        )
        findings = await ThirdPartyDetector(StubSmith(), {}).scan(page, "http://localhost:5000", "http://localhost:5000/", {})
        assert findings, "external script + sensitive inputs must be flagged"
        f = findings[0]
        assert f.attack_type == AttackType.SKIMMER
        assert f.verified is False, "skimmer is a heuristic — never marked verified"

    async def test_known_good_cdn_alone_is_not_flagged(self):
        from titan.modules.clientside.thirdparty.detector import ThirdPartyDetector
        page = FakePage(
            evaluate_results={"document.querySelectorAll('script[src]')": {
                "scripts": [{"src": "https://cdn.jsdelivr.net/npm/lib/dist.js"}],
                "sensitive_inputs": [],
                "origin": "https://shop.example",
            }},
        )
        findings = await ThirdPartyDetector(StubSmith(), {}).scan(page, "http://localhost:5000", "http://localhost:5000/", {})
        assert findings == [], f"known-good CDN without sensitive inputs must not be flagged, got {findings}"

    def test_score_threshold(self):
        from titan.modules.clientside.thirdparty.detector import ThirdPartyDetector
        # Same-origin script: score must be low.
        score, reasons = ThirdPartyDetector._score_script("https://shop.example/app.js", "https://shop.example", [])
        assert score < 2, f"same-origin script must not reach threshold, score={score} reasons={reasons}"
        # External + sensitive inputs + unlisted: score >= 2.
        score2, reasons2 = ThirdPartyDetector._score_script("https://evil.example/x.js", "https://shop.example", ["cardnumber"])
        assert score2 >= 2, f"external + sensitive inputs must reach threshold, score={score2} reasons={reasons2}"


# ─── CSP audit ───────────────────────────────────────────────────────────────


class TestCSP:
    async def test_missing_csp_is_found(self):
        from titan.modules.clientside.csp.detector import CSPDetector
        page = FakePage(evaluate_results={"meta[http-equiv": ""})
        findings = await CSPDetector(StubSmith(), {}).scan(page, "http://localhost:5000", "http://localhost:5000/", {})
        assert findings, "missing CSP must be found"
        assert any("csp:missing" in f.diffs for f in findings)

    async def test_unsafe_inline_script_src_is_high(self):
        from titan.modules.clientside.csp.detector import CSPDetector
        policy = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com"
        page = FakePage(
            evaluate_results={"meta[http-equiv": ""},
            headers={"content-security-policy": policy},
        )
        findings = await CSPDetector(StubSmith(), {}).scan(page, "http://localhost:5000", "http://localhost:5000/", {})
        highs = [f for f in findings if f.attack_type == AttackType.CSP_WEAKNESS and f.severity.value == "high"]
        assert highs, f"unsafe-inline in script-src must be a HIGH CSP finding, got {findings}"

    async def test_strong_csp_is_not_high(self):
        from titan.modules.clientside.csp.detector import CSPDetector
        policy = ("default-src 'none'; script-src 'self'; style-src 'self'; "
                  "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
                  "frame-ancestors 'none'")
        page = FakePage(
            evaluate_results={"meta[http-equiv": ""},
            headers={"content-security-policy": policy},
        )
        findings = await CSPDetector(StubSmith(), {}).scan(page, "http://localhost:5000", "http://localhost:5000/", {})
        highs = [f for f in findings if f.severity.value == "high"]
        assert highs == [], f"strong CSP must not produce HIGH findings, got {findings}"

    def test_parse_directives(self):
        from titan.modules.clientside.csp.detector import CSPDetector
        d = CSPDetector._parse_directives("default-src 'self'; script-src 'self' 'unsafe-inline'")
        assert d["default-src"] == ["'self'"]
        assert d["script-src"] == ["'self'", "'unsafe-inline'"]


# ─── Engine wiring ───────────────────────────────────────────────────────────


class TestClientsideEngineWiring:
    async def test_browser_matrix_runs_through_engine(self):
        from titan.core.engine import TitanEngine
        cfg = {"governance": {"enabled": False}, "ai": {"enabled": False},
               "clientside": {"enabled": True}}
        engine = TitanEngine(cfg)

        class FakeContext:
            async def new_page(self):
                return FakePage(
                    evaluate_results={
                        "window.__titan_sinks__": [{"sink": "innerHTML", "value": "<img src=x onerror=alert('titanmxdeadbeef')>"}],
                        "window.__titan_messages__": {"handlers": [], "received": []},
                        "fresh[marker]": None,
                        "scripts.length": {"scripts": [], "sensitive_inputs": [], "origin": "http://localhost:5000"},
                        "meta[http-equiv": "",
                    },
                )

        engine.visited = {"http://localhost:5000/page?q=test"}
        # Pin the per-scan marker so the fake page's canned sink data matches.
        engine._client_marker = "titanmxdeadbeef"

        from titan.core.models import ScanResult
        result = ScanResult(target="http://localhost:5000", started_at=0)
        await engine._run_browser_modules(FakeContext(), None, "http://localhost:5000", {}, result)
        domxss = [f for f in result.findings if f.attack_type == AttackType.DOM_XSS]
        assert domxss, f"DOM XSS must fire through the engine browser seam, got {result.findings}"

    async def test_browser_seam_skips_when_driver_dead(self):
        from titan.core.engine import TitanEngine
        from titan.core.models import ScanResult
        cfg = {"governance": {"enabled": False}, "ai": {"enabled": False}}
        engine = TitanEngine(cfg)
        engine._driver_dead = True

        class BoomContext:
            async def new_page(self):
                raise AssertionError("must not open a page when driver is dead")

        result = ScanResult(target="t", started_at=0)
        await engine._run_browser_modules(BoomContext(), None, "http://localhost:5000", {}, result)
        assert result.findings == []
