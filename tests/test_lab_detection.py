"""Integration tests: run the real detectors against the real local lab.

Boots local_lab/app.py through Flask's test client wrapped in a fake
playwright-style async context, then asserts the detectors actually find
the vulnerabilities the lab was built to contain.
"""

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from local_lab.app import app as lab_app

from titan.ai.payloadforge import PayloadForge
from titan.core.models import AttackType
from titan.modules.idor.detector import IDORDetector
from titan.modules.lfi.detector import LFIDetector
from titan.modules.rce.detector import RCEDetector
from titan.modules.sqli.detector import SQLiDetector


class StubSmith:
    """Minimal payload_smith stand-in: real payloads, no AI, no network."""

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


class FakeResponse:
    def __init__(self, status_code, body_bytes, headers, url):
        self.status_code = status_code
        self._body = body_bytes
        # Normalise to lowercase keys (matching Playwright's behaviour).
        self._headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.url = url

    @property
    def status(self):
        return self.status_code

    @property
    def headers(self):
        return self._headers

    async def text(self):
        return self._body.decode("utf-8", "replace")


class FakeRequest:
    def __init__(self, client):
        self._client = client

    async def get(self, url, params=None, headers=None, timeout=3000, **kwargs):
        return await asyncio.to_thread(self._do, "GET", url, params, None, headers)

    async def post(self, url, data=None, json=None, headers=None, timeout=3000, **kwargs):
        return await asyncio.to_thread(self._do, "POST", url, None, data, headers)

    def _do(self, method, url, params, data, headers):
        parsed = urlparse(url)
        path = parsed.path or "/"
        hdrs = {k: v for k, v in (headers or {}).items()}
        if method == "GET":
            resp = self._client.get(path, query_string=params, headers=hdrs)
        else:
            resp = self._client.post(path, data=data or {}, headers=hdrs)
        return FakeResponse(resp.status_code, resp.data, dict(resp.headers), url)


class FakeLabContext:
    def __init__(self, client):
        self.request = FakeRequest(client)


@pytest.fixture(scope="module")
def client():
    lab_app.testing = True
    return lab_app.test_client()


@pytest.fixture()
def context(client):
    return FakeLabContext(client)


def _fast_blind(detector):
    """Disable real timing waits for fast, deterministic tests."""
    async def _no_blind(*args, **kwargs):
        return False, 0.0
    detector.blind_detector.detect_time_based = _no_blind
    return detector


class TestLabSQLi:
    async def test_finds_boolean_sqli(self, context):
        detector = _fast_blind(SQLiDetector(StubSmith(), {}))
        findings = await detector.scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/sqli", {"id": "1"},
        )
        assert findings, "SQLi detector should find the lab's /sqli endpoint"
        f = findings[0]
        assert f.attack_type == AttackType.SQLI
        assert f.verified is True, f"expected verified boolean-based SQLi, got diffs={f.diffs}"
        assert f.confidence >= 0.7


class TestLabIDOR:
    async def test_finds_structural_idor(self, context):
        detector = IDORDetector(StubSmith(), {})
        findings = await detector.scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/api/user", {"id": "1"},
        )
        assert findings, "IDOR detector should find /api/user?id=1 -> id=2"
        f = findings[0]
        assert f.attack_type == AttackType.IDOR
        assert f.verified is True, f"expected verified structural IDOR, got diffs={f.diffs}"
        assert f.confidence >= 0.7


class TestLabLFI:
    async def test_finds_lfi_via_error_class(self, context):
        detector = LFIDetector(StubSmith(), {})
        # The lab resolves ``file`` relative to its own directory (so the
        # advertised baseline ``file=app.py`` works from any cwd); passing
        # ``local_lab/app.py`` would double the prefix and error.
        findings = await detector.scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/lfi", {"file": "app.py"},
        )
        assert findings, "LFI detector should find the lab's /lfi endpoint"
        f = findings[0]
        assert f.attack_type == AttackType.LFI
        assert f.verified is True, f"expected verified LFI (errno/error-class), got diffs={f.diffs}"
        assert f.confidence >= 0.7


class TestLabRCE:
    def test_delay_payloads_carry_both_os_flavours(self):
        """Cross-platform pin: the blind timing payload set must include BOTH
        Windows (`ping -n 3`) and POSIX (`ping -c 3`) delay probes. A
        Windows-only set made time-based RCE verification near-useless on
        Linux/macOS targets (e.g. the Docker lab, whose /cmd runs GNU ping)."""
        delays = RCEDetector.DELAY_PAYLOADS
        assert any("ping -n 3" in p for p in delays), "Windows ping variant missing"
        assert any("ping -c 3" in p for p in delays), "POSIX ping variant missing"
        assert any("sleep 4" in p for p in delays), "portable sleep variant missing"
        # The engine cap must never trim the delay payloads: they are appended
        # AFTER the [:8] output-probe cap, so a WAF-heavy base can't starve
        # the blind evidence path.
        assert len([p for p in delays]) >= 5

    async def test_no_false_positive_on_blind_pong(self, context):
        # The lab's /cmd never reflects command output — the detector must
        # NOT invent an RCE finding from an unchanged {"status": "pong"} body.
        detector = _fast_blind(RCEDetector(StubSmith(), {}))
        findings = await detector.scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/cmd", {"host": "localhost"},
        )
        assert findings == [], f"blind non-reflective endpoint must not false-positive, got {findings}"

    @pytest.mark.skipif(sys.platform != "win32", reason="real timing path pins the Windows lab delay (ping -n); CI runs Linux")
    async def test_blind_timing_confirms_cmd(self, context):
        """Regression: /cmd delays ~2.4s on `| ping -n 3` but the historical
        `cookies=` TypeError made detect_time_based swallow the exception and
        return elapsed=0.0 — killing the timing oracle entirely. Run the REAL
        timing path (no _fast_blind) and require the delay to be measured and
        confirmed. Windows-only: the lab's delay comes from Windows ping
        syntax, so on Linux the oracle would measure no delay and this test
        (and CI) would burn the module's full timing budget."""
        detector = RCEDetector(StubSmith(), {})  # real BlindDetector, real timing
        findings = await detector.scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/cmd", {"host": "localhost"},
        )
        assert findings, "timing oracle should confirm blind RCE on /cmd"
        f = findings[0]
        assert f.verified is True, f"expected verified time-based RCE, got diffs={f.diffs}"
        delays = [d for d in f.diffs if d.startswith("time_delay:")]
        assert delays, f"expected time_delay evidence, got diffs={f.diffs}"
        # The lab delays ~2.4s per injected sample; a measured delay proves the
        # timing path actually ran (the bug returned 0.0).
        measured = float(delays[0].split(":")[1].rstrip("s"))
        assert measured > 1.0, f"timing oracle measured {measured}s — expected the real ~2.4s delay"


class TestLabXSS:
    async def test_finds_reflected_xss(self, context):
        from titan.modules.xss.detector import XSSDetector
        detector = XSSDetector(StubSmith(), {})
        findings = await detector.scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/xss", {"name": "test"},
        )
        assert findings, "XSS detector should find the lab's /xss endpoint"
        f = findings[0]
        assert f.attack_type == AttackType.XSS
        assert f.confidence >= 0.5


class TestIDORNoEchoFalsePositive:
    """Regression: /sqli?id=1 -> id=2 changes only the echoed "query" field.
    That is input reflection, NOT a different record — must not be flagged IDOR."""

    async def test_does_not_flag_input_echo(self, context):
        detector = IDORDetector(StubSmith(), {})
        findings = await detector.scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/sqli", {"id": "1"},
        )
        assert findings == [], f"echo-only change must not be IDOR, got {findings}"


class TestIDORBaselineFailure:
    """Regression: if the baseline request fails but the test request succeeds,
    the detector must stay silent instead of comparing against an empty string
    and false-positiving on every sensitive-looking word in the test body."""

    class BrokenBaselineContext:
        class _Request:
            def __init__(self):
                self._calls = 0

            async def get(self, url, params=None, headers=None, timeout=3000, **kwargs):
                self._calls += 1
                if self._calls == 1:
                    raise RuntimeError("baseline connection failed")
                body = b'{"name": "User", "email": "victim@example.com", "ssn": "000-00-0000"}'
                return FakeResponse(200, body, {}, url)

        def __init__(self):
            self.request = self._Request()

    async def test_silent_when_baseline_fails(self):
        detector = IDORDetector(StubSmith(), {})
        findings = await detector.scan(
            self.BrokenBaselineContext(), "http://localhost:5000", "GET",
            "http://localhost:5000/api/user", {"id": "1"},
        )
        assert findings == [], "must not flag IDOR when the baseline is missing"
