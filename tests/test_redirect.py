"""Track F — client-side redirect hijack tests.

The zairaku.rest shape: HTTP 200 with the hijack living in client-side JS /
meta tags — invisible to curl. These tests drive the RedirectDetector against
a scripted fake page (the client-side analogue of FakeLabContext): the fake
returns canned recorded-navigation state, and the assertions enforce the
oracle semantics — off-origin navigation is a hijack, same-origin navigation
is normal app routing, a clean page finds nothing, and a server redirect to
an off-origin host is caught too.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from titan.core.models import AttackType
from titan.exploit.consent import (
    ConsentError, FLAG_REDIRECT, create_consent, require_consent, write_consent,
)
from tests.test_clientside import FakePage, StubSmith


class _FakeDetector:
    """Stand-in payload_smith — the redirect detector never touches it."""

    def get_base_payloads(self, *a, **k):
        return []

    def get_waf_bypass_payloads(self, *a, **k):
        return []

    def detect_waf(self, *a, **k):
        return None

    async def mutate(self, *a, **k):
        return []


async def _scan(evaluate_results, page_url="http://localhost:5000/", target="http://localhost:5000/"):
    from titan.modules.redirect.detector import RedirectDetector
    page = FakePage(
        evaluate_results={"window.__titan_redirects__": evaluate_results},
        page_url=page_url,
    )
    return await RedirectDetector(_FakeDetector(), {}).scan(
        page, target, target, {},
    )


class TestRedirectDetector:
    async def test_js_redirect_off_origin_is_flagged(self):
        findings = await _scan({
            "redirects": [{
                "dest": "https://evil.example/phish",
                "mechanism": "location.replace",
                "trigger": "script",
                "source": "Error\n    at https://evil.example/inject.js:1:1",
                "timing": 120,
            }],
            "origin": "http://localhost:5000",
            "finalUrl": "http://localhost:5000/",
        })
        assert findings, "off-origin JS redirect must be flagged"
        f = findings[0]
        assert f.attack_type == AttackType.REDIRECT_HIJACK
        assert f.verified is False, "heuristic — never marked verified"
        assert f.metadata["mechanism"] == "location.replace"
        assert f.metadata["dest_host"] == "evil.example"
        assert f.metadata["timing_ms"] == 120
        assert "redirect:off-origin:evil.example" in f.diffs
        # Fires within 1.5s of load -> the worst kind -> HIGH.
        assert f.severity.value == "high"

    async def test_meta_refresh_on_load_is_flagged(self):
        findings = await _scan({
            "redirects": [{
                "dest": "https://evil.example/steal",
                "mechanism": "meta-refresh",
                "trigger": "parse",
                "source": '<meta http-equiv="refresh" content="0;url=https://evil.example/steal">',
                "timing": 5,
            }],
            "origin": "http://localhost:5000",
            "finalUrl": "http://localhost:5000/",
        })
        assert findings, "meta-refresh hijack must be flagged"
        f = findings[0]
        assert f.metadata["mechanism"] == "meta-refresh"
        assert f.severity.value == "high"

    async def test_same_origin_navigation_is_not_a_hijack(self):
        findings = await _scan({
            "redirects": [{
                "dest": "http://localhost:5000/dashboard",
                "mechanism": "location.assign",
                "trigger": "script",
                "source": "",
                "timing": 800,
            }],
            "origin": "http://localhost:5000",
            "finalUrl": "http://localhost:5000/",
        })
        assert findings == [], f"same-origin app routing must not be a hijack, got {findings}"

    async def test_clean_page_finds_nothing(self):
        findings = await _scan({
            "redirects": [],
            "origin": "http://localhost:5000",
            "finalUrl": "http://localhost:5000/",
        })
        assert findings == []

    async def test_server_redirect_to_off_origin_is_flagged(self):
        """Even without any JS redirect recorded, a final page URL on a
        different host than the request is a server-side hijack."""
        findings = await _scan({
            "redirects": [],
            "origin": "http://localhost:5000",
            "finalUrl": "https://evil.example/landed",
        })
        assert findings, "server redirect to an off-origin host must be flagged"
        assert findings[0].metadata["mechanism"] == "server-redirect"


class TestRedirectConsentGate:
    def test_redirect_flag_is_accepted_and_enforced(self, tmp_path):
        doc = create_consent("http://lab.local", flags=[FLAG_REDIRECT],
                             expiry="1h", key_path=tmp_path / "k.pem")
        write_consent(doc, consent_dir=tmp_path / "consent")
        # Granted -> passes.
        require_consent("http://lab.local/deep/path", need=FLAG_REDIRECT,
                        consent_dir=tmp_path / "consent", key_path=tmp_path / "k.pem")
        # Not granted -> refused.
        doc2 = create_consent("http://lab2.local", flags=["write"],
                              expiry="1h", key_path=tmp_path / "k.pem")
        write_consent(doc2, consent_dir=tmp_path / "consent")
        with pytest.raises(ConsentError, match="lacks flag"):
            require_consent("http://lab2.local", need=FLAG_REDIRECT,
                            consent_dir=tmp_path / "consent", key_path=tmp_path / "k.pem")


@pytest.fixture(scope="module")
def lab_client():
    from local_lab.app import app as lab_app
    lab_app.testing = True
    return lab_app.test_client()


class TestRedirectLab:
    """The CI-safe redirect lab: the endpoints' HTML proves the exact hijack
    shapes (meta refresh / location.replace), and the clean control stays
    same-origin. No external navigation happens in the Flask test client."""

    def test_meta_refresh_endpoint_serves_off_origin_hijack(self, lab_client):
        body = lab_client.get("/redirect-meta").data.decode("utf-8")
        assert 'http-equiv="refresh"' in body
        assert "https://evil.example/steal" in body

    def test_js_redirect_endpoint_serves_location_replace(self, lab_client):
        body = lab_client.get("/redirect-js").data.decode("utf-8")
        assert "location.replace" in body
        assert "https://evil.example/phish" in body

    def test_clean_control_stays_same_origin(self, lab_client):
        body = lab_client.get("/redirect-clean").data.decode("utf-8")
        assert "content=\"0;url=/\"" in body or "content='0;url=/'" in body
        assert "evil.example" not in body
