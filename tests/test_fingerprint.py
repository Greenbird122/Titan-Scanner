"""PUSH-TO-100 B2 — fingerprint grounded in real markers.

The old fingerprint did naive substring matching over a giant keyword table,
so every HTML page inherited a stack from ordinary English: "display" ->
Play Framework, "interest" -> REST API, "expression" -> Express, "value" ->
Vue. That poisoned the benchmark scorecard and WAF/posture logic. The fix:
strong framework markers (SPA manifests, framework globals, distinctive
attributes) are checked FIRST; the generic keyword table matches only on
WORD BOUNDARIES; hopelessly generic English words are denied entirely; and
accumulated lists are reset + deduped across analyze() calls.
"""

import asyncio

from titan.core.fingerprint import TechFingerprinter


async def _fp(headers=None, body="", url="http://example.com/"):
    tp = TechFingerprinter()
    return await tp.analyze(headers or {}, body, url)


# ---------------------------------------------------------------------------
# The observed bug: "Play Framework on every scan"
# ---------------------------------------------------------------------------

def test_display_word_does_not_yield_play_framework():
    """The literal bug: a page whose CSS/text contains 'display' must NOT be
    fingerprinted as Play Framework."""
    body = "<html><head><style>.x { display: block; }</style></head><body>display flex</body></html>"
    fp = asyncio.run(_fp(body=body))
    assert "Play Framework" not in fp["technologies"]
    assert "Play Framework" not in fp["frameworks"]


def test_interest_and_expression_do_not_yield_rest_or_express():
    body = "<p>interest rates and our express service, value for money</p>"
    fp = asyncio.run(_fp(body=body))
    assert "REST API" not in fp["technologies"]
    assert "Express" not in fp["technologies"]
    assert "Vue" not in fp["technologies"]


def test_clean_page_stays_clean():
    body = "<html><head><title>Home</title></head><body><h1>Welcome</h1></body></html>"
    fp = asyncio.run(_fp(body=body))
    # no generic English word may claim a framework
    for bad in ("Play Framework", "Express", "Vue", "React", "Spring",
                "Slim", "Unity", "Foundation"):
        assert bad not in fp["technologies"], bad


# ---------------------------------------------------------------------------
# Strong markers: known apps fingerprint correctly
# ---------------------------------------------------------------------------

def test_angular_app_fingerprints_angular_not_play():
    """A real Angular shell (the Juice Shop shape): ng-version + <app-root>.
    Must fingerprint as Angular — and NEVER as Play Framework even though the
    bundle text contains common English words."""
    body = (
        '<app-root _nghost-ng-c123 ng-version="17.1.0"></app-root>'
        "<script src='runtime.js'></script><script src='polyfills.js'></script>"
        "<p>Display your profile. Express delivery options.</p>"
    )
    fp = asyncio.run(_fp(body=body))
    assert "Angular" in fp["frameworks"]
    assert "Play Framework" not in fp["technologies"]


def test_react_app_fingerprints_react():
    body = '<div id="root" data-reactroot=""><h1>React</h1></div>'
    fp = asyncio.run(_fp(body=body))
    assert "React" in fp["frameworks"]


def test_nextjs_fingerprints_nextjs():
    body = '<script id="__NEXT_DATA__" type="application/json">{}</script>'
    fp = asyncio.run(_fp(body=body))
    assert "Next.js" in fp["frameworks"]


def test_vue_app_fingerprints_vue():
    body = '<div data-v-7ba5bd90 class="app"></div><script src="app.js"></script>'
    fp = asyncio.run(_fp(body=body))
    assert "Vue" in fp["frameworks"]


def test_express_fingerprinted_by_header():
    fp = asyncio.run(_fp(headers={"x-powered-by": "Express"}, body="<html></html>"))
    assert "Express" in fp["technologies"]


# ---------------------------------------------------------------------------
# Word-boundary + denylist discipline
# ---------------------------------------------------------------------------

def test_word_boundary_still_detects_real_markers():
    """Word-boundary matching must not kill genuine signals: 'django' stands
    alone as a real framework word, 'php' stands alone as a real language."""
    body = "<meta name='generator' content='django'>php 8"
    fp = asyncio.run(_fp(body=body))
    assert "Django" in fp["frameworks"]
    assert "PHP" in fp["technologies"]


def test_frameworks_deduped_across_sources():
    """A page with Django in body AND a Django CSRF cookie names it twice;
    the list must read clean."""
    body = "<form>django</form>"
    fp = asyncio.run(_fp(
        headers={"set-cookie": "csrftoken=abc; Path=/"},
        body=body,
    ))
    assert fp["technologies"].count("Django") == 1


def test_analyze_resets_between_calls():
    """The fingerprinter instance is reused across scans; a second analyze()
    must not carry the first page's technologies."""
    tp = TechFingerprinter()
    async def run():
        await tp.analyze({}, "<p>django</p>", "http://a.com/")
        assert "Django" in tp.fingerprint["technologies"]
        await tp.analyze({}, "<p>clean page</p>", "http://b.com/")
        assert "Django" not in tp.fingerprint["technologies"]
    asyncio.run(run())


# ---------------------------------------------------------------------------
# URL detection
# ---------------------------------------------------------------------------

def test_url_restaurant_not_rest_api():
    """A URL containing 'rest' as part of a domain/path word must not be an
    API type claim ('restaurant' is not a REST API)."""
    fp = asyncio.run(_fp(url="http://restaurant.example.com/menu"))
    assert "REST API" not in fp["api_types"]


def test_url_graphql_still_detected():
    fp = asyncio.run(_fp(url="https://api.example.com/graphql"))
    assert "GraphQL" in fp["api_types"]
