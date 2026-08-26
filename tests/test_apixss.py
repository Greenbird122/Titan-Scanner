"""Tests for the API-fed DOM-sink detector (git-vizor F6 harvest)."""
import asyncio
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest
from flask import Flask

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from titan.core.models import AttackType, Severity  # noqa: E402
from titan.modules.apixss.detector import ApiXssDetector  # noqa: E402

# The exact git-vizor F6 shape: a repo analyzer whose fetch() response
# (repo.description/name/language/html_url) flows into card.innerHTML.
ANALYZER_HTML = """<html><body>
<script src="/js/analyzer.js"></script>
</body></html>"""

ANALYZER_JS = """let allRepos = [];
async function syncRegistry() {
    const inputVal = targetInput.value.trim();
    currentTarget = inputVal;
    const response = await fetch(`https://api.github.com/users/${currentTarget}/repos`);
    const repos = await response.json();
    allRepos = repos;
    applyFiltersAndSort();
}
function applyFiltersAndSort() {
    let result = [...allRepos];
    let filteredRepos = result;
    filteredRepos.forEach(repo => {
        const card = document.createElement('div');
        card.innerHTML = `
            <span>${repo.name.toUpperCase()}</span>
            <p>${repo.description || "No docs."}</p>
            <span>LANG: ${repo.language || "DATA"}</span>
            <a href="${repo.html_url}">VIEW</a>`;
    });
}
"""

# A page whose only bundle is third-party (CDN) — out of scope.
CDN_ONLY = """<html><body>
<script src="https://cdn.jsdelivr.net/npm/thing@1/app.js"></script>
</body></html>"""

# Static-only scripts — must produce zero findings.
CLEAN = """<html><body>
<script>
const greeting = 'hello';
el.innerHTML = '<b>welcome</b>';
stats.innerHTML = '<option value="all">ALL</option>';
el.innerText = 'no taint';
</script>
</body></html>"""

# Param-fed sink: user input (location.hash) straight into innerHTML.
PARAM_FED = """<html><body>
<script>
const frag = location.hash.slice(1);
el.innerHTML = frag;
</script>
</body></html>"""

mini = Flask(__name__)


@mini.route("/analyzer")
def analyzer():
    return ANALYZER_HTML


@mini.route("/js/analyzer.js")
def analyzer_js():
    return ANALYZER_JS


@mini.route("/cdn")
def cdn():
    return CDN_ONLY


@mini.route("/clean")
def clean():
    return CLEAN


@mini.route("/param")
def param():
    return PARAM_FED


class FakeResponse:
    def __init__(self, status_code, data, headers, url):
        self.status_code = status_code
        self._data = data
        self._headers = headers
        self.url = url

    @property
    def status(self):
        return self.status_code

    @property
    def headers(self):
        return self._headers

    async def text(self):
        return self._data.decode("utf-8", "replace")


class FakeRequest:
    def __init__(self, client):
        self._client = client

    async def get(self, url, params=None, headers=None, timeout=3000, **kwargs):
        return await asyncio.to_thread(self._do, url, params, headers)

    def _do(self, url, params, headers):
        path = urlparse(url).path or "/"
        resp = self._client.get(path, query_string=params, headers=dict(headers or {}))
        return FakeResponse(resp.status_code, resp.data, dict(resp.headers), url)


class FakeLabContext:
    def __init__(self, client):
        self.request = FakeRequest(client)


def _ctx():
    mini.testing = True
    return FakeLabContext(mini.test_client())


def test_git_vizor_api_fed_sink_fires():
    """The F6 harvest: fetch() -> repo.description -> card.innerHTML."""
    ctx = _ctx()
    findings = asyncio.run(
        ApiXssDetector(None, {}).scan(ctx, "http://x", "GET", "http://x/analyzer", {})
    )
    api = [f for f in findings if f.metadata.get("source") == "api"]
    assert api, "expected an api-fed sink finding"
    f = api[0]
    assert f.attack_type == AttackType.DOM_XSS
    assert f.severity == Severity.HIGH
    # Honest evidence: static candidate — never verified by reflection alone.
    assert f.verified is False
    assert "innerHTML" in " ".join(f.diffs)
    assert f.metadata["sink"] == "innerHTML"
    assert f.metadata["bundle"].endswith("/js/analyzer.js")


def test_param_fed_sink_fires_medium():
    ctx = _ctx()
    findings = asyncio.run(
        ApiXssDetector(None, {}).scan(ctx, "http://x", "GET", "http://x/param", {})
    )
    assert any(f.metadata.get("source") == "param" for f in findings)
    f = [f for f in findings if f.metadata.get("source") == "param"][0]
    assert f.severity == Severity.HIGH  # user input into innerHTML is classic DOM XSS


def test_static_page_no_findings():
    ctx = _ctx()
    findings = asyncio.run(
        ApiXssDetector(None, {}).scan(ctx, "http://x", "GET", "http://x/clean", {})
    )
    assert findings == []


def test_third_party_bundle_not_fetched():
    """CDN-only bundles are out of scope — the fetcher must skip them."""
    ctx = _ctx()
    findings = asyncio.run(
        ApiXssDetector(None, {}).scan(ctx, "http://x", "GET", "http://x/cdn", {})
    )
    assert findings == []


def test_string_literals_do_not_collide_with_identifiers():
    """value=\"all\" inside a static string must not read as the identifier `value`."""
    det = ApiXssDetector(None, {})
    js = "el.innerHTML = '<option value=\"all\">ALL</option>';"
    assert det._analyze_chunk(js) == []


def test_numeric_fields_not_flagged():
    """${repos.length} / ${repo.id} are numeric — not a finding on their own."""
    det = ApiXssDetector(None, {})
    js = """
    const response = await fetch('/api');
    const repos = await response.json();
    card.innerHTML = `TOTAL: ${repos.length} FIRST: ${repos[0].id}`;
    """
    assert det._analyze_chunk(js) == []
