"""Evidence-scoring oracle tests for the five upgraded detectors.

Each test runs the real detector against a deterministic mini Flask app (one
route per vulnerability class) through a fake playwright-style async context.
The assertions verify the *oracle semantics*: findings only fire on typed
evidence (content leak, parser error, boolean/math differential), never on
mere body diffs or echoed payloads.
"""

import asyncio
import json
import sys
from pathlib import Path
from urllib.parse import quote, quote_plus, urlparse

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flask import Flask, Response, request

from titan.ai.payloadforge import PayloadForge
from titan.core.models import AttackType


# ─── Mini vulnerable lab (deterministic, offline) ────────────────────────────

mini = Flask(__name__)

PASSWD_SNIPPET = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"


@mini.route("/ssrf")
def ssrf():
    url = request.args.get("url", "")
    if "169.254" in url:
        # Simulates a fetched cloud metadata document.
        return "ami-id: ami-12345678\ninstance-type: t2.micro\nmeta-data: present"
    if url:
        return f"ok fetched {url}"
    return "ok"


@mini.route("/ssrf_echo")
def ssrf_echo():
    # Benign: reflects the url parameter verbatim, no server-side fetch.
    return f"Echo: {request.args.get('url', '')}"


@mini.route("/ssrf_encoded_echo")
def ssrf_encoded_echo():
    # GitHub-branded-404 shape: reflects the RAW (still URL-encoded) query
    # string inside an HTML page. An SSRF probe sent as url=... comes back as
    # url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F, so a raw-only
    # payload strip leaves "169.254"/"meta-data" alive inside the echo and
    # self-verifies a content leak (the github.com DVIA storm).
    raw = request.query_string.decode("utf-8", "replace")
    # Fully encode like a real browser request line / Playwright params: a
    # server that reflects the requested URL back (GitHub's 404 title) shows
    # url=http%3A%2F%2F169.254.169.254%2F... — NOT the raw form.
    return f"<html><title>Page not found</title>404 - {quote(raw, safe='')} was not found</html>"


@mini.route("/ssrf_double_encoded_echo")
def ssrf_double_encoded_echo():
    # GitHub SPA-JS-state shape: the request URL (with its already-encoded
    # query string) is embedded into the page's JS state, which re-encodes it
    # once more — each % becomes %25, so a probe of url=http%3A%2F%2F169.254...
    # comes back as ...%253A%252F%252F169.254... A single-level payload strip
    # leaves the markers alive inside this nested echo (the github.com DVIA
    # CRITICAL SSRF findings).
    raw = request.query_string.decode("utf-8", "replace")
    encoded = quote(quote(raw, safe=""), safe="")
    return f"<html><body><script>window.__STATE__={{path:'{encoded}'}}</script></body></html>"


@mini.route("/xxe")
def xxe():
    data = request.args.get("data", "")
    if "<!DOCTYPE" in data and "file:///etc/passwd" in data:
        # Vulnerable parser: expands the external entity.
        return PASSWD_SNIPPET
    if "<!DOCTYPE" in data:
        # Parser chokes on the entity declaration.
        return "XML parser error: not well-formed", 500
    return "<foo>ok</foo>"


@mini.route("/xxe_parser")
def xxe_parser():
    # Vulnerable parser: chokes on ANY external-entity declaration.
    data = request.args.get("data", "")
    if "<!DOCTYPE" in data:
        return "XML parser error: not well-formed", 500
    return "<foo>ok</foo>"


@mini.route("/xxe_echo")
def xxe_echo():
    # Benign: echoes the XML payload without parsing it.
    return f"received: {request.args.get('data', '')}"


USERS = {
    "1": {"name": "Admin", "role": "admin"},
    "2": {"name": "User", "role": "user"},
}


@mini.route("/nosqli")
def nosqli():
    user_id = request.args.get("id", "1")
    try:
        parsed = json.loads(user_id)
    except Exception:
        parsed = user_id
    if isinstance(parsed, dict):
        if "$ne" in parsed:
            return json.dumps(list(USERS.values()))  # operator bypass: all records
        if "$eq" in parsed:
            return "[]"  # logical opposite: no records match
        return json.dumps(parsed)
    return json.dumps(USERS.get(str(parsed), {}))


@mini.route("/ssti")
def ssti():
    name = request.args.get("name", "World")
    if "777*777" in name:
        return "Result: 603729"  # distinctive eval answer
    if "7*'7'" in name:
        return "Result: 7777777"  # Jinja2 string multiplication
    if "7*7" in name:
        return "Result: 49"  # canonical eval answer
    return f"Hello {name}"


@mini.route("/ssti_counter")
def ssti_counter():
    # Benign page that happens to contain "49" in the baseline itself.
    return f"49 items for {request.args.get('name', 'World')}"


@mini.route("/ssti_603729")
def ssti_603729():
    # Evaluates ONLY the distinctive probe, so the 603729 oracle is exercised.
    name = request.args.get("name", "World")
    if "777*777" in name:
        return "Result: 603729"
    return f"Hello {name}"


@mini.route("/ssti_49_in_hash")
def ssti_49_in_hash():
    # github.com/signup shape: the page embeds a per-request session hash that
    # happens to CONTAIN the substring "49" (its hex token). A substring match
    # on "49" verifies a CRITICAL SSTI off random noise — only a standalone
    # token (word-bounded) proves the engine executed 7*7.
    name = request.args.get("name", "World")
    token = "353c49df957c40a1" + "0" * 16 if "*" in name else "353c" + "0" * 28
    return (
        "<html><head><title>Sign up</title></head><body>"
        f"<input type='hidden' name='session' value='{token}'>"
        "<h1>Create your account</h1></body></html>"
    )


@mini.route("/ssti_7777777")
def ssti_7777777():
    # Evaluates ONLY the Jinja2 string-multiplication probe.
    name = request.args.get("name", "World")
    if "7*'7'" in name:
        return "Result: 7777777"
    return f"Hello {name}"


@mini.route("/ssti_echo")
def ssti_echo():
    # Benign: prints the template source without evaluating it.
    return f"Template: {request.args.get('name', 'World')}"


@mini.route("/xss_escaped")
def xss_escaped():
    from markupsafe import escape
    return f"<h1>Hello {escape(request.args.get('name', ''))}</h1>"


@mini.route("/xss_attr")
def xss_attr():
    # Reflects input raw but INSIDE a quoted attribute value: the marker
    # renders as inert text and can never execute.
    return f'<input value="{request.args.get("name", "")}">'


@mini.route("/xss_json")
def xss_json():
    # Returns the input inside JSON with correct content-type — raw marker
    # but no HTML context; the XSS detector must not fire.
    import json
    body = json.dumps({"echo": request.args.get("name", "")})
    return Response(body, mimetype='application/json')


@mini.route("/xss_error")
def xss_error():
    # Returns a filesystem-style error echoing the input (like the LFI endpoint).
    return f"No such file or directory: '{request.args.get('name', '')}'", 500


@mini.route("/lfi_stub")
def lfi_stub():
    # Simulates an LFI endpoint: returns a filesystem error for any param.
    fn = request.args.get("file", "")
    if fn:
        return f"[Errno 2] No such file or directory: '{fn}'"
    return "OK"


@mini.route("/sqli_echo")
def sqli_echo():
    # Simulates a parameter that reflects the value verbatim (like /xss or /lfi
    # echoing SQL payloads).  Body changes should never be mistaken for SQL.
    return f"echo: {request.args.get('id', '')}"


@mini.route("/sqli_encoded_echo")
def sqli_encoded_echo():
    # Soft-404-shaped endpoint: reflects the RAW (still URL-encoded) query
    # string inside an HTML "page not found" body — the exact shape that made
    # WordPress sites produce verified SQLi storms (the payload is echoed as
    # %27+OR+1%3D1--, not as the raw string).
    raw = request.query_string.decode("utf-8", "replace")
    return (
        "<html><title>Page not found</title>"
        f"404 - the requested URL /sqli_encoded_echo?{raw} was not found</html>"
    )


@mini.route("/sqli_dynamic_no_reflect")
def sqli_dynamic_no_reflect():
    # A login-style page with PER-REQUEST dynamic content (a CSRF token) that
    # does NOT reflect the query params — the exact shape that made
    # ctflearn's /user/login produce verified SQLi: the sanity-pair oracle
    # saw token noise as a boolean differential.
    import random
    return (
        "<html><h1>Login</h1>"
        f"<input type='hidden' name='csrf' value='tok{random.randint(0, 10**9)}'>"
        "</html>"
    )


# ─── routes for the five newly-wired modules ─────────────────────────────────


@mini.route("/cache_echo")
def cache_echo():
    # Reflects input but NO caching layer — reflection alone is not cache
    # poisoning.
    return f"Echo: {request.args.get('id', '')}"


@mini.route("/logic_static_form")
def logic_static_form():
    # owasp.org/donate shape: a static donation form. The page answers 200
    # with a real body to ANY amount value — including -1 — but never echoes
    # or processes it. A detector that fires on "200 + body" verifies a HIGH
    # business-logic finding off a static page.
    amt = request.args.get("custom-amount-field", "")
    return f"<html><head><title>Donate</title></head><body>" \
        "<form action='/donate' method='post'>" \
        "<input name='custom-amount-field' value='{amt}'>" \
        "<button>Donate</button></form><p>Support our work</p></body></html>"


@mini.route("/logic_negative_accepted")
def logic_negative_accepted():
    # A real (simulated) vulnerable cart: the negative amount is ACCEPTED and
    # echoed into the order total — the evidence the oracle must require.
    amt = request.args.get("amount", "0")
    total = 100 + int(amt)
    return f"<html><body><h1>Order</h1><p>Subtotal: $100</p>" \
        f"<p>Adjustment: ${amt}</p><p>Total: ${total}</p></body></html>"


@mini.route("/cache_private_no_cache")
def cache_private_no_cache():
    # github.com shape: reflects input AND sends the standard cache headers,
    # but Cache-Control explicitly forbids shared caching
    # (``max-age=0, private, must-revalidate``). The pre-fix detector verified
    # a HIGH cache-poisoning finding on github.com's dead /upload route off
    # these headers — a private response can never be poisoned via a shared
    # cache.
    body = f"Cache: {request.args.get('id', '')}"
    resp = Response(body, mimetype="text/html")
    resp.headers["Cache-Control"] = "max-age=0, private, must-revalidate"
    resp.headers["ETag"] = 'W/"1913ddd2706dffaaebb696d016a8ae38"'
    resp.headers["Age"] = "0"
    return resp


@mini.route("/cache_poisonable")
def cache_poisonable():
    # A real (simulated) caching CDN: reflects input AND sends cache headers.
    body = f"Cache: {request.args.get('id', '')}"
    resp = Response(body, mimetype="text/html")
    resp.headers["X-Cache"] = "HIT"
    resp.headers["Age"] = "5"
    resp.headers["Via"] = "1.1 cdn"
    return resp


@mini.route("/crypto_secret")
def crypto_secret():
    # Response body contains a hardcoded Google API key (35-char alphanumeric
    # segment after the AIza prefix, per the pattern).
    return json.dumps({"api_key": "AIza" + "A" * 35, "ok": 1})


@mini.route("/crypto_clean")
def crypto_clean():
    return "nothing sensitive here"


@mini.route("/crypto_aws")
def crypto_aws():
    # AWS access key in the canonical credential-assignment form.
    return json.dumps({"accessKeyId": "AKIAIOSFODNN7EXAMPLE", "ok": 1})


@mini.route("/crypto_aws_bare")
def crypto_aws_bare():
    # A bare AKIA mention in prose/docs — no credential assignment context.
    return (
        "<p>See the AWS docs example key AKIAIOSFODNN7EXAMPLE in our "
        "getting-started guide.</p>"
    )


@mini.route("/crypto_aws_env")
def crypto_aws_env():
    # Unquoted env-style leak (.env / docker-env format).
    return "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"


@mini.route("/deser_java")
def deser_java():
    # Body leaks Java serialization classes.
    return "error: java.io.ObjectInputStream could not read com.sun.rowset.JdbcRowSetImpl"


@mini.route("/deser_clean")
def deser_clean():
    return "no gadget classes here"


@mini.route("/race_get")
def race_get():
    # GET lookup: different id -> different record. NOT a race condition.
    n = int(request.args.get("id", "1")) if str(request.args.get("id", "1")).isdigit() else 1
    return f"balance {'X' * n}"


@mini.route("/race_post", methods=["POST"])
def race_post():
    # POST state-changing endpoint that is deterministic: identical requests
    # return identical bodies (no race).
    n = int(request.form.get("id", "1")) if str(request.form.get("id", "1")).isdigit() else 1
    return f"redeemed voucher {'X' * n}"


_race_counter = {"n": 0}


@mini.route("/race_counter", methods=["POST"])
def race_counter():
    # Simulates a TOCTOU double-spend: each concurrent identical request
    # mutates shared state, so responses DIVERGE (1st wins, rest differ).
    _race_counter["n"] += 1
    return f"use {_race_counter['n']}"


@mini.route("/race_noise", methods=["POST"])
def race_noise():
    # Diverges per request for a NORMAL reason (an alphanumeric CSRF token),
    # not a TOCTOU counter — the hellboundhackers login/register shape that
    # produced 15 false 'Race Condition' findings.
    import secrets
    return f"<html><input name='csrf' value='tok{secrets.token_hex(8)}'>status ok</html>"


@mini.route("/smuggle_stub")
def smuggle_stub():
    # Echoes the file param verbatim (like an LFI error dump).
    return f"No such file or directory: '{request.args.get('file', '')}'"


@mini.route("/smuggle_encoded_echo")
def smuggle_encoded_echo():
    # github.com/login shape: the request URL (with the already-encoded CL.TE
    # probe) is embedded into the page's JS state, which re-encodes it
    # (% -> %25). A raw-only strip leaves "content-length" alive inside the
    # nested echo — the payload-encoding strip must peel it (the github.com
    # MEDIUM request-smuggling FP).
    # The CL.TE probe is ALREADY encoded (test%0d%0a...), so the browser
    # re-encodes it on the wire quote_plus-style (space -> '+', % -> %25):
    # test%250d%250aContent-Length%3A%25200...X-Test%3A+true. GitHub embeds
    # that request-URL form into the login value as-is. A raw-only strip of
    # the level-1 payload leaves "content-length" alive inside this level-2
    # echo (the github.com MEDIUM smuggling FP).
    val = request.args.get("return_to", "")
    encoded = quote_plus(val, safe="")
    return f"<html><body><form action='/login' method='post'>" \
        f"<input type='hidden' name='return_to' value='{encoded}'>" \
        "</form></body></html>"


@mini.route("/nosqli_echo")
def nosqli_echo():
    # Echoes back the operator payload — an endpoint that reflects JSON
    # operators in a "query" field, like the lab's /sqli endpoint.
    val = request.args.get("id", "")
    return json.dumps({"query": f"SELECT * FROM users WHERE id = {val}", "result": "user"})


# ─── Fake playwright-style context ────────────────────────────────────────────


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


class FakeResponse:
    def __init__(self, status_code, body_bytes, headers, url):
        self.status_code = status_code
        self._body = body_bytes
        # Normalise to lowercase keys (matching Playwright's behaviour; Flask
        # test clients return title-cased header names).
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
    mini.testing = True
    return mini.test_client()


@pytest.fixture()
def context(client):
    return FakeLabContext(client)


async def _scan(detector, context, path, params):
    return await detector.scan(
        context, "http://localhost:5000", "GET",
        f"http://localhost:5000{path}", params,
    )


async def _scan_post(detector, context, path, params):
    return await detector.scan(
        context, "http://localhost:5000", "POST",
        f"http://localhost:5000{path}", params,
    )


# ─── XSS ──────────────────────────────────────────────────────────────────────


class TestXSSOracle:
    @staticmethod
    def _raw_xss_context():
        # A raw unescaped reflective endpoint (the real-lab /xss shape, which
        # test_lab_detection.py also covers end-to-end).
        raw = Flask("raw")
        raw.add_url_rule("/xss", "xss", lambda: f"<h1>Hello {request.args.get('name', '')}</h1>")
        raw.testing = True
        return FakeLabContext(raw.test_client())

    async def test_raw_marker_reflection_is_verified(self, context):
        from titan.modules.xss.detector import XSSDetector
        findings = await _scan(XSSDetector(StubSmith(), {}), self._raw_xss_context(), "/xss", {"name": "test"})
        assert findings, "raw reflective endpoint must be found"
        f = findings[0]
        assert f.attack_type == AttackType.XSS
        assert f.verified is True, f"expected verified XSS, got diffs={f.diffs}"
        assert f.confidence == 0.9, f"xss_unescaped alone must score exactly 0.9, got {f.confidence}"

    async def test_escaped_output_is_not_xss(self, context):
        from titan.modules.xss.detector import XSSDetector
        findings = await _scan(XSSDetector(StubSmith(), {}), context, "/xss_escaped", {"name": "test"})
        assert findings == [], f"HTML-escaped reflection must not be flagged XSS, got {findings}"

    async def test_attribute_context_is_not_xss(self, context):
        from titan.modules.xss.detector import XSSDetector
        findings = await _scan(XSSDetector(StubSmith(), {}), context, "/xss_attr", {"name": "test"})
        assert findings == [], f"marker inside an attribute value cannot execute, got {findings}"

    async def test_json_echo_is_not_xss(self, context):
        from titan.modules.xss.detector import XSSDetector
        findings = await _scan(XSSDetector(StubSmith(), {}), context, "/xss_json", {"name": "test"})
        assert findings == [], f"marker in JSON echo must not be flagged XSS, got {findings}"

    async def test_error_echo_is_not_xss(self, context):
        from titan.modules.xss.detector import XSSDetector
        findings = await _scan(XSSDetector(StubSmith(), {}), context, "/xss_error", {"name": "test"})
        assert findings == [], f"marker in error dump must not be flagged XSS, got {findings}"


# ─── SSRF ─────────────────────────────────────────────────────────────────────


class TestSSRFOracle:
    async def test_metadata_content_leak_is_verified(self, context):
        from titan.modules.ssrf.detector import SSRFDetector
        findings = await _scan(
            SSRFDetector(StubSmith(), {}), context, "/ssrf",
            {"url": "http://example.com"},
        )
        assert findings, "metadata fetch must be found"
        f = findings[0]
        assert f.attack_type == AttackType.SSRF
        assert f.verified is True, f"expected verified SSRF (content leak), got diffs={f.diffs}"
        assert f.confidence >= 0.8

    async def test_echo_only_url_is_not_ssrf(self, context):
        from titan.modules.ssrf.detector import SSRFDetector
        findings = await _scan(
            SSRFDetector(StubSmith(), {}), context, "/ssrf_echo",
            {"url": "http://example.com"},
        )
        assert findings == [], f"payload reflection must not self-verify SSRF, got {findings}"

    async def test_encoded_url_echo_is_not_ssrf(self, context):
        """A URL-ENCODED reflection of the probe URL (GitHub's branded-404
        echo) must not self-verify content-leak markers — stripping only the
        raw payload left "169.254"/"meta-data" alive inside the encoded echo."""
        from titan.modules.ssrf.detector import SSRFDetector
        findings = await _scan(
            SSRFDetector(StubSmith(), {}), context, "/ssrf_encoded_echo",
            {"url": "http://example.com"},
        )
        assert findings == [], f"encoded URL reflection must not be SSRF, got {findings}"

    async def test_double_encoded_url_echo_is_not_ssrf(self, context):
        """The nested echo: GitHub embeds the request URL in SPA JS state and
        re-encodes it (% -> %25), so a probe comes back double-encoded
        (http%253A%252F%252F169.254...). payload_encodings() must generate the
        nested forms or the markers survive the strip and a dead route
        self-verifies CRITICAL SSRF content leaks (the github.com DVIA storm)."""
        from titan.modules.ssrf.detector import SSRFDetector
        findings = await _scan(
            SSRFDetector(StubSmith(), {}), context, "/ssrf_double_encoded_echo",
            {"url": "http://example.com"},
        )
        assert findings == [], f"double-encoded URL reflection must not be SSRF, got {findings}"


# ─── XXE ──────────────────────────────────────────────────────────────────────


class TestXXEOracle:
    async def test_file_content_leak_is_verified(self, context):
        from titan.modules.xxe.detector import XXEDetector
        findings = await _scan(XXEDetector(StubSmith(), {}), context, "/xxe", {"data": "<foo/>"})
        assert findings, "XXE with entity expansion must be found"
        f = findings[0]
        assert f.attack_type == AttackType.XXE
        assert f.verified is True, f"expected verified XXE (content leak), got diffs={f.diffs}"
        assert f.confidence >= 0.8

    async def test_parser_error_is_verified(self, context):
        from titan.modules.xxe.detector import XXEDetector
        # /xxe_parser 500s with a parser error on any DOCTYPE -> error:xml
        # (strong signal) must verify even without leaked content.
        findings = await _scan(XXEDetector(StubSmith(), {}), context, "/xxe_parser", {"data": "ok"})
        assert findings, "XXE parser error must be found"
        f = findings[0]
        assert f.attack_type == AttackType.XXE
        assert f.verified is True, f"expected verified XXE (parser error), got diffs={f.diffs}"

    async def test_payload_echo_is_not_xxe(self, context):
        from titan.modules.xxe.detector import XXEDetector
        findings = await _scan(XXEDetector(StubSmith(), {}), context, "/xxe_echo", {"data": "<foo/>"})
        assert findings == [], f"payload reflection must not be flagged XXE, got {findings}"


# ─── NoSQLi ───────────────────────────────────────────────────────────────────


class TestNoSQLiOracle:
    async def test_boolean_differential_is_verified(self, context):
        from titan.modules.nosqli.detector import NoSQLiDetector
        findings = await _scan(NoSQLiDetector(StubSmith(), {}), context, "/nosqli", {"id": "1"})
        assert findings, "$ne operator bypass must be found"
        f = findings[0]
        assert f.attack_type == AttackType.NO_SQLI
        assert f.verified is True, f"expected verified NoSQLi (boolean differential), got diffs={f.diffs}"
        assert f.confidence >= 0.8

    def test_opposite_payload_swaps_from_original(self):
        """Regression: chained replaces used to undo themselves ($gt -> $lt ->
        $gt), silently disabling the sanity oracle for those payloads."""
        from titan.modules.nosqli.detector import NoSQLiDetector
        detector = NoSQLiDetector(StubSmith(), {})
        assert detector._get_opposite_payload('{"$ne": null}') == '{"$eq": null}'
        assert detector._get_opposite_payload('{"$gt": ""}') == '{"$lt": ""}'
        assert detector._get_opposite_payload('{"$lt": ""}') == '{"$gt": ""}'
        assert detector._get_opposite_payload('{"$exists": true}') == '{"$exists": false}'


# ─── SSTI ─────────────────────────────────────────────────────────────────────


class TestSSTIOracle:
    async def test_math_eval_is_verified(self, context):
        from titan.modules.ssti.detector import SSTIDetector
        findings = await _scan(SSTIDetector(StubSmith(), {}), context, "/ssti", {"name": "World"})
        assert findings, "{{7*7}} -> 49 must be found"
        f = findings[0]
        assert f.attack_type == AttackType.SSTI
        assert f.verified is True, f"expected verified SSTI (math eval), got diffs={f.diffs}"
        assert f.confidence >= 0.8

    async def test_distinctive_math_token_verifies(self, context):
        """{{777*777}} -> 603729 is the unambiguous SSTI proof."""
        from titan.modules.ssti.detector import SSTIDetector
        findings = await _scan(SSTIDetector(StubSmith(), {}), context, "/ssti_603729", {"name": "World"})
        assert findings, "distinctive probe must be found"
        f = findings[0]
        assert f.verified is True, f"expected 603729 to verify, got diffs={f.diffs}"
        assert "603729" in "".join(f.diffs)

    async def test_jinja_string_mult_discriminator(self, context):
        """{{7*'7'}} -> 7777777 (Jinja2) must verify when evaluated."""
        from titan.modules.ssti.detector import SSTIDetector
        findings = await _scan(SSTIDetector(StubSmith(), {}), context, "/ssti_7777777", {"name": "World"})
        assert findings, "Jinja discriminator probe must be found"
        f = findings[0]
        assert f.verified is True, f"expected 7*'7' to verify, got diffs={f.diffs}"
        assert "7777777" in "".join(f.diffs)

    async def test_baseline_containing_49_is_not_fp(self, context):
        """A page whose baseline already contains '49' must never verify on it."""
        from titan.modules.ssti.detector import SSTIDetector
        findings = await _scan(SSTIDetector(StubSmith(), {}), context, "/ssti_counter", {"name": "World"})
        assert findings == [], f"benign '49' in baseline must not be flagged SSTI, got {findings}"

    async def test_echoed_template_source_is_not_ssti(self, context):
        from titan.modules.ssti.detector import SSTIDetector
        findings = await _scan(SSTIDetector(StubSmith(), {}), context, "/ssti_echo", {"name": "World"})
        assert findings == [], f"printed-but-not-evaluated template must not be flagged, got {findings}"

    async def test_49_inside_session_hash_is_not_fp(self, context):
        """The github.com /signup case: a per-request session hash contains the
        substring "49". Only a STANDALONE "49" (word-bounded) proves the
        engine executed 7*7 — a substring match verified a CRITICAL SSTI off
        random hex noise."""
        from titan.modules.ssti.detector import SSTIDetector
        findings = await _scan(SSTIDetector(StubSmith(), {}), context, "/ssti_49_in_hash", {"name": "World"})
        assert findings == [], f"49 inside a session hash must not be SSTI, got {findings}"


# ─── Cross-module FP regression ─────────────────────────────────────────────


class TestCrossModuleFPs:
    """A detection from module X must not steal evidence that belongs to
    module Y.  In particular, a filesystem error ("No such file or directory")
    on an LFI-like endpoint belongs to LFI — RCE, SSRF, XXE, SSTI, and NoSQLi
    must not claim it via ``error:filesystem``."""

    async def _assert_no_findings(self, detector_cls, context, path, params, label):
        findings = await _scan(detector_cls(StubSmith(), {}), context, path, params)
        assert findings == [], f"{label} must not fire on {path}: {findings}"

    async def test_rce_not_on_filesystem_error(self, context):
        from titan.modules.rce.detector import RCEDetector
        await self._assert_no_findings(RCEDetector, context, "/lfi_stub", {"file": "/etc/passwd"}, "RCE")

    async def test_ssrf_not_on_filesystem_error(self, context):
        from titan.modules.ssrf.detector import SSRFDetector
        await self._assert_no_findings(SSRFDetector, context, "/lfi_stub", {"url": "http://169.254.169.254/latest/meta-data/"}, "SSRF")

    async def test_xxe_not_on_filesystem_error(self, context):
        from titan.modules.xxe.detector import XXEDetector
        await self._assert_no_findings(XXEDetector, context, "/lfi_stub", {"data": "<foo/>"}, "XXE")

    async def test_ssti_not_on_filesystem_error(self, context):
        from titan.modules.ssti.detector import SSTIDetector
        await self._assert_no_findings(SSTIDetector, context, "/lfi_stub", {"name": "{{7*7}}"}, "SSTI")

    async def test_nosqli_not_on_filesystem_error(self, context):
        from titan.modules.nosqli.detector import NoSQLiDetector
        await self._assert_no_findings(NoSQLiDetector, context, "/lfi_stub", {"id": "1"}, "NoSQLi")

    async def test_nosqli_not_on_echo_differential(self, context):
        """NoSQLi must not fire when the only body difference between the
        payload and its opposite is an echoed operator string."""
        from titan.modules.nosqli.detector import NoSQLiDetector
        await self._assert_no_findings(
            NoSQLiDetector, context, "/nosqli_echo", {"id": "1"}, "NoSQLi on echo"
        )

    async def test_sqli_not_on_echo_differential(self, context):
        """SQLi must not produce a verified finding when the payload is merely
        echoed (no interpreter was reached)."""
        from titan.modules.sqli.detector import SQLiDetector
        detector = SQLiDetector(StubSmith(), {})
        async def _no_blind(*args, **kwargs):
            return False, 0.0
        detector.blind_detector.detect_time_based = _no_blind
        findings = await _scan(detector, context, "/sqli_echo", {"id": "1"})
        assert findings == [], f"SQLi must not fire on echo-only differential, got {findings}"

    async def test_sqli_not_on_url_encoded_echo(self, context):
        """SQLi must not verify when the payload is echoed URL-ENCODED (the
        soft-404 shape: %27+OR+1%3D1--, not the raw string). Regression: the
        echo guard compared raw payloads against encoded reflections, so a
        WordPress-style 404 page that echoed the URL "confirmed" every SQLi
        payload."""
        from titan.modules.sqli.detector import SQLiDetector
        detector = SQLiDetector(StubSmith(), {})
        async def _no_blind(*args, **kwargs):
            return False, 0.0
        detector.blind_detector.detect_time_based = _no_blind
        findings = await _scan(detector, context, "/sqli_encoded_echo", {"id": "1"})
        assert findings == [], f"SQLi must not fire on URL-encoded echo, got {findings}"

    async def test_sqli_not_on_dynamic_page_without_reflection(self, context):
        """A page with per-request dynamic content (CSRF token) but ZERO
        reflection must not confirm SQLi. Regression: the sanity-pair oracle
        saw token noise as a boolean differential — the ctflearn /user/login
        storm (3 verified SQLi + 2 NoSQLi on a Django login page)."""
        from titan.modules.sqli.detector import SQLiDetector
        detector = SQLiDetector(StubSmith(), {})
        async def _no_blind(*args, **kwargs):
            return False, 0.0
        detector.blind_detector.detect_time_based = _no_blind
        findings = await _scan(detector, context, "/sqli_dynamic_no_reflect", {"id": "1"})
        assert findings == [], f"dynamic non-reflecting page must not confirm SQLi, got {findings}"


class TestBlindTimingGate:
    """The declared-sleep gate: SLEEP(3) must delay by ~3s, not just be
    slower than baseline — server load variance otherwise "confirms" timing
    SQLi on clean production sites."""

    class _DelayedContext:
        def __init__(self, delay):
            self._delay = delay

        @property
        def request(self):
            return self

        async def get(self, *a, **kw):
            await asyncio.sleep(self._delay)

            class _R:
                status = 200
            return _R()

        async def post(self, *a, **kw):
            return await self.get()

    async def test_declared_sleep_confirms_when_delay_matches(self):
        from titan.verify import BlindDetector
        detector = BlindDetector(samples=2, confidence=0.95)
        ok, delay = await detector.detect_time_based(
            self._DelayedContext(3.2), "http://x", "GET", {"id": "1"}, {}, {},
            "' AND SLEEP(3)--", "query", [0.5, 0.5, 0.5], param_name="id",
        )
        assert ok is True, f"3s sleep vs 0.5s baseline must confirm, delay={delay}"

    async def test_load_variance_is_not_declared_sleep(self):
        """+1.2s of latency variance must NOT confirm SLEEP(3) (declared
        delay is 3s, delta is only 40% of it)."""
        from titan.verify import BlindDetector
        detector = BlindDetector(samples=2, confidence=0.95)
        ok, delay = await detector.detect_time_based(
            self._DelayedContext(2.0), "http://x", "GET", {"id": "1"}, {}, {},
            "' AND SLEEP(3)--", "query", [0.8, 0.8, 0.8], param_name="id",
        )
        assert ok is False, f"1.2s load variance must NOT confirm SLEEP(3), delay={delay}"


class TestEchoDifferentialOracle:
    """is_echo_differential must recognize URL-encoded reflections as pure
    echo — the soft-404 storm depended on it failing (raw-payload subtraction
    vs. encoded reflection)."""

    P = "' OR 1=1--"
    O = "' AND 1=2--"

    def test_url_encoded_echo_is_pure_echo(self):
        from titan.verify.oracles import is_echo_differential
        enc_test = "<html>404 - the requested URL /x?page=%27+OR+1%3D1-- was not found</html>"
        enc_opp = "<html>404 - the requested URL /x?page=%27+AND+1%3D2-- was not found</html>"
        assert is_echo_differential(enc_test, enc_opp, self.P, self.O) is True

    def test_entity_escaped_echo_is_pure_echo(self):
        """Servers may reflect params HTML-escaped (&#39;) on top of URL
        encoding — both layers must be peeled before comparing."""
        from titan.verify.oracles import is_echo_differential
        esc_test = "<html>value=&#39;+OR+1%3D1--</html>"
        esc_opp = "<html>value=&#39;+AND+1%3D2--</html>"
        assert is_echo_differential(esc_test, esc_opp, self.P, self.O) is True

    def test_unrelated_noise_without_reflection_is_not_differential(self):
        """Per-request dynamic content (CSRF tokens) with NO reflection of the
        payload is page noise, not a boolean differential — the sanity oracle
        must not confirm on it."""
        from titan.verify.oracles import is_echo_differential
        noisy_test = "<html><input name='csrf' value='tok-AAAA'><h1>Login</h1></html>"
        noisy_opp = "<html><input name='csrf' value='tok-BBBB'><h1>Login</h1></html>"
        assert is_echo_differential(noisy_test, noisy_opp, self.P, self.O) is True

    def test_reflected_payload_with_token_noise_is_pure_echo(self):
        """The GitHub login shape: the param IS reflected (form action, hidden
        fields) but the page also carries per-request random tokens (session
        hashes, CSRF nonces, analytics payloads). The sanity-pair oracle read
        that tiny residue as a boolean differential — 12 CRITICAL
        SQLi/NoSQLi/SSRF on github.com. Near-identical residue in a large
        page is noise, not a differential."""
        from titan.verify.oracles import is_echo_differential

        boilerplate = (
            "<nav><a href='/'>Home</a><a href='/features'>Features</a>"
            "<a href='/pricing'>Pricing</a><a href='/docs'>Docs</a></nav>"
            "<footer><p>&copy; 2026 Acme. Terms. Privacy.</p></footer>"
        )

        def page(hash_, token, echo):
            return (
                "<html><head>"
                f"<meta name='current-catalog-service-hash' content='{hash_}'>"
                f"<meta name='html-safe-nonce' content='nonce-{hash_}'>"
                "</head><body>"
                f"<form action='/login?return_to={echo}' method='post'>"
                f"<input name='authenticity_token' value='{token}'>"
                "<h1>Sign in to Acme</h1></form>"
                f"<script>window._hydro={{sid:'{hash_}'}}</script>"
                + boilerplate * 20
                + "</body></html>"
            )

        gh_test = page("c0ed1326e995", "tok-AAAA", "q=%27+OR+1%3D1--")
        gh_opp = page("d9370c8081b", "tok-BBBB", "q=%27+AND+1%3D2--")
        assert is_echo_differential(gh_test, gh_opp, self.P, self.O) is True

    def test_reflected_with_real_rowset_change_is_differential(self):
        """Reflection PLUS a real row-set change (full table vs empty) is
        still a differential — the magnitude gate must not swallow real
        evidence along with the noise."""
        from titan.verify.oracles import is_echo_differential
        rows = "<tr><td>admin</td></tr><tr><td>user</td></tr><tr><td>guest</td></tr>"
        real_test = f"<html>echo: ' OR 1=1--<table>{rows * 4}</table></html>"
        real_opp = "<html>echo: ' AND 1=2--<table>0 rows</table></html>"
        assert is_echo_differential(real_test, real_opp, self.P, self.O) is False

    def test_raw_echo_is_pure_echo(self):
        from titan.verify.oracles import is_echo_differential
        raw_test = "<html>echo: ' OR 1=1--</html>"
        raw_opp = "<html>echo: ' AND 1=2--</html>"
        assert is_echo_differential(raw_test, raw_opp, self.P, self.O) is True

    def test_real_differential_is_not_echo(self):
        from titan.verify.oracles import is_echo_differential
        real_test = "<html>SQL syntax error near ' OR 1=1-- line 1</html>"
        real_opp = "<html>ok</html>"
        assert is_echo_differential(real_test, real_opp, self.P, self.O) is False

    def test_literal_plus_signs_preserved(self):
        """unquote_plus corrupts literal '+' in BOTH bodies equally, so the
        equality verdict for a true echo must be unaffected."""
        from titan.verify.oracles import is_echo_differential
        plus_test = "C++ guide: echo ' OR 1=1--"
        plus_opp = "C++ guide: echo ' AND 1=2--"
        assert is_echo_differential(plus_test, plus_opp, self.P, self.O) is True


# ─── Newly-wired modules: crypto / deser / race / cache / smuggling ─────────


class TestCryptoOracle:
    async def test_hardcoded_api_key_found(self, context):
        from titan.modules.crypto.detector import CryptoDetector
        findings = await _scan(CryptoDetector(StubSmith(), {}), context, "/crypto_secret", {"token": "1"})
        assert findings, "hardcoded API key must be found"
        f = findings[0]
        assert f.attack_type == AttackType.CRYPTO_WEAKNESS
        assert f.verified is True
        assert any("hardcoded_google_api_key" in d for d in f.diffs), f"got {f.diffs}"

    async def test_clean_page_no_crypto(self, context):
        from titan.modules.crypto.detector import CryptoDetector
        findings = await _scan(CryptoDetector(StubSmith(), {}), context, "/crypto_clean", {"token": "1"})
        assert findings == [], f"clean page must not be flagged, got {findings}"

    async def test_paramless_body_is_scanned(self, context):
        """Hardcoded creds in a body with NO crypto-named param (e.g. a
        /config endpoint) must still be found — crypto is a body scan."""
        from titan.modules.crypto.detector import CryptoDetector
        findings = await _scan(CryptoDetector(StubSmith(), {}), context, "/crypto_secret", {})
        assert findings, "param-less body with hardcoded creds must be scanned"
        f = findings[0]
        assert any("hardcoded" in d for d in f.diffs), f"got {f.diffs}"

    async def test_aws_access_key_in_context_found(self, context):
        """An AKIA key in a credential assignment (accessKeyId) is a leak."""
        from titan.modules.crypto.detector import CryptoDetector
        findings = await _scan(CryptoDetector(StubSmith(), {}), context, "/crypto_aws", {"token": "1"})
        assert findings, "AKIA under accessKeyId must be found"
        assert any("hardcoded_aws_access_key_id" in d for d in findings[0].diffs), \
            f"got {findings[0].diffs}"

    async def test_bare_aws_mention_not_flagged(self, context):
        """A bare AKIA mention in prose must NOT be a finding (regression:
        the old regex matched anywhere, flagging shared JS bundles on every
        page of a site)."""
        from titan.modules.crypto.detector import CryptoDetector
        findings = await _scan(CryptoDetector(StubSmith(), {}), context, "/crypto_aws_bare", {"token": "1"})
        assert findings == [], f"bare AKIA mention must not be a finding, got {findings}"

    async def test_unquoted_env_style_aws_key_found(self, context):
        """The unquoted .env/docker form (AWS_ACCESS_KEY_ID=AKIA...) is a
        primary real-world leak shape and must still be caught."""
        from titan.modules.crypto.detector import CryptoDetector
        findings = await _scan(CryptoDetector(StubSmith(), {}), context, "/crypto_aws_env", {"token": "1"})
        assert findings, "unquoted env-style AWS key must be found"
        assert any("hardcoded_aws_access_key_id" in d for d in findings[0].diffs), \
            f"got {findings[0].diffs}"


class TestDeserOracle:
    async def test_java_gadget_class_found(self, context):
        from titan.modules.deser.detector import DeserDetector
        findings = await _scan(DeserDetector(StubSmith(), {}), context, "/deser_java", {"data": "1"})
        assert findings, "Java gadget classes in body must be found"
        f = findings[0]
        assert f.attack_type == AttackType.DESERIALIZATION
        assert f.verified is True

    async def test_clean_page_no_deser(self, context):
        from titan.modules.deser.detector import DeserDetector
        findings = await _scan(DeserDetector(StubSmith(), {}), context, "/deser_clean", {"data": "1"})
        assert findings == [], f"clean page must not be flagged, got {findings}"


class TestRaceOracle:
    async def test_get_lookup_is_not_raced(self, context):
        """Concurrent GET lookups are normal reads, not races."""
        from titan.modules.race.detector import RaceDetector
        findings = await _scan(RaceDetector(StubSmith(), {}), context, "/race_get", {"id": "1"})
        assert findings == [], f"GET lookup must not be flagged as a race, got {findings}"

    async def test_identical_post_responses_are_not_raced(self, context):
        """Deterministic POST: identical concurrent requests -> identical
        responses.  Must NOT fire (this is the old different-id FP)."""
        from titan.modules.race.detector import RaceDetector
        findings = await _scan_post(RaceDetector(StubSmith(), {}), context, "/race_post", {"id": "1"})
        assert findings == [], f"identical concurrent responses must not be a race, got {findings}"

    async def test_divergent_concurrent_responses_are_raced(self, context):
        """TOCTOU double-spend: identical concurrent requests mutate shared
        state and DIVERGE as a monotonic counter -> that is the race
        signature."""
        _race_counter["n"] = 0
        from titan.modules.race.detector import RaceDetector
        findings = await _scan_post(RaceDetector(StubSmith(), {}), context, "/race_counter", {"id": "1"})
        assert findings, "divergent identical concurrent responses must be flagged as a race"
        f = findings[0]
        assert f.attack_type == AttackType.RACE_CONDITION

    async def test_token_noise_divergence_is_not_raced(self, context):
        """Per-request alphanumeric token noise is NOT a race — the
        hellboundhackers login/register shape (15 FPs)."""
        from titan.modules.race.detector import RaceDetector
        findings = await _scan_post(RaceDetector(StubSmith(), {}), context, "/race_noise", {"id": "1"})
        assert findings == [], f"per-request token noise must not be a race, got {findings}"


class TestCacheOracle:
    async def test_reflection_without_cache_headers_is_not_poisoning(self, context):
        from titan.modules.cache.detector import CacheDetector
        findings = await _scan(CacheDetector(StubSmith(), {}), context, "/cache_echo", {"id": "1"})
        assert findings == [], f"plain reflection with no caching layer must not be flagged, got {findings}"

    async def test_poison_reflected_on_cached_response(self, context):
        from titan.modules.cache.detector import CacheDetector
        findings = await _scan(CacheDetector(StubSmith(), {}), context, "/cache_poisonable", {"id": "1"})
        assert findings, "reflection + cache headers is the cache-poisoning condition"
        f = findings[0]
        assert f.attack_type == AttackType.CACHE_POISONING
        assert f.verified is True

    async def test_private_response_is_not_poisonable(self, context):
        """github.com's shape: standard cache headers (Cache-Control, ETag,
        Age) but the response is explicitly non-cacheable
        (``max-age=0, private, must-revalidate``). A private response can
        never be poisoned via a shared cache — the pre-fix detector verified a
        HIGH finding off these headers alone."""
        from titan.modules.cache.detector import CacheDetector
        findings = await _scan(CacheDetector(StubSmith(), {}), context, "/cache_private_no_cache", {"id": "1"})
        assert findings == [], f"non-cacheable response must not be cache-poisoning, got {findings}"


class TestSmugglingOracle:
    async def test_echoed_probe_is_not_smuggling(self, context):
        """The probe string itself contains 'content-length' — an app that
        echoes the parameter would self-verify without the echo-strip."""
        from titan.modules.smuggling.detector import SmugglingDetector
        findings = await _scan(SmugglingDetector(StubSmith(), {}), context, "/smuggle_stub", {"file": "/etc/passwd"})
        assert findings == [], f"echoed probe must not be flagged as smuggling, got {findings}"

    async def test_double_encoded_echo_is_not_smuggling(self, context):
        """github.com/login shape: the request URL (with the encoded CL.TE
        probe) is re-encoded into SPA JS state (% -> %25). A raw-only strip
        leaves "content-length" alive inside the nested echo; payload_encodings
        must peel every form (the github.com MEDIUM smuggling FP)."""
        from titan.modules.smuggling.detector import SmugglingDetector
        findings = await _scan(SmugglingDetector(StubSmith(), {}), context, "/smuggle_encoded_echo", {"return_to": "/dashboard"})
        assert findings == [], f"double-encoded echo must not be flagged as smuggling, got {findings}"


class TestLogicOracle:
    async def test_static_page_with_amount_param_is_not_fp(self, context):
        """owasp.org/donate shape: the page answers 200 to ANY amount (incl.
        -1) but never echoes or processes it. The pre-fix detector verified a
        HIGH business-logic finding off "200 + body > 100 chars" — no baseline,
        no reflection."""
        from titan.modules.logic.detector import LogicDetector
        findings = await _scan(
            LogicDetector(StubSmith(), {}), context, "/logic_static_form",
            {"custom-amount-field": "25"},
        )
        assert findings == [], f"static page must not be business-logic, got {findings}"

    async def test_reflected_negative_amount_is_verified(self, context):
        """A cart that echoes the accepted -1 into the total (Adjustment: $-1)
        is real evidence — the app processed the negative value."""
        from titan.modules.logic.detector import LogicDetector
        findings = await _scan(
            LogicDetector(StubSmith(), {}), context, "/logic_negative_accepted",
            {"amount": "10"},
        )
        assert findings, "reflected negative amount must be found"
        f = findings[0]
        assert f.attack_type == AttackType.BUSINESS_LOGIC
        assert f.verified is True, f"expected verified negative-price, got diffs={f.diffs}"


class TestModuleWiring:
    """Integration: the five modules must actually run inside the engine's
    per-endpoint attack pipeline (_run_attack_modules)."""

    @staticmethod
    async def _pipeline_findings(context, path, params):
        from titan.core.engine import TitanEngine
        cfg = {
            "governance": {"enabled": False},
            "ai": {"enabled": False},
            "modules": {m: {"enabled": True} for m in
                         ("sqli", "xss", "ssrf", "idor", "lfi", "rce", "nosqli", "ssti", "xxe",
                          "upload", "logic", "cors", "headers", "crypto", "deser", "race",
                          "cache", "smuggling")},
        }
        engine = TitanEngine(cfg)
        engine.interactsh = None
        return await engine._run_attack_modules(
            context, "http://localhost:5000", "GET",
            f"http://localhost:5000{path}", params, {},
        )

    async def test_cache_module_runs_in_attack_pipeline(self, context):
        findings = await self._pipeline_findings(context, "/cache_poisonable", {"id": "1"})
        cache_findings = [f for f in findings if f.attack_type == AttackType.CACHE_POISONING]
        assert cache_findings, "cache module must fire through the engine pipeline " \
                               f"(crypto/deser/race/cache/smuggling are wired together); got {findings}"

    async def test_crypto_module_runs_in_attack_pipeline(self, context):
        """Crypto fires through the same list even with a non-crypto param,
        proving the dropped param gate works end-to-end."""
        findings = await self._pipeline_findings(context, "/crypto_secret", {"id": "1"})
        crypto_findings = [f for f in findings if f.attack_type == AttackType.CRYPTO_WEAKNESS]
        assert crypto_findings, "crypto module must fire through the engine pipeline, got {findings}"
