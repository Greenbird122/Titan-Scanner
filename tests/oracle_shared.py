"""Shared oracle fixtures, vulnerable Flask apps, and scan helpers.

Extracted from tests/test_oracle_detectors.py so the oracle test suite
stays readable. Imported back via ``from oracle_shared import *``.
"""

__all__ = ['PASSWD_SNIPPET', 'ROOT', 'USERS', 'AttackType', 'FakeLabContext', 'FakeRequest', 'FakeResponse', 'Flask', 'Path', 'PayloadForge', 'Response', 'StubSmith', '_race_counter', '_scan', '_scan_post', 'asyncio', 'cache_echo', 'cache_poisonable', 'cache_private_no_cache', 'client', 'context', 'crypto_aws', 'crypto_aws_bare', 'crypto_aws_env', 'crypto_clean', 'crypto_secret', 'deser_clean', 'deser_java', 'json', 'lfi_double_encoded_echo', 'lfi_echo', 'lfi_encoded_echo', 'lfi_errno', 'lfi_real', 'lfi_soft404', 'lfi_stub', 'logic_negative_accepted', 'logic_static_form', 'mini', 'nosqli', 'nosqli_echo', 'pytest', 'quote', 'quote_plus', 'race_counter', 'race_get', 'race_noise', 'race_post', 'request', 'smuggle_encoded_echo', 'smuggle_stub', 'sqli_dynamic_no_reflect', 'sqli_echo', 'sqli_encoded_echo', 'ssrf', 'ssrf_double_encoded_echo', 'ssrf_echo', 'ssrf_encoded_echo', 'ssti', 'ssti_49_in_hash', 'ssti_603729', 'ssti_7777777', 'ssti_counter', 'ssti_echo', 'sys', 'urlparse', 'xss_attr', 'xss_error', 'xss_escaped', 'xss_json', 'xxe', 'xxe_echo', 'xxe_parser']

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
    # Reflects input INSIDE a quoted attribute value with HTML entity escaping
    # for < > " so no payload can break out of the attribute.
    # The marker renders as plain text and can never execute — this tests the
    # attribute-context inert echo guard.
    from markupsafe import escape as _e
    val = str(_e(request.args.get("name", "")))
    return f'<input value="{val}">'


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


@mini.route("/lfi_real")
def lfi_real():
    # Genuinely vulnerable: a traversal value reads /etc/passwd content.
    fn = request.args.get("file", "")
    if "etc/passwd" in fn:
        return PASSWD_SNIPPET
    return "ok"


@mini.route("/lfi_errno")
def lfi_errno():
    # Vulnerable open() sink: a traversal value reaches the filesystem and
    # errors; a benign value returns cleanly (baseline is error-free).
    fn = request.args.get("file", "")
    if ".." in fn:
        return f"[Errno 2] No such file or directory: '{fn}'"
    return "ok"


@mini.route("/lfi_soft404")
def lfi_soft404():
    # Soft-404 shape: EVERY value (including the baseline) produces the same
    # filesystem error — a catch-all that always says "no such file". The
    # baseline differential must exclude it (the zairaku.rest storm).
    fn = request.args.get("file", "")
    return f"No such file or directory: '{fn}'"


@mini.route("/lfi_echo")
def lfi_echo():
    # Benign catch-all: echoes the file param verbatim, no filesystem sink.
    return f"Echo: {request.args.get('file', '')}"


@mini.route("/lfi_encoded_echo")
def lfi_encoded_echo():
    # GitHub-branded-404 shape: reflects the RAW (still URL-encoded) query
    # string. A traversal probe comes back URL-encoded, and the OLD detector
    # self-verified because "etc/passwd" (a path marker inside the payload)
    # survived the raw-only strip.
    raw = request.query_string.decode("utf-8", "replace")
    return f"<html><title>Page not found</title>404 - {quote(raw, safe='')} was not found</html>"


@mini.route("/lfi_double_encoded_echo")
def lfi_double_encoded_echo():
    # SPA-JS-state shape: the request URL is re-encoded (% -> %25).
    raw = request.query_string.decode("utf-8", "replace")
    encoded = quote(quote(raw, safe=""), safe="")
    return f"<html><body><script>window.__STATE__={{path:'{encoded}'}}</script></body></html>"


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
    request.args.get("custom-amount-field", "")
    return "<html><head><title>Donate</title></head><body>" \
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
    return json.dumps({"query": f"SELECT * FROM users WHERE id = {val}", "result": "user"})  # noqa: S608


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

