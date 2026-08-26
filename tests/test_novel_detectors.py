"""PUSH-TO-100 B3 — novel-class detectors (fuzzer + parser-differential).

The framework, not a stub: pure decision logic pinned exactly (tests never
copy it), tiering under the A1 discipline verified, and LIVE local-server
proofs that both detectors fire real findings — including the parser
differential: same bytes through two parsers, encoded form reaches a sink
the plain form couldn't.
"""

import http.server
import threading
from unittest.mock import AsyncMock

from titan.core.models import AttackType, Finding, Severity
from titan.modules.fuzzer.detector import FuzzerDetector, _mutate, classify_differential
from titan.modules.parserdiff.detector import (
    ParserDiffDetector,
    _encodings,
    classify_parser_differential,
)
from titan.verify.oracles import enforce_evidence


# ---------------------------------------------------------------------------
# Fuzzer: mutation dictionary + differential classification (pure)
# ---------------------------------------------------------------------------

def test_mutation_dictionary_is_bounded_and_varied():
    mutations = _mutate("Search")  # mixed case so both upper AND lower fire
    labels = [label for label, _ in mutations]
    assert "upper" in labels
    assert "lower" in labels
    assert "url-encoded" in labels
    assert "double-url-encoded" in labels
    assert "empty" in labels
    assert "null-byte" in labels
    assert len(mutations) <= 20  # bounded: no explosion per param


def test_mutation_empty_value_yields_nothing():
    assert _mutate("") == []


def test_classify_new_sql_error_is_strong():
    label, sev, conf = classify_differential(
        200, "<html>ok</html>", 200,
        "<html>ok</html> SQLSTATE[42000]: syntax error",
    )
    assert label == "error:sql"
    assert sev == Severity.HIGH


def test_classify_500_flip_is_weak_behavioral():
    label, sev, conf = classify_differential(200, "<html>ok</html>", 500, "<html>err</html>")
    assert label == "status_500"
    assert sev == Severity.MEDIUM


def test_classify_no_differential():
    label, sev, conf = classify_differential(200, "<html>same</html>", 200, "<html>same</html>")
    assert label is None


# ---------------------------------------------------------------------------
# Parser-differential: encodings + pure decision (the novel core)
# ---------------------------------------------------------------------------

def test_encodings_produce_varied_wire_forms():
    # A payload with <, > and spaces so EVERY encoding produces a distinct
    # wire form (html-entity needs <>, tab/newline need spaces).
    encs = _encodings("<script> alert('x') </script>")
    labels = [label for label, _ in encs]
    assert "double-url" in labels
    assert "html-entity" in labels
    assert "fullwidth" in labels
    assert "mixed-case" in labels
    assert "null-byte" in labels
    assert "tab" in labels
    assert "newline" in labels
    # same logical bytes, different wire forms
    forms = {form for _, form in encs}
    assert len(forms) == len(encs)


def test_encoded_sink_reaching_plain_couldnt_is_confirmed():
    """The novel case: plain payload yields nothing, encoded form reaches a
    SQL parser -> verified (confirmed tier, scored + repro'd)."""
    label, sev, conf, verified = classify_parser_differential(
        baseline_body="<html>normal</html>",
        plain_body="<html>normal</html>",       # plain form filtered/neutral
        encoded_body="<html>normal SQLSTATE[42000]: syntax error</html>",
        plain_status=200,
        encoded_status=200,
    )
    assert label == "error:sql"
    assert verified is True


def test_content_leak_only_in_encoded_is_confirmed():
    label, sev, conf, verified = classify_parser_differential(
        baseline_body="<html>normal</html>",
        plain_body="<html>normal</html>",
        encoded_body="<html>root:x:0:0:root:/root:/bin/bash</html>",
        plain_status=200,
        encoded_status=200,
    )
    assert label == "content_leak"
    assert verified is True


def test_plain_already_reaching_sink_is_not_a_new_differential():
    """If the plain payload ALSO reaches the sink, there's no disagreement —
    the rulebook detectors already own that case. No parser-diff finding."""
    label, sev, conf, verified = classify_parser_differential(
        baseline_body="<html>normal</html>",
        plain_body="<html>SQLSTATE[42000]: syntax error</html>",
        encoded_body="<html>SQLSTATE[42000]: syntax error</html>",
        plain_status=200,
        encoded_status=200,
    )
    assert label is None


def test_weak_encoded_flip_stays_suspicious():
    label, sev, conf, verified = classify_parser_differential(
        baseline_body="<html>normal</html>",
        plain_body="<html>normal</html>",
        encoded_body="<html>different page entirely</html>",
        plain_status=200,
        encoded_status=200,
    )
    assert label in (None, "content_change")
    if label:
        assert verified is False


# ---------------------------------------------------------------------------
# A1 tiering discipline
# ---------------------------------------------------------------------------

def test_fuzzer_findings_tier_suspicious_never_scored():
    """Fuzzer findings are behavioral differentials by design: they must tier
    `suspicious` and never be scored as proven."""
    f = Finding(
        target="http://lab.local", url="http://lab.local/search", method="GET",
        param="q", location="query", payload="SEARCH",
        attack_type=AttackType.FUZZ_DIFFERENTIAL, severity=Severity.LOW,
        verified=False, confidence=0.5, status=200,
        diffs=["content_change", "fuzz:upper"],
    )
    enforce_evidence([f])
    assert f.tier == "suspicious"
    assert f.verified is False


def test_parserdiff_confirmed_finding_tiers_confirmed():
    f = Finding(
        target="http://lab.local", url="http://lab.local/search", method="GET",
        param="q", location="query", payload="%252e%252e%252f",
        attack_type=AttackType.PARSER_DIFFERENTIAL, severity=Severity.HIGH,
        verified=True, confidence=0.85, status=200,
        diffs=["error:filesystem", "parserdiff:double-url", "class:lfi"],
    )
    enforce_evidence([f])
    assert f.tier == "confirmed"
    assert f.verified is True


# ---------------------------------------------------------------------------
# LIVE proofs
# ---------------------------------------------------------------------------

class _VulnLabHandler(http.server.BaseHTTPRequestHandler):
    """A lab that models the parser disagreement:

    * /fuzz: echoes param value; `UPPER` flips the response (behavioral diff).
    * /pdiff: the plain `../etc/passwd` is FILTERED (returns the neutral
      page); the double-URL-encoded form is DECODED TWICE by the origin and
      leaks /etc/passwd content.
    """

    def do_GET(self):
        import urllib.parse as up
        parsed = up.urlparse(self.path)
        qs = up.parse_qs(parsed.query)
        if parsed.path == "/fuzz":
            v = qs.get("q", [""])[0]
            body = f"<html>result for {v}</html>"
            if v.isupper() and v:
                # Case sensitivity changes the query result volume: a much
                # longer results page (the length classifier must catch it).
                body = (
                    "<html><h1>PROCESSED ADMIN RESULTS</h1><table>"
                    + "<tr><td>row</td></tr>" * 60
                    + "</table></html>"
                )
            payload = body.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif parsed.path == "/pdiff":
            v = qs.get("file", [""])[0]
            # plain traversal is filtered at the entry layer
            if "../etc/passwd" in v and "%" not in v:
                body = "<html>filtered</html>"
            else:
                decoded_once = up.unquote(v)
                decoded_twice = up.unquote(decoded_once)
                if decoded_twice == "../../../etc/passwd":
                    body = "<html>root:x:0:0:root:/root:/bin/bash daemon:x:1:1</html>"
                else:
                    body = "<html>no file</html>"
            payload = body.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            payload = b"not found"
            self.send_response(404)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    def log_message(self, *args):
        pass


class _FakeContext:
    """Minimal Playwright-API-shaped context for the live detector tests."""

    def __init__(self, base):
        self.base = base
        self.request = _FakeRequest(base)


class _FakeRequest:
    def __init__(self, base):
        self.base = base

    async def get(self, url, params=None, headers=None, timeout=None):
        import urllib.parse as up
        import urllib.request as ur
        url = self.base + url
        if params:
            qs = up.urlencode(params, doseq=True)
            url = url + ("&" if "?" in url else "?") + qs
        req = ur.Request(url)
        with ur.urlopen(req, timeout=5) as resp:
            return _FakeResponse(resp.status, resp.read().decode("utf-8", "replace"))


class _FakeResponse:
    def __init__(self, status, text):
        self.status = status
        self.url = ""
        self.headers = {}
        self._text = text

    async def text(self):
        return self._text


def _live_context():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _VulnLabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    return server, base


import asyncio


def test_live_fuzzer_detects_behavioral_differential():
    server, base = _live_context()
    try:
        detector = FuzzerDetector(AsyncMock(), {})
        ctx = _FakeContext(base)
        findings = asyncio.run(detector.scan(
            ctx, base, "GET", "/fuzz", {"q": "search"}
        ))
        # the UPPER mutation flips the response -> a differential fires
        labels = {f.metadata.get("mutation") for f in findings}
        assert any(f.attack_type == AttackType.FUZZ_DIFFERENTIAL for f in findings)
        assert "upper" in labels
        for f in findings:
            assert f.baseline_body and f.verification_body  # evidence present
    finally:
        server.shutdown()
        server.server_close()


def test_live_parserdiff_encoded_form_reaches_sink():
    """The headline B3 case, live: the plain traversal is filtered, the
    double-encoded form leaks /etc/passwd — two parsers disagreed."""
    server, base = _live_context()
    try:
        detector = ParserDiffDetector(AsyncMock(), {})
        ctx = _FakeContext(base)
        findings = asyncio.run(detector.scan(
            ctx, base, "GET", "/pdiff", {"file": "report.pdf"}
        ))
        pdiff = [f for f in findings if f.attack_type == AttackType.PARSER_DIFFERENTIAL]
        assert pdiff, "parser differential must fire on the disagreeing lab"
        f = pdiff[0]
        assert "content_leak" in f.diffs
        assert f.verified is True
        assert "root:x:0" in f.verification_body
    finally:
        server.shutdown()
        server.server_close()


def test_live_parserdiff_no_false_positive_on_agreeing_server():
    """A server that filters BOTH forms equally produces no differential."""
    import urllib.parse as up

    class _AgreeHandler(_VulnLabHandler):
        def do_GET(self):
            parsed = up.urlparse(self.path)
            qs = up.parse_qs(parsed.query)
            if parsed.path == "/pdiff":
                v = qs.get("file", [""])[0]
                if "etc/passwd" in v:
                    body = "<html>filtered</html>"
                else:
                    body = "<html>no file</html>"
                payload = body.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            else:
                super().do_GET()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _AgreeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        detector = ParserDiffDetector(AsyncMock(), {})
        findings = asyncio.run(detector.scan(
            _FakeContext(base), base, "GET", "/pdiff", {"file": "report.pdf"}
        ))
        assert findings == [], "a filter that treats both forms the same is NOT a differential"
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# Same-origin SSRF: the crawl discovers an internal route (/internal/meta) and
# the SSRF module probes it as an absolute payload — the "SSRF to an internal
# service" shape its cloud-metadata IP list can't catch. Grounded: only paths
# the crawler actually found are probed, never guessed.
# ---------------------------------------------------------------------------

from titan.modules.ssrf.detector import SSRFDetector  # noqa: E402


class _SSRFLabHandler(http.server.BaseHTTPRequestHandler):
    """/ssrf fetches ?url= server-side; /internal/meta is the internal prize."""

    def do_GET(self):
        import urllib.parse as up
        import urllib.request as ur

        parsed = up.urlparse(self.path)
        qs = up.parse_qs(parsed.query)
        if parsed.path == "/ssrf":
            u = qs.get("url", [""])[0]
            if not u:
                body = b"provide url"
                self.send_response(400)
            else:
                try:
                    with ur.urlopen(u, timeout=3) as r:
                        body = r.read(2000)
                    self.send_response(200)
                except Exception:
                    body = b"fetch failed"
                    self.send_response(502)
        elif parsed.path == "/internal/meta":
            body = b"ami-id: i-0lab1234\ninstance-type: t3.micro"
            self.send_response(200)
        else:
            body = b"not found"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_ssrf_same_origin_internal_route_is_confirmed():
    """Probing a crawl-DISCOVERED internal route verifies via content leak."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SSRFLabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    from titan.ai.payloadsmith import PayloadSmith

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SSRFLabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        detector = SSRFDetector(PayloadSmith({}), {})
        findings = asyncio.run(detector.scan(
            _FakeContext(base), base, "GET", "/ssrf",
            {"url": "http://example.com/"},
            internal_paths=[base + "/internal/meta"],
        ))
        ssrf = [f for f in findings if f.attack_type == AttackType.SSRF]
        assert ssrf, "same-origin internal probe must fire"
        f = ssrf[0]
        assert any("ssrf:content:" in d for d in f.diffs)  # strong oracle marker
        assert f.verified is True
        assert "ami-id" in f.verification_body
    finally:
        server.shutdown()
        server.server_close()


def test_ssrf_without_internal_paths_stays_clean():
    """No discovered internal route -> no same-origin payload -> no leak
    finding on this lab (the payload list alone can't reach it)."""
    from titan.ai.payloadsmith import PayloadSmith

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SSRFLabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        detector = SSRFDetector(PayloadSmith({}), {})
        findings = asyncio.run(detector.scan(
            _FakeContext(base), base, "GET", "/ssrf",
            {"url": "http://example.com/"},
            internal_paths=[],
        ))
        ssrf = [f for f in findings if f.attack_type == AttackType.SSRF and "content_leak" in f.diffs]
        assert ssrf == [], "no discovered route must mean no same-origin SSRF claim"
    finally:
        server.shutdown()
        server.server_close()
