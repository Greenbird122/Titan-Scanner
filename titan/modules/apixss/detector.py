"""API-fed DOM-sink analysis — the git-vizor F6 class (Track A, static pass).

The browser-context DomXSSDetector proves a URL-param marker reaching a
hooked sink. It is blind to the class F6 exposed: an ``innerHTML`` sink fed
by **API response data** (git-vizor renders ``repo.description`` from
``api.github.com`` into ``card.innerHTML`` — GitHub returns descriptions
verbatim, so a crafted repo description executes in any visitor's browser).

This module is the static counterpart: it pulls the page's inline scripts
plus same-origin JS bundles and runs a small taint pass — external data
seeds (``fetch``/``axios``/XHR responses, user input, storage) are tracked
through assignments and callback params into dangerous sinks
(``innerHTML``, ``outerHTML``, ``insertAdjacentHTML``, ``document.write``,
``eval``, ``new Function``, string ``setTimeout``). A sink whose argument
references tainted data is a candidate DOM XSS.

Evidence honesty (the A1 discipline): this is code-level proof of the
*class*, not runtime proof of exploitability — the bundle may feed the sink
fields the API never controls. Findings are therefore reported UNVERIFIED
(tier "suspicious" via the evidence gate); the browser hook (DomXSSDetector,
or a route-intercept replay) is the confirm step that upgrades to verified.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

from titan.core.models import AttackType, Finding, Severity

MAX_SCRIPTS = 3
MAX_FINDINGS = 5

SCRIPT_SRC_RE = re.compile(r"""<script[^>]*\bsrc=["']([^"']+)["']""", re.I)
INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)

# --- external data seeds -------------------------------------------------
# identifier = <rhs that marks it tainted>, with the source label.

# user input (.value / location / params / hash)
VALUE_SEED_RE = re.compile(
    r"""(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*[^;\n]*?\.value\b""",
    re.I,
)
LOCATION_SEED_RE = re.compile(
    r"""(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*[^;\n]*?(?:location\.search|location\.hash|location\.href|URLSearchParams)""",
    re.I,
)
# fetch / axios / XHR / ajax responses
FETCH_SEED_RE = re.compile(
    r"""(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:fetch|axios)\s*\(""",
    re.I,
)
RESPONSE_SEED_RE = re.compile(
    r"""(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*[^;\n]*?(?:\.json\(\)|\.text\(\)|\.data\b|response|res\b)""",
    re.I,
)
# storage
STORAGE_SEED_RE = re.compile(
    r"""(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*[^;\n]*?localStorage\.getItem""",
    re.I,
)

# --- sinks ---------------------------------------------------------------
SINK_PATTERNS: List[tuple] = [
    (re.compile(r"""\.innerHTML\s*=\s*([^;]+)"""), "innerHTML"),
    (re.compile(r"""\.outerHTML\s*=\s*([^;]+)"""), "outerHTML"),
    (re.compile(r"""\.insertAdjacentHTML\(\s*(?:["'][^"']*["']\s*,\s*)([^)]+)"""), "insertAdjacentHTML"),
    (re.compile(r"""document\.write\(\s*([^)]+)"""), "document.write"),
    (re.compile(r"""document\.writeln\(\s*([^)]+)"""), "document.write"),
    (re.compile(r"""(?<![\w$.])eval\(\s*([^)]+)"""), "eval"),
    (re.compile(r"""new\s+Function\(\s*([^)]+)"""), "Function"),
    (re.compile(r"""setTimeout\(\s*["'`]([^"'`]+)"""), "setTimeout"),
    (re.compile(r"""setInterval\(\s*["'`]([^"'`]+)"""), "setInterval"),
]

# Property fields that are provably numeric (length, counts, ids, status)
# never carry HTML — a sink referencing them alone is not a finding.
NUMERIC_FIELDS = {
    "length", "count", "total", "size", "id", "index", "number", "status",
    "stargazers_count", "forks_count", "open_issues_count", "watchers_count",
    "position", "offset", "year", "month", "day", "timestamp", "page",
    "per_page", "limit", "offset", "width", "height", "top", "left",
}

# Fields that routinely hold attacker-influenced strings.
STRINGISH_FIELDS = {
    "description", "name", "title", "message", "text", "language",
    "html_url", "clone_url", "url", "href", "src", "value", "username",
    "login", "email", "error", "label", "content", "body", "subject",
}

# Bounded fixed-point passes for assignment transitivity.
TAINT_PASSES = 4

# lhs must not be a property (``card.innerHTML =`` is a sink, not a
# variable) and ``=`` must not be an arrow (``repo => ``).
ASSIGN_RE = re.compile(
    r"""(?:const|let|var)?\s*(?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*(?!>)([^;]+?)(?:;|$)""",
    re.I,
)
CALLBACK_RE = re.compile(
    r"""\.(?:forEach|map|filter|reduce|then|catch|finally)\(\s*(?:async\s+)?\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>""",
    re.I,
)
CALLBACK_OBJ_RE = re.compile(
    r"""([A-Za-z_$][\w$]*)\s*\.(?:forEach|map|filter|reduce)\(\s*(?:async\s+)?\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>""",
    re.I,
)

# Heuristic catch-param taint: a catch handler next to network code gets the
# "error" source (its .message is rendered in many apps).
CATCH_RE = re.compile(r"""catch\s*\(\s*([A-Za-z_$][\w$]*)\s*\)""")

# Identifiers too generic to trust as taint carriers — seeding them makes
# every ``value="..."`` attribute or ``url:`` key look tainted. The F6 class
# needs specific names (``repo.description``), not collisions.
GENERIC_NAMES = {
    "value", "url", "href", "src", "id", "name", "key", "data", "text",
    "title", "body", "type", "status", "length", "count", "size", "index",
    "top", "left", "width", "height", "el", "node", "html", "json",
    "item", "items", "current", "target", "onclick", "innerHTML",
    "outerHTML", "className", "blob", "dataStr", "download", "btn", "lang",
    "pid", "sortBy", "searchTerm", "inputVal", "currentLang", "langVal",
    "resetDate", "apiStatusDiv", "scanBtn", "repoSearch", "themeStatus",
    "currentIdx", "breachCount", "aPinned", "bPinned", "targetUpper",
    "innerText", "e", "i", "j", "k", "n", "x", "y", "fn", "cb", "res",
    "req", "err", "a", "b", "r", "l",
}


class ApiXssDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(
        self, context, target: str, method: str, url: str, params: Dict[str, str]
    ) -> List[Finding]:
        try:
            resp = await context.request.get(url, timeout=4000)
            body = (await resp.text()) or ""
        except Exception:
            return []

        chunks: List[tuple] = []  # (js, origin_url)
        for inline in INLINE_SCRIPT_RE.findall(body):
            if inline.strip():
                chunks.append((inline, url))
        origin = urlparse(url).netloc.lower()
        for src in SCRIPT_SRC_RE.findall(body)[:MAX_SCRIPTS]:
            if "?" in src or not src.lower().endswith(".js"):
                continue
            # Only the site's own bundles — third-party CDN code is out of
            # scope for "the site renders attacker data into a sink".
            if urlparse(urljoin(url, src)).netloc.lower() != origin:
                continue
            try:
                js_resp = await context.request.get(urljoin(url, src), timeout=3000)
                js = (await js_resp.text()) or ""
            except Exception:
                js = ""
            if js.strip():
                chunks.append((js, urljoin(url, src)))

        findings: List[Finding] = []
        for js, chunk_url in chunks:
            for sink_name, snippet, source in self._analyze_chunk(js):
                findings.append(
                    self._finding(target, url, chunk_url, sink_name, source, snippet)
                )
                if len(findings) >= MAX_FINDINGS:
                    return findings
        return findings

    # --- pure taint pass (the unit-testable core) ------------------------
    def _analyze_chunk(self, js: str) -> List[tuple]:
        """Return [(sink_name, snippet, source)] for tainted sinks in one chunk."""
        tainted: Dict[str, str] = {}

        def seed(name: str, source: str) -> None:
            if name and name not in tainted and name not in GENERIC_NAMES:
                tainted[name] = source

        for m in VALUE_SEED_RE.finditer(js):
            seed(m.group(1), "param")
        for m in LOCATION_SEED_RE.finditer(js):
            seed(m.group(1), "param")
        for m in FETCH_SEED_RE.finditer(js):
            seed(m.group(1), "api")
        for m in RESPONSE_SEED_RE.finditer(js):
            seed(m.group(1), "api")
        for m in STORAGE_SEED_RE.finditer(js):
            seed(m.group(1), "storage")

        # Catch handlers next to network code can render server/URL-derived
        # error text — taint the catch param as the "error" source.
        for m in CATCH_RE.finditer(js):
            window = js[max(0, m.start() - 400): m.end()]
            if re.search(r"fetch\(|axios|XMLHttpRequest|\bresponse\b|\.value\b", window):
                seed(m.group(1), "error")

        # Fixed-point: assignments and callback params propagate taint.
        for _ in range(TAINT_PASSES):
            changed = False
            for m in ASSIGN_RE.finditer(js):
                lhs, rhs = m.group(1), m.group(2)
                if lhs in tainted:
                    continue
                src = self._taint_source(rhs, tainted)
                if src:
                    tainted[lhs] = src
                    changed = True
            for m in CALLBACK_OBJ_RE.finditer(js):
                obj, param = m.group(1), m.group(2)
                if obj in tainted and param not in tainted:
                    tainted[param] = tainted[obj]
                    changed = True
            # Generic .then(cb => ...) after a tainted promise chain.
            for m in CALLBACK_RE.finditer(js):
                param = m.group(1)
                if param not in tainted and self._taint_source(js[max(0, m.start() - 120): m.start()], tainted):
                    tainted[param] = "api"
                    changed = True
            if not changed:
                break

        hits: List[tuple] = []
        for pattern, sink_name in SINK_PATTERNS:
            for m in pattern.finditer(js):
                arg = m.group(1)
                source = self._arg_source(arg, tainted)
                if source:
                    start = max(0, m.start() - 60)
                    snippet = js[start:min(len(js), m.end() + 60)].replace("\n", " ")[:220]
                    hits.append((sink_name, snippet, source))
        return hits

    @staticmethod
    def _strip_strings(arg: str) -> str:
        """Remove string literals, keeping template ``${...}`` interpolations.

        Identifier matching on the raw argument collides with attribute text
        (``value="all"`` looks like the identifier ``value``). Strip quotes;
        for backtick templates keep only the interpolation expressions.
        """
        arg = re.sub(r"'[^'\\]*(?:\\.[^'\\]*)*'", " ", arg)
        arg = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', " ", arg)
        arg = re.sub(
            r"`[^`]*`",
            lambda m: " ".join(re.findall(r"\$\{([^}]*)", m.group(0))),
            arg,
        )
        return arg

    def _taint_source(self, expr: str, tainted: Dict[str, str]) -> str:
        """Source label if ``expr`` references a tainted identifier, else ""."""
        code = self._strip_strings(expr)
        for name, source in tainted.items():
            if re.search(rf"(?<![\w$.]){re.escape(name)}(?![\w$])", code):
                return source
            # spread/rest syntax: ``[...allRepos]`` — the leading dot defeats
            # the lookbehind above.
            if re.search(rf"\.\.\.{re.escape(name)}(?![\w$])", code):
                return source
        if re.search(r"localStorage|sessionStorage", code):
            return "storage"
        if re.search(r"location\.(search|hash|href)|URLSearchParams", code):
            return "param"
        if re.search(r"fetch\(|axios|XMLHttpRequest|\.json\(\)|\.text\(\)|\bresponse\b|\bres\b|\.data\b", code):
            return "api"
        return ""

    def _arg_source(self, arg: str, tainted: Dict[str, str]) -> str:
        """Does a sink argument reference tainted data that can carry HTML?"""
        code = self._strip_strings(arg)
        # Direct taint tokens in code position (literals already stripped).
        if re.search(r"location\.(search|hash|href)|URLSearchParams", code):
            return "param"
        if re.search(r"localStorage|sessionStorage", code):
            return "storage"
        if re.search(r"fetch\(|axios|XMLHttpRequest|\bresponse\b|\bres\b", code):
            return "api"

        for name, source in tainted.items():
            # property access on a tainted object: x.field — flag unless the
            # field is provably numeric (length/count/id ...).
            for pm in re.finditer(rf"(?<![\w$.]){re.escape(name)}\.([A-Za-z_$][\w$]*)", code):
                field = pm.group(1).lower()
                if field not in NUMERIC_FIELDS:
                    return source
            # bare reference to a user-input seed (e.g. a URL fragment used
            # directly) or an error object (renders .message) is a sink hit;
            # bare references to API objects are "[object Object]" noise.
            if source in ("param", "error") and re.search(
                rf"(?<![\w$.]){re.escape(name)}(?![\w$])", code
            ):
                return source
        return ""

    def _finding(self, target, url, chunk_url, sink_name, source, snippet) -> Finding:
        severity = Severity.HIGH if source in ("api", "param") else Severity.MEDIUM
        return Finding(
            target=target,
            url=url,
            method="GET",
            param="api-dom-sink",
            location="client",
            payload=f"DOM XSS candidate: {sink_name} sink fed by {source}-controlled data",
            attack_type=AttackType.DOM_XSS,
            severity=severity,
            verified=False,
            confidence=0.6,
            status=200,
            body="",
            diffs=[f"apixss:sink:{sink_name}", f"apixss:source:{source}"],
            verification_body="",
            verification_status=200,
            metadata={
                "sink": sink_name,
                "source": source,
                "bundle": chunk_url,
                "snippet": snippet,
                "confirm": "replay in browser with a route-intercepted payload to upgrade tier",
            },
            tags=["clientside", "dom-xss", "static", "api-fed"],
            notes=(
                f"Static taint: {source}-controlled data flows into a {sink_name} "
                f"sink in {chunk_url}. Candidate only — browser verification "
                "(DomXSSDetector marker or route-intercept replay) is required "
                "to upgrade from suspicious to confirmed."
            ),
        )
