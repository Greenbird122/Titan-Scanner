"""Evidence oracles for vulnerability confirmation.

Turns raw response comparison into *typed, weighted evidence*. Instead of a
detector asking "does the body contain 'root:'?", it collects named signals
(reflection, error class, structural change, timing, OOB) and the scorer
combines them into a confidence score and a verified/unverified verdict.

This is the differential-confirmation layer: the payload is a *hypothesis*,
the oracles produce *evidence*, and the score decides how much to trust it.
"""

from __future__ import annotations

import html
import json
import re
from difflib import SequenceMatcher
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import quote, quote_plus, unquote, unquote_plus


# ─── Error-class extraction ─────────────────────────────────────────────────
# Error classes are *behavioral* signatures: they indicate the parameter
# reached a dangerous sink (SQL interpreter, filesystem, XML parser, shell),
# not which specific payload triggered it. Framework-agnostic.

ERROR_CLASSES: Dict[str, List[str]] = {
    "sql": [
        r"sql\s+syntax", r"mysql_fetch", r"ora-\d{4,5}", r"postgresql",
        r"sqlstate", r"unclosed quotation mark", r"quoted string not properly terminated",
        r"you have an error in your sql syntax", r"warning:\s+mysql",
        r"pg_query", r"sqlite3\.", r"operationalerror", r"npsql",
    ],
    "filesystem": [
        r"errno\s+\d+", r"no such file or directory", r"file not found",
        r"cannot open", r"permission denied", r"access is denied",
        r"system cannot find", r"filenotfounderror", r"permissionerror",
        r"isadirectoryerror", r"path does not exist", r"no such file",
        r"not a directory", r"directory not found",
    ],
    "xml": [
        r"parser error", r"not well-formed", r"xml parsing",
        r"javax\.xml", r"org\.xml", r"libxml", r"entity expansion",
        r"saxparseexception", r"failed to parse xml", r"xml\s+error",
    ],
    "java": [
        r"java\.lang\.[a-z]+exception", r"exception in thread",
        r"at\s+[a-z_][\w.$]*\.\w+\(", r"servlet", r"springframework",
        r"stacktrace", r"stack trace", r"catalina",
    ],
    "python": [
        r"traceback \(most recent call last\)", r"filenotfounderror",
        r"valueerror", r"typeerror", r"attributeerror", r"keyerror",
        r"indexerror", r"zerodivisionerror", r"\bline \d+.*\berror",
    ],
    "generic": [
        r"internal server error", r"500 internal", r"server error",
        r"unhandled exception", r"exception occurred", r"nullreferenceexception",
        r"stack trace", r"segmentation fault", r"fatal error",
    ],
}

_ERROR_CACHE: Dict[str, re.Pattern] = {}


def _compile(pattern: str) -> re.Pattern:
    if pattern not in _ERROR_CACHE:
        _ERROR_CACHE[pattern] = re.compile(pattern, re.IGNORECASE)
    return _ERROR_CACHE[pattern]


def extract_error_classes(body: str) -> List[str]:
    """Return the list of error classes (sql, filesystem, xml, ...) present in a body."""
    if not body:
        return []
    lower = body.lower()
    found: List[str] = []
    for name, patterns in ERROR_CLASSES.items():
        for pattern in patterns:
            try:
                if _compile(pattern).search(lower):
                    found.append(name)
                    break
            except re.error:
                continue
    return found


def extract_new_error_classes(baseline_body: str, test_body: str) -> List[str]:
    """Return error classes that appear in the test response but NOT in the
    baseline response. This is the baseline-diffing oracle: if the page's own
    JavaScript contains "exception" or "java" (Moodle YUI, React, Angular),
    those are baseline noise and must never confirm an injection.

    The absolute matcher above is kept for backward compatibility with tests
    that call it directly, but detectors should use this diffing version when
    a baseline is available.
    """
    if not test_body:
        return []
    # If the response is byte-identical to the baseline, the payload had no
    # effect — no error class signal should fire, even if the baseline itself
    # contains error-like strings (Moodle YUI "exception", React "java",
    # Angular "error"). This is the single fix that kills the baseline-
    # contamination false positive class.
    if baseline_body and test_body == baseline_body:
        return []
    baseline_classes = set(extract_error_classes(baseline_body)) if baseline_body else set()
    test_classes = set(extract_error_classes(test_body)) if test_body else set()
    return list(test_classes - baseline_classes)


def is_baseline_identical(baseline_body: str, test_body: str) -> bool:
    """Return True if the test response is byte-identical to the baseline.

    Detectors should check this BEFORE generating any signal: a payload that
    produces the exact same response as the benign baseline had no effect on
    the server and cannot be a finding.
    """
    return bool(baseline_body) and bool(test_body) and baseline_body == test_body


# ─── Structural JSON differential ────────────────────────────────────────────

def json_differential(baseline_body: str, test_body: str) -> List[str]:
    """Structural diff between two JSON documents.

    Returns typed signals: ``json:value_changed:path`` (strongest),
    ``json:key_added/removed`` (schema change / not-found record),
    ``json:length_changed``, ``json:type_changed``.
    """
    try:
        baseline = json.loads(baseline_body)
        test = json.loads(test_body)
    except Exception:
        return []
    signals: List[str] = []

    def walk(bv: Any, tv: Any, path: str = "<root>") -> None:
        if type(bv) is not type(tv):
            signals.append(f"json:type_changed:{path}")
            return
        if isinstance(bv, dict):
            b_keys, t_keys = set(bv), set(tv)
            for k in sorted(b_keys - t_keys):
                signals.append(f"json:key_removed:{path}.{k}")
            for k in sorted(t_keys - b_keys):
                signals.append(f"json:key_added:{path}.{k}")
            for k in sorted(b_keys & t_keys):
                if bv[k] != tv[k]:
                    if isinstance(bv[k], (dict, list)):
                        walk(bv[k], tv[k], f"{path}.{k}")
                    else:
                        signals.append(f"json:value_changed:{path}.{k}")
        elif isinstance(bv, list):
            if len(bv) != len(tv):
                signals.append(f"json:length_changed:{path}")
            else:
                for i, (x, y) in enumerate(zip(bv, tv)):
                    if x != y:
                        walk(x, y, f"{path}[{i}]")

    walk(baseline, test)
    return signals


def json_value_changes(baseline_body: str, test_body: str) -> List[Tuple[str, Any, Any]]:
    """Return ``(path, old_value, new_value)`` for every scalar field whose
    value changed between two JSON documents.

    Unlike :func:`json_differential` (which only reports paths), this exposes
    the values so callers can distinguish *record data* changes from *input
    echo* (e.g. a ``query`` field that simply reflects the injected id).
    """
    try:
        baseline = json.loads(baseline_body)
        test = json.loads(test_body)
    except Exception:
        return []
    changes: List[Tuple[str, Any, Any]] = []

    def walk(bv: Any, tv: Any, path: str = "<root>") -> None:
        if type(bv) is not type(tv):
            return
        if isinstance(bv, dict):
            for k in sorted(set(bv) & set(tv)):
                p = f"{path}.{k}"
                if bv[k] != tv[k]:
                    if isinstance(bv[k], (dict, list)):
                        walk(bv[k], tv[k], p)
                    else:
                        changes.append((p, bv[k], tv[k]))
        elif isinstance(bv, list) and len(bv) == len(tv):
            for i, (x, y) in enumerate(zip(bv, tv)):
                if x != y:
                    walk(x, y, f"{path}[{i}]")

    walk(baseline, test)
    return changes


# ─── Evidence scoring ────────────────────────────────────────────────────────
# Noisy-OR combination: confidence = 1 - product(1 - weight). A single strong
# signal (OOB hit, file-content leak) is sufficient to *verify*; stacking weak
# signals raises confidence without ever crossing into "verified" on its own.

WEIGHTS: Dict[str, float] = {
    "oob_confirmed": 1.0,       # out-of-band callback observed — conclusive
    "content_leak": 0.9,        # known file/secret content appeared in body
    "sanity_pair": 0.85,        # positive vs negative control differ → boolean oracle
    "time_delay": 0.85,         # statistical timing deviation
    "error:sql": 0.9,           # parameter reached a SQL interpreter
    "error:filesystem": 0.8,    # parameter reached a filesystem sink
    "error:xml": 0.8,           # parameter reached an XML parser
    "error:java": 0.7,
    "error:python": 0.65,
    "error:generic": 0.5,
    "reflection": 0.6,          # payload echoed back (injection point confirmed)
    "xss_unescaped": 0.9,       # <script> payload echoed with raw angle brackets — direct XSS
    "json_structure": 0.6,      # structural change across two identifiers (IDOR)
    "error:template": 0.75,     # template engine error class (jinja2, twig, freemarker, ...)
    "status_500": 0.45,
    "content_change": 0.25,     # weak: body differs, nothing specific
}

STRONG_SIGNALS = {
    "oob_confirmed", "content_leak", "sanity_pair", "time_delay",
    "error:sql", "error:filesystem", "error:xml", "xss_unescaped",
}

# After stripping the echoed payload/opposite from two response bodies, how
# similar may the residue be before we call it page noise instead of a real
# boolean differential? Real pages that reflect params (GitHub login/signup)
# also carry per-request random tokens (session hashes, CSRF nonces, analytics
# payloads) — a tiny token-level residue in a large body. A GENUINE boolean
# differential (error page vs normal page, different row sets) flips
# substantial content. Above this ratio the residue is noise: the sanity-pair
# oracle must not confirm an injection on it.
ECHO_NOISE_RATIO = 0.95


def payload_encodings(payload: str) -> List[str]:
    """All the ways a server can reflect a submitted value back into a
    response body: raw, fully/minimally URL-encoded, plus-as-space, and
    HTML-entity-escaped. Longest form first so nested encodings strip fully.

    Nested/double-encoded forms are included: a SPA that embeds the request
    URL in its JS state re-encodes the query string, so a submitted URL can
    come back as ``http%253A%252F%252F169.254...`` (each ``%`` -> ``%25``).
    GitHub's branded 404 page does exactly this — a single-level strip left
    the markers alive inside the nested echo and self-verified 12 CRITICAL
    SSRF findings against dead routes.

    Used to peel reflections before checking for content leaks — an app that
    merely echoes the injected URL back (e.g. into a 404 page title) must
    never self-verify an SSRF content leak via markers inside its own echo.
    """
    forms = {
        payload,
        unquote(payload),
        unquote_plus(payload),
        html.unescape(payload),
        quote(payload, safe=""),
        quote(payload, safe=":/?&="),
        # Browsers/API clients encode query values with quote_plus (space ->
        # '+'), NOT quote (space -> %20). The wire form of a probe that
        # already contains '%' (e.g. the CL.TE payload) is
        # test%250d%250a...X-Test%3A+true — missing this shape leaves the
        # whole encoded echo unstripped (github.com /login smuggling FP).
        quote_plus(payload, safe=""),
        quote_plus(payload, safe=":/?&="),
        html.escape(payload),
        html.escape(payload, quote=True),
    }
    # Second encoding layer: SPA JS state re-encodes the full query string.
    nested = set()
    for form in list(forms):
        nested.add(quote(form, safe=""))
        nested.add(quote(form, safe=":/?&="))
        nested.add(quote_plus(form, safe=""))
        nested.add(quote_plus(form, safe=":/?&="))
        nested.add(html.escape(form, quote=True))
    forms |= nested
    return sorted(forms, key=len, reverse=True)


def is_echo_differential(test_body: str, opp_body: str, payload: str, opposite: str) -> bool:
    """Return True if the *only* JSON-level difference between two response
    bodies is the echoed payload/opposite strings themselves (i.e. no record
    or structure change beyond reflection of input).

    This handles JSON escaping: if the server wraps the payload in
    ``json.dumps()`` inner double-quotes become ``\"`` and a naive
    ``body.replace(payload, "")`` would silently miss them.

    When either body is not parseable as JSON the function falls back to a
    simple string-replace comparison — sufficient for HTML/text responses.
    """
    try:
        a = json.loads(test_body)
        b = json.loads(opp_body)
    except (json.JSONDecodeError, ValueError, TypeError):
        # Not JSON — use string replace (adequate for HTML/text errors).
        # Normalize BOTH bodies and payload strings: servers reflect query
        # params URL-ENCODED (%27+OR+1%3D1--) and/or HTML-ESCAPED (&#39;), so a
        # naive compare sees a "difference" that is only an encoding of the
        # same echo and would confirm a sanity pair that never fired (the
        # real-site false-positive storms).
        norm_test = html.unescape(unquote_plus(test_body))
        norm_opp = html.unescape(unquote_plus(opp_body))
        p = html.unescape(unquote_plus(payload))
        o = html.unescape(unquote_plus(opposite))
        # No reflection of the payload (or its opposite) at all: any body
        # difference is page noise (CSRF tokens, session nonces, cache
        # busting), NOT an injection signal — a boolean oracle needs the
        # parameter to reach somewhere visible. Skip instead of confirming.
        # This is what killed the ctflearn /user/login storm: a Django login
        # page with per-request CSRF tokens and zero reflection.
        if p not in norm_test and o not in norm_opp:
            return True
        t = norm_test.replace(p, "")
        o2 = norm_opp.replace(o, "")
        if t == o2:
            return True
        # The payload IS reflected but a residue remains. Two very different
        # cases hide here: (a) page noise — real pages that reflect params
        # (GitHub login/signup reflect return_to in form actions and hidden
        # fields) also carry per-request random tokens, which is NOT an
        # injection signal; (b) a genuine boolean differential, which flips
        # substantial content. Only (b) may confirm. Measure the residue: if
        # the two cleaned bodies are near-identical, the difference is
        # token-level noise (GitHub login storm: 12 CRITICAL SQLi/NoSQLi/SSRF
        # on reflected params + nonces).
        if t and o2 and SequenceMatcher(None, t, o2).ratio() > ECHO_NOISE_RATIO:
            return True
        return False

    def _is_echo_only(a_val: Any, b_val: Any) -> bool:
        """Recursively check whether every value difference between ``a_val``
        and ``b_val`` is attributable to the payload/opposite strings."""
        if type(a_val) != type(b_val):
            return False
        if isinstance(a_val, dict):
            if set(a_val.keys()) != set(b_val.keys()):
                return False
            for k in a_val:
                if a_val[k] != b_val[k]:
                    sa, sb = str(a_val[k]), str(b_val[k])
                    if (payload not in sa and opposite not in sb) and (opposite not in sa and payload not in sb):
                        return False
                    if not _is_echo_only(a_val[k], b_val[k]):
                        return False
            return True
        if isinstance(a_val, list):
            if len(a_val) != len(b_val):
                return False
            for i in range(len(a_val)):
                if a_val[i] != b_val[i]:
                    sa, sb = str(a_val[i]), str(b_val[i])
                    if (payload not in sa and opposite not in sb) and (opposite not in sa and payload not in sb):
                        return False
                    if not _is_echo_only(a_val[i], b_val[i]):
                        return False
            return True
        # Scalars: payload/opposite strings in either value = echo
        sa, sb = str(a_val), str(b_val)
        return payload in sa or opposite in sa or payload in sb or opposite in sb

    return _is_echo_only(a, b)


def score_signals(signals: Iterable[str]) -> Tuple[float, bool, List[str]]:
    """Combine evidence signals into (confidence, verified, matched).

    Duplicate signals are deduped: noisy-OR must not count the same evidence
    twice (e.g. two detectors both reporting ``reflection``).
    """
    matched = list(dict.fromkeys(s for s in signals if s in WEIGHTS))
    if not matched:
        return 0.0, False, []
    p = 1.0
    for s in matched:
        p *= 1.0 - WEIGHTS[s]
    confidence = round(1.0 - p, 3)
    verified = any(s in STRONG_SIGNALS for s in matched)
    return confidence, verified, matched


# ─── Evidence grading (SCAN-QUALITY M1) ──────────────────────────────────────
# A finding's ``verified`` flag is only as honest as the diff strings that
# back it. The injection-family detectors verify exclusively through a small
# set of strong oracle signals (content leak, boolean sanity pair, timing
# delay, unique-marker reflection, parser error), each of which appends a diff
# carrying the marker below. When a finding is marked verified but its diffs
# name NONE of them, it was verified off reflection/echo alone — the exact
# failure that produced 21 identical "CRITICAL LFI" findings on a Next.js
# catch-all that echoed the query string.

# Attack classes that must carry a named strong oracle marker before the
# "verified" label is trusted. Every other class (headers, crypto, idor,
# cors, ...) verifies through its own typed evidence and is graded but never
# auto-demoted.
INJECTION_ATTACK_TYPES = frozenset({
    "LFI", "SQLi", "NoSQLi", "SSRF", "XSS", "RCE", "SSTI", "XXE",
    "Request Smuggling", "Open Redirect", "OOB", "Deserialization",
})

# Substrings that identify a strong oracle marker inside a finding's diff
# list. Verified but missing all of these = weak evidence.
STRONG_DIFF_MARKERS = (
    "content_leak", "content:", "sanity_pair", "boolean_confirmed",
    "time_delay", "marker_reflected", "math_eval", "xss_unescaped",
    "error:sql", "error:filesystem", "error:xml", "error_class:sql",
    "error_class:filesystem", "error_class:xml", "oob",
)


def grade_finding(finding) -> str:
    """Evidence grade for a single finding (does not mutate it).

    ``confirmed`` — a named strong oracle marker sits in the diffs AND the
    finding is verified (the only way the injection detectors are allowed to
    verify). Non-injection classes (headers, crypto, idor, ...) verify
    through their own typed evidence, so a verified flag is ``confirmed`` by
    construction for them.
    ``corroborated`` — injection-family, marked verified but no strong marker
    named; the label outran its evidence.
    ``indicative`` — weak signals only (reflection, content change, status),
    or a strong marker present on an UNVERIFIED finding (a detector
    inconsistency — a strong oracle that did not verify must never read as
    ``confirmed`` in the report).
    ``none`` — no scored evidence.
    """
    joined = " ".join(finding.diffs or []).lower()
    strong = any(m in joined for m in STRONG_DIFF_MARKERS)
    is_injection = (
        finding.attack_type is not None
        and finding.attack_type.value in INJECTION_ATTACK_TYPES
    )
    if not is_injection:
        # Non-injection classes have their own typed evidence standard — the
        # verified flag is ``confirmed`` by construction, never "corroborated"
        # (which would read as weak/demoted in the report's evidence column).
        if finding.verified:
            return "confirmed"
        if finding.confidence and finding.confidence >= 0.3:
            return "indicative"
        return "none"
    if finding.verified:
        return "confirmed" if strong else "corroborated"
    if strong:
        return "indicative"
    if finding.confidence and finding.confidence >= 0.3:
        return "indicative"
    return "none"


def enforce_evidence(findings: list) -> Dict[str, int]:
    """Attach an evidence grade to every finding and auto-demote weak ones.

    Demotion rule (SCAN-QUALITY spec D9): an injection-family finding marked
    ``verified`` whose diffs name no strong oracle marker is demoted to
    unverified and its severity capped at MEDIUM — reflection alone never
    verifies. Returns ``{"graded": n, "demoted": n, "capped": n}``.
    """
    from titan.core.models import Severity
    stats: Dict[str, int] = {"graded": 0, "demoted": 0, "capped": 0, "suspicious": 0}
    for f in findings:
        grade = grade_finding(f)
        f.evidence = grade
        stats["graded"] += 1
        demoted = False
        if (
            f.verified
            and f.attack_type is not None
            and f.attack_type.value in INJECTION_ATTACK_TYPES
            and grade != "confirmed"
        ):
            f.verified = False
            f.metadata["evidence_demotion"] = (
                f"verified but diffs name no strong oracle marker (grade={grade})"
            )
            stats["demoted"] += 1
            demoted = True
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                f.severity = Severity.MEDIUM
                stats["capped"] += 1
        # PUSH-TO-100 A1 tier: confirmed = verified AND not demoted AND the
        # grade is genuinely strong (for injection classes, a named strong
        # marker; for non-injection classes, the verified flag itself is the
        # typed-evidence standard). Everything with a weak/behavioral signal
        # is `suspicious`; nothing else is `none`.
        if grade == "confirmed" and f.verified and not demoted:
            f.tier = "confirmed"
        elif grade in ("corroborated", "indicative"):
            f.tier = "suspicious"
            stats["suspicious"] += 1
        else:
            f.tier = ""
    return stats
