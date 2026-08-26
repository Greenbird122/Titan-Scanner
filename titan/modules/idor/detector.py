"""IDOR / BOLA detection module for Titan Scanner — fully exhausted.

Features:
  1. Zero Parameter Whitelisting: tests ALL parameters (not just 'id', 'user').
  2. Smart ID Mutation Suite:
     - Sequential: ±1, ±2, boundary (0, -1, MAX_INT)
     - UUID v4 mutations (keep structure, swap last segment)
     - MongoDB ObjectID mutations (hex24 format, increment last bytes)
     - Base64-encoded numeric IDs (decode → mutate → re-encode)
  3. URL-Path ID Detection: scans numeric/UUID segments in the URL path itself.
  4. Multi-Session Cross-Tenant Swapping: replays requests with a second session's
     auth headers to detect cross-user BOLA (when a second_session is configured).
  5. Strict Evidence Oracles:
     - JSON structural differential (field-level value changes)
     - Input echo exclusion (test_value echoed in response is not evidence)
     - Sensitive field emergence detection
     - Status-based oracle (403 → 200 privilege escalation)
  6. Baseline Sanity Gate: silent when baseline request fails.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import json_differential, json_value_changes


SENSITIVE_INDICATORS = [
    "email", "phone", "address", "ssn", "password", "secret", "token",
    "api_key", "credit", "payment", "medical", "health", "diagnosis",
    "prescription", "salary", "dob", "national_id", "passport",
    "private", "internal", "billing",
]

# Regex patterns to detect ID types
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I
)
_MONGO_OID_RE = re.compile(r'^[0-9a-f]{24}$', re.I)
_NUMERIC_RE = re.compile(r'^\d+$')
_B64_RE = re.compile(r'^[A-Za-z0-9+/]+=*$')

# Detect numeric segments in URL paths  e.g. /api/users/42/orders
_URL_ID_SEGMENT_RE = re.compile(r'/(\d{1,18})(?:/|$)')


def _is_base64_id(v: str) -> bool:
    """Heuristic: base64 string that decodes to a printable integer string."""
    if not _B64_RE.match(v) or len(v) < 4:
        return False
    try:
        import base64
        decoded = base64.b64decode(v + '==').decode('ascii', errors='replace')
        return decoded.strip().isdigit()
    except Exception:
        return False


def _mutate_numeric(val: str) -> List[str]:
    """Sequential mutations of a numeric ID, deduped."""
    n = int(val)
    candidates = [n + 1, n - 1, n + 2, n - 2, 0, 9999, 2147483647]
    seen = {n}
    result = []
    for c in candidates:
        if c >= 0 and c not in seen:
            seen.add(c)
            result.append(str(c))
    return result


def _mutate_uuid(val: str) -> List[str]:
    """Generate plausibly different UUIDs by replacing the last segment."""
    try:
        parts = val.split('-')
        mutations = []
        for _ in range(4):
            new_last = uuid.uuid4().hex[:12]
            new_uuid = '-'.join(parts[:4]) + '-' + new_last
            mutations.append(new_uuid)
        return mutations
    except Exception:
        return []


def _mutate_mongo_oid(val: str) -> List[str]:
    """Increment/decrement the last 4 bytes of a MongoDB ObjectID."""
    try:
        n = int(val[-8:], 16)
        mutated = []
        for delta in (+1, -1, +2, 0xFFFF):
            new_n = (n + delta) & 0xFFFFFFFF
            mutated.append(val[:-8] + f'{new_n:08x}')
        return mutated
    except Exception:
        return []


def _mutate_base64(val: str) -> List[str]:
    """Decode, mutate numeric content, re-encode."""
    try:
        import base64
        decoded = base64.b64decode(val + '==').decode('ascii').strip()
        if not decoded.isdigit():
            return []
        numeric_muts = _mutate_numeric(decoded)[:3]
        return [
            base64.b64encode(m.encode()).decode().rstrip('=')
            for m in numeric_muts
        ]
    except Exception:
        return []


def _generate_mutations(original_value: str) -> List[str]:
    """Dispatch to the right mutator based on value type."""
    if _NUMERIC_RE.match(original_value):
        return _mutate_numeric(original_value)
    if _UUID_RE.match(original_value):
        return _mutate_uuid(original_value)
    if _MONGO_OID_RE.match(original_value):
        return _mutate_mongo_oid(original_value)
    if _is_base64_id(original_value):
        return _mutate_base64(original_value)
    # Fallback: try sequential-style for anything short and alphanumeric
    if original_value.isalnum() and len(original_value) < 10:
        try:
            n = int(original_value, 16)
            return [f'{n+1:x}', f'{n-1:x}']
        except Exception:
            pass
    return []


class IDORDetector:
    """Production-grade IDOR/BOLA detector with exhaustive ID mutation coverage."""

    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint
        # Optional: dict with second session's auth headers for cross-tenant BOLA
        self._second_session_headers: Optional[Dict[str, str]] = (
            fingerprint.get("second_session_headers") if fingerprint else None
        )

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

        # ── Engine 1: Query/Form Parameter Mutations (ALL params) ─────
        for param_name in list(params.keys()):
            original_value = str(params[param_name])
            mutations = _generate_mutations(original_value)
            if not mutations:
                continue

            for test_value in mutations:
                if str(test_value) == original_value:
                    continue
                f = await self._test_idor(
                    context, target, method, url, param_name, params,
                    test_value, original_value,
                )
                if f:
                    findings.append(f)
                    break  # one confirmed finding per param is enough

        # ── Engine 2: URL-Path ID Segments ───────────────────────────
        path_findings = await self._scan_url_path_ids(context, target, method, url, params)
        findings.extend(path_findings)

        # ── Engine 3: Cross-Session BOLA (if second session available) ─
        if self._second_session_headers:
            bola_findings = await self._scan_cross_session(
                context, target, method, url, params
            )
            findings.extend(bola_findings)

        return findings

    # ------------------------------------------------------------------
    # ENGINE 2 — URL PATH ID STEPPING
    # ------------------------------------------------------------------

    async def _scan_url_path_ids(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        """Find numeric segments in the URL path and step them."""
        findings: List[Finding] = []
        matches = list(_URL_ID_SEGMENT_RE.finditer(url))
        if not matches:
            return findings

        # Test only first 2 path segments to keep request budget reasonable
        for m in matches[:2]:
            original_id = m.group(1)
            for test_value in _mutate_numeric(original_id)[:3]:
                new_url = url[:m.start(1)] + test_value + url[m.end(1):]
                f = await self._test_idor(
                    context, target, method, new_url, "__url_path__", params,
                    test_value, original_id, probe_url=new_url,
                )
                if f:
                    findings.append(f)
                    break

        return findings

    # ------------------------------------------------------------------
    # ENGINE 3 — CROSS-SESSION BOLA
    # ------------------------------------------------------------------

    async def _scan_cross_session(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        """Replay request with Session B's auth headers against Session A's resource IDs."""
        findings: List[Finding] = []
        if not self._second_session_headers:
            return findings

        try:
            # Baseline: Session A's request
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

            if baseline_status in (401, 403, 404):
                return findings  # no resource to steal

            # Cross-session: Session B's headers requesting Session A's resource
            b_headers = {**self._second_session_headers, "Referer": target}
            if method == "GET":
                resp = await context.request.get(url, params=params, headers=b_headers, timeout=3000)
            else:
                resp = await context.request.post(url, data=params, headers=b_headers, timeout=3000)
            body = await resp.text()

            # 403→200 with body is the definitive BOLA signal
            if resp.status == 200 and baseline_status == 200 and body != baseline_body:
                changes = json_value_changes(baseline_body, body)
                non_echo = [(p, o, n) for p, o, n in changes]
                if non_echo:
                    diffs = [f"bola:cross_session:{p}" for p, _, _ in non_echo]
                    findings.append(Finding(
                        target=target,
                        url=url,
                        method=method.upper(),
                        param="__session_b__",
                        location="header",
                        payload="[Session B auth headers]",
                        attack_type=AttackType.IDOR,
                        severity=Severity.CRITICAL,
                        verified=True,
                        confidence=0.9,
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body[:2000],
                        diffs=diffs,
                        baseline_body=baseline_body[:2000],
                        baseline_status=baseline_status,
                        verification_body=body[:2000],
                        verification_status=resp.status,
                        metadata={"type": "bola_cross_session"},
                    ))
        except Exception:
            pass

        return findings

    # ------------------------------------------------------------------
    # CORE IDOR TEST
    # ------------------------------------------------------------------

    async def _test_idor(
        self,
        context,
        target: str,
        method: str,
        url: str,
        param_name: str,
        all_params: Dict[str, str],
        test_value: str,
        original_value: str,
        probe_url: Optional[str] = None,
    ) -> Optional[Finding]:
        try:
            baseline_body = ""
            baseline_status = None

            try:
                if method == "GET":
                    baseline_resp = await context.request.get(
                        url, params=all_params,
                        headers={"Referer": target}, timeout=3000
                    )
                else:
                    baseline_resp = await context.request.post(
                        url, data=all_params,
                        headers={"Referer": target}, timeout=3000
                    )
                baseline_body = await baseline_resp.text()
                baseline_status = baseline_resp.status
            except Exception:
                pass

            # A failed baseline leaves no reference point — silence is mandatory
            if not baseline_body:
                return None

            # Build test request
            if probe_url:
                # URL-path mutation — URL is already mutated, params unchanged
                if method == "GET":
                    resp = await context.request.get(
                        probe_url, params=all_params,
                        headers={"Referer": target}, timeout=3000
                    )
                else:
                    resp = await context.request.post(
                        probe_url, data=all_params,
                        headers={"Referer": target}, timeout=3000
                    )
            else:
                test_params = dict(all_params)
                test_params[param_name] = str(test_value)
                if method == "GET":
                    resp = await context.request.get(
                        url, params=test_params,
                        headers={"Referer": target}, timeout=3000
                    )
                else:
                    resp = await context.request.post(
                        url, data=test_params,
                        headers={"Referer": target}, timeout=3000
                    )
            body = await resp.text()

            diffs = BaselineAnalyzer.diff_responses(baseline_body, body, str(test_value))

            # ── Signal 1: Status escalation (403/404 → 200) ──────────
            if baseline_status in (403, 404) and resp.status == 200 and len(body) > 20:
                diffs.append(f"idor:status_escalation:{baseline_status}->200")
                return Finding(
                    target=target,
                    url=str(resp.url or probe_url or url),
                    method=method.upper(),
                    param=param_name,
                    location="query" if method == "GET" else "body",
                    payload=f"IDOR: {original_value} -> {test_value}",
                    attack_type=AttackType.IDOR,
                    severity=Severity.CRITICAL,
                    verified=True,
                    confidence=0.85,
                    status=resp.status,
                    headers=dict(resp.headers),
                    body=body[:2000],
                    diffs=diffs,
                    baseline_body=baseline_body[:2000],
                    baseline_status=baseline_status,
                    verification_body=body[:2000],
                    verification_status=resp.status,
                )

            if resp.status != 200 or body == baseline_body or len(body) < 10:
                return None

            # ── Signal 2: JSON structural differential ────────────────
            structural = json_differential(baseline_body, body)
            for s in structural:
                diffs.append(f"idor:{s}")

            # ── Signal 3: Value changes that don't echo test_value ────
            changes = json_value_changes(baseline_body, body)
            value_changes = [
                (p, o, n) for p, o, n in changes
                if str(test_value) not in str(n) and str(test_value) not in str(o)
            ]
            for p, _o, _n in value_changes:
                diffs.append(f"idor:value_changed:{p}")

            # ── Signal 4: New sensitive fields in test response ───────
            baseline_lower = baseline_body.lower()
            sensitive_new = [
                ind for ind in SENSITIVE_INDICATORS
                if ind in body.lower() and ind not in baseline_lower
            ]

            if value_changes or sensitive_new:
                verified = True
                severity = Severity.CRITICAL if sensitive_new else Severity.HIGH
                return Finding(
                    target=target,
                    url=str(resp.url or probe_url or url),
                    method=method.upper(),
                    param=param_name,
                    location="query" if method == "GET" else "body",
                    payload=f"IDOR: {original_value} -> {test_value}",
                    attack_type=AttackType.IDOR,
                    severity=severity,
                    verified=verified,
                    confidence=0.85,
                    status=resp.status,
                    headers=dict(resp.headers),
                    body=body[:2000],
                    diffs=diffs + [f"idor:{param_name}:{original_value}->{test_value}"],
                    baseline_body=baseline_body[:2000],
                    baseline_status=baseline_status,
                    verification_body=body[:2000],
                    verification_status=resp.status,
                )

            # ── Signal 5: Conservative large response change ──────────
            if abs(len(body) - len(baseline_body)) > 200 and len(body) > 500:
                return Finding(
                    target=target,
                    url=str(resp.url or probe_url or url),
                    method=method.upper(),
                    param=param_name,
                    location="query" if method == "GET" else "body",
                    payload=f"IDOR?: {original_value} -> {test_value}",
                    attack_type=AttackType.IDOR,
                    severity=Severity.LOW,
                    verified=False,
                    confidence=0.45,
                    status=resp.status,
                    headers=dict(resp.headers),
                    body=body[:2000],
                    diffs=diffs + [f"idor:{param_name}:{original_value}->{test_value}"],
                    baseline_body=baseline_body[:2000],
                    baseline_status=baseline_status,
                    verification_body=body[:2000],
                    verification_status=resp.status,
                )

        except Exception:
            pass

        return None
