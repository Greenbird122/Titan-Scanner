"""PUSH-TO-100 B3 — parser-differential detector (the novel class).

The home of a large fraction of real 0-days: TWO PARSERS DISAGREEING ON THE
SAME BYTES. A WAF / input filter / proxy parses a request one way and the
origin parses it another. When the plain payload is filtered or neutral but
an ENCODED form of the same logical bytes reaches a sink oracle (a SQL
interpreter, a filesystem reader, an XML parser, unescaped markup), that is
proof two parsers disagreed — the filter saw benign bytes, the origin
decoded them into the dangerous form.

How it works per injection-class param:

  1. Baseline probe (the discovered value) — establishes the neutral response.
  2. Plain payload probe — usually filtered/neutral (that's why rulebook
     detectors miss these targets) or already caught elsewhere.
  3. Encoded variants — double-URL, HTML-entity, unicode-normalized, mixed
     case, null-byte. Same logical bytes, different wire forms.

A PARSER DIFFERENTIAL fires when the plain form yields NO strong oracle but
an encoded variant DOES (a new sink error class, a content-leak marker, or
unescaped reflection). That finding is ``verified=True`` -> ``confirmed``
tier (scored, repro'd). A weaker differential (status/length only) stays
``suspicious``.

Pure logic lives in classify_parser_differential so the tests pin exactly
what the engine's detector uses.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from titan.core.models import AttackType, Finding, Severity
from titan.verify.oracles import extract_error_classes

# (label, builder) encoding dictionary. Each takes a plain payload and yields
# a wire form a different parser might decode differently.
ENCODINGS: List[Tuple[str, Any]] = []


def _encodings(payload: str) -> List[Tuple[str, str]]:
    """Bounded set of (label, encoded) variants for a payload.

    Each variant is the SAME logical bytes with different wire encoding — the
    exact disagreement surface between a filter layer and an origin.
    """
    out: List[Tuple[str, str]] = []
    if not payload:
        return out
    q = quote(payload, safe="")
    out.append(("double-url", quote(q, safe="")))
    out.append(("html-entity", payload.replace("<", "&lt;").replace(">", "&gt;")
                .replace('"', "&quot;")))
    # Unicode normalization: full-width / lookalike characters parse
    # identically after normalization in many stacks.
    out.append(("fullwidth", "".join(
        chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in payload
    )))
    # Mixed case (for case-insensitive keyword filters).
    out.append(("mixed-case", "".join(
        c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)
    )))
    # Null-byte terminator: many C-based filters stop at \x00, the parser
    # keeps going.
    out.append(("null-byte", payload + "\x00"))
    # Tab/newline inside the payload: some filters match single-line regexes.
    out.append(("tab", payload.replace(" ", "\t")))
    out.append(("newline", payload.replace(" ", "\n")))
    return out


# Canonical payload per injection class (the plain form is usually filtered —
# that's the point — so rulebook detectors never see these targets reachable).
CLASS_PAYLOADS: List[Tuple[str, str]] = [
    ("lfi", "../../../etc/passwd"),
    ("sqli", "' OR 1=1--"),
    ("xss", "<script>alert(1)</script>"),
    ("ssti", "{{7*7}}"),
    ("ssrf", "http://169.254.169.254/latest/meta-data/"),
]

# Error classes that prove the encoded bytes reached a real parser sink.
STRONG_SINKS = {"sql", "filesystem", "xml", "template", "java", "python"}

# Content-leak markers: DISTINCTIVE file/credential content. Generic words
# ("password", "secret") are excluded — they appear on every login page and
# the plain-vs-encoded comparison would already cancel them out; only
# content that could ONLY come from a file/secret read counts as a leak.
CONTENT_LEAK_MARKERS = (
    "root:x:0", "daemon:x:", "/bin/bash", "uid=", "aws_access_key_id",
    "AKIA[0-9A-Z]{16}", "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
    "[extensions]\nversion",  # php.ini shape
)


def _content_leak(body_lower: str) -> bool:
    for marker in CONTENT_LEAK_MARKERS:
        try:
            if re.search(marker, body_lower):
                return True
        except re.error:
            if marker in body_lower:
                return True
    return False


def classify_parser_differential(
    baseline_body: str,
    plain_body: str,
    encoded_body: str,
    plain_status: Optional[int],
    encoded_status: Optional[int],
) -> Tuple[Optional[str], Severity, float, bool]:
    """Pure decision: did an ENCODED form reach a parser the PLAIN form
    couldn't?

    Returns (diff_label, severity, confidence, verified). ``verified=True``
    (=> confirmed tier, scored + repro'd) only when the encoded variant
    produced a strong sink oracle the plain variant did not — proof of a
    parser disagreement. Weaker flips stay suspicious.

    Pure — the tests pin this exactly.
    """
    base_lower = (baseline_body or "").lower()
    plain_lower = (plain_body or "").lower()
    enc_lower = (encoded_body or "").lower()

    base_classes = set(extract_error_classes(base_lower))
    plain_classes = set(extract_error_classes(plain_lower))
    enc_classes = set(extract_error_classes(enc_lower))

    # Sink reached by the encoded form but NOT by the plain form = parser
    # disagreement on the same bytes.
    new_sinks = (enc_classes - base_classes) - plain_classes
    for cls in sorted(new_sinks):
        if cls in STRONG_SINKS:
            return f"error:{cls}", Severity.HIGH, 0.85, True

    # Content leak in the encoded response that wasn't in baseline or plain.
    if _content_leak(enc_lower) and not _content_leak(plain_lower):
        return "content_leak", Severity.HIGH, 0.9, True

    # Unescaped XSS: encoded variant reflected raw angle brackets the plain
    # form didn't (filter decodes once, origin reflects what the filter
    # produced) — a genuine two-parser disagreement.
    if "<script>" in enc_lower and "<script>" not in plain_lower and \
            "<script>" not in base_lower:
        return "xss_unescaped", Severity.HIGH, 0.85, True

    # Weaker differentials: encoded variant flipped behavior but no strong
    # sink named — suspicious, triaged, never scored.
    if (plain_status or 0) != (encoded_status or 0) and \
            encoded_status == 500 and (plain_status or 0) < 500:
        return "status_500", Severity.MEDIUM, 0.55, False
    if len(enc_lower) != len(plain_lower) and abs(len(enc_lower) - len(plain_lower)) > max(200, len(plain_lower) * 0.5):
        return "content_change", Severity.LOW, 0.45, False

    return None, Severity.UNCONFIRMED, 0.0, False


class ParserDiffDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(
        self, context, target: str, method: str, url: str, params: Dict[str, str]
    ) -> List[Finding]:
        findings: List[Finding] = []
        if not params:
            return findings

        for param_name in params:
            if not param_name:
                continue
            # Baseline with the discovered value.
            try:
                base_resp = await context.request.get(url, params=params, timeout=3000)
                baseline_body = (await base_resp.text()) or ""
                baseline_status = base_resp.status
            except Exception:
                continue

            for class_name, payload in CLASS_PAYLOADS:
                # Plain payload — the form a WAF usually filters.
                plain_params = dict(params)
                plain_params[param_name] = payload
                try:
                    plain_resp = await context.request.get(url, params=plain_params, timeout=3000)
                    plain_body = (await plain_resp.text()) or ""
                    plain_status = plain_resp.status
                except Exception:
                    continue

                for label, encoded in _encodings(payload)[:6]:
                    enc_params = dict(params)
                    enc_params[param_name] = encoded
                    try:
                        enc_resp = await context.request.get(url, params=enc_params, timeout=3000)
                        enc_body = (await enc_resp.text()) or ""
                        enc_status = enc_resp.status
                    except Exception:
                        continue

                    diff_label, severity, confidence, verified = classify_parser_differential(
                        baseline_body, plain_body, enc_body,
                        plain_status, enc_status,
                    )
                    if not diff_label:
                        continue

                    findings.append(
                        Finding(
                            target=target,
                            url=url,
                            method="GET",
                            param=param_name,
                            location="query",
                            payload=encoded,
                            attack_type=AttackType.PARSER_DIFFERENTIAL,
                            severity=severity,
                            verified=verified,
                            confidence=confidence,
                            status=enc_status,
                            diffs=[diff_label, f"parserdiff:{label}", f"class:{class_name}"],
                            baseline_body=baseline_body[:2000],
                            baseline_status=baseline_status,
                            verification_body=enc_body[:2000],
                            verification_status=enc_status,
                            metadata={
                                "class": class_name,
                                "encoding": label,
                                "plain_payload": payload,
                            },
                            tags=["parser-differential", class_name],
                        )
                    )
                if len(findings) >= 8:
                    break
            if len(findings) >= 8:
                break
        return findings
