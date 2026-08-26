"""PUSH-TO-100 A2 — per-finding executable repro scripts.

A ``confirmed`` finding ships an executable repro that ASSERTS the flaw on
the live target: run it against the still-vulnerable site and it prints PASS
and exits 0; after the fix lands it prints FAIL and exits 1 (the Ground-Truth
contract, same shape as the Repairai ``validate_fix.py`` pattern).

The assertion is built from the finding's OWN verified evidence, never from
textbook guessing:

  * If the finding was verified by a body differential (``verification_body``
    vs ``baseline_body``), the repro extracts a distinctive oracle signature —
    the first body region present in the verified response but absent from the
    baseline — and asserts it still appears when the payload is replayed.
  * If the finding carries an error-class diff (``error:sql``, ...), the repro
    additionally asserts that error class is still present in the response.
  * Reflected markers fall back to asserting the payload is still reflected.

When the fix lands, the oracle signature / error class / reflection
disappears -> the repro flips PASS -> FAIL. The script is dependency-free
(urllib) so it runs anywhere the operator can reach the target.
"""

from __future__ import annotations

import json
from difflib import SequenceMatcher
from typing import List, Optional

from titan.core.models import Finding

# Substrings that identify content-leak / reflection oracles inside diffs,
# so the signature chooser knows what kind of evidence backs the finding.
_ERROR_CLASS_DIFF_PREFIX = "error:"


def oracle_signature(finding: Finding, max_len: int = 60) -> str:
    """A distinctive substring that proves the flaw, derived from the
    finding's own verified evidence.

    Preference order:
      1. A body region present in ``verification_body`` but absent from
         ``baseline_body`` (a real differential, not an echo — the same
         source the evidence gate trusted).
      2. The payload itself, when the finding is a reflection-class oracle
         (LFI/XSS/reflected injection) and no differential exists.
      3. Empty (the repro will then rely on status + error-class checks).
    """
    vbody = finding.verification_body or ""
    bbody = finding.baseline_body or ""
    if vbody and vbody != bbody:
        sig = _first_differential_chunk(vbody, bbody)
        if sig:
            return sig[:max_len]
    if finding.payload:
        return str(finding.payload)[:max_len]
    return ""


def _first_differential_chunk(a: str, b: str, min_len: int = 12) -> str:
    """First region of ``a`` not matched in ``b`` (SequenceMatcher's first
    ``replace``/``insert`` block), stripped and normalized."""
    if not a or not b:
        return a or ""
    sm = SequenceMatcher(None, b, a, autojunk=False)
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op in ("replace", "insert") and (j2 - j1) >= min_len:
            return a[j1:j2].strip()
    return ""


def _error_classes_from_diffs(diffs: List[str]) -> List[str]:
    out: List[str] = []
    for d in diffs or []:
        d = d.lower()
        if d.startswith(_ERROR_CLASS_DIFF_PREFIX):
            cls = d[len(_ERROR_CLASS_DIFF_PREFIX):].strip()
            if cls:
                out.append(cls)
    return out


def generate_repro(finding: Finding, ordinal: int = 1) -> str:
    """Return a standalone, dependency-free repro script for a finding.

    The script replays the exact request (method/url/param/payload/location)
    and asserts the flaw via the oracle signature + status + error classes.
    Exit 0 = still vulnerable (PASS), 1 = fixed or no longer reproducible.
    """
    method = (finding.method or "GET").upper()
    url = finding.url or ""
    param = finding.param or ""
    payload = str(finding.payload or "")
    location = finding.location or ""
    status = finding.status or 0
    signature = oracle_signature(finding)
    error_classes = _error_classes_from_diffs(finding.diffs or [])
    target = finding.target or ""

    # How the request should carry the payload (mirrors PoCGenerator).
    if location == "query" and method == "GET":
        req_mode = "query"
    elif location == "body":
        req_mode = "body"
    else:
        req_mode = "plain"

    # --- embed values with JSON so escaping is airtight in the script -------
    J = json.dumps
    checks = []
    if signature:
        checks.append(
            (f"oracle signature {signature[:24]!r} in response body",
             f"signature in body")
        )
    if status:
        checks.append((f"response status is {status}", "status match"))
    for ec in error_classes:
        checks.append((f"error class {ec!r} in response", f"error {ec}"))

    if not checks:
        # Nothing assertable: emit a probe that reports, does not claim.
        mode = "probe-only"
    else:
        mode = "assert"

    header = (
        f"#!/usr/bin/env python3\n"
        f"\"\"\"Repro {ordinal} — {finding.attack_type.value if finding.attack_type else 'Unknown'}\n"
        f"at {url} (param {param!r}).\n\n"
        f"PASS (exit 0) = the flaw is STILL present. FAIL (exit 1) = fixed or\n"
        f"no longer reproducible. Dependency-free (urllib).\n"
        f"\"\"\"\n"
    )

    lines = [
        header,
        "import sys",
        "import urllib.request",
        "import urllib.error",
        "import urllib.parse",
        "",
        f"URL = {J(url)}",
        f"METHOD = {J(method)}",
        f"PARAM = {J(param)}",
        f"PAYLOAD = {J(payload)}",
        f"SIGNATURE = {J(signature)}",
        f"EXPECT_STATUS = {J(status)}",
        f"ERROR_CLASSES = {J(error_classes)}",
        "",
        "def request():",
        f"    if METHOD == 'GET' and PARAM and {J(req_mode)} == 'query':",
        "        sep = '&' if '?' in URL else '?'",
        "        target = URL + sep + urllib.parse.quote(PARAM) + '=' + urllib.parse.quote(PAYLOAD)",
        "        data = None",
        f"    elif {J(req_mode)} == 'body':",
        "        target = URL",
        f"        data = urllib.parse.urlencode({{{J(param)}: PAYLOAD}}).encode()",
        "    else:",
        "        target = URL",
        "        data = None",
        "    req = urllib.request.Request(target, data=data, method=METHOD,",
        "                                headers={'User-Agent': 'Titan-repro/1.0'})",
        "    try:",
        "        with urllib.request.urlopen(req, timeout=20) as r:",
        "            return r.status, r.read(100000).decode('utf-8', 'replace')",
        "    except urllib.error.HTTPError as e:",
        "        return e.code, e.read(100000).decode('utf-8', 'replace')",
        "    except Exception as e:",
        "        return 0, str(e)",
        "",
        "def main():",
        "    status, body = request()",
        "    results = []",
    ]

    if mode == "assert":
        for label, cond in checks:
            if cond == "status match":
                lines.append(
                    f"    results.append(({J(label)}, status == EXPECT_STATUS, f'got {{status}}'))"
                )
            elif cond == "signature in body":
                lines.append(
                    f"    results.append(({J(label)}, bool(SIGNATURE) and SIGNATURE in body, "
                    f"'sig present' if SIGNATURE in body else 'sig ABSENT'))"
                )
            elif cond.startswith("error "):
                ec = cond[len("error "):]
                lines.append(
                    f"    results.append(({J(label)}, bool(ERROR_CLASSES) and {J(ec)} in body.lower(), "
                    f"'class present' if {J(ec)} in body.lower() else 'class ABSENT'))"
                )
    else:
        lines.append(
            "    results.append(('probe executed (no assertable oracle in evidence)', "
            "status != 0, f'status {{status}}, {len(body)} bytes'))"
        )

    lines += [
        "    ok = True",
        "    for label, passed, detail in results:",
        "        print(f\"[{'PASS' if passed else 'FAIL'}] {label} — {detail}\")",
        "        ok = ok and passed",
        "    print(f\"\\n{len(results)}/{len(results)} checks pass\" if ok "
        "else f\"\\n{sum(1 for _ in results if _[1])}/{len(results)} checks pass\")",
        "    return 0 if ok else 1",
        "",
        "if __name__ == '__main__':",
        "    sys.exit(main())",
        "",
    ]
    return "\n".join(lines)


def generate_repros(findings: List[Finding]) -> dict:
    """Generate repro scripts for all CONFIRMED findings.

    Returns ``{finding_index_in_list: script}``. Suspicious/no-evidence
    findings get no repro (their contract is 'triaged, not proven').
    """
    out: dict = {}
    for i, f in enumerate(findings):
        if f.tier == "confirmed":
            out[i] = generate_repro(f, ordinal=i + 1)
    return out
