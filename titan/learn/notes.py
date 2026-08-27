"""Note miner — extracts structured findings from deep-audit FINDINGS.md.

Deep-audit sites (blink, mkulima, peak, sales, tulia, coast, git-vizor …)
were documented in human FINDINGS.md files, often WITHOUT a machine-readable
findings.json. The estate corpus and trend analyzer would otherwise be blind
to them. This miner reads the conventional finding heading —

    ### F1 — CRITICAL · Public Firestore read: farmer PII + forum content exposed

— and extracts ``{severity, title, attack_type}`` rows. It is deliberately
conservative: only headings matching the convention are mined, and the
attack-type mapping is a small keyword table that falls back to the raw
title (so nothing is silently dropped or mislabeled).

Everything here is deterministic and unit-tested.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

# ### F1 — CRITICAL · Title here        (also accepts - or – as separators)
FINDING_HEADING_RE = re.compile(
    r"""^#{2,4}\s*F\d+\s*[—\-–]\s*([A-Za-z]+)\s*[·•]\s*(.+?)\s*$""",
    re.M | re.I,
)

SEVERITIES = {"critical", "high", "medium", "low", "info"}

# (regex keywords, attack type) — ordered, first match wins. \b on storage
# keeps "localStorage-only" (which means NO real storage) out of the public-
# storage class.
TITLE_TO_ATTACK: List[tuple] = [
    ((r"privilege escalation", r"self-declared role", r"mass assignment"), "Privilege Escalation"),
    ((r"idor", r"object reference", r"missing function-level auth"), "IDOR"),
    ((r"sql",), "SQLi"),
    ((r"dom xss",), "DOM XSS"),
    ((r"xss",), "XSS"),
    ((r"firestore", r"bucket", r"\bstorage\b", r"firebase read", r"public firebase"), "Public Cloud Storage"),
    ((r"hardcoded", r"api key", r"secret", r"credential"), "Hardcoded Secret"),
    ((r"csp", r"content-security-policy"), "CSP Weakness"),
    ((r"clickjack", r"\bframe\b"), "Info Leak"),
    ((r"header",), "Info Leak"),
    ((r"auth bypass", r"authentication", r"login", r"signup", r"register", r"session"), "Auth Bypass"),
    ((r"reset token", r"token leak", r"\bpii\b", r"information disclosure", r"info leak", r"\bleak\b"), "Info Leak"),
    ((r"prototype pollution",), "Prototype Pollution"),
    ((r"ssrf",), "SSRF"),
]


def attack_type_from_title(title: str) -> Optional[str]:
    t = title.lower()
    for keywords, atk in TITLE_TO_ATTACK:
        if any(re.search(k, t) for k in keywords):
            return atk
    return None


def mine_findings_md(text: str) -> List[Dict[str, str]]:
    """Extract [{severity, title, attack_type}] from FINDINGS.md text."""
    rows: List[Dict[str, str]] = []
    for m in FINDING_HEADING_RE.finditer(text):
        sev = m.group(1).strip().lower()
        if sev not in SEVERITIES:
            continue
        title = m.group(2).strip()
        atk = attack_type_from_title(title) or "Info Leak"
        rows.append({"severity": sev, "title": title, "attack_type": atk})
    return rows


def mine_findings_md_file(path) -> List[Dict[str, str]]:
    try:
        return mine_findings_md(path.read_text(encoding="utf-8"))
    except Exception:
        return []
