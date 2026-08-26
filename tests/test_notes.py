"""Tests for the FINDINGS.md note miner."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from titan.learn.notes import attack_type_from_title, mine_findings_md  # noqa: E402


def test_mines_conventional_headings():
    text = """# Audit

### F1 — CRITICAL · Public Firestore read: farmer PII + forum content exposed
### F2 — MEDIUM · Signup form is localStorage-only
### F3 — LOW · Missing security headers

| table | row |
|---|---|
"""
    rows = mine_findings_md(text)
    assert len(rows) == 3
    assert rows[0]["severity"] == "critical"
    assert rows[0]["attack_type"] == "Public Cloud Storage"
    assert rows[1]["attack_type"] == "Auth Bypass"  # signup keyword
    assert rows[2]["attack_type"] == "Info Leak"  # headers


def test_attack_type_mapping():
    assert attack_type_from_title("Privilege escalation: self-declared role at registration") == "Privilege Escalation"
    assert attack_type_from_title("Broken object-level authorization (IDOR)") == "IDOR"
    assert attack_type_from_title("Stored SQL injection in search") == "SQLi"
    assert attack_type_from_title("DOM XSS via innerHTML") == "DOM XSS"
    assert attack_type_from_title("Hardcoded Firebase API key in bundle") == "Hardcoded Secret"
    assert attack_type_from_title("Missing Content-Security-Policy header") == "CSP Weakness"


def test_malformed_headings_ignored():
    text = """
Some prose about F1. Critical issue here.
### not-a-finding — NOPE · text
#### F7 — UNKNOWN · bad severity
"""
    assert mine_findings_md(text) == []
