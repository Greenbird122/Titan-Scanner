"""Playbook loader and executor.

Playbooks are YAML files in titan/playbooks/. Each playbook describes a
platform-specific attack surface map: how to fingerprint it, how to
authenticate, what endpoints and APIs to probe, and what findings to
expect. The AI agent reads playbooks to decide which one applies, then
Titan executes the probes.

A playbook is NOT a replacement for the module matrix. It runs BEFORE the
matrix, discovering platform-specific surface (web service APIs, admin
panels, known CVE vectors) that the generic crawler would miss. The
module matrix then runs against the expanded surface.

Usage:
    from titan.playbooks import load_playbook, match_playbook

    pb = match_playbook("https://elearning.kibu.ac.ke")
    if pb:
        results = await pb.run(target, session)
        # results.endpoints feed into the module matrix
        # results.findings are pre-verified platform-specific findings
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

PLAYBOOK_DIR = Path(__file__).resolve().parent


def list_playbooks() -> List[str]:
    """Return all available playbook names (without .yml extension)."""
    return sorted(p.stem for p in PLAYBOOK_DIR.glob("*.yml"))


def load_playbook(name: str) -> Optional[Dict[str, Any]]:
    """Load a playbook by name. Returns None if not found."""
    path = PLAYBOOK_DIR / f"{name}.yml"
    if not path.exists():
        return None
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def match_playbook(html_body: str, headers: Dict[str, str], url: str) -> Optional[Dict[str, Any]]:
    """Try every playbook's fingerprint patterns against the target's
    HTML body and headers. Return the first match or None.

    Fingerprint matching is in priority order (playbooks are sorted by
    specificity — platform-specific before generic). Each playbook's
    ``fingerprint`` section lists body/header patterns; ALL must match.
    """
    for name in list_playbooks():
        pb = load_playbook(name)
        if not pb:
            continue
        fp = pb.get("fingerprint", {})
        if not fp:
            continue
        matched = True
        # Body patterns (regex, case-insensitive)
        for pattern in fp.get("body", []):
            if not re.search(pattern, html_body, re.I):
                matched = False
                break
        if not matched:
            continue
        # Header patterns (key: value regex)
        for hkey, hval_pattern in fp.get("headers", {}).items():
            actual = headers.get(hkey, "")
            if not re.search(hval_pattern, actual, re.I):
                matched = False
                break
        if not matched:
            continue
        # URL patterns
        for pattern in fp.get("url", []):
            if not re.search(pattern, url, re.I):
                matched = False
                break
        if matched:
            pb["_name"] = name
            return pb
    return None
