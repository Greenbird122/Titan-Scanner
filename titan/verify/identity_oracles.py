"""Cross-identity differential oracles for stateful API testing (Track B).

The stateless oracles (titan/verify/oracles.py) diff a payload against its
baseline. The identity oracles here diff TWO IDENTITIES against the same
resource: the only honest proof of BOLA is \"identity B received identity A's
unique record content when requesting A's object id\".
"""

from __future__ import annotations

import json
import re
from typing import Any, List, Optional


def json_string_values(body: str) -> List[str]:
    """All string values in a JSON body (recursive). Non-JSON -> empty list."""
    try:
        data = json.loads(body)
    except Exception:
        return []

    values: List[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
        elif isinstance(node, str):
            values.append(node)

    walk(data)
    return values


def _is_marker(value: str, ignored: List[str], min_len: int = 5) -> bool:
    v = value.strip()
    if len(v) < min_len:
        return False
    if v in ignored:
        return False
    if v.isdigit():
        return False
    # Timestamps / ids are per-record noise, not owner-identifying content.
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}[T ].*", v):
        return False
    if re.fullmatch(r"[0-9a-f]{16,}", v):
        return False
    if "{" in v or "<" in v:
        return False
    return True


def unique_owner_markers(
    owner_body: str,
    attacker_own_body: str,
    ignored: Optional[List[str]] = None,
) -> List[str]:
    """Content present in the owner's record but absent from the attacker's
    own record — i.e. what makes the owner's record unique. This is the BOLA
    evidence vocabulary: if the attacker's request for the owner's id returns
    any of these markers, the attacker read another tenant's data.

    ``ignored``: param values (the injected id etc.) that may legitimately
    appear in both records.
    """
    ignored = ignored or []
    owner_values = json_string_values(owner_body)
    attacker_values = json_string_values(attacker_own_body)

    markers = []
    for v in owner_values:
        if not _is_marker(v, ignored):
            continue
        if v not in attacker_values:
            markers.append(v)
    return markers


def markers_present(body: str, markers: List[str]) -> List[str]:
    """Which markers appear in the given body (case-sensitive, whole value)."""
    return [m for m in markers if m in body]
