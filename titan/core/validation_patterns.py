"""Declared input-validation patterns for Titan's input boundaries.

This module is the single source of truth for the input grammar accepted at
the attack-module boundary (``titan/core/scan_params.py``). Every pattern is
a named, compiled regex that is *enforced* — patterns here are not decorative
documentation; ``validate_scan_params`` rejects input that fails them.

Rules of the house:

- Add a pattern here **before** accepting a new input class at a boundary.
- Enforcement is fail-closed: a pattern that cannot be found raises, and an
  unrecognized declaration rejects rather than defaulting to permission.
- Patterns must state exactly the contract the caller already relies on. A
  pattern stricter than current behavior is a behavior change and needs its
  own commit with the callers audited; a pattern looser than the checks is a
  lie in both directions.

The registry also gives audits (DataFactor-style repo scoring, security
review) one greppable place to see which input classes are validated and
how, instead of inferring the grammar from scattered validator bodies.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final

# Declared patterns. Enforcement is ``re.fullmatch`` semantics: the whole
# value must satisfy the pattern, not just a prefix.
#
# - ``http_method``       the exact HTTP verb set the dispatch layer supports
#                         (applied to the already-normalized, uppercased verb).
# - ``absolute_http_url`` scheme http/https plus a non-empty authority: at
#                         least one character after ``://`` that is not a
#                         path/query/fragment delimiter. Mirrors the
#                         ``urlparse`` scheme+netloc check it sits in front
#                         of, including its permissiveness (ports, IPv6,
#                         userinfo are the semantic layer's business).
# - ``absolute_path``     path-qualified URL on the target origin — the
#                         local-lab convention (``/logic_negative_accepted``).
# - ``non_empty_text``    contains at least one non-whitespace character
#                         (the machine-readable form of ``v.strip()`` being
#                         truthy — leading/trailing whitespace stays legal).
# - ``non_empty_key``     at least one character of any kind. Deliberately
#                         weaker than ``non_empty_text``: param keys are only
#                         checked for emptiness, not stripped, and a
#                         whitespace-only key is data the target may
#                         legitimately be probed with.
VALIDATION_PATTERNS: Final[Mapping[str, re.Pattern[str]]] = {
    "http_method": re.compile(r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$"),
    "absolute_http_url": re.compile(r"(?is)^https?://[^/?#].*$"),
    "absolute_path": re.compile(r"(?s)^/.*$"),
    "non_empty_text": re.compile(r"(?s)^.*\S.*$"),
    "non_empty_key": re.compile(r"(?s)^.+$"),
}


def matches(name: str, value: str) -> bool:
    """Fullmatch ``value`` against the declared pattern ``name``.

    Fail-closed by construction: an unknown pattern name raises ``KeyError``
    instead of returning True, so a typo'd name can never widen acceptance.
    """
    return VALIDATION_PATTERNS[name].fullmatch(value) is not None


__all__ = ["VALIDATION_PATTERNS", "matches"]
