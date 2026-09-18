"""Verdict classification — the "non-answer is not a verdict" doctrine.

Folded from the 2026-09-12/13 engagements (see findings/LEARNINGS.md):

  * ``VALIDATION-ERROR`` from a probe (empty/malformed variables, rejected
    input shape) means **UNVERDICTED** — the operation never executed, so it
    proves neither reachability nor gating. The Parool pass initially counted
    such non-answers as verdicts and published an inflated coverage number
    (88/93 until the lead-recovery pass corrected it).
  * Only unambiguous responses are verdicts: the operation ran (REACHABLE),
    the authorization gate refused it (GATED), or it does not exist
    (NOT_FOUND). Everything else — validation errors, 5xx, timeouts —
    requires a re-probe with well-formed input before any coverage number
    is published.

``VerdictLedger`` is the honest-coverage companion: it records one verdict
per operation and counts only real verdicts toward coverage.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from enum import Enum

from titan.core.logger import get_logger

logger = get_logger("verify.verdicts")


class Verdict(str, Enum):
    """Outcome classes for a single probe.

    REACHABLE / GATED / NOT_FOUND are *verdicts* — the probe answered the
    question asked. UNVERDICTED is a *non-answer*: the probe never reached
    the decision point, and treating it as either a positive or a negative
    is the exact failure mode this module exists to prevent.
    """

    REACHABLE = "reachable"
    GATED = "gated"
    NOT_FOUND = "not_found"
    UNVERDICTED = "unverdicted"


# GraphQL input-validation signals. A response carrying these was rejected
# before the resolver ran — the operation's behavior was never exercised.
_VALIDATION_CODES = {
    "GRAPHQL_VALIDATION_FAILED",
    "BAD_USER_INPUT",
    "VALIDATION_ERROR",
}

_VALIDATION_MESSAGE = re.compile(
    r"(?:variable\s+\$|cannot\s+query\s+field|"
    r"field.*of\s+required\s+type|argument.*of\s+required\s+type|"
    r"must\s+provide\s+a\s+value|expected\s+a\s+value\s+for)",
    re.IGNORECASE,
)

_GATE_STATUSES = {401, 403}
_NOT_FOUND_STATUSES = {404, 405, 410}


def _extract_graphql_errors(body: str | None) -> list[dict]:
    """Best-effort extraction of errors[] from a GraphQL-style body."""
    if not body:
        return []
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(parsed, dict):
        return []
    errors = parsed.get("errors")
    if not isinstance(errors, list):
        return []
    return [e for e in errors if isinstance(e, dict)]


def _is_validation_response(status: int, body: str | None) -> bool:
    """True when the response is an input-validation rejection, not a verdict.

    Matches both HTTP-400-with-GraphQL-errors and in-envelope validation
    errors (status 200 with an errors[] payload), because both flavors
    appeared on the Parool engagement.
    """
    for err in _extract_graphql_errors(body):
        code = str((err.get("extensions") or {}).get("code", "")).upper()
        message = str(err.get("message", ""))
        if code in _VALIDATION_CODES or _VALIDATION_MESSAGE.search(message):
            return True
    # Some gateways return plain 400s with the marker in the body text.
    if status == 400 and body and _VALIDATION_MESSAGE.search(body):
        return True
    return False


def classify(
    status: int,
    body: str | None,
    *,
    well_formed: bool = True,
) -> Verdict:
    """Classify a probe response into a Verdict.

    Args:
        status: HTTP status code of the probe response.
        body: Response body (parsed for GraphQL validation signals).
        well_formed: Whether the probe carried well-formed input. A
            validation rejection on a malformed probe is doubly a
            non-answer; the caller must re-probe with proper variables.

    Returns:
        Verdict. UNVERDICTED for validation errors, server faults, and any
        ambiguous status; callers must re-probe rather than count it.
    """
    if _is_validation_response(status, body):
        if not well_formed:
            logger.debug("validation error on malformed probe — UNVERDICTED, re-probe required")
        return Verdict.UNVERDICTED

    if status in _GATE_STATUSES:
        return Verdict.GATED

    if 200 <= status < 300:
        return Verdict.REACHABLE

    if status in _NOT_FOUND_STATUSES:
        return Verdict.NOT_FOUND

    # 5xx, 429, redirects, anything unmapped — not a verdict.
    return Verdict.UNVERDICTED


def classify_exception(exc: Exception) -> Verdict:
    """A probe that died is never a negative — it is UNVERDICTED."""
    logger.debug(f"probe exception {type(exc).__name__}: {exc} — UNVERDICTED")
    return Verdict.UNVERDICTED


class VerdictLedger:
    """Per-operation verdict record with honest coverage math.

    Coverage counts only REACHABLE / GATED / NOT_FOUND — the responses that
    actually answer the question. UNVERDICTED operations are reported
    separately as re-probe work, never silently folded into coverage.
    """

    _VERDICTED = {Verdict.REACHABLE, Verdict.GATED, Verdict.NOT_FOUND}

    def __init__(self) -> None:
        self._verdicts: dict[str, Verdict] = {}

    def record(self, operation: str, verdict: Verdict) -> Verdict:
        """Record (or re-record) the verdict for an operation."""
        if not operation:
            raise ValueError("operation name required")
        previous = self._verdicts.get(operation)
        if previous is not None and previous != verdict:
            logger.debug(f"verdict change for {operation}: {previous.value} -> {verdict.value}")
        self._verdicts[operation] = verdict
        return verdict

    def get(self, operation: str) -> Verdict | None:
        return self._verdicts.get(operation)

    @property
    def operations(self) -> list[str]:
        return list(self._verdicts)

    @property
    def unverdicted(self) -> list[str]:
        """Operations whose current verdict is a non-answer — re-probe list."""
        return sorted(op for op, v in self._verdicts.items() if v is Verdict.UNVERDICTED)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {v.value: 0 for v in Verdict}
        for v in self._verdicts.values():
            out[v.value] += 1
        return out

    def coverage(self, total_registered: int | None = None) -> tuple[int, int]:
        """(verdicted, total) — the honest pair for any coverage claim.

        ``total`` defaults to the number of operations ever recorded. Pass
        ``total_registered`` when the ledger knows about operations that
        have no probe attempt yet (e.g. a staged script that never ran —
        it must depress coverage, not disappear from the denominator).
        """
        verdicted = sum(1 for v in self._verdicts.values() if v in self._VERDICTED)
        total = total_registered if total_registered is not None else len(self._verdicts)
        if total_registered is not None and total_registered < len(self._verdicts):
            raise ValueError("total_registered smaller than recorded operations")
        return verdicted, total

    def summary(self, total_registered: int | None = None) -> str:
        verdicted, total = self.coverage(total_registered)
        counts = self.counts()
        parts = [
            f"{counts['reachable']} reachable",
            f"{counts['gated']} gated",
            f"{counts['not_found']} not_found",
            f"{counts['unverdicted']} UNVERDICTED (re-probe)",
        ]
        return f"coverage: {verdicted}/{total} verdicted | " + ", ".join(parts)

    def extend(self, pairs: Iterable[tuple[str, Verdict]]) -> None:
        for op, verdict in pairs:
            self.record(op, verdict)
