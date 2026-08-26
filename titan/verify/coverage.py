"""PUSH-TO-100 A3 — the coverage verdict as a pure function.

The engine accumulates counters during a scan; ``finalize_coverage`` turns
them into the auditable claim the operator sees:

  * ``complete`` — the crawl provably drained its queue and nothing capped
    the discovered surface (all discovered endpoints ran the module matrix).
  * ``partial`` — with a ``reason`` naming WHY (checkpoint, crawl budget,
    driver death, max_pages cap, API cap, depth cap) so the operator can fix
    the cause instead of re-scanning blind.

The function is pure (no engine dependency) so the verdict logic is testable
in isolation and the engine can never drift from its tests.
"""

from __future__ import annotations

from typing import Any, Dict


def finalize_coverage(
    coverage: Dict[str, Any],
    driver_dead: bool = False,
    max_pages: int = 0,
    max_depth: int = 0,
) -> Dict[str, Any]:
    """Compute the coverage verdict from the accumulated counters.

    Returns a NEW dict (the counters ride along, so the claim is auditable).
    Priority: checkpoint > crawl budget > driver death > queue-not-drained
    (max_pages cap) > API cap > depth cap > complete.
    """
    cov = dict(coverage)
    if cov.get("checkpoint_blocked"):
        cov["status"] = "partial"
        cov["reason"] = "security checkpoint blocked access before crawling"
    elif cov.get("crawl_timed_out"):
        cov["status"] = "partial"
        cov["reason"] = "crawl budget exceeded (timeout)"
    elif driver_dead:
        cov["status"] = "partial"
        cov["reason"] = "driver death mid-scan truncated the crawl"
    elif not cov.get("queue_exhausted"):
        if cov.get("capped_max_pages"):
            cov["status"] = "partial"
            cov["reason"] = (
                f"max_pages cap ({max_pages}) reached before the crawl queue drained"
            )
        else:
            cov["status"] = "partial"
            cov["reason"] = "crawl ended with URLs still queued (aborted early)"
    elif cov.get("capped_apis"):
        cov["status"] = "partial"
        cov["reason"] = "discovered-API cap reached; some endpoints never ran the module matrix"
    elif cov.get("capped_depth"):
        cov["status"] = "partial"
        cov["reason"] = f"depth cap ({max_depth}) limited the crawl"
    else:
        cov["status"] = "complete"
        cov["reason"] = "crawl queue drained; all discovered endpoints ran the module matrix"
    return cov
