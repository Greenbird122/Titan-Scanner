"""Titan reporting subsystem — per-site findings documentation.

Every scanned site gets its own directory under ``output_dir`` (default
``findings/``) so findings are always documented under the site they came
from:

    findings/
      sites.json                 index of every scanned site
      <site-slug>/               e.g. localhost-5000, repairai-co-ke
        report.md                human-readable documentation (the report)
        findings.json            full machine-readable results
        scan_meta.json           target, timing, counts, errors, fingerprint
"""

from __future__ import annotations

import copy
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from titan.core.models import ScanResult


# Keys redacted from the persisted config snapshot: credentials must never
# land on disk inside per-site finding docs.
_REDACT_KEYS = ("password", "token", "secret", "api_key", "apikey")


def site_slug(target: str) -> str:
    """Deterministic, filesystem-safe slug for a target URL.

    ``http://localhost:8080/login.php`` -> ``localhost-8080``
    ``https://repairai.co.ke/``        -> ``repairai-co-ke``
    """
    raw = target if "://" in (target or "") else f"http://{target}"
    try:
        parsed = urlparse(raw)
        host = parsed.hostname or "unknown"
    except Exception:
        host, parsed = "unknown", None
    slug = re.sub(r"[^a-z0-9]+", "-", host.lower()).strip("-") or "unknown"
    if parsed is not None and parsed.port is not None:
        is_default = (parsed.scheme == "http" and parsed.port == 80) or (
            parsed.scheme == "https" and parsed.port == 443
        )
        if not is_default:
            slug += f"-{parsed.port}"
    return slug


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unconfirmed"]


class SiteReportWriter:
    """Writes a scan's findings under a per-site directory.

    Usage::

        writer = SiteReportWriter(output_dir="findings")
        writer.write(result)          # writes all docs, returns site directory
    """

    def __init__(self, output_dir: str = "findings"):
        self.output_dir = Path(output_dir)

    def slug_for(self, target: str) -> str:
        return site_slug(target)

    def write(self, result: ScanResult) -> Path:
        """Persist the per-site documentation for this scan.

        Returns the site directory that was written.
        """
        slug = self.slug_for(result.target)
        site_dir = self.output_dir / slug
        site_dir.mkdir(parents=True, exist_ok=True)

        (site_dir / "findings.json").write_text(
            json.dumps(self._redacted_to_dict(result), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        (site_dir / "scan_meta.json").write_text(
            json.dumps(self._meta(result, slug), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        (site_dir / "report.md").write_text(self._markdown(result), encoding="utf-8")
        self._update_index(slug, result)
        return site_dir

    @staticmethod
    def _redacted_to_dict(result: ScanResult) -> Dict[str, Any]:
        """result.to_dict() with credentials scrubbed from config_snapshot.

        The snapshot carries the live config (including auth.username/password)
        — a deep copy is redacted so the in-memory config object is untouched.
        """
        data = result.to_dict()
        snap = data.get("config_snapshot")
        if isinstance(snap, dict):
            cleaned = copy.deepcopy(snap)

            def _scrub(obj: Any) -> Any:
                if isinstance(obj, dict):
                    return {
                        k: ("[REDACTED]" if k in _REDACT_KEYS else _scrub(v))
                        for k, v in obj.items()
                    }
                if isinstance(obj, list):
                    return [_scrub(v) for v in obj]
                return obj

            data["config_snapshot"] = _scrub(cleaned)
        return data

    # ------------------------------------------------------------------ meta

    @staticmethod
    def _iso(epoch: float) -> Optional[str]:
        if not epoch:
            return None
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()

    def _meta(self, result: ScanResult, slug: str) -> Dict[str, Any]:
        return {
            "target": result.target,
            "slug": slug,
            "started_at": result.started_at,
            "started_at_iso": self._iso(result.started_at),
            "finished_at": result.finished_at,
            "finished_at_iso": self._iso(result.finished_at),
            "duration_seconds": result.duration_seconds,
            "findings": len(result.findings),
            "verified": result.verified_count,
            "critical": result.critical_count,
            "high": result.high_count,
            "chains": result.chain_count,
            "errors": result.errors,
            "technologies": (result.fingerprint or {}).get("technologies", []),
            "ai_escalation": result.ai_escalation or {},
        }

    # --------------------------------------------------------------- markdown

    def _markdown(self, result: ScanResult) -> str:
        lines: List[str] = [
            f"# Scan Report — {result.target}",
            "",
            "| | |",
            "|---|---|",
            f"| **Site slug** | `{self.slug_for(result.target)}` |",
            f"| **Scanned** | {self._iso(result.started_at) or 'n/a'} |",
            f"| **Duration** | {result.duration_seconds}s |",
            f"| **Technologies** | {', '.join((result.fingerprint or {}).get('technologies', [])[:8]) or 'unknown'} |",
            "",
            "## Summary",
            "",
            "| Total | Verified | Critical | High | Medium | Low | Unconfirmed | Chains |",
            "|---|---|---|---|---|---|---|---|",
            f"| {len(result.findings)} | {result.verified_count} | {result.critical_count} "
            f"| {result.high_count} | "
            f"{sum(1 for f in result.findings if f.severity.value == 'medium')} | "
            f"{sum(1 for f in result.findings if f.severity.value == 'low')} | "
            f"{sum(1 for f in result.findings if f.severity.value == 'unconfirmed')} | "
            f"{result.chain_count} |",
            "",
        ]

        if not result.findings:
            lines += ["No findings recorded for this site.", ""]
        else:
            lines += ["## Findings", ""]
            by_severity: Dict[str, List[Any]] = {}
            for f in result.findings:
                by_severity.setdefault(f.severity.value, []).append(f)

            ordinal = 0
            for sev in _SEVERITY_ORDER:
                for f in by_severity.get(sev, []):
                    ordinal += 1
                    lines += self._finding_section(ordinal, f)
                    lines += ["---", ""]

        if result.errors:
            lines += ["## Scan errors", ""]
            for err in result.errors:
                lines += [f"- {err}"]
            lines += [""]

        if result.ai_escalation:
            esc = result.ai_escalation
            lines += [
                "## AI escalation",
                "",
                f"- Sent: {esc.get('sent', 0)} · Confirmed: {esc.get('confirmed', 0)} "
                f"· Rejected: {esc.get('rejected', 0)} · Failed: {esc.get('failed', 0)}",
                "",
            ]

        return "\n".join(lines)

    def _finding_section(self, ordinal: int, f) -> List[str]:
        label = f.attack_type.value if f.attack_type else "Unknown"
        mark = " — verified" if f.verified else ""
        lines = [
            f"### {ordinal}. [{f.severity.value.upper()}] {label}{mark}",
            "",
            f"- **URL** `{f.method.upper()} {f.url}`",
            f"- **Param** `{f.param}` ({f.location}) · **Confidence** {f.confidence:.2f} "
            f"· **Status** {f.status or 'n/a'}",
        ]
        if f.cvss_score is not None:
            lines.append(
                f"- **CVSS** {f.cvss_score} — `{f.cvss_vector}`"
            )
        if f.payload:
            # Guard the code fence: a payload containing ``` would break out
            # and inject raw markdown into the report.
            payload = f.payload.replace("```", "`` `")
            lines += ["- **Payload**", "", "```text", payload, "```", ""]
        if f.diffs:
            lines += ["- **Evidence**", ""]
            for d in f.diffs:
                lines.append(f"  - `{d}`")
            lines += [""]
        if f.chain:
            lines += [f"- **Chain** `{'` -> `'.join(f.chain)}`", ""]
        if f.tags:
            lines += [f"- **Tags** {', '.join(f.tags)}", ""]
        if f.poc_curl:
            lines += ["- **PoC (curl)**", "", "```bash", f.poc_curl, "```", ""]
        if f.poc_python:
            lines += ["- **PoC (python)**", "", "```python", f.poc_python, "```", ""]
        return lines

    # ------------------------------------------------------------------ index

    def _update_index(self, slug: str, result: ScanResult) -> None:
        index_path = self.output_dir / "sites.json"
        index: Dict[str, Any] = {"sites": []}
        if index_path.exists():
            try:
                index = json.loads(index_path.read_text(encoding="utf-8"))
            except Exception:
                index = {"sites": []}

        entry = {
            "slug": slug,
            "target": result.target,
            "last_scan": self._iso(result.started_at) or time.ctime(result.started_at),
            "findings": len(result.findings),
            "verified": result.verified_count,
            "critical": result.critical_count,
            "high": result.high_count,
            "report": f"{slug}/report.md",
        }
        sites = [s for s in index.get("sites", []) if s.get("slug") != slug]
        sites.append(entry)
        sites.sort(key=lambda s: s.get("target", ""))
        index["sites"] = sites

        # Atomic write (temp + rename) so a crash mid-write can't corrupt the
        # site index.
        tmp = index_path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        tmp.replace(index_path)
