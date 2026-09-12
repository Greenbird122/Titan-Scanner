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
from typing import Any
from urllib.parse import urlparse

from titan.core.logger import get_logger
from titan.core.models import ScanResult

logger = get_logger("__init__")


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

        # PUSH-TO-100 A2 — per-finding repro proof. Every CONFIRMED finding
        # ships an executable repro script (the Ground-Truth receipt): run it
        # against the still-vulnerable site and it asserts the flaw (PASS,
        # exit 0); after the fix lands it flips FAIL (exit 1). Suspicious /
        # no-evidence findings get no repro — their contract is "triaged, not
        # proven". The relative path lands in the finding's metadata BEFORE
        # findings.json is serialized, so the machine record carries the
        # receipt.
        from titan.verify.repro import generate_repro

        repro_dir = site_dir / "repros"
        repro_count = 0
        for f in result.findings:
            if f.tier == "confirmed":
                repro_count += 1
                repro_dir.mkdir(parents=True, exist_ok=True)
                name = f"repro_{repro_count:02d}.py"
                (repro_dir / name).write_text(generate_repro(f, ordinal=repro_count), encoding="utf-8")
                f.metadata["repro"] = f"repros/{name}"

        (site_dir / "findings.json").write_text(
            json.dumps(self._redacted_to_dict(result), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        (site_dir / "scan_meta.json").write_text(
            json.dumps(self._meta(result, slug), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        (site_dir / "report.md").write_text(self._markdown(result), encoding="utf-8")
        # Track G — persist the hostile-surface profile + observed intel so
        # the S5 dashboard can render them and the next scan can diff flux.
        hostile = result.hostile or {}
        if hostile:
            (site_dir / "hostile.json").write_text(json.dumps(hostile, indent=2, ensure_ascii=False), encoding="utf-8")
            observed = hostile.get("observed") or {}
            if observed:
                (site_dir / "intel.json").write_text(
                    json.dumps(observed, indent=2, ensure_ascii=False), encoding="utf-8"
                )
        self._update_index(slug, result)
        return site_dir

    @staticmethod
    def _redacted_to_dict(result: ScanResult) -> dict[str, Any]:
        """result.to_dict() with credentials scrubbed from config_snapshot.

        The snapshot carries the live config (including auth.username/password)
        — a deep copy is redacted so the in-memory config object is untouched.
        """
        data = result.to_dict()
        # SCAN-QUALITY M4: consumers can check schema_version to know whether
        # evidence grades / demotion metadata are present.
        data["schema_version"] = 2
        snap = data.get("config_snapshot")
        if isinstance(snap, dict):
            cleaned = copy.deepcopy(snap)

            def _scrub(obj: Any) -> Any:
                if isinstance(obj, dict):
                    return {k: ("[REDACTED]" if k in _REDACT_KEYS else _scrub(v)) for k, v in obj.items()}
                if isinstance(obj, list):
                    return [_scrub(v) for v in obj]
                return obj

            data["config_snapshot"] = _scrub(cleaned)
        return data

    # ------------------------------------------------------------------ meta

    @staticmethod
    def _iso(epoch: float) -> str | None:
        if not epoch:
            return None
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()

    def _meta(self, result: ScanResult, slug: str) -> dict[str, Any]:
        meta = {
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
            "exploit_sessions": len(result.exploit_sessions or []),
            "repros": sum(1 for f in result.findings if f.metadata.get("repro")),
            "coverage": result.coverage,
        }
        hostile = result.hostile or {}
        if hostile:
            meta["hostile"] = {
                "monetization_score": hostile.get("profile", {}).get("monetization_score"),
                "origins": len(hostile.get("profile", {}).get("origins", [])),
                "hostile_findings": len(hostile.get("findings", [])),
                "active_probes": hostile.get("active_probes", False),
            }
        return meta

    # --------------------------------------------------------------- markdown

    # --------------------------------------------------------------- markdown

    def _markdown(self, result: ScanResult) -> str:
        """Render the full markdown report (moved to markdown_report.py)."""
        return render_markdown_report(result, self)

    # ------------------------------------------------------------ estate avg

    def _estate_average(self) -> float | None:
        """Average finding count across all scanned sites in the estate."""
        index_path = self.output_dir / "sites.json"
        if not index_path.exists():
            return None
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
            sites = index.get("sites", [])
            if not sites:
                return None
            totals = [s.get("findings", 0) for s in sites]
            return sum(totals) / len(totals)
        except Exception:
            return None

    # --------------------------------------------------------------- consent

    def _consent_line(self, target: str, key_path=None, consent_dir=None) -> str | None:
        """Authorization story for the target, if a consent file exists.

        Reads the consent ledger and returns a one-line summary: basis + flags
        + expiry. Returns None when no consent covers the target (read-only
        path may still be authorized by the practice manifest — the report
        simply omits the consent row in that case).
        """
        try:
            from titan.exploit.consent import (
                DEFAULT_CONSENT_DIR,
                consent_filename,
                verify_consent,
            )

            cdir = consent_dir if consent_dir is not None else DEFAULT_CONSENT_DIR
            file = cdir / f"{consent_filename(target)}.json"
            if not file.exists():
                return None
            doc = verify_consent(target, consent_dir=cdir, key_path=key_path)
            basis = doc.get("basis") or "undeclared"
            flags = doc.get("flags", []) or []
            expiry = doc.get("expires_at")
            exp = self._iso(expiry) if expiry else "n/a"
            flag_txt = ", ".join(flags) if flags else "read-only"
            return f"basis={basis} · flags={flag_txt} · expires {exp}"
        except Exception:
            # Consent missing, expired, or invalid — the report shouldn't
            # crash over the authorization row; it just omits it.
            return None

    # ------------------------------------------------------------------ index

    def _update_index(self, slug: str, result: ScanResult) -> None:
        index_path = self.output_dir / "sites.json"
        index: dict[str, Any] = {"sites": []}
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
        tmp.write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(index_path)


from titan.reporting.estate import estate_rollup
from titan.reporting.markdown_report import (
    _SEVERITY_ORDER,
    business_logic_section,
    finding_section,
    render_markdown_report,
)
from titan.reporting.remediation import REMEDIATION_MAP, generate_remediation, remediation_rollup

__all__ = [
    "REMEDIATION_MAP",
    "_SEVERITY_ORDER",
    "SiteReportWriter",
    "business_logic_section",
    "estate_rollup",
    "finding_section",
    "generate_remediation",
    "remediation_rollup",
    "render_markdown_report",
    "site_slug",
]
