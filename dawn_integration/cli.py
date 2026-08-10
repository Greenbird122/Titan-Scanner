import asyncio
import json
from typing import Any, Dict, List, Optional

from scanner.config import load_config, get_scanner_config
from scanner.engine import ScanEngine
from scanner.models import Finding, ScanResult, Severity
from dawn_integration.memory import DawnMemory


async def run_scan(target: str, config_path: str = "config.yaml", output_format: Optional[List[str]] = None) -> ScanResult:
    engine = ScanEngine(config_path)
    result = await engine.run(target)
    output_format = output_format or ["json", "markdown"]
    if "json" in output_format:
        _write_json(result)
    if "markdown" in output_format:
        _write_markdown(result)
    if result.config_snapshot.get("scanner", {}).get("dawn", {}).get("memory", True):
        DawnMemory().append_daily(f"SCAN: {target} — {len(result.findings)} findings ({result.critical_count} critical)")
        for f in result.findings:
            DawnMemory().memorize_finding(f.to_dict())
    return result


def _write_json(result):
    import os
    out_dir = result.config_snapshot.get("scanner", {}).get("output_dir", "findings")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "findings.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)


def _write_markdown(result):
    import os
    out_dir = result.config_snapshot.get("scanner", {}).get("output_dir", "findings")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "report.md")
    lines = [
        f"# Scan Report",
        f"Target: {result.target}",
        f"Date: {__import__('time').ctime(result.started_at)}",
        f"Duration: {result.duration_seconds}s",
        f"",
        f"## Summary",
        f"- Total: {len(result.findings)}",
        f"- Verified: {result.verified_count}",
        f"- Critical: {result.critical_count}",
        f"- High: {result.high_count}",
        f"",
    ]
    by_severity = {}
    for f in result.findings:
        by_severity.setdefault(f.severity.value, []).append(f)
    for sev in ["critical", "high", "medium", "low", "info", "unconfirmed"]:
        items = by_severity.get(sev, [])
        if not items:
            continue
        lines.append(f"## {sev.upper()} ({len(items)})")
        for item in items[:10]:
            verified = " [verified]" if item.verified else ""
            diffs = f" diffs={item.diffs}" if item.diffs else ""
            lines.append(f"- {item.url} param={item.param} payload={item.payload}{verified}{diffs}")
            lines.append(f"  snippet: {item.body[:150]}")
            if item.baseline_body:
                lines.append(f"  baseline: {item.baseline_body[:150]}")
        if len(items) > 10:
            lines.append(f"  ... and {len(items) - 10} more.")
        lines.append("")
    if result.errors:
        lines.append("## Errors")
        for err in result.errors:
            lines.append(f"- {err}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
