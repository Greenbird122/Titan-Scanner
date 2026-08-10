"""Dawn CLI extension — drop-in commands for the vulnerability scanner.

Add to dawn/dawn/cli.py:
    COMMANDS = [
        "/help", "/new", "/resume", "/model", "/auth", "/config", "/memory",
        "/prefs", "/projects", "/audit", "/ask", "/voice", "/quit",
        "/scan", "/findings", "/vulns",
    ]

Add to CLI.run() before the regular-message branch:
    if cmd.startswith("/scan"):
        print(self._cmd_scan(cmd))
        continue
    if cmd == "/findings":
        print(self._cmd_findings())
        continue
    if cmd == "/vulns":
        print(self._cmd_vulns())
        continue

Add these methods to the CLI class.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime
from typing import List, Optional


def _scan_target(raw: str) -> str:
    arg = raw[len("/scan"):].strip()
    if not arg:
        return ""
    return arg


def _get_dawn_memory():
    try:
        parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if parent not in sys.path:
            sys.path.insert(0, parent)
        from dawn_integration.memory import DawnMemory
        return DawnMemory()
    except Exception:
        return None


def _get_scanner_engine(config_path: str = "config.yaml"):
    try:
        from scanner.engine import ScanEngine
        return ScanEngine(config_path)
    except Exception:
        return None


def cmd_scan(target: str, config_path: str = "config.yaml") -> str:
    if not target:
        return "Usage: /scan <url>"
    memory = _get_dawn_memory()
    if memory:
        memory.append_daily(f"SCAN_START: {target}")
    try:
        import asyncio
        engine = _get_scanner_engine(config_path)
        if engine is None:
            return "ERROR: scanner engine unavailable"
        result = asyncio.run(engine.run(target))
        lines = [
            f"[scan] Target: {result.target}",
            f"[scan] Duration: {result.duration_seconds}s",
            f"[scan] Findings: {len(result.findings)} (verified: {result.verified_count}, critical: {result.critical_count}, high: {result.high_count})",
        ]
        for f in result.findings[:5]:
            lines.append(f"- {f.severity.value.upper()}: {f.url} param={f.param} payload={f.payload[:40]}")
        if len(result.findings) > 5:
            lines.append(f"... and {len(result.findings) - 5} more.")
        if result.errors:
            lines.append("[scan] Errors:")
            for err in result.errors:
                lines.append(f"  - {err}")
        if memory:
            memory.append_daily(f"SCAN_COMPLETE: {target} — {len(result.findings)} findings ({result.critical_count} critical)")
            for f in result.findings:
                memory.memorize_finding(f.to_dict())
        return "\n".join(lines)
    except Exception as exc:
        if memory:
            memory.append_daily(f"SCAN_ERROR: {target} — {exc}")
        return f"ERROR: scan failed: {exc}"


def cmd_findings(target: Optional[str] = None, days: int = 7) -> str:
    memory = _get_dawn_memory()
    if memory is None:
        return "ERROR: Dawn memory unavailable"
    results = memory.query_findings(target=target, days=days)
    if not results:
        return f"No findings found for {target or 'any target'} in the last {days} days."
    lines = [f"Findings ({len(results)}) — last {days} days:"]
    for entry in results[:20]:
        lines.append(f"- [{entry['severity']}] {entry['attack_type']} on {entry['target']}")
        lines.append(f"    {entry['url']} param={entry['param']} payload={entry['payload'][:40]}")
    if len(results) > 20:
        lines.append(f"... and {len(results) - 20} more.")
    return "\n".join(lines)


def cmd_vulns(severity: Optional[str] = None, target: Optional[str] = None, days: int = 7) -> str:
    memory = _get_dawn_memory()
    if memory is None:
        return "ERROR: Dawn memory unavailable"
    results = memory.query_findings(target=target, days=days)
    if severity:
        results = [r for r in results if r.get("severity", "").lower() == severity.lower()]
    if not results:
        return f"No vulnerabilities found for {target or 'any target'} with severity={severity or 'any'} in the last {days} days."
    lines = [f"Vulnerabilities ({len(results)}) — severity={severity or 'any'}:"]
    for entry in results[:20]:
        lines.append(f"- [{entry['severity']}] {entry['attack_type']} on {entry['target']}")
        lines.append(f"    {entry['url']} param={entry['param']} payload={entry['payload'][:40]}")
    if len(results) > 20:
        lines.append(f"... and {len(results) - 20} more.")
    return "\n".join(lines)
