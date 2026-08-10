import asyncio
import re
from typing import Optional

TOOL_SCAN_RE = re.compile(r"^TOOL:scan:(.+)$", re.IGNORECASE)


def parse_scan_blocks(text: str) -> list[dict]:
    blocks = []
    for line in text.splitlines():
        m = TOOL_SCAN_RE.match(line.strip())
        if m:
            blocks.append({"kind": "scan", "arg": m.group(1).strip()})
    return blocks


async def execute_scan_block(arg: str, config_path: str = "config.yaml") -> str:
    from dawn_integration.cli import run_scan
    result = await run_scan(arg, config_path)
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
    return "\n".join(lines)
