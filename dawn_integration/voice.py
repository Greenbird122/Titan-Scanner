"""Voice/TTS integration for vulnerability scanner findings.

Provides spoken summaries of scan results for Dawn's voice system.
"""

from __future__ import annotations

from typing import List, Optional


def findings_for_speech(findings: List[dict], limit: int = 3) -> str:
    """Summarize critical/high findings for TTS output.

    Args:
        findings: List of finding dicts from ScanResult
        limit: Maximum findings to include

    Returns:
        Short spoken summary string
    """
    if not findings:
        return "No vulnerabilities found."

    critical = [f for f in findings if f.get("severity") == "critical"]
    high = [f for f in findings if f.get("severity") == "high"]
    medium = [f for f in findings if f.get("severity") == "medium"]

    parts = []
    if critical:
        n = min(len(critical), limit)
        parts.append(f"{n} critical vulnerability{'s' if n > 1 else ''} found")
        for f in critical[:limit]:
            attack = f.get("attack_type", "unknown")
            url = f.get("url", "unknown target")
            parts.append(f"{attack} on {url}")
    if high and len(parts) - 1 < limit:
        n = min(len(high), limit - (len(parts) - 1))
        parts.append(f"{n} high severity vulnerability{'s' if n > 1 else ''}")
        for f in high[: limit - len(parts) + 1]:
            attack = f.get("attack_type", "unknown")
            url = f.get("url", "unknown target")
            parts.append(f"{attack} on {url}")
    if medium and not critical and not high:
        parts.append(f"{len(medium)} medium severity findings")

    total = len(findings)
    verified = sum(1 for f in findings if f.get("verified"))
    parts.append(f"Total {total} findings, {verified} verified.")

    return ". ".join(parts[: limit + 3])


def render_findings_for_tts(scan_result) -> str:
    """Render a ScanResult object for TTS output.

    Args:
        scan_result: ScanResult object from scanner.engine

    Returns:
        Spoken summary string
    """
    findings = [f.to_dict() for f in scan_result.findings]
    return findings_for_speech(findings)
