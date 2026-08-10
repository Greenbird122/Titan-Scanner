"""Dawn integration for Titan Scanner."""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


MEMORY_DIR = Path.home() / ".kilo" / "dawn" / "memory"


class DawnMemory:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        if self.enabled:
            MEMORY_DIR.mkdir(parents=True, exist_ok=True)

    def memorize_finding(self, finding: Dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        try:
            day = datetime.now().strftime("%Y-%m-%d")
            path = MEMORY_DIR / f"{day}.md"
            ts = datetime.now().strftime("%H:%M:%S")
            target = finding.get("target", "unknown")
            url = finding.get("url", "")
            param = finding.get("param", "")
            payload = finding.get("payload", "")[:50]
            severity = finding.get("severity", "unconfirmed")
            attack_type = finding.get("attack_type", "unknown")
            line = f"- [{ts}] MEMORIZE: vuln|{target}|{attack_type}|{severity}|{url}|{param}|{payload}\n"
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
            return True
        except Exception:
            return False

    def append_daily(self, text: str) -> bool:
        if not self.enabled:
            return False
        try:
            day = datetime.now().strftime("%Y-%m-%d")
            path = MEMORY_DIR / f"{day}.md"
            ts = datetime.now().strftime("%H:%M:%S")
            line = f"- [{ts}] {text}\n"
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
            return True
        except Exception:
            return False

    def query_findings(self, target: Optional[str] = None, days: int = 7) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not self.enabled:
            return results
        try:
            from datetime import datetime, timedelta
            cutoff = datetime.now() - timedelta(days=days)
            for path in MEMORY_DIR.glob("*.md"):
                if path.stem < cutoff.strftime("%Y-%m-%d"):
                    continue
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("- [") and "MEMORIZE: vuln|" in line:
                            parts = line.strip().split("MEMORIZE: vuln|")[1].split("|")
                            if len(parts) >= 5:
                                entry = {
                                    "target": parts[0],
                                    "attack_type": parts[1],
                                    "severity": parts[2],
                                    "url": parts[3],
                                    "param": parts[4],
                                    "payload": parts[5] if len(parts) > 5 else "",
                                }
                                if target is None or entry["target"] == target:
                                    results.append(entry)
        except Exception:
            pass
        return results
