"""Structured Logging — JSON logs for every test.

Every test execution is logged with:
- Timestamp
- Endpoint
- Attack type
- Payload
- Response code
- Duration
- Result (pass/fail/error)
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utc_now() -> str:
    """ISO-8601 UTC timestamp with microseconds.

    time.strftime("%f") is not supported on Windows, so use datetime's
    strftime, which implements %f on every platform.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class LogEntry:
    """A single log entry."""
    timestamp: str
    level: str  # "info", "warning", "error", "debug"
    category: str  # "test", "finding", "coverage", "error"
    message: str
    data: Dict[str, Any]


class TitanLogger:
    """Structured logger for Titan."""

    def __init__(self, log_dir: Optional[str] = None, verbose: bool = False):
        self.log_dir = log_dir or "titan_logs"
        self.verbose = verbose
        self._entries: List[LogEntry] = []
        os.makedirs(self.log_dir, exist_ok=True)

    def log_test(
        self,
        endpoint: str,
        attack_type: str,
        payload: str,
        response_code: int,
        duration_ms: float,
        result: str,
        notes: str = "",
    ) -> None:
        """Log a test execution."""
        entry = LogEntry(
            timestamp=_utc_now(),
            level="info",
            category="test",
            message=f"{attack_type} on {endpoint}",
            data={
                "endpoint": endpoint,
                "attack_type": attack_type,
                "payload": payload[:200],
                "response_code": response_code,
                "duration_ms": duration_ms,
                "result": result,
                "notes": notes,
            },
        )
        self._entries.append(entry)
        if self.verbose:
            self._print_entry(entry)

    def log_finding(
        self,
        endpoint: str,
        attack_type: str,
        severity: str,
        confidence: float,
        notes: str,
    ) -> None:
        """Log a finding discovery."""
        entry = LogEntry(
            timestamp=_utc_now(),
            level="warning",
            category="finding",
            message=f"FINDING: {severity} {attack_type} on {endpoint}",
            data={
                "endpoint": endpoint,
                "attack_type": attack_type,
                "severity": severity,
                "confidence": confidence,
                "notes": notes,
            },
        )
        self._entries.append(entry)
        self._print_entry(entry)

    def log_coverage(
        self,
        score: float,
        grade: str,
        tests_run: int,
    ) -> None:
        """Log coverage update."""
        entry = LogEntry(
            timestamp=_utc_now(),
            level="info",
            category="coverage",
            message=f"Coverage: {score}% ({grade}) — {tests_run} tests",
            data={
                "score": score,
                "grade": grade,
                "tests_run": tests_run,
            },
        )
        self._entries.append(entry)
        if self.verbose:
            self._print_entry(entry)

    def log_warning(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a warning."""
        entry = LogEntry(
            timestamp=_utc_now(),
            level="warning",
            category="warning",
            message=message,
            data=context or {},
        )
        self._entries.append(entry)
        self._print_entry(entry)

    def log_error(
        self,
        error: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log an error."""
        entry = LogEntry(
            timestamp=_utc_now(),
            level="error",
            category="error",
            message=error,
            data=context or {},
        )
        self._entries.append(entry)
        self._print_entry(entry)

    def log_info(self, message: str, data: Optional[Dict[str, Any]] = None) -> None:
        """Log general info."""
        entry = LogEntry(
            timestamp=_utc_now(),
            level="info",
            category="info",
            message=message,
            data=data or {},
        )
        self._entries.append(entry)
        if self.verbose:
            self._print_entry(entry)

    def save(self, filename: Optional[str] = None) -> str:
        """Save logs to file."""
        if filename is None:
            filename = f"titan_{int(time.time())}.jsonl"

        filepath = os.path.join(self.log_dir, filename)
        with open(filepath, "w") as f:
            for entry in self._entries:
                f.write(json.dumps({
                    "timestamp": entry.timestamp,
                    "level": entry.level,
                    "category": entry.category,
                    "message": entry.message,
                    "data": entry.data,
                }) + "\n")

        return filepath

    def get_entries(
        self,
        level: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[LogEntry]:
        """Get log entries with optional filtering."""
        entries = self._entries
        if level:
            entries = [e for e in entries if e.level == level]
        if category:
            entries = [e for e in entries if e.category == category]
        return entries

    def get_summary(self) -> Dict[str, Any]:
        """Get log summary."""
        total = len(self._entries)
        by_level: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        for entry in self._entries:
            by_level[entry.level] = by_level.get(entry.level, 0) + 1
            by_category[entry.category] = by_category.get(entry.category, 0) + 1

        return {
            "total_entries": total,
            "by_level": by_level,
            "by_category": by_category,
        }

    def _print_entry(self, entry: LogEntry) -> None:
        """Print entry to console."""
        icons = {
            "info": "[*]",
            "warning": "[!]",
            "error": "[-]",
            "debug": "[~]",
        }
        icon = icons.get(entry.level, "[?]")
        print(f"{icon} {entry.message}")

    def clear(self) -> None:
        """Clear all entries."""
        self._entries.clear()


# ---------------------------------------------------------------------------
# Module-level facade: get_logger(name) -> .info/.warning/.error
# ---------------------------------------------------------------------------

_SINK = TitanLogger(log_dir=os.environ.get("TITAN_LOG_DIR", "titan_logs"))


class _ModuleLogger:
    """Thin per-module facade over the shared TitanLogger sink.

    Each call records a structured LogEntry (level + module + any extra
    structured fields) and mirrors the raw message to stdout so existing
    console behavior is preserved — engine messages already carry their own
    "[+] " / "[!] " prefix.
    """

    def __init__(self, name: str, sink: TitanLogger) -> None:
        self._name = name
        self._sink = sink

    def info(self, message: str, **data: Any) -> None:
        """Record an info entry and mirror it to the console."""
        self._sink.log_info(message, {"module": self._name, **(data or {})})
        print(message)

    def warning(self, message: str, **data: Any) -> None:
        """Record a warning entry and mirror it to the console."""
        self._sink.log_warning(message, {"module": self._name, **(data or {})})
        print(message)

    def error(self, message: str, **data: Any) -> None:
        """Record an error entry and mirror it to the console."""
        self._sink.log_error(message, {"module": self._name, **(data or {})})
        print(message)


def get_logger(name: str) -> _ModuleLogger:
    """Return the shared module logger facade for ``name``.

    All facades share one TitanLogger sink, so entries from every module land
    in the same structured stream and are saved together via ``save()``.
    """
    return _ModuleLogger(name, _SINK)
