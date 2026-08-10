"""Dawn memory integration for vulnerability scanner.

Dual persistence:
- Daily markdown notes (human-readable)
- SQLite findings table (structured queries)
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional


MEMORY_DIR = os.path.expanduser("~/.kilo/dawn/memory")
FINDINGS_DB_PATH = os.path.join(MEMORY_DIR, "findings.db")


def _init_findings_db(db_path: Optional[str] = None):
    path = db_path or FINDINGS_DB_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            target TEXT,
            url TEXT,
            method TEXT,
            param TEXT,
            location TEXT,
            payload TEXT,
            status INTEGER,
            attack_type TEXT,
            severity TEXT,
            verified INTEGER,
            diffs TEXT,
            baseline_body TEXT,
            verification_body TEXT,
            cvss_score REAL,
            poc_curl TEXT,
            notes TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
    conn.commit()
    return conn


class DawnMemory:
    def __init__(self, enabled: bool = True, memory_dir: Optional[str] = None):
        self.enabled = enabled
        self.memory_dir = Path(memory_dir or MEMORY_DIR)
        self.findings_db_path = self.memory_dir / "findings.db"
        if self.enabled:
            self.memory_dir.mkdir(parents=True, exist_ok=True)

    def append_daily(self, text: str) -> bool:
        if not self.enabled:
            return False
        try:
            day = datetime.now().strftime("%Y-%m-%d")
            path = self.memory_dir / f"{day}.md"
            ts = datetime.now().strftime("%H:%M:%S")
            line = f"- [{ts}] {text}\n"
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
            return True
        except Exception:
            return False

    def memorize_finding(self, finding: Dict[str, Any]) -> bool:
        target = finding.get("target", "unknown")
        url = finding.get("url", "")
        param = finding.get("param", "")
        payload = finding.get("payload", "")[:50]
        severity = finding.get("severity", "unconfirmed")
        attack_type = finding.get("attack_type", "unknown")
        text = f"MEMORIZE: vuln|{target}|{attack_type}|{severity}|{url}|{param}|{payload}"
        daily_ok = self.append_daily(text)

        try:
            conn = _init_findings_db(str(self.findings_db_path))
            conn.execute(
                """INSERT INTO findings (ts, target, url, method, param, location, payload, status, attack_type, severity, verified, diffs, baseline_body, verification_body, cvss_score, poc_curl, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    datetime.now().isoformat(),
                    target,
                    url,
                    finding.get("method"),
                    param,
                    finding.get("location"),
                    payload,
                    finding.get("status"),
                    attack_type,
                    severity,
                    int(bool(finding.get("verified"))),
                    json.dumps(finding.get("diffs", [])),
                    finding.get("baseline_body", "")[:2000],
                    finding.get("verification_body", "")[:2000],
                    finding.get("cvss_score"),
                    finding.get("poc_curl", ""),
                    finding.get("notes", ""),
                ),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

        return daily_ok

    def recent_daily(self, limit: int = 2) -> List[str]:
        if not self.enabled:
            return []
        lines: List[str] = []
        try:
            days = sorted(self.memory_dir.glob("*.md"), reverse=True)[:limit]
            for day_file in days:
                with open(day_file, "r", encoding="utf-8") as f:
                    lines.extend(f.readlines()[-40:])
        except Exception:
            pass
        return lines

    def query_findings(self, target: Optional[str] = None, days: int = 7, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not self.enabled:
            return results
        try:
            cutoff = datetime.now() - timedelta(days=days)
            cutoff_str = cutoff.isoformat()
            conn = sqlite3.connect(str(self.findings_db_path))
            conn.row_factory = sqlite3.Row
            query = "SELECT * FROM findings WHERE ts >= ?"
            params: List[Any] = [cutoff_str]
            if target:
                query += " AND target = ?"
                params.append(target)
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            query += " ORDER BY ts DESC"
            rows = conn.execute(query, params).fetchall()
            conn.close()
            results = [dict(r) for r in rows]
        except Exception:
            pass
        return results

    def get_scan_summary(self, days: int = 7) -> Dict[str, Any]:
        try:
            conn = sqlite3.connect(str(self.findings_db_path))
            conn.row_factory = sqlite3.Row
            cutoff = (datetime.now() - timedelta(days=days)).isoformat()
            total = conn.execute("SELECT COUNT(*) FROM findings WHERE ts >= ?", (cutoff,)).fetchone()[0]
            by_severity = {}
            rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings WHERE ts >= ? GROUP BY severity",
                (cutoff,),
            ).fetchall()
            for r in rows:
                by_severity[r["severity"]] = r["cnt"]
            by_target = {}
            rows = conn.execute(
                "SELECT target, COUNT(*) as cnt FROM findings WHERE ts >= ? GROUP BY target ORDER BY cnt DESC LIMIT 10",
                (cutoff,),
            ).fetchall()
            for r in rows:
                by_target[r["target"]] = r["cnt"]
            conn.close()
            return {
                "total": total,
                "by_severity": by_severity,
                "by_target": by_target,
                "days": days,
            }
        except Exception:
            return {"total": 0, "by_severity": {}, "by_target": {}, "days": days}
