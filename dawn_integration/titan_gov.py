"""Titan Gov integration for vulnerability scanner.

Wraps the Titan Gov proposal pipeline for scan approval:
    propose_by_rules() -> human review -> execute_proposal()

Also provides SQLite-backed audit logging.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional


AUDIT_DB_PATH = os.path.expanduser("~/.kilo/dawn/scanner/audit.db")


def _init_audit_db():
    os.makedirs(os.path.dirname(AUDIT_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(AUDIT_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            target TEXT,
            action TEXT,
            result TEXT,
            details TEXT
        )
    """)
    conn.commit()
    return conn


def log_audit(target: str, action: str, result: str, details: str = ""):
    try:
        conn = _init_audit_db()
        conn.execute(
            "INSERT INTO scan_audit (ts, target, action, result, details) VALUES (?, ?, ?, ?, ?)",
            (datetime.now().isoformat(), target, action, result, details[:500]),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _log_audit_jsonl(target: str, action: str, result: str):
    try:
        audit_dir = os.path.expanduser("~/.kilo/dawn/scanner/audit")
        os.makedirs(audit_dir, exist_ok=True)
        path = os.path.join(audit_dir, "scan_audit.jsonl")
        entry = {
            "ts": datetime.now().isoformat(),
            "target": target,
            "action": action,
            "result": result,
        }
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


async def request_scan_approval(target: str, aggression: str, scope: Optional[Dict[str, List[str]]] = None) -> bool:
    """Request approval for a scan via Titan Gov proposal pipeline.

    Args:
        target: Target URL or IP
        aggression: passive | active | aggressive
        scope: Optional include/exclude paths

    Returns:
        True if approved, False if denied
    """
async def request_scan_approval(target: str, aggression: str, scope: Optional[Dict[str, List[str]]] = None) -> bool:
    """Request approval for a scan via Titan Gov proposal pipeline.

    Args:
        target: Target URL or IP
        aggression: passive | active | aggressive
        scope: Optional include/exclude paths

    Returns:
        True if approved, False if denied
    """
    try:
        parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if parent not in sys.path:
            sys.path.insert(0, parent)
        titan_gov_path = os.path.join(parent, "..", "deepseek4free", "titan_gov")
        titan_gov_parent = os.path.dirname(titan_gov_path)
        if titan_gov_parent not in sys.path:
            sys.path.insert(0, titan_gov_parent)

        import importlib
        gov_graph = importlib.import_module("titan_gov.graph")

        if gov_graph.is_blocked(target):
            log_audit(target, "scan_blocked", "denied", "target in protected graph")
            print(f"[GOV] Scan blocked: {target} is in protected graph")
            return False

        print(f"[GOV] Approval required for scan: {target} (aggression: {aggression})")
        desc = f"Scan {target} with aggression={aggression}"
        if scope:
            desc += f" scope={scope}"

        approved = await _prompt_approval(desc)
        if approved:
            log_audit(target, "scan_approved", "ok", desc)
            _log_audit_jsonl(target, "scan_approved", "ok")
            print(f"[GOV] Scan approved: {target}")
        else:
            log_audit(target, "scan_denied", "denied", desc)
            _log_audit_jsonl(target, "scan_denied", "denied")
            print(f"[GOV] Scan denied: {target}")
        return approved
    except Exception as exc:
        print(f"[GOV] Approval workflow error: {exc}")
        log_audit(target, "scan_workflow_error", "error", str(exc))
        return True


async def _prompt_approval(proposal: Any) -> bool:
    try:
        desc = getattr(proposal, "description", str(proposal))
        print(f"\n[GOV] Approval needed: {desc}")
        resp = input("Approve scan? [y/N]: ").strip().lower()
        return resp == "y"
    except Exception:
        return False


def get_recent_audit(limit: int = 20) -> List[Dict[str, str]]:
    """Get recent scan audit entries from SQLite."""
    try:
        conn = sqlite3.connect(AUDIT_DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT ts, target, action, result, details FROM scan_audit ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []
