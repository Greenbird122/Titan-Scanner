"""Titan Gov integration for Titan Scanner."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional


async def request_scan_approval(target: str, aggression: str) -> bool:
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
            print(f"[GOV] Scan blocked: {target} is in protected graph")
            return False

        print(f"[GOV] Approval required for scan: {target} (aggression: {aggression})")
        desc = f"Scan {target} with aggression={aggression}"
        approved = await _prompt_approval(desc)
        if approved:
            print(f"[GOV] Scan approved: {target}")
        else:
            print(f"[GOV] Scan denied: {target}")
        return approved
    except Exception as exc:
        print(f"[GOV] Approval workflow error: {exc}")
        return True


async def _prompt_approval(desc: str) -> bool:
    try:
        print(f"\n[GOV] Approval needed: {desc}")
        resp = input("Approve scan? [y/N]: ").strip().lower()
        return resp == "y"
    except Exception:
        return False


def get_recent_audit(limit: int = 20) -> List[Dict[str, str]]:
    try:
        import sqlite3
        audit_db = os.path.expanduser("~/.kilo/dawn/scanner/audit.db")
        conn = sqlite3.connect(audit_db)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT ts, target, action, result, details FROM scan_audit ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []
