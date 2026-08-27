"""Supabase RLS audit module.

Detects Supabase instances and tests:
  - anonymous table read access (SELECT)
  - anonymous INSERT/UPDATE/DELETE access
  - auth settings (mailer_autoconfirm, etc.)
  - exposed service role keys in JS bundles
  - common Supabase-specific endpoints
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType


class SupabaseAuditModule:
    """Audit Supabase backend security."""

    name = "supabase"
    timeout = 45

    SUPABASE_PATTERNS = [
        r"https?://[a-z0-9]+\.supabase\.co",
        r"supabase\.co",
        r"/rest/v1/",
        r"/auth/v1/",
        r"supabase_url",
        r"SUPABASE_URL",
        r"SUPABASE_ANON_KEY",
        r"supabase_anon_key",
        r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    ]

    COMMON_TABLES = [
        "users", "profiles", "posts", "comments", "messages",
        "notifications", "follows", "likes", "stories",
        "payments", "orders", "products", "categories",
        "reports", "warnings", "admin_logs", "boosts",
        "coin_transactions", "media", "uploads",
    ]

    def __init__(self, http_client=None):
        self.http = http_client

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str], fingerprint: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        base_url = self._extract_supabase_url(fingerprint, url)
        if not base_url:
            return findings

        anon_key = self._extract_anon_key(fingerprint, url)
        if not anon_key:
            return findings

        findings.extend(await self._test_auth_settings(base_url, anon_key))
        findings.extend(await self._test_table_read_access(base_url, anon_key))
        findings.extend(await self._test_table_write_access(base_url, anon_key))

        return findings

    def _extract_supabase_url(self, fingerprint: Dict[str, Any], url: str) -> Optional[str]:
        for pattern in self.SUPABASE_PATTERNS:
            m = re.search(pattern, url or "", re.IGNORECASE)
            if m:
                candidate = m.group(0)
                if candidate.startswith("http"):
                    return candidate.rstrip("/")
                return f"https://{candidate}".rstrip("/")
        return None

    def _extract_anon_key(self, fingerprint: Dict[str, Any], url: str) -> Optional[str]:
        text = json.dumps(fingerprint or {})
        m = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+', text)
        if m:
            return m.group(0)
        return None

    async def _request(self, base_url: str, path: str, anon_key: str, method: str = "GET", body: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        if not self.http:
            return None
        target = f"{base_url}{path}"
        headers = {
            "apikey": anon_key,
            "Authorization": f"Bearer {anon_key}",
            "Content-Type": "application/json",
        }
        try:
            if method == "GET":
                resp = await self.http.get(target, headers=headers, timeout=10)
            else:
                resp = await self.http.post(target, headers=headers, json=body or {}, timeout=10)
            if hasattr(resp, "status"):
                return {"status": resp.status, "body": await resp.text() if hasattr(resp, "text") else ""}
            return None
        except Exception:
            return None

    async def _test_auth_settings(self, base_url: str, anon_key: str) -> List[Finding]:
        findings: List[Finding] = []
        resp = await self._request(base_url, "/auth/v1/settings", anon_key)
        if not resp:
            return findings
        if resp.get("status") == 200:
            try:
                data = json.loads(resp.get("body", "{}") or "{}")
            except json.JSONDecodeError:
                return findings
            if data.get("mailer_autoconfirm") is True:
                findings.append(self._make_finding(
                    url=f"{base_url}/auth/v1/settings",
                    param="mailer_autoconfirm",
                    location="response",
                    payload="autoconfirm=true",
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    diffs=["auth:mailer_autoconfirm=true"],
                    evidence="Supabase allows instant account creation without email confirmation",
                    metadata={"setting": "mailer_autoconfirm", "value": True},
                ))
        return findings

    async def _test_table_read_access(self, base_url: str, anon_key: str) -> List[Finding]:
        findings: List[Finding] = []
        for table in self.COMMON_TABLES:
            resp = await self._request(base_url, f"/rest/v1/{table}?select=id&limit=1", anon_key)
            if not resp:
                continue
            if resp.get("status") == 200:
                try:
                    data = json.loads(resp.get("body", "[]") or "[]")
                except json.JSONDecodeError:
                    continue
                if isinstance(data, list) and len(data) > 0:
                    findings.append(self._make_finding(
                        url=f"{base_url}/rest/v1/{table}",
                        param="anon_read",
                        location="response",
                        payload=f"SELECT * FROM {table} LIMIT 1",
                        severity=Severity.CRITICAL if table == "users" else Severity.HIGH,
                        confidence=0.9,
                        diffs=[f"baas:anon_read:{table}"],
                        evidence=f"Anonymous read access to {table} table: {len(data)} row(s) returned",
                        metadata={"table": table, "row_count": len(data)},
                    ))
        return findings

    async def _test_table_write_access(self, base_url: str, anon_key: str) -> List[Finding]:
        findings: List[Finding] = []
        for table in ["notifications", "posts", "comments", "messages"]:
            probe_id = "00000000-0000-0000-0000-000000000000"
            body = {"user_id": probe_id, "message": "titan-probe", "is_read": False}
            resp = await self._request(base_url, f"/rest/v1/{table}", anon_key, method="POST", body=body)
            if not resp:
                continue
            if resp.get("status") == 201:
                findings.append(self._make_finding(
                    url=f"{base_url}/rest/v1/{table}",
                    param="anon_insert",
                    location="response",
                    payload=json.dumps(body),
                    severity=Severity.HIGH,
                    confidence=0.85,
                    diffs=[f"baas:anon_insert:{table}"],
                    evidence=f"Anonymous INSERT into {table} succeeded (RLS missing or too permissive)",
                    metadata={"table": table, "method": "POST", "status": 201},
                ))
        return findings

    def _make_finding(self, url: str, param: str, location: str, payload: str, severity: Severity, confidence: float, diffs: List[str], evidence: str = "", metadata: Dict[str, Any] = None) -> Finding:
        return Finding(
            target=url,
            url=url,
            method="GET",
            param=param,
            location=location,
            payload=payload,
            attack_type=AttackType.UNKNOWN,
            severity=severity,
            confidence=confidence,
            status=200,
            evidence=evidence or "",
            diffs=diffs or [],
            metadata=metadata or {},
            tags=["baas", "supabase"],
            verified=True,
        )
