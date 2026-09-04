"""Webhook Alerts — notify when critical findings discovered.

When a critical finding is discovered, Titan sends alerts to:
- Slack
- Discord
- Email
- Custom webhooks
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from titan.core.models import Finding


@dataclass
class WebhookConfig:
    """Configuration for a webhook endpoint."""
    url: str
    type: str  # "slack", "discord", "email", "custom"
    events: List[str]  # ["finding", "critical", "scan_complete"]
    headers: Dict[str, str] = None
    enabled: bool = True


class WebhookManager:
    """Manage webhook alerts."""

    def __init__(self):
        self._webhooks: List[WebhookConfig] = []
        self._sent: List[Dict[str, Any]] = []

    def add_webhook(self, config: WebhookConfig) -> None:
        """Add a webhook endpoint."""
        self._webhooks.append(config)

    def add_slack(self, url: str, events: Optional[List[str]] = None) -> None:
        """Add Slack webhook."""
        self._webhooks.append(WebhookConfig(
            url=url,
            type="slack",
            events=events or ["finding", "critical", "scan_complete"],
        ))

    def add_discord(self, url: str, events: Optional[List[str]] = None) -> None:
        """Add Discord webhook."""
        self._webhooks.append(WebhookConfig(
            url=url,
            type="discord",
            events=events or ["finding", "critical", "scan_complete"],
        ))

    def add_custom(self, url: str, headers: Dict[str, str], events: Optional[List[str]] = None) -> None:
        """Add custom webhook."""
        self._webhooks.append(WebhookConfig(
            url=url,
            type="custom",
            events=events or ["finding", "critical"],
            headers=headers,
        ))

    async def send_finding_alert(self, finding: Finding) -> List[Dict[str, Any]]:
        """Send alert for a new finding."""
        results = []
        severity = str(finding.severity)

        for webhook in self._webhooks:
            if not webhook.enabled:
                continue

            # Check if this event type is subscribed
            event_type = "critical" if severity in ("CRITICAL", "HIGH") else "finding"
            if event_type not in webhook.events and "finding" not in webhook.events:
                continue

            payload = self._format_finding_payload(finding, webhook.type)
            result = await self._send(webhook, payload)
            results.append(result)

        return results

    async def send_scan_complete(
        self,
        target: str,
        score: float,
        grade: str,
        findings_count: int,
    ) -> List[Dict[str, Any]]:
        """Send scan completion alert."""
        results = []

        for webhook in self._webhooks:
            if not webhook.enabled:
                continue

            if "scan_complete" not in webhook.events:
                continue

            payload = self._format_scan_complete_payload(
                target, score, grade, findings_count, webhook.type
            )
            result = await self._send(webhook, payload)
            results.append(result)

        return results

    def _format_finding_payload(self, finding: Finding, webhook_type: str) -> Dict[str, Any]:
        """Format finding for webhook."""
        if webhook_type == "slack":
            return {
                "text": f"🚨 *{finding.severity}* Finding Discovered",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"🚨 *{finding.severity}* Finding\n"
                                f"*Target:* {finding.target}\n"
                                f"*URL:* {finding.url}\n"
                                f"*Type:* {finding.attack_type}\n"
                                f"*Confidence:* {finding.confidence:.0%}\n"
                                f"*Notes:* {finding.notes or 'N/A'}"
                            ),
                        },
                    }
                ],
            }
        elif webhook_type == "discord":
            return {
                "embeds": [{
                    "title": f"🚨 {finding.severity} Finding",
                    "description": (
                        f"**Target:** {finding.target}\n"
                        f"**URL:** {finding.url}\n"
                        f"**Type:** {finding.attack_type}\n"
                        f"**Confidence:** {finding.confidence:.0%}\n"
                        f"**Notes:** {finding.notes or 'N/A'}"
                    ),
                    "color": 16711680 if str(finding.severity) == "CRITICAL" else 255,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }],
            }
        else:
            return {
                "event": "finding",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "finding": {
                    "target": finding.target,
                    "url": finding.url,
                    "method": finding.method,
                    "severity": str(finding.severity),
                    "confidence": finding.confidence,
                    "attack_type": str(finding.attack_type),
                    "notes": finding.notes,
                },
            }

    def _format_scan_complete_payload(
        self,
        target: str,
        score: float,
        grade: str,
        findings_count: int,
        webhook_type: str,
    ) -> Dict[str, Any]:
        """Format scan complete for webhook."""
        if webhook_type == "slack":
            return {
                "text": f"✅ Scan Complete: {target}",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"✅ *Scan Complete*\n"
                                f"*Target:* {target}\n"
                                f"*Score:* {score}% ({grade})\n"
                                f"*Findings:* {findings_count}"
                            ),
                        },
                    }
                ],
            }
        elif webhook_type == "discord":
            return {
                "embeds": [{
                    "title": "✅ Scan Complete",
                    "description": (
                        f"**Target:** {target}\n"
                        f"**Score:** {score}% ({grade})\n"
                        f"**Findings:** {findings_count}"
                    ),
                    "color": 65280,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }],
            }
        else:
            return {
                "event": "scan_complete",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "target": target,
                "score": score,
                "grade": grade,
                "findings_count": findings_count,
            }

    async def _send(self, webhook: WebhookConfig, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send webhook payload."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                headers = webhook.headers or {}
                headers.setdefault("Content-Type", "application/json")

                async with session.post(
                    webhook.url,
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    result = {
                        "webhook_type": webhook.type,
                        "status": resp.status,
                        "success": resp.status in (200, 201, 204),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }
                    self._sent.append(result)
                    return result
        except Exception as e:
            result = {
                "webhook_type": webhook.type,
                "status": 0,
                "success": False,
                "error": str(e),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            self._sent.append(result)
            return result

    def get_sent(self) -> List[Dict[str, Any]]:
        return self._sent

    def get_webhooks(self) -> List[WebhookConfig]:
        return self._webhooks
