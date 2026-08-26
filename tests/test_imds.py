"""Tests for the IMDS Prober — Cloud Instance Metadata Service exploitation.

Covers:
  - Multi-cloud probing (AWS, GCP, Azure)
  - IMDSv1 vs IMDSv2 access
  - Credential extraction (AWS role creds, GCP tokens, Azure tokens)
  - User-data exposure
  - Finding generation
  - Error handling (timeouts, connection failures)
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from titan.modules.cloud_control.imds import (
    ALL_IMDS,
    AWS_IMDS_V1,
    AWS_IMDS_V2_TOKEN,
    AZURE_IMDS,
    GCP_IMDS,
    IMDSEndpoint,
    IMDSProber,
    IMDSReport,
    IMDSProbeResult,
)


# ---------------------------------------------------------------------------
# IMDSEndpoint tests
# ---------------------------------------------------------------------------

class TestIMDSEndpoint:
    def test_defaults(self):
        ep = IMDSEndpoint(url="http://169.254.169.254/latest/meta-data/")
        assert ep.method == "GET"
        assert ep.headers == {}
        assert ep.provider == "aws"
        assert ep.requires_token is False
        assert ep.sensitive is False

    def test_custom(self):
        ep = IMDSEndpoint(
            url="http://metadata.google.internal/test",
            method="GET",
            headers={"Metadata-Flavor": "Google"},
            provider="gcp",
            sensitive=True,
        )
        assert ep.provider == "gcp"
        assert ep.sensitive is True
        assert ep.headers["Metadata-Flavor"] == "Google"


# ---------------------------------------------------------------------------
# IMDS endpoint definitions
# ---------------------------------------------------------------------------

class TestIMDSEndpointDefs:
    def test_aws_has_endpoints(self):
        assert len(AWS_IMDS_V1) >= 6

    def test_gcp_has_endpoints(self):
        assert len(GCP_IMDS) >= 5

    def test_azure_has_endpoints(self):
        assert len(AZURE_IMDS) >= 2

    def test_all_providers_in_all_imds(self):
        assert "aws" in ALL_IMDS
        assert "gcp" in ALL_IMDS
        assert "azure" in ALL_IMDS

    def test_imdsv2_token_endpoint(self):
        assert AWS_IMDS_V2_TOKEN.method == "PUT"
        assert "X-aws-ec2-metadata-token-ttl-seconds" in AWS_IMDS_V2_TOKEN.headers

    def test_gcp_requires_metadata_flavor(self):
        for ep in GCP_IMDS:
            assert "Metadata-Flavor" in ep.headers

    def test_azure_requires_metadata_header(self):
        for ep in AZURE_IMDS:
            assert "Metadata" in ep.headers


# ---------------------------------------------------------------------------
# IMDSProber tests
# ---------------------------------------------------------------------------

class TestIMDSProber:
    def test_init_defaults(self):
        prober = IMDSProber()
        assert prober.providers == ["aws", "gcp", "azure"]
        assert prober.timeout == 5.0

    def test_init_custom_providers(self):
        prober = IMDSProber(providers=["aws"])
        assert prober.providers == ["aws"]

    @pytest.mark.asyncio
    async def test_probe_no_access(self):
        """When IMDS is not accessible, report should show no access."""
        async def failing_sink(url, method="GET", headers=None, timeout=5.0):
            return (0, {}, "")

        prober = IMDSProber(providers=["aws"], timeout=1.0)
        report = await prober.probe(failing_sink)

        assert report.accessible is False
        assert report.provider is None
        assert len(report.findings) == 0

    @pytest.mark.asyncio
    async def test_probe_aws_imdsv1(self):
        """When AWS IMDSv1 is accessible, should extract metadata."""
        async def aws_sink(url, method="GET", headers=None, timeout=5.0):
            if "security-credentials/" in url and url.endswith("/"):
                return (200, {}, "test-role-name")
            elif "instance-id" in url:
                return (200, {}, "i-1234567890abcdef0")
            elif "instance-type" in url:
                return (200, {}, "t2.micro")
            elif "region" in url:
                return (200, {}, "us-east-1")
            elif "user-data" in url:
                return (200, {}, "#!/bin/bash\napt-get update")
            return (404, {}, "")

        prober = IMDSProber(providers=["aws"], timeout=2.0)
        report = await prober.probe(aws_sink)

        assert report.accessible is True
        assert report.provider == "aws"
        assert report.instance_id == "i-1234567890abcdef0"
        assert report.instance_type == "t2.micro"
        assert report.region == "us-east-1"
        assert report.user_data is not None
        assert "apt-get" in report.user_data

    @pytest.mark.asyncio
    async def test_probe_aws_credential_extraction(self):
        """When role credentials are exposed, should extract and report."""
        role_creds = {
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "Token": "FwoGZXIvYXdzEBY...",
            "Expiration": "2026-08-21T12:00:00Z",
            "RoleName": "test-role",
        }

        async def aws_cred_sink(url, method="GET", headers=None, timeout=5.0):
            if "security-credentials/test-role" in url:
                return (200, {}, json.dumps(role_creds))
            elif "security-credentials/" in url and url.endswith("/"):
                return (200, {}, "test-role")
            return (404, {}, "")

        prober = IMDSProber(providers=["aws"], timeout=2.0)
        report = await prober.probe(aws_cred_sink)

        assert report.accessible is True
        assert report.credentials is not None
        assert report.credentials["AccessKeyId"] == "AKIAIOSFODNN7EXAMPLE"
        # Should have a credential exposure finding
        cred_findings = [f for f in report.findings if f["type"] == "cloud_credential_exposure"]
        assert len(cred_findings) == 1
        assert cred_findings[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_probe_gcp_metadata(self):
        """When GCP metadata is accessible, should extract project and SA."""
        gcp_metadata = {
            "instance": {
                "id": "1234567890",
                "machineType": "projects/123456/zones/us-central1-a/machineTypes/n1-standard-1",
                "zone": "projects/123456/zones/us-central1-a",
                "serviceAccounts": [
                    {"email": "123456-compute@developer.gserviceaccount.com"}
                ],
            },
            "project": {"projectId": "my-gcp-project"},
        }

        async def gcp_sink(url, method="GET", headers=None, timeout=5.0):
            if "metadata.google.internal" in url:
                return (200, {}, json.dumps(gcp_metadata))
            return (404, {}, "")

        prober = IMDSProber(providers=["gcp"], timeout=2.0)
        report = await prober.probe(gcp_sink)

        assert report.accessible is True
        assert report.provider == "gcp"
        assert report.project_id == "my-gcp-project"
        assert report.service_account_email == "123456-compute@developer.gserviceaccount.com"

    @pytest.mark.asyncio
    async def test_probe_azure_metadata(self):
        """When Azure metadata is accessible, should extract compute info."""
        azure_metadata = {
            "compute": {
                "vmId": "abc123-def456",
                "vmSize": "Standard_D2s_v3",
                "location": "eastus",
            }
        }

        async def azure_sink(url, method="GET", headers=None, timeout=5.0):
            if "169.254.169.254/metadata" in url:
                return (200, {}, json.dumps(azure_metadata))
            return (404, {}, "")

        prober = IMDSProber(providers=["azure"], timeout=2.0)
        report = await prober.probe(azure_sink)

        assert report.accessible is True
        assert report.provider == "azure"
        assert report.instance_id == "abc123-def456"
        assert report.instance_type == "Standard_D2s_v3"
        assert report.region == "eastus"

    @pytest.mark.asyncio
    async def test_probe_timeout_handling(self):
        """Timeouts should be handled gracefully."""
        async def slow_sink(url, method="GET", headers=None, timeout=5.0):
            await asyncio.sleep(10)  # Will timeout
            return (200, {}, "")

        prober = IMDSProber(providers=["aws"], timeout=0.1)
        report = await prober.probe(slow_sink)

        assert report.accessible is False
        assert len(report.findings) == 0

    @pytest.mark.asyncio
    async def test_probe_exception_handling(self):
        """Exceptions in sink should be handled gracefully."""
        async def error_sink(url, method="GET", headers=None, timeout=5.0):
            raise ConnectionError("network unreachable")

        prober = IMDSProber(providers=["aws"], timeout=1.0)
        report = await prober.probe(error_sink)

        assert report.accessible is False

    @pytest.mark.asyncio
    async def test_probe_generates_imds_finding(self):
        """When IMDS is accessible, should generate a cloud_imds_exposure finding."""
        async def working_sink(url, method="GET", headers=None, timeout=5.0):
            if "meta-data/" in url and url.endswith("/"):
                return (200, {}, "ami-id\ninstance-id\ninstance-type")
            return (404, {}, "")

        prober = IMDSProber(providers=["aws"], timeout=2.0)
        report = await prober.probe(working_sink)

        imds_findings = [f for f in report.findings if f["type"] == "cloud_imds_exposure"]
        assert len(imds_findings) == 1
        assert imds_findings[0]["severity"] == "critical"
        assert imds_findings[0]["oracle"] == "imds_endpoint_response"
        assert imds_findings[0]["tier"] == "confirmed"

    @pytest.mark.asyncio
    async def test_probe_generates_userdata_finding(self):
        """When user-data is accessible, should generate a userdata finding."""
        async def userdata_sink(url, method="GET", headers=None, timeout=5.0):
            if "user-data" in url:
                return (200, {}, "#!/bin/bash\napt-get update && apt-get install -y docker.io")
            if "meta-data/" in url:
                return (200, {}, "ami-id")
            return (404, {}, "")

        prober = IMDSProber(providers=["aws"], timeout=2.0)
        report = await prober.probe(userdata_sink)

        ud_findings = [f for f in report.findings if f["type"] == "cloud_userdata_exposure"]
        assert len(ud_findings) == 1
        assert ud_findings[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_probe_generates_imdsv1_finding(self):
        """When IMDSv1 works, should warn about lack of token protection."""
        async def imdsv1_sink(url, method="GET", headers=None, timeout=5.0):
            if "meta-data/" in url:
                return (200, {}, "ami-id")
            return (404, {}, "")

        prober = IMDSProber(providers=["aws"], timeout=2.0)
        report = await prober.probe(imdsv1_sink)

        v1_findings = [f for f in report.findings if f["type"] == "cloud_imdsv1_enabled"]
        assert len(v1_findings) == 1
        assert v1_findings[0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_probe_gcp_service_account_finding(self):
        """When GCP SA email is exposed, should generate a finding."""
        async def gcp_sa_sink(url, method="GET", headers=None, timeout=5.0):
            if "service-accounts/default/email" in url:
                return (200, {}, "sa@project.iam.gserviceaccount.com")
            return (404, {}, "")

        prober = IMDSProber(providers=["gcp"], timeout=2.0)
        report = await prober.probe(gcp_sa_sink)

        sa_findings = [f for f in report.findings if f["type"] == "cloud_service_account_exposure"]
        assert len(sa_findings) == 1
        assert "sa@project.iam.gserviceaccount.com" in sa_findings[0]["evidence"]


# ---------------------------------------------------------------------------
# CloudControlDetector integration tests
# ---------------------------------------------------------------------------

class TestCloudControlDetectorIMDS:
    def test_detect_from_response_imds(self):
        from titan.modules.cloud_control.detector import CloudControlDetector
        detector = CloudControlDetector()

        findings = detector.detect_from_response(
            url="http://169.254.169.254/latest/meta-data/",
            status=200,
            headers={},
            body="ami-id\ninstance-id\ninstance-type",
        )
        assert len(findings) >= 1
        assert any(f["type"] == "cloud_imds_exposure" for f in findings)

    def test_detect_from_response_creds(self):
        from titan.modules.cloud_control.detector import CloudControlDetector
        detector = CloudControlDetector()

        creds_body = json.dumps({
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "Token": "FwoGZXIvYXdzEBY...",
        })
        findings = detector.detect_from_response(
            url="http://169.254.169.254/latest/meta-data/iam/security-credentials/my-role",
            status=200,
            headers={},
            body=creds_body,
        )
        assert any(f["type"] == "cloud_credential_exposure" for f in findings)

    def test_detect_from_response_userdata(self):
        from titan.modules.cloud_control.detector import CloudControlDetector
        detector = CloudControlDetector()

        findings = detector.detect_from_response(
            url="http://169.254.169.254/latest/user-data/",
            status=200,
            headers={},
            body="#!/bin/bash\napt-get update",
        )
        assert any(f["type"] == "cloud_userdata_exposure" for f in findings)

    def test_generate_imds_payloads(self):
        from titan.modules.cloud_control.detector import CloudControlDetector
        detector = CloudControlDetector()

        payloads = detector.generate_imds_payloads()
        assert len(payloads) >= 8
        assert any("169.254.169.254" in p["url"] for p in payloads)
        assert any(p["method"] == "PUT" for p in payloads)  # IMDSv2 token

    @pytest.mark.asyncio
    async def test_probe_imds_integration(self):
        """CloudControlDetector.probe_imds should return findings."""
        from titan.modules.cloud_control.detector import CloudControlDetector
        detector = CloudControlDetector()

        async def mock_sink(url, method="GET", headers=None, timeout=5.0):
            if "meta-data/" in url and url.endswith("/"):
                return (200, {}, "ami-id\ninstance-id")
            return (404, {}, "")

        findings = await detector.probe_imds(mock_sink, providers=["aws"])
        assert isinstance(findings, list)
        assert len(findings) >= 1
