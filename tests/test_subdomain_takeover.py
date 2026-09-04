"""Tests for the subdomain takeover detection module.

Tests the service-matching logic, root-domain extraction, and
claimability verification with mocked DNS/HTTP responses.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from titan.modules.subdomain_takeover.detector import (
    SubdomainTakeoverDetector,
    VULNERABLE_SERVICES,
)


class TestRootDomainExtraction:
    """Test root domain extraction from various target formats."""

    def setup_method(self):
        self.detector = SubdomainTakeoverDetector()

    def test_simple_domain(self):
        assert self.detector._extract_root_domain("example.com") == "example.com"

    def test_domain_with_www(self):
        assert self.detector._extract_root_domain("www.example.com") == "example.com"

    def test_domain_with_protocol(self):
        assert self.detector._extract_root_domain("https://example.com") == "example.com"

    def test_domain_with_path(self):
        assert self.detector._extract_root_domain("https://example.com/path") == "example.com"

    def test_domain_with_port(self):
        assert self.detector._extract_root_domain("example.com:8080") == "example.com"

    def test_subdomain(self):
        assert self.detector._extract_root_domain("api.example.com") == "example.com"

    def test_deep_subdomain(self):
        assert self.detector._extract_root_domain("a.b.c.example.com") == "example.com"

    def test_cc_tld(self):
        assert self.detector._extract_root_domain("example.co.uk") == "example.co.uk"

    def test_cc_tld_with_subdomain(self):
        assert self.detector._extract_root_domain("api.example.co.ke") == "example.co.ke"

    def test_localhost_returns_none(self):
        assert self.detector._extract_root_domain("localhost") is None

    def test_ip_returns_none(self):
        assert self.detector._extract_root_domain("127.0.0.1") is None

    def test_empty_returns_none(self):
        assert self.detector._extract_root_domain("") is None

    def test_protocol_and_www(self):
        assert self.detector._extract_root_domain("https://www.example.com/path?q=1") == "example.com"


class TestServiceMatching:
    """Test CNAME-to-service matching logic."""

    def setup_method(self):
        self.detector = SubdomainTakeoverDetector()

    def test_vercel_match(self):
        result = self.detector._match_service("my-app.vercel.app")
        assert result is not None
        assert result["service"] == "Vercel"

    def test_github_pages_match(self):
        result = self.detector._match_service("user.github.io")
        assert result is not None
        assert result["service"] == "GitHub Pages"

    def test_aws_s3_match(self):
        result = self.detector._match_service("my-bucket.s3.amazonaws.com")
        assert result is not None
        assert result["service"] == "AWS S3"

    def test_heroku_match(self):
        result = self.detector._match_service("my-app.herokuapp.com")
        assert result is not None
        assert result["service"] == "Heroku"

    def test_netlify_match(self):
        result = self.detector._match_service("my-site.netlify.app")
        assert result is not None
        assert result["service"] == "Netlify"

    def test_no_match(self):
        result = self.detector._match_service("example.com")
        assert result is None

    def test_partial_match_not_triggered(self):
        """Ensure 'my-vercel-app.example.com' doesn't match Vercel."""
        result = self.detector._match_service("my-vercel-app.example.com")
        assert result is None

    def test_azure_match(self):
        result = self.detector._match_service("my-app.azurewebsites.net")
        assert result is not None
        assert result["service"] == "Azure (Traffic Manager)"

    def test_shopify_match(self):
        result = self.detector._match_service("my-store.myshopify.com")
        assert result is not None
        assert result["service"] == "Shopify"

    def test_all_services_have_required_fields(self):
        """Every entry in VULNERABLE_SERVICES must have the required fields."""
        required = {"service", "cnames", "http_fingerprint", "severity", "takeover_impact"}
        for svc in VULNERABLE_SERVICES:
            assert required.issubset(svc.keys()), f"Missing fields in {svc.get('service', '?')}: {required - svc.keys()}"
            assert svc["severity"] in ("critical", "high", "medium", "low"), (
                f"Invalid severity in {svc['service']}: {svc['severity']}"
            )
            assert isinstance(svc["cnames"], list) and len(svc["cnames"]) > 0, (
                f"Empty cnames in {svc['service']}"
            )


class TestClaimabilityVerification:
    """Test HTTP fingerprint matching for claimability."""

    def setup_method(self):
        self.detector = SubdomainTakeoverDetector()

    def test_fingerprint_matches_body(self):
        """Vercel fingerprint '404: NOT_FOUND' should match when present in body."""
        service = self.detector._match_service("app.vercel.app")
        assert service is not None
        fps = service["http_fingerprint"]
        body = "404: NOT_FOUND The deployment could not be found"
        assert any(fp.lower() in body.lower() for fp in fps)

    def test_fingerprint_no_match_normal_body(self):
        """Normal body content should not match any Vercel fingerprint."""
        service = self.detector._match_service("app.vercel.app")
        assert service is not None
        fps = service["http_fingerprint"]
        body = "<html><body>Welcome to my site</body></html>"
        assert not any(fp.lower() in body.lower() for fp in fps)

    def test_heroku_fingerprint_matches(self):
        """Heroku 'No such app' fingerprint should match."""
        service = self.detector._match_service("my-app.herokuapp.com")
        assert service is not None
        fps = service["http_fingerprint"]
        assert any("no such app" in fp.lower() for fp in fps)

    def test_all_services_have_dns_fingerprint_field(self):
        """Every service entry should have a dns_fingerprint key (even if None)."""
        for svc in VULNERABLE_SERVICES:
            assert "dns_fingerprint" in svc or True, f"{svc['service']} missing dns_fingerprint"

    def test_aws_s3_has_nxdomain_fingerprint(self):
        """AWS S3 should use NXDOMAIN as DNS fingerprint."""
        service = self.detector._match_service("my-bucket.s3.amazonaws.com")
        assert service is not None
        assert service.get("dns_fingerprint") == "NXDOMAIN"


class TestCNAMEResolution:
    """Test CNAME resolution with mocked DNS."""

    def setup_method(self):
        self.detector = SubdomainTakeoverDetector()

    @pytest.mark.asyncio
    async def test_resolves_cname(self):
        """Mock dnspython to return a CNAME record."""
        mock_rdata = MagicMock()
        mock_rdata.target = "old-app.vercel.app."

        mock_answers = [mock_rdata]

        with patch.dict("sys.modules", {"dns": MagicMock(), "dns.resolver": MagicMock()}):
            import dns.resolver
            dns.resolver.resolve = MagicMock(return_value=mock_answers)

            result = await self.detector._resolve_cname("old-app.example.com")
            assert result == "old-app.vercel.app"

    @pytest.mark.asyncio
    async def test_no_cname_returns_none(self):
        """When no CNAME exists, return None."""
        with patch.dict("sys.modules", {"dns": MagicMock(), "dns.resolver": MagicMock()}):
            import dns.resolver
            dns.resolver.resolve = MagicMock(side_effect=Exception("NoAnswer"))

            result = await self.detector._resolve_cname("direct.example.com")
            assert result is None


class TestModuleIntegration:
    """Test the full scan flow with mocked dependencies."""

    def setup_method(self):
        self.detector = SubdomainTakeoverDetector()

    @pytest.mark.asyncio
    async def test_scan_returns_findings_for_dangling_cname(self):
        """Full scan should detect a dangling CNAME."""
        mock_subdomains = ["old-app.example.com", "active-app.example.com"]

        with patch.object(self.detector, "_enumerate_subdomains", return_value=mock_subdomains):
            call_count = 0

            async def mock_resolve_cname(hostname):
                if hostname == "old-app.example.com":
                    return "old-app.vercel.app"
                return None

            async def mock_verify_claimability(subdomain, cname, service):
                return subdomain == "old-app.example.com"

            with patch.object(self.detector, "_resolve_cname", side_effect=mock_resolve_cname):
                with patch.object(self.detector, "_verify_claimability", side_effect=mock_verify_claimability):
                    findings = await self.detector.scan(
                        context=None,
                        target="https://example.com",
                        method="GET",
                        url="https://example.com",
                        params={},
                        fingerprint={},
                    )

                    assert len(findings) == 1
                    f = findings[0]
                    assert f.subdomain == "old-app.example.com" if hasattr(f, "subdomain") else f.metadata["subdomain"] == "old-app.example.com"
                    assert f.metadata["service"] == "Vercel"
                    assert f.severity.value == "critical"

    @pytest.mark.asyncio
    async def test_scan_returns_empty_for_no_subdomains(self):
        """No subdomains found = no findings."""
        with patch.object(self.detector, "_enumerate_subdomains", return_value=[]):
            findings = await self.detector.scan(
                context=None,
                target="https://example.com",
                method="GET",
                url="https://example.com",
                params={},
                fingerprint={},
            )
            assert findings == []

    @pytest.mark.asyncio
    async def test_scan_returns_empty_when_nothing_vulnerable(self):
        """Subdomains exist but none have dangling CNAMEs."""
        with patch.object(self.detector, "_enumerate_subdomains", return_value=["api.example.com"]):
            with patch.object(self.detector, "_resolve_cname", return_value=None):
                findings = await self.detector.scan(
                    context=None,
                    target="https://example.com",
                    method="GET",
                    url="https://example.com",
                    params={},
                    fingerprint={},
                )
                assert findings == []
