"""Integration tests against DVWA (Damn Vulnerable Web Application).

Run these tests only against a local DVWA instance.
Set DVWA_URL environment variable to the target URL.
Default: http://localhost:8080
"""

import os
import pytest

from titan.core.engine import TitanEngine
from titan.core.models import Severity


@pytest.fixture
def dvwa_url():
    return os.getenv("DVWA_URL", "http://localhost:8080")


@pytest.mark.skipif(not os.getenv("DVWA_URL"), reason="DVWA_URL not set")
@pytest.mark.asyncio
async def test_dvwa_sqli_detection(dvwa_url):
    config = {
        "target": dvwa_url,
        "headless": True,
        "crawl": {"max_pages": 20, "max_depth": 2},
    }
    engine = TitanEngine(config)
    result = await engine.scan(dvwa_url)

    sqli_findings = [f for f in result.findings if f.attack_type and f.attack_type.value == "SQLi"]
    assert len(sqli_findings) > 0, "Expected at least one SQLi finding against DVWA"


@pytest.mark.skipif(not os.getenv("DVWA_URL"), reason="DVWA_URL not set")
@pytest.mark.asyncio
async def test_dvwa_xss_detection(dvwa_url):
    config = {
        "target": dvwa_url,
        "headless": True,
        "crawl": {"max_pages": 20, "max_depth": 2},
    }
    engine = TitanEngine(config)
    result = await engine.scan(dvwa_url)

    xss_findings = [f for f in result.findings if f.attack_type and f.attack_type.value == "XSS"]
    assert len(xss_findings) > 0, "Expected at least one XSS finding against DVWA"


@pytest.mark.skipif(not os.getenv("DVWA_URL"), reason="DVWA_URL not set")
@pytest.mark.asyncio
async def test_dvwa_lfi_detection(dvwa_url):
    config = {
        "target": dvwa_url,
        "headless": True,
        "crawl": {"max_pages": 20, "max_depth": 2},
    }
    engine = TitanEngine(config)
    result = await engine.scan(dvwa_url)

    lfi_findings = [f for f in result.findings if f.attack_type and f.attack_type.value == "LFI"]
    assert len(lfi_findings) > 0, "Expected at least one LFI finding against DVWA"
