"""Tests for the SBOM Analyzer — Supply chain analysis from served content.

Covers:
  - Script/link tag extraction
  - SRI (Subresource Integrity) detection
  - Cleartext loading detection
  - Known vulnerability matching
  - CDN URL parsing
  - Origin profiling
  - Finding generation
"""

from __future__ import annotations

import pytest

from titan.modules.supplychain.sbom import (
    KNOWN_VULNERABLE,
    DependencyInfo,
    SBOMAnalyzer,
    SBOMReport,
    ScriptTag,
)


# ---------------------------------------------------------------------------
# SBOMAnalyzer tests
# ---------------------------------------------------------------------------

class TestSBOMAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return SBOMAnalyzer()

    def test_empty_html(self, analyzer):
        report = analyzer.analyze("", page_url="https://example.com")
        assert report.scripts == []
        assert report.findings == []

    def test_extract_script_tags(self, analyzer):
        html = '''
        <html>
        <head>
            <script src="https://cdn.jsdelivr.net/npm/react@18.2.0/umd/react.production.min.js"></script>
            <script src="https://example.com/app.js"></script>
        </head>
        </html>
        '''
        report = analyzer.analyze(html, page_url="https://example.com")
        assert len(report.scripts) == 2
        assert report.scripts[0].is_external is True
        assert report.scripts[1].is_external is False  # Same origin

    def test_extract_link_tags(self, analyzer):
        html = '''
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        '''
        report = analyzer.analyze(html, page_url="https://example.com")
        assert len(report.scripts) == 1
        assert report.scripts[0].tag == "link"

    def test_extract_iframe_tags(self, analyzer):
        html = '<iframe src="https://www.youtube.com/embed/abc123"></iframe>'
        report = analyzer.analyze(html, page_url="https://example.com")
        assert len(report.scripts) == 1
        assert report.scripts[0].tag == "iframe"
        assert report.scripts[0].is_external is True

    def test_sri_detection(self, analyzer):
        html = '''
        <script src="https://cdn.jsdelivr.net/npm/react@18.2.0/react.js"
                integrity="sha384-abc123" crossorigin="anonymous"></script>
        <script src="https://cdn.jsdelivr.net/npm/vue@3.3.4/vue.js"></script>
        '''
        report = analyzer.analyze(html, page_url="https://example.com")
        assert len(report.sri_missing) == 1
        assert "vue" in report.sri_missing[0].src

    def test_cleartext_detection(self, analyzer):
        html = '''
        <script src="http://example.com/old-lib.js"></script>
        <script src="https://example.com/modern-lib.js"></script>
        '''
        report = analyzer.analyze(html, page_url="https://example.com")
        assert len(report.cleartext_loads) == 1
        assert "old-lib" in report.cleartext_loads[0].src

    def test_cdn_url_parsing_jsdelivr(self, analyzer):
        dep = analyzer._parse_cdn_url("https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js")
        assert dep is not None
        assert dep.name == "lodash"
        assert dep.version == "4.17.21"
        assert dep.registry == "npm"

    def test_cdn_url_parsing_unpkg(self, analyzer):
        dep = analyzer._parse_cdn_url("https://unpkg.com/react@18.2.0/umd/react.production.min.js")
        assert dep is not None
        assert dep.name == "react"
        assert dep.version == "18.2.0"

    def test_cdn_url_parsing_google(self, analyzer):
        dep = analyzer._parse_cdn_url("https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js")
        assert dep is not None
        assert dep.name == "jquery"
        assert dep.version == "3.6.0"

    def test_cdn_url_parsing_cloudflare(self, analyzer):
        dep = analyzer._parse_cdn_url("https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js")
        assert dep is not None
        assert dep.name == "lodash.js"
        assert dep.version == "4.17.21"

    def test_known_vulnerability_matching(self, analyzer):
        deps = [
            DependencyInfo(name="lodash", version="4.17.15", source="cdn"),
            DependencyInfo(name="minimist", version="1.2.5", source="cdn"),
            DependencyInfo(name="react", version="18.2.0", source="cdn"),
        ]
        vulns = analyzer._match_vulnerabilities(deps)
        assert len(vulns) == 2
        packages = [v["package"] for v in vulns]
        assert "lodash" in packages
        assert "minimist" in packages
        assert "react" not in packages

    def test_vulnerability_severity(self, analyzer):
        deps = [DependencyInfo(name="shell-quote", version="1.7.2", source="cdn")]
        vulns = analyzer._match_vulnerabilities(deps)
        assert len(vulns) == 1
        assert vulns[0]["severity"] == "critical"

    def test_origin_profiling(self, analyzer):
        html = '''
        <script src="https://cdn.jsdelivr.net/npm/react@18.2.0/react.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/vue@3.3.4/vue.js"></script>
        <script src="https://example.com/app.js"></script>
        '''
        report = analyzer.analyze(html, page_url="https://example.com")
        assert "cdn.jsdelivr.net" in report.origins
        assert report.origins["cdn.jsdelivr.net"]["count"] == 2
        assert "cdn:jsdelivr" in report.origins["cdn.jsdelivr.net"]["category"]

    def test_categorize_cdn(self, analyzer):
        assert analyzer._categorize_origin("cdn.jsdelivr.net") == "cdn:jsdelivr"
        assert analyzer._categorize_origin("cdnjs.cloudflare.com") == "cdn:cloudflare"
        assert analyzer._categorize_origin("ajax.googleapis.com") == "cdn:google"

    def test_categorize_risky(self, analyzer):
        assert analyzer._categorize_origin("some-random-site.com") == "third-party"
        assert analyzer._categorize_origin("doubleclick.net") == "advertising"

    def test_inline_dependencies(self, analyzer):
        content = '''
        const _ = require('lodash');
        import React from 'react';
        const url = "https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js";
        '''
        deps = analyzer._extract_inline_dependencies(content)
        names = [d.name for d in deps]
        assert "lodash" in names
        assert "react" in names
        assert "axios" in names

    def test_finding_sri_missing(self, analyzer):
        html = '<script src="https://cdn.jsdelivr.net/npm/react@18.2.0/react.js"></script>'
        report = analyzer.analyze(html, page_url="https://example.com")
        sri_findings = [f for f in report.findings if f["type"] == "supply_chain_sri_missing"]
        assert len(sri_findings) == 1
        assert sri_findings[0]["severity"] == "medium"
        assert sri_findings[0]["oracle"] == "sri_missing"

    def test_finding_cleartext(self, analyzer):
        html = '<script src="http://example.com/lib.js"></script>'
        report = analyzer.analyze(html, page_url="https://example.com")
        ctext_findings = [f for f in report.findings if f["type"] == "supply_chain_cleartext_load"]
        assert len(ctext_findings) == 1
        assert ctext_findings[0]["severity"] == "high"

    def test_finding_known_vuln(self, analyzer):
        html = '<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js"></script>'
        report = analyzer.analyze(html, page_url="https://example.com")
        vuln_findings = [f for f in report.findings if f["type"] == "supply_chain_known_vuln"]
        assert len(vuln_findings) >= 1
        assert "lodash" in vuln_findings[0]["evidence"]
        assert "CVE" in vuln_findings[0]["evidence"]

    def test_finding_risky_origins(self, analyzer):
        html = '<script src="https://some-random-tracker.com/track.js"></script>'
        report = analyzer.analyze(html, page_url="https://example.com")
        risky = [f for f in report.findings if f["type"] == "supply_chain_risky_origins"]
        assert len(risky) == 1

    def test_no_findings_clean_page(self, analyzer):
        html = '''
        <script src="https://example.com/app.js"></script>
        <link rel="stylesheet" href="https://example.com/style.css">
        '''
        report = analyzer.analyze(html, page_url="https://example.com")
        # Same-origin resources should not trigger findings
        assert len([f for f in report.findings if f["severity"] in ("high", "critical")]) == 0

    def test_is_external(self, analyzer):
        assert analyzer._is_external("https://cdn.example.com/lib.js", "example.com") is True
        assert analyzer._is_external("https://example.com/app.js", "example.com") is False
        assert analyzer._is_external("//cdn.example.com/lib.js", "example.com") is True
        assert analyzer._is_external("/local.js", "example.com") is False

    def test_extract_attr(self, analyzer):
        tag = '<script src="test.js" integrity="sha384-abc" crossorigin="anonymous">'
        assert analyzer._extract_attr(tag, "integrity") == "sha384-abc"
        assert analyzer._extract_attr(tag, "crossorigin") == "anonymous"
        assert analyzer._extract_attr(tag, "nonexistent") == ""


# ---------------------------------------------------------------------------
# Known vulnerable packages tests
# ---------------------------------------------------------------------------

class TestKnownVulnerable:
    def test_has_entries(self):
        assert len(KNOWN_VULNERABLE) > 0

    def test_all_have_required_fields(self):
        for pkg, vulns in KNOWN_VULNERABLE.items():
            for v in vulns:
                assert "cve" in v
                assert "versions" in v
                assert "severity" in v
                assert "description" in v

    def test_covers_common_packages(self):
        common = ["lodash", "minimist", "axios", "express", "django", "flask", "werkzeug"]
        for pkg in common:
            assert pkg in KNOWN_VULNERABLE


# ---------------------------------------------------------------------------
# SBOMReport tests
# ---------------------------------------------------------------------------

class TestSBOMReport:
    def test_defaults(self):
        report = SBOMReport()
        assert report.scripts == []
        assert report.dependencies == []
        assert report.findings == []
