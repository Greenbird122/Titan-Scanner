"""Tests for reflection false positive detection in auto-verify.

The genohealth.co.uk 192-finding storm was caused by WordPress echoing
every payload into an error page with HTTP 200. The auto-verifier's
_should_demote now detects this pattern and demotes reflection FPs.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from titan.core.models import AttackType, Finding, Severity
from titan.verify.auto_verify import AutoVerifier


def _make_finding(
    payload="<script>alert(1)</script>",
    body=None,
    baseline_body="",
    status=200,
    attack_type=AttackType.XSS,
    verified=True,
    confidence=0.8,
    param="q",
    url="https://example.com/search",
):
    return Finding(
        target="https://example.com",
        url=url,
        method="GET",
        param=param,
        location="query",
        payload=payload,
        attack_type=attack_type,
        severity=Severity.HIGH,
        verified=verified,
        confidence=confidence,
        status=status,
        body=body or "",
        baseline_body=baseline_body,
    )


class TestReflectionFPDetection:
    """Test the _is_reflection_finding method."""

    def setup_method(self):
        self.av = AutoVerifier()

    def test_wordpress_echo_storm_detected(self):
        """WordPress reflects any payload into the error page — should be demoted."""
        # Realistic WordPress error page (longer than 5x payload)
        base = '<html><head><title>Error</title></head><body><div class="wrap"><h1>Oops!</h1><p>The page you were looking for does not exist.</p><form><input name="s" value=""></form><p>Try searching:</p></div></body></html>'
        finding = _make_finding(
            payload="<script>alert(1)</script>",
            body=base.replace('value=""', 'value="<script>alert(1)</script>"'),
            baseline_body=base,
            status=200,
        )
        control_body = base.replace('value=""', 'value="hello world"')
        result = self.av._is_reflection_finding(
            finding, finding.body, control_body, finding.baseline_body
        )
        assert result is True, "WordPress echo storm should be detected as reflection FP"

    def test_real_xss_not_flagged(self):
        """A real XSS finding where the payload triggers different behavior should NOT be flagged."""
        finding = _make_finding(
            payload="<script>alert(1)</script>",
            body='<html><body><h1>Dashboard</h1><script>alert(1)</script><p>Welcome user</p></body></html>',
            baseline_body='<html><body><h1>Dashboard</h1><p>Welcome user</p></body></html>',
            status=200,
        )
        # Control returns a completely different page (the payload was processed)
        control_body = '<html><body><h1>Access Denied</h1><p>You do not have permission.</p></body></html>'
        result = self.av._is_reflection_finding(
            finding, finding.body, control_body, finding.baseline_body
        )
        assert result is False, "Real XSS should not be flagged as reflection FP"

    def test_sqli_reflection_detected(self):
        """SQLi payload reflected in error page — should be demoted."""
        base = '<html><head><title>Search</title></head><body><div class="results"><h2>Results for: </h2><p>No results found.</p><form><input name="q" value=""></form></div></body></html>'
        finding = _make_finding(
            payload="' OR 1=1--",
            body=base.replace('value=""', "value\"' OR 1=1--\""),
            baseline_body=base,
            status=200,
            attack_type=AttackType.SQLI,
        )
        control_body = base.replace('value=""', 'value="hello world"')
        result = self.av._is_reflection_finding(
            finding, finding.body, control_body, finding.baseline_body
        )
        assert result is True, "SQLi reflection should be detected"

    def test_empty_baseline_not_flagged(self):
        """When baseline is empty, we can't determine reflection — should not flag."""
        finding = _make_finding(
            payload="<script>alert(1)</script>",
            body='<html><body><div><h1>Results</h1><p>Found: <script>alert(1)</script></p></div></body></html>',
            baseline_body="",
            status=200,
        )
        control_body = '<html><body><div><h1>Results</h1><p>Found: hello world</p></div></body></html>'
        result = self.av._is_reflection_finding(
            finding, finding.body, control_body, finding.baseline_body
        )
        assert result is False, "Empty baseline should not trigger reflection detection"

    def test_payload_not_reflected_not_flagged(self):
        """When payload is NOT in the response body, it's not a reflection FP."""
        finding = _make_finding(
            payload="<script>alert(1)</script>",
            body='<html><body>normal page with no payload</body></html>',
            baseline_body='<html><body>normal page</body></html>',
            status=200,
        )
        control_body = '<html><body>normal page with no payload</body></html>'
        result = self.av._is_reflection_finding(
            finding, finding.body, control_body, finding.baseline_body
        )
        assert result is False, "Payload not reflected should not be flagged"

    def test_high_body_similarity_triggers_demotion(self):
        """When control and original are very similar (same page, different payload), flag it."""
        base = '<html><head><title>Error</title></head><body><div class="wrap"><h1>Invalid Input</h1><p>The value  is not valid. Please try again.</p><p>Need help? Contact support.</p></div></body></html>'
        finding = _make_finding(
            payload="test123",
            body=base.replace('value  is', 'value test123 is'),
            baseline_body=base,
            status=200,
        )
        control_body = base.replace('value  is', 'value hello world is')
        result = self.av._is_reflection_finding(
            finding, finding.body, control_body, finding.baseline_body
        )
        assert result is True, "Similar bodies with different payloads should be flagged"

    def test_different_error_classes_not_flagged(self):
        """When control triggers different error classes, it's processing input — don't flag."""
        finding = _make_finding(
            payload="' OR 1=1--",
            body='<html><body><h1>Error</h1><p>sql syntax error near line 1 mysql_fetch</p></body></html>',
            baseline_body='<html><body><h1>Error</h1><p>normal output</p></body></html>',
            status=200,
            attack_type=AttackType.SQLI,
        )
        # Control triggers a DIFFERENT error class (filesystem instead of sql)
        control_body = '<html><body><h1>Error</h1><p>no such file or directory at line 1</p></body></html>'
        result = self.av._is_reflection_finding(
            finding, finding.body, control_body, finding.baseline_body
        )
        assert result is False, "Different error classes means real processing, not reflection"


class TestShouldDemoteWithReflection:
    """Test the full _should_demote flow with reflection detection."""

    def setup_method(self):
        self.av = AutoVerifier()

    def test_wordpress_reflection_demoted_on_200(self):
        """WordPress echo storm on 200 OK should be demoted via reflection detection."""
        base = '<html><head><title>Error</title></head><body><div class="wrap"><h1>Oops!</h1><p>The page you were looking for does not exist.</p><form><input name="s" value=""></form><p>Try searching:</p></div></body></html>'
        finding = _make_finding(
            payload="<script>alert(1)</script>",
            body=base.replace('value=""', 'value="<script>alert(1)</script>"'),
            baseline_body=base,
            status=200,
        )
        controls = [
            (base.replace('value=""', 'value="hello world"'), [], 200),
        ]
        result = self.av._should_demote(finding, controls)
        assert result is True, "WordPress reflection on 200 should be demoted"

    def test_real_vuln_not_demoted(self):
        """A real vulnerability with different error classes should NOT be demoted."""
        finding = _make_finding(
            payload="' OR 1=1--",
            body='<html><body><h1>Error</h1><p>sql syntax error near line 1</p></body></html>',
            baseline_body='<html><body><h1>Error</h1><p>normal output</p></body></html>',
            status=200,
            attack_type=AttackType.SQLI,
        )
        # Control triggers a different error class (filesystem)
        controls = [
            ('<html><body><h1>Error</h1><p>no such file or directory</p></body></html>', [], 200),
        ]
        result = self.av._should_demote(finding, controls)
        assert result is False, "Real SQLi should not be demoted"

    def test_error_class_match_still_demoted(self):
        """Original error-class logic still works alongside reflection detection."""
        finding = _make_finding(
            payload="' OR 1=1--",
            body='<html><body>sql syntax error</body></html>',
            baseline_body='<html><body>normal</body></html>',
            status=500,
            attack_type=AttackType.SQLI,
        )
        # Control produces the SAME error class — demoted by original logic
        controls = [
            ('<html><body>sql syntax error</body></html>', ["sql"], 500),
        ]
        result = self.av._should_demote(finding, controls)
        assert result is True, "Same error class should be demoted"
