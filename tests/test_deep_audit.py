"""Tests for the Deep Audit module."""

import pytest
from titan.modules.deep_audit.prober import DeepAuditor, CloudConfig, AuditFinding, AuditResult


class TestCloudConfig:
    """Test CloudConfig data class."""

    def test_defaults(self):
        cfg = CloudConfig(provider="firebase")
        assert cfg.provider == "firebase"
        assert cfg.api_key == ""
        assert cfg.project_id == ""

    def test_custom_fields(self):
        cfg = CloudConfig(
            provider="supabase",
            api_key="test-key",
            project_id="my-project",
        )
        assert cfg.api_key == "test-key"
        assert cfg.project_id == "my-project"


class TestAuditFinding:
    """Test AuditFinding data class."""

    def test_defaults(self):
        f = AuditFinding(
            id="TEST-001",
            severity="high",
            title="Test",
            description="Test finding",
            proof="GET /test -> 200",
            impact="Test impact",
            remediation="Fix it",
            category="misconfiguration",
        )
        assert f.id == "TEST-001"
        assert f.verified is False
        assert f.cvss == 0.0

    def test_verified_finding(self):
        f = AuditFinding(
            id="TEST-002",
            severity="critical",
            title="Critical",
            description="Critical finding",
            proof="GET /critical -> 200",
            impact="Critical impact",
            remediation="Fix now",
            category="pii_exposure",
            verified=True,
        )
        assert f.verified is True


class TestDeepAuditor:
    """Test DeepAuditor core functionality."""

    def test_init(self):
        auditor = DeepAuditor()
        assert len(auditor.FIRESTORE_COLLECTION_NAMES) > 0
        assert len(auditor.SENSITIVE_PATHS) > 0
        assert len(auditor.COMMON_JS_PATTERNS) > 0

    def test_parse_firebase_config(self):
        auditor = DeepAuditor()
        js = """
        const firebaseConfig = {
            apiKey: "AIzaSyTest123",
            authDomain: "test.firebaseapp.com",
            projectId: "test-project",
            storageBucket: "test.appspot.com",
        };
        firebase.initializeApp(firebaseConfig);
        """
        configs = auditor._parse_js_for_config(js, "test.js")
        assert len(configs) == 1
        assert configs[0].provider == "firebase"
        assert configs[0].api_key == "AIzaSyTest123"
        assert configs[0].project_id == "test-project"

    def test_parse_supabase_config(self):
        auditor = DeepAuditor()
        js = """
        const supabase = supabase.createClient(
            "https://xyz.supabase.co",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        );
        """
        configs = auditor._parse_js_for_config(js, "test.js")
        assert len(configs) == 1
        assert configs[0].provider == "supabase"
        assert configs[0].api_key.startswith("eyJ")

    def test_parse_aws_key(self):
        auditor = DeepAuditor()
        js = 'const key = "AKIAIOSFODNN7EXAMPLE";'
        configs = auditor._parse_js_for_config(js, "test.js")
        assert len(configs) == 1
        assert configs[0].provider == "aws"
        assert configs[0].api_key == "AKIAIOSFODNN7EXAMPLE"

    def test_parse_stripe_key(self):
        auditor = DeepAuditor()
        js = 'const key = "sk_live_1234567890abcdef";'
        configs = auditor._parse_js_for_config(js, "test.js")
        assert len(configs) == 1
        assert configs[0].provider == "stripe"

    def test_no_config_in_clean_js(self):
        auditor = DeepAuditor()
        js = "console.log('hello world');"
        configs = auditor._parse_js_for_config(js, "test.js")
        assert len(configs) == 0


class TestAttackChain:
    """Test attack chain generation."""

    def test_build_attack_chain(self):
        auditor = DeepAuditor()
        result = AuditResult(target="https://test.com")
        result.findings = [
            AuditFinding(
                id="F1", severity="critical", title="PII",
                description="PII exposed", proof="200",
                impact="Data leak", remediation="Fix",
                category="pii_exposure", verified=True,
            ),
            AuditFinding(
                id="F2", severity="high", title="Headers",
                description="Missing headers", proof="200",
                impact="XSS risk", remediation="Add headers",
                category="misconfiguration", verified=True,
            ),
        ]
        result.cloud_config = CloudConfig(provider="firebase")

        chain = auditor._build_attack_chain(result)
        assert len(chain) > 0
        assert any("Read exposed data" in step for step in chain)

    def test_build_positive_controls(self):
        auditor = DeepAuditor()
        result = AuditResult(target="https://test.com")
        result.findings = [
            AuditFinding(
                id="F1", severity="info", title="Password Login Disabled",
                description="Disabled", proof="200",
                impact="None", remediation="N/A",
                category="positive_control", verified=True,
            ),
        ]
        controls = auditor._build_positive_controls(result)
        assert len(controls) == 1
        assert "Password Login Disabled" in controls[0]


class TestTestSuiteGeneration:
    """Test pytest suite generation."""

    def test_generate_test_suite(self):
        auditor = DeepAuditor()
        result = AuditResult(target="https://test.com")
        result.findings = [
            AuditFinding(
                id="DEEP-TEST-001",
                severity="high",
                title="Test Finding",
                description="A test finding",
                proof="GET /test -> 200",
                impact="Test impact",
                remediation="Fix it",
                category="misconfiguration",
                verified=True,
            ),
        ]
        suite = auditor.generate_test_suite(result)
        assert "import pytest" in suite
        assert "DEEP_TEST_001" in suite
        assert "async def" in suite
