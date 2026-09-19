"""Tests for the Deep Audit module."""

from titan.modules.deep_audit.cloud_probes import CloudProbes
from titan.modules.deep_audit.models import AuditFinding as ModelsAuditFinding
from titan.modules.deep_audit.models import AuditResult as ModelsAuditResult
from titan.modules.deep_audit.models import CloudConfig as ModelsCloudConfig
from titan.modules.deep_audit.prober import AuditFinding, AuditResult, CloudConfig, DeepAuditor


class _StubResponse:
    """Minimal async-CM response: JSON error body, configurable status."""

    def __init__(self, status=403, payload=None, headers=None, text="<html></html>"):
        self.status = status
        self._payload = payload if payload is not None else {"error": {"message": "PERMISSION_DENIED"}}
        self.headers = headers or {}
        self._text = text

    async def json(self):
        return self._payload

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _StubSession:
    """Every request returns the same stub response; nothing opens a socket."""

    def __init__(self, response=None):
        self.response = response or _StubResponse()
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        return self.response

    def post(self, url, **kwargs):
        self.calls.append(url)
        return self.response


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
            api_key="test-key",  # pragma: allowlist secret
            project_id="my-project",
        )
        assert cfg.api_key == "test-key"  # pragma: allowlist secret
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
            apiKey: "AIzaSyTest123",  # pragma: allowlist secret
            authDomain: "test.firebaseapp.com",
            projectId: "test-project",
            storageBucket: "test.appspot.com",
        };
        firebase.initializeApp(firebaseConfig);
        """
        configs = auditor._parse_js_for_config(js, "test.js")
        assert len(configs) == 1
        assert configs[0].provider == "firebase"
        assert configs[0].api_key == "AIzaSyTest123"  # pragma: allowlist secret
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
        js = 'const key = "AKIAIOSFODNN7EXAMPLE";'  # pragma: allowlist secret
        configs = auditor._parse_js_for_config(js, "test.js")
        assert len(configs) == 1
        assert configs[0].provider == "aws"
        assert configs[0].api_key == "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret

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
                id="F1",
                severity="critical",
                title="PII",
                description="PII exposed",
                proof="200",
                impact="Data leak",
                remediation="Fix",
                category="pii_exposure",
                verified=True,
            ),
            AuditFinding(
                id="F2",
                severity="high",
                title="Headers",
                description="Missing headers",
                proof="200",
                impact="XSS risk",
                remediation="Add headers",
                category="misconfiguration",
                verified=True,
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
                id="F1",
                severity="info",
                title="Password Login Disabled",
                description="Disabled",
                proof="200",
                impact="None",
                remediation="N/A",
                category="positive_control",
                verified=True,
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


class TestSplitSeams:
    """Pin the prober.py -> models.py + cloud_probes.py split.

    Regression context: audit() called self._enum_firestore although no
    such method existed, so every audit that found a Firebase config
    crashed with AttributeError (silently swallowed by the caller's
    except in post_scan_phases). These tests keep that call site live.
    """

    def test_models_are_single_source(self):
        """prober re-exports the models; no divergent copies may appear."""
        assert AuditFinding is ModelsAuditFinding
        assert AuditResult is ModelsAuditResult
        assert CloudConfig is ModelsCloudConfig

    def test_data_tables_move_with_probes_but_stay_aliasable(self):
        """Tables live on CloudProbes now; auditor aliases them for callers."""
        auditor = DeepAuditor()
        assert auditor.FIRESTORE_COLLECTION_NAMES is CloudProbes.FIRESTORE_COLLECTION_NAMES
        assert auditor.SENSITIVE_PATHS is CloudProbes.SENSITIVE_PATHS
        assert auditor.COMMON_JS_PATTERNS is CloudProbes.COMMON_JS_PATTERNS
        assert len(auditor.FIRESTORE_COLLECTION_NAMES) > 0
        assert len(auditor.SENSITIVE_PATHS) > 0

    async def test_audit_with_firebase_config_no_longer_crashes(self):
        """Regression: finding a Firebase config used to AttributeError inside
        audit() and lose the whole audit. With the enum primitive restored,
        the run must complete and return a well-formed result."""
        auditor = DeepAuditor()
        session = _StubSession()
        result = await auditor.audit("https://test.com", budget=1.0, _session=session)
        assert isinstance(result, AuditResult)
        assert result.target == "https://test.com"
        assert isinstance(result.collections, list)

    async def test_enum_firestore_collects_public_collections(self):
        """The restored primitive returns one entry per public collection."""
        probes = CloudProbes()
        body = {"documents": [{"fields": {"email": {"stringValue": "x"}}}]}
        session = _StubSession(_StubResponse(status=200, payload=body))
        cfg = CloudConfig(provider="firebase", project_id="proj", api_key="k")  # pragma: allowlist secret
        out = await probes.enum_firestore(session, cfg, collections=["users", "logs"])
        assert [r["name"] for r in out] == ["users", "logs"]
        assert all(r["count"] == 1 for r in out)
        assert len(session.calls) == 2
        assert all("firestore.googleapis.com" in u for u in session.calls)

    async def test_enum_firestore_degrades_on_errors(self):
        """Failing collection probes are skipped, not raised."""
        probes = CloudProbes()
        session = _StubSession(_StubResponse(status=403))
        cfg = CloudConfig(provider="firebase", project_id="proj", api_key="k")  # pragma: allowlist secret
        out = await probes.enum_firestore(session, cfg, collections=["users"])
        assert out == []

    async def test_probes_shared_between_auditor_and_bundle(self):
        """Delegators route to the same bundle instance (one source of truth)."""
        auditor = DeepAuditor()
        assert isinstance(auditor._cloud_probes, CloudProbes)
        session = _StubSession()
        out = await auditor._probe_sensitive_files(session, "https://test.com")
        assert out == await auditor._cloud_probes._probe_sensitive_files(_StubSession(), "https://test.com")
