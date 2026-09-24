"""Coverage for the auth-services payload split (DataFactor hygiene pass).

``titan/modules/baas/auth_payloads.py`` holds the pure payload tables extracted
from ``authservices.py``. These tests pin the split: catalog shape, the
class-level aliases staying identical objects, entry well-formedness, and the
tester's verdict/evidence paths still consuming exactly those catalogs.
"""

import pytest

from titan.core.models import Severity
from titan.modules.baas import auth_payloads as ap
from titan.modules.baas.authservices import AuthServicesTester

ALL_TABLES = [
    ("AUTH0_PAYLOADS", ap.AUTH0_PAYLOADS, 10),
    ("CLERK_PAYLOADS", ap.CLERK_PAYLOADS, 10),
    ("OAUTH_ABUSE_PAYLOADS", ap.OAUTH_ABUSE_PAYLOADS, 6),
    ("SESSION_MANAGEMENT_PAYLOADS", ap.SESSION_MANAGEMENT_PAYLOADS, 3),
    ("MFA_BYPASS_PAYLOADS", ap.MFA_BYPASS_PAYLOADS, 3),
]


class TestSplitIntegrity:
    """The split must not lose or duplicate catalog entries."""

    @pytest.mark.parametrize(("attr", "table", "expected_count"), ALL_TABLES, ids=[t[0] for t in ALL_TABLES])
    def test_entry_counts_preserved(self, attr, table, expected_count):
        assert len(table) == expected_count

    def test_class_aliases_are_the_extracted_tables(self):
        """Legacy access via the tester must yield the *same* objects."""
        assert AuthServicesTester.AUTH0_PAYLOADS is ap.AUTH0_PAYLOADS
        assert AuthServicesTester.CLERK_PAYLOADS is ap.CLERK_PAYLOADS
        assert AuthServicesTester.OAUTH_ABUSE_PAYLOADS is ap.OAUTH_ABUSE_PAYLOADS
        assert AuthServicesTester.SESSION_MANAGEMENT_PAYLOADS is ap.SESSION_MANAGEMENT_PAYLOADS
        assert AuthServicesTester.MFA_BYPASS_PAYLOADS is ap.MFA_BYPASS_PAYLOADS

    @pytest.mark.parametrize(("attr", "table", "expected_count"), ALL_TABLES, ids=[t[0] for t in ALL_TABLES])
    def test_names_unique_within_catalog(self, attr, table, expected_count):
        names = [p.name for p in table]
        assert len(names) == len(set(names))


class TestCatalogWellFormedness:
    """Every payload entry must carry the fields the verdict path relies on."""

    @pytest.mark.parametrize(
        ("attr", "table", "expected_count"),
        [(t[0], t[1], t[2]) for t in ALL_TABLES for t in (t,)],
    )
    def test_entries_wellformed(self, attr, table, expected_count):
        assert expected_count > 0  # guard against parametrize mistakes
        for payload in table:
            assert payload.name, "every entry needs a name"
            assert payload.category, "every entry needs a category"
            assert payload.endpoint.startswith("/"), f"{payload.name}: endpoint must be rooted"
            assert payload.method in {"GET", "POST", "PATCH"}, f"{payload.name}: unknown method"
            assert payload.expected_effect, f"{payload.name}: expected_effect required"
            assert isinstance(payload.severity, Severity), f"{payload.name}: severity type"
            assert 0.0 <= payload.confidence <= 1.0, f"{payload.name}: confidence range"
            assert payload.headers is None or isinstance(payload.headers, dict)


def _ok_response():
    return {
        "status": 200,
        "body": '{"issuer": "https://tenant", "email": "a@b.c"}',
        "headers": {},
    }


class TestTesterConsumesExtractedCatalogs:
    """The tester's request/verdict paths still run against the split tables."""

    async def test_auth0_verdict_fires_and_records_payload_metadata(self, monkeypatch):
        tester = AuthServicesTester()
        seen = []

        async def fake_send(url, method, payload, headers=None):
            seen.append((url, method))
            return _ok_response()

        monkeypatch.setattr(tester, "_send_request", fake_send)

        findings = await tester.test_auth0(
            target_url="https://app.example.com",
            auth0_domain="tenant.example.com",
        )

        assert seen, "tester must have issued requests"
        assert seen[0][0] == "https://tenant.example.com/.well-known/openid-configuration"
        assert all(method in {"GET", "POST"} for _, method in seen)

        assert findings, "200 + issuer/email body must trigger the verdict path"
        first = findings[0]
        assert first.param == "oidc_discovery"
        assert first.location == "auth0"
        assert first.tier == "confirmed"  # confidence 0.90 > 0.85
        source = ap.AUTH0_PAYLOADS[0]
        assert first.severity == source.severity
        assert first.confidence == pytest.approx(source.confidence)

    async def test_clerk_path_uses_clerk_table(self, monkeypatch):
        tester = AuthServicesTester()

        async def fake_send(url, method, payload, headers=None):
            return _ok_response()

        monkeypatch.setattr(tester, "_send_request", fake_send)
        findings = await tester.test_clerk(
            target_url="https://app.example.com",
            clerk_domain="clerk.example.com",
        )
        assert findings
        assert all(f.location == "clerk" for f in findings)
        clerk_names = {p.name for p in ap.CLERK_PAYLOADS}
        assert {f.param for f in findings} <= clerk_names

    async def test_no_findings_on_uninteresting_response(self, monkeypatch):
        tester = AuthServicesTester()

        async def fake_send(url, method, payload, headers=None):
            return {"status": 404, "body": "not found", "headers": {}}

        monkeypatch.setattr(tester, "_send_request", fake_send)
        assert await tester.test_auth0("https://app.example.com", "tenant.example.com") == []
        assert tester.get_findings() == []

    async def test_findings_accumulate_across_test_methods(self, monkeypatch):
        tester = AuthServicesTester()

        async def fake_send(url, method, payload, headers=None):
            return _ok_response()

        monkeypatch.setattr(tester, "_send_request", fake_send)
        await tester.test_auth0("https://app.example.com", "tenant.example.com")
        await tester.test_clerk("https://app.example.com", "clerk.example.com")
        assert len(tester.get_findings()) >= 2
