"""Regression: bare-host consent targets must match themselves.

The historical failure: ``consent add argusttrust.com`` wrote a signed file
whose ``target`` is the bare host, but every later ``_scope_matches`` call
against the same string returned False — ``urlparse('argusttrust.com')``
parses the host as a *path*, so ``hostname`` came back None and the guard
rejected it. ``consent list`` showed "does not cover argusttrust.com (scope
mismatch)" for a consent that plainly did cover it.
"""

from titan.exploit.consent import _scope_matches


class TestScopeMatches:
    def test_bare_host_matches_itself(self):
        assert _scope_matches("argusttrust.com", "argusttrust.com") is True

    def test_full_url_matches_bare_host_consent(self):
        assert _scope_matches("https://argusttrust.com/api/verify/tcc", "argusttrust.com") is True

    def test_bare_host_consent_covers_url_consent(self):
        assert _scope_matches("argusttrust.com", "https://argusttrust.com") is True

    def test_subdomain_covered(self):
        assert _scope_matches("https://api.example.com/v1", "example.com") is True

    def test_unrelated_host_rejected(self):
        assert _scope_matches("evil.example", "argusttrust.com") is False

    def test_lookalike_suffix_not_covered(self):
        """endswith('.'+host) must not be fooled by a shared suffix."""
        assert _scope_matches("notargusttrust.com", "argusttrust.com") is False

    def test_empty_rejected(self):
        assert _scope_matches("", "argusttrust.com") is False
        assert _scope_matches("argusttrust.com", "") is False
