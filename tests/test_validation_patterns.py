"""Tests for the declared input-validation pattern registry.

``titan/core/validation_patterns.py`` declares the input grammar enforced at
the attack-module boundary (``titan/core/scan_params.py``). These tests pin
both layers: the registry's own contract (patterns match whole values,
lookups fail closed) and the enforcement (ScanParams rejects values that
fail their declared pattern, with unchanged error semantics).
"""

import re

import pytest

from titan.core.scan_params import TitanValidationError, validate_scan_params
from titan.core.validation_patterns import VALIDATION_PATTERNS, matches


class TestRegistryShape:
    def test_registry_is_non_empty_and_compiled(self):
        assert VALIDATION_PATTERNS, "the registry must declare at least one pattern"
        for name, pattern in VALIDATION_PATTERNS.items():
            assert isinstance(name, str) and name
            assert isinstance(pattern, re.Pattern)

    def test_unknown_pattern_name_fails_closed(self):
        # A typo'd name must raise, never silently return True/False acceptance.
        with pytest.raises(KeyError):
            matches("absoulute_http_url", "https://app.example.com")  # deliberately misspelled

    def test_fullmatch_semantics(self):
        # Partial matches must not count: the whole value has to satisfy
        # the pattern, not just a prefix.
        assert matches("http_method", "GET")
        assert not matches("http_method", "GETX")
        assert not matches("http_method", "XGET")
        assert not matches("http_method", " GET")


class TestDeclaredPatterns:
    def test_http_method(self):
        for verb in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            assert matches("http_method", verb)
        # lowercase is rejected: the pattern applies to the already
        # normalized, uppercased verb (ScanParams normalizes first).
        assert not matches("http_method", "get")
        assert not matches("http_method", "BREW")

    def test_absolute_http_url(self):
        for good in (
            "https://app.example.com",
            "http://localhost:8080/x",
            "https://app.example.com/cart?qty=2#frag",
            "HTTPS://APP.EXAMPLE.COM",  # case-insensitive scheme
        ):
            assert matches("absolute_http_url", good), good
        for bad in ("app.example.com/cart", "/absolute/path", "ftp://host", "https://", ""):
            assert not matches("absolute_http_url", bad), bad

    def test_absolute_path(self):
        for good in ("/logic_negative_accepted", "/x?q=1", "//double/slash"):
            assert matches("absolute_path", good), good
        for bad in ("cart/checkout", "x", "", " ./relative"):
            assert not matches("absolute_path", bad), bad

    def test_non_empty_text(self):
        assert matches("non_empty_text", "https://x")
        assert matches("non_empty_text", " padded ")  # surrounding whitespace stays legal
        assert not matches("non_empty_text", "   ")
        assert not matches("non_empty_text", "")

    def test_non_empty_key_is_deliberately_weaker_than_non_empty_text(self):
        # Param keys are only checked for emptiness, never stripped: a
        # whitespace-only key is data the target may legitimately be probed
        # with. This pins that distinction.
        assert matches("non_empty_key", " ")
        assert matches("non_empty_key", "a")
        assert not matches("non_empty_key", "")


class TestEnforcementAtBoundary:
    """The declared patterns are enforced by ScanParams, not decorative."""

    def _validate(self, **overrides):
        base = dict(
            target="https://app.example.com",
            method="GET",
            url="/logic_negative_accepted",
            params={"amount": "10"},
        )
        base.update(overrides)
        return validate_scan_params(**base)

    def test_valid_inputs_still_pass(self):
        model = self._validate()
        assert model.target == "https://app.example.com"
        assert model.method == "GET"

    def test_whitespace_only_target_rejected(self):
        with pytest.raises(TitanValidationError):
            self._validate(target="   ")

    def test_unsupported_method_rejected(self):
        with pytest.raises(TitanValidationError) as excinfo:
            self._validate(method="BREW")
        assert "unsupported HTTP method" in str(excinfo.value)

    def test_relative_url_rejected(self):
        with pytest.raises(TitanValidationError):
            self._validate(url="cart/checkout")

    def test_empty_param_key_rejected(self):
        with pytest.raises(TitanValidationError):
            self._validate(params={"": "1"})

    def test_error_is_a_valueerror(self):
        with pytest.raises(ValueError):
            self._validate(method="BREW")
