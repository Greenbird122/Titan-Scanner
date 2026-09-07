"""Direct coverage for the extracted WAF profile data (titan/ai/waf_profiles.py).

Also pins that ResponseAnalyzer still re-exposes the same objects as class
attributes, so its ``cls.X`` call sites and the public API are unchanged.
"""

from __future__ import annotations

from titan.ai.adaptive import ResponseAnalyzer
from titan.ai.waf_profiles import (
    ERROR_DIALECT_PATTERNS,
    WAF_FINGERPRINT_PAYLOADS,
    WAF_RULE_PATTERNS,
)


def test_waf_rule_patterns_cover_core_attacks():
    for rule in ("sql_injection", "xss_injection", "path_traversal", "command_injection", "ssrf"):
        assert rule in WAF_RULE_PATTERNS
        assert WAF_RULE_PATTERNS[rule], f"{rule} must have keywords"


def test_dialect_patterns_cover_major_backends():
    for dialect in ("mysql", "postgresql", "mssql", "sqlite", "oracle", "nosql", "php", "java"):
        assert dialect in ERROR_DIALECT_PATTERNS
        assert ERROR_DIALECT_PATTERNS[dialect], f"{dialect} must have patterns"


def test_fingerprint_payloads_nonempty():
    assert len(WAF_FINGERPRINT_PAYLOADS) >= 5
    assert "<script>alert(1)</script>" in WAF_FINGERPRINT_PAYLOADS


def test_response_analyzer_still_exposes_the_same_objects():
    assert ResponseAnalyzer.WAF_RULE_PATTERNS is WAF_RULE_PATTERNS
    assert ResponseAnalyzer.WAF_FINGERPRINT_PAYLOADS is WAF_FINGERPRINT_PAYLOADS
    assert ResponseAnalyzer.ERROR_DIALECT_PATTERNS is ERROR_DIALECT_PATTERNS
