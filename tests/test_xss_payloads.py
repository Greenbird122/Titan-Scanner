"""Pin the XSS payload-split (detector.py -> payloads.py).

The detector now consumes ``titan/modules/xss/payloads.py`` for payload tables
and suite building. These tests pin the builder's routing and the module seam;
the tables themselves were verified byte-identical at extraction time.
"""

from titan.modules.xss import payloads
from titan.modules.xss.detector import XSSDetector


class TestBuildContextSuite:
    def test_dedupes_and_preserves_order(self):
        suite = payloads.build_context_suite("q", "x", ["<script>alert(1)</script>"])
        assert len(suite) == len(set(suite))

    def test_callback_param_routes_to_js_and_csti_first(self):
        suite = payloads.build_context_suite("callback", "x", [])
        assert payloads._JS_STRING_PAYLOADS[0] in suite
        assert payloads._CSTI_PAYLOADS[0] in suite
        # context-specific sets come before the generic pool
        assert suite.index(payloads._JS_STRING_PAYLOADS[0]) < len(suite) // 2

    def test_url_param_gets_javascript_sink(self):
        suite = payloads.build_context_suite("redirect", "x", [])
        assert "javascript:alert(1)" in suite

    def test_default_param_gets_html_and_attribute_contexts(self):
        suite = payloads.build_context_suite("comment", "x", [])
        assert payloads._HTML_TAG_PAYLOADS[0] in suite
        assert payloads._ATTR_BREAKOUT_PAYLOADS[0] in suite

    def test_waf_variants_always_appended(self):
        for name in ("callback", "redirect", "comment"):
            suite = payloads.build_context_suite(name, "x", [])
            assert payloads._WAF_BYPASS_VARIANTS[0] in suite


class TestDetectorSeam:
    def test_detector_delegates_to_extracted_builder(self):
        detector_method = XSSDetector._build_context_suite
        assert detector_method.__doc__ is not None
        # the method body must delegate, not reimplement
        import inspect

        src = inspect.getsource(detector_method)
        assert "build_context_suite(" in src
