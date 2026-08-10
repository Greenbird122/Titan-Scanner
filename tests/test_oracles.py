"""Behavioral tests for the evidence-oracle engine (titan.verify.oracles)."""

import pytest

from titan.verify.oracles import (
    extract_error_classes,
    json_differential,
    score_signals,
)


class TestErrorClassExtraction:
    def test_python_traceback_and_errno(self):
        body = "Traceback (most recent call last)\n  File \"app.py\", line 4\n[Errno 2] No such file or directory: '../../etc/passwd'"
        classes = extract_error_classes(body)
        assert "python" in classes
        assert "filesystem" in classes

    def test_sql_error(self):
        assert "sql" in extract_error_classes("You have an error in your SQL syntax near 'OR 1=1'")

    def test_mysql_warning(self):
        assert "sql" in extract_error_classes("Warning: mysql_fetch_array() expects parameter 1")

    def test_xml_parser_error(self):
        assert "xml" in extract_error_classes("javax.xml.parsers.ParserConfigurationException")

    def test_clean_page_has_no_error_classes(self):
        assert extract_error_classes("<html><h1>Welcome</h1></html>") == []

    def test_doctype_alone_is_not_an_xml_error(self):
        # Regression: the old "doctype" regex matched every HTML page and
        # would have "verified" findings on arbitrary sites.
        page = "<!DOCTYPE html><html><head><title>Home</title></head><body>ok</body></html>"
        assert "xml" not in extract_error_classes(page)
        assert extract_error_classes(page) == []

    def test_empty_body(self):
        assert extract_error_classes("") == []


class TestJsonDifferential:
    def test_different_records_show_value_changes(self):
        baseline = '{"name": "Admin", "role": "admin", "ssn": "123-45-6789"}'
        test = '{"name": "User", "role": "user", "ssn": "987-65-4321"}'
        signals = json_differential(baseline, test)
        assert any(s.startswith("json:value_changed:") for s in signals)
        assert len([s for s in signals if s.startswith("json:value_changed")]) == 3

    def test_identical_documents_no_signals(self):
        body = '{"a": 1, "b": [1, 2]}'
        assert json_differential(body, body) == []

    def test_missing_resource_is_key_removal_not_value_change(self):
        baseline = '{"name": "Admin", "role": "admin"}'
        empty = "{}"
        signals = json_differential(baseline, empty)
        assert any(s.startswith("json:key_removed") for s in signals)
        # The IDOR oracle relies on value changes specifically — a not-found
        # resource must NOT look like a different record.
        assert not any(s.startswith("json:value_changed") for s in signals)

    def test_invalid_json_no_signals(self):
        assert json_differential("not json", "also not json") == []


class TestScoreSignals:
    def test_no_signals_no_confidence(self):
        confidence, verified, matched = score_signals([])
        assert confidence == 0.0
        assert verified is False
        assert matched == []

    def test_oob_is_conclusive(self):
        confidence, verified, matched = score_signals(["oob_confirmed"])
        assert confidence == 1.0
        assert verified is True
        assert matched == ["oob_confirmed"]

    def test_sanity_pair_verifies(self):
        confidence, verified, _ = score_signals(["sanity_pair"])
        assert verified is True
        assert confidence == 0.85

    def test_content_leak_verifies(self):
        confidence, verified, _ = score_signals(["content_leak"])
        assert verified is True
        assert confidence >= 0.9

    def test_weak_signals_do_not_verify(self):
        confidence, verified, _ = score_signals(["reflection", "status_500", "content_change"])
        assert verified is False
        assert confidence > 0.3  # suspicious, but not confirmed
        assert confidence < 1.0

    def test_noisy_or_combines_signals(self):
        conf_reflection, _, _ = score_signals(["reflection"])
        conf_stack, _, _ = score_signals(["reflection", "error:generic", "status_500"])
        assert conf_stack > conf_reflection  # more evidence → higher confidence

    def test_sql_error_is_strong(self):
        _, verified, _ = score_signals(["error:sql"])
        assert verified is True

    def test_duplicate_signals_are_not_double_counted(self):
        # Regression: noisy-OR over duplicate evidence must not inflate the
        # score (e.g. two detectors both reporting "reflection").
        single_conf, _, _ = score_signals(["reflection"])
        dup_conf, _, _ = score_signals(["reflection", "reflection"])
        assert dup_conf == single_conf
        assert dup_conf == 0.6
