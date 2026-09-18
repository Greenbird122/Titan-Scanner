"""Guards for the SQLi detector / signatures module split.

The data tables moved from detector.py to signatures.py must remain
reachable under the same public surface: the detector's class attribute,
its private module aliases, and the signatures module itself — with the
exact table contents intact.
"""

from __future__ import annotations


def _signatures():
    from titan.modules.sqli import signatures

    return signatures


def test_signatures_module_imports():
    sig = _signatures()
    assert hasattr(sig, "SQLI_ERROR_SIGNATURES")
    assert hasattr(sig, "INJECTABLE_HEADERS")
    assert hasattr(sig, "OOB_TEMPLATES")


def test_error_signatures_content():
    sig = _signatures()
    table = sig.SQLI_ERROR_SIGNATURES
    assert isinstance(table, tuple)
    # Count is stable (65 strings across 13 engine families); a revert or
    # silent truncation shows up here.
    assert len(table) == 65
    # Representative members across the engine families.
    for member in (
        "sql syntax",
        "incorrect syntax near",
        "sqlite3.operationalerror",
        "db2 sql error",
        "syntax error at or near",
        "conversion failed",
        "database error",
    ):
        assert member in table, f"signature '{member}' missing from SQLI_ERROR_SIGNATURES"


def test_injectable_headers_content():
    sig = _signatures()
    headers = sig.INJECTABLE_HEADERS
    assert isinstance(headers, tuple)
    assert len(headers) == 13
    assert "User-Agent" in headers
    assert "X-Forwarded-For" in headers
    assert "Authorization" in headers


def test_oob_templates_content():
    sig = _signatures()
    templates = sig.OOB_TEMPLATES
    assert isinstance(templates, dict)
    assert set(templates) == {"mssql", "postgresql", "mysql", "oracle", "db2", "snowflake", "hana"}
    # The MySQL UNC-path template is backslash-heavy; guard its exact shape.
    mysql = templates["mysql"]
    assert len(mysql) == 2
    assert "'{domain}'" in mysql[0]
    assert "LOAD_FILE" in mysql[0]


def test_detector_imports_from_signatures():
    """The detector keeps its class attribute; mixins import their own aliases.

    After the mixin split: detector.py keeps _SQLI_ERROR_SIGNATURES (public
    ERROR_SIGNATURES), surfaces.py carries the header-table alias, and oob.py
    carries the OOB-template alias — each imported from signatures.py.
    """
    from titan.modules.sqli import detector, oob, surfaces

    sig = _signatures()
    assert detector._SQLI_ERROR_SIGNATURES is detector.SQLiDetector.ERROR_SIGNATURES
    assert detector._SQLI_ERROR_SIGNATURES is sig.SQLI_ERROR_SIGNATURES
    assert surfaces._INJECTABLE_HEADERS is sig.INJECTABLE_HEADERS
    assert oob._OOB_TEMPLATES is sig.OOB_TEMPLATES


def test_detector_module_still_inspectable():
    """The getsource-based test in test_sqli_s3.py must keep working."""
    import inspect

    from titan.modules.sqli.detector import SQLiDetector

    src = inspect.getsource(SQLiDetector._test_param)
    for sig in (
        "incorrect syntax near",
        "microsoft ole db",
        "sqlite3.operationalerror",
        "database error",
        "syntax error at or near",
        "conversion failed",
        "db2 sql error",
        "microsoft sql server",
        "ora-",
    ):
        assert sig in src.lower(), f"error signature '{sig}' missing from _test_param source"


def test_signatures_module_is_data_only():
    """The split module must stay pure data — no logic sneaks back in."""
    import ast
    import inspect

    from titan.modules.sqli import signatures

    tree = ast.parse(inspect.getsource(signatures))
    # Every top-level assignment must target a known constant.
    targets = {
        t.id for node in tree.body if isinstance(node, ast.Assign) for t in node.targets if isinstance(t, ast.Name)
    }
    ann_targets = {
        t.id
        for node in tree.body
        if isinstance(node, ast.AnnAssign) and node.value is not None and isinstance(node.target, ast.Name)
        for t in [node.target]
    }
    expected = {"SQLI_ERROR_SIGNATURES", "INJECTABLE_HEADERS", "OOB_TEMPLATES"}
    assert targets | ann_targets == expected
