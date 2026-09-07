"""WAF profile data used by ResponseAnalyzer.

Extracted from titan/ai/adaptive.py so the rule/dialect dictionaries can be
tested directly. ResponseAnalyzer re-exposes these as class attributes, so
``cls.WAF_RULE_PATTERNS`` etc. keep working unchanged.
"""

from __future__ import annotations

from typing import Dict, List

# WAF rule patterns — what triggered the block
WAF_RULE_PATTERNS: Dict[str, List[str]] = {
    "sql_injection": [
        "union", "select", "from", "where", "order by",
        "insert", "update", "delete", "drop", "create",
        "exec", "execute", "xp_cmdshell", "sp_executesql",
    ],
    "xss_injection": [
        "script", "alert", "onerror", "onload", "javascript:",
        "<img", "<svg", "<iframe", "document.cookie", "eval(",
    ],
    "path_traversal": [
        "..", "../", "..\\", "/etc/passwd", "/etc/shadow",
        "win.ini", "boot.ini", "proc/self",
    ],
    "command_injection": [
        "; id", "| id", "&& id", "`id`", "$(id)",
        "; cat", "| cat", "; ls", "| ls",
    ],
    "ssrf": [
        "169.254.169.254", "127.0.0.1", "localhost",
        "metadata.google.internal", "100.100.100.200",
    ],
}

# WAF fingerprinting payloads — send these to identify the WAF
WAF_FINGERPRINT_PAYLOADS: List[str] = [
    # SQL injection test
    "' OR '1'='1",
    # XSS test
    "<script>alert(1)</script>",
    # Path traversal test
    "../../../etc/passwd",
    # Command injection test
    "; echo TITAN_FINGERPRINT",
    # SSRF test
    "http://169.254.169.254/latest/meta-data/",
]

# Error message patterns → database dialect
ERROR_DIALECT_PATTERNS: Dict[str, List[str]] = {
    "mysql": [
        "mysql", "mariadb", "you have an error in your sql syntax",
        "warning: mysql", "mysql_fetch", "mysql_num_rows",
        "supplied argument is not a valid mysql",
    ],
    "postgresql": [
        "postgresql", "pg_query", "pg_exec", "psql",
        "syntax error at or near", "relation does not exist",
        "column does not exist",
    ],
    "mssql": [
        "mssql", "microsoft sql", "unclosed quotation mark",
        "incorrect syntax near", "conversion failed",
        "quoted string not properly terminated",
    ],
    "sqlite": [
        "sqlite", "sqlite3", "sqlITE_ERROR",
        "no such table", "no such column",
        "near \"\": syntax error",
    ],
    "oracle": [
        "oracle", "ora-", "ora00933", "ora00942",
        "table or view does not exist",
        "quoted identifier not properly terminated",
    ],
    "nosql": [
        "mongo", "mongodb", "nosql",
        "bson", "collection", "$ne", "$gt",
    ],
    "template": [
        "jinja", "twig", "freemarker", "smarty",
        "template", "render", "undefined variable",
        "no filter named",
    ],
    "python": [
        "traceback", "error:", "exception",
        "import", "module", "nameerror",
        "typeerror", "attributeerror",
    ],
    "php": [
        "php", "warning:", "fatal error:",
        "parse error", "notice:", "deprecated:",
        "call to undefined function",
    ],
    "java": [
        "java", "exception", "stacktrace",
        "classnotfound", "nullpointer",
        "at com.", "at java.",
    ],
    "ruby": [
        "ruby", "rails", "actioncontroller",
        "no method error", "nameerror:",
        "syntaxerror", "undefined method",
    ],
    "nodejs": [
        "node", "express", "typeerror:",
        "referenceerror:", "syntaxerror:",
        "cannot read property",
    ],
}