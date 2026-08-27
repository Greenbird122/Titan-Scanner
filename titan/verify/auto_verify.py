"""Auto-verification with negative controls.

For each finding, re-run the payload with a controlled benign input and
compare the response against the original. If both responses are identical
or contain the same error classes, the finding is auto-demoted.

This eliminates the majority of scanner noise without any AI involvement.
"""
from __future__ import annotations

import asyncio
import random
import string
from typing import Any, Dict, List, Optional, Tuple

from titan.core.models import Finding, Severity


class AutoVerifier:
    """Deterministic auto-verification using negative controls."""

    def __init__(self, max_control_payloads: int = 3):
        self.max_control_payloads = max_control_payloads

    async def verify_finding(self, context, finding: Finding) -> Finding:
        """Run negative controls against a finding and demote if unverified."""
        if not finding.verified or finding.confidence < 0.3:
            return finding

        control_results = await self._run_controls(context, finding)
        if not control_results:
            return finding

        # Compare each control against the original response
        demote = self._should_demote(finding, control_results)
        if demote:
            finding.verified = False
            finding.confidence = max(0.1, finding.confidence - 0.4)
            finding.metadata["auto_demoted"] = True
            finding.metadata["demotion_reason"] = "failed_negative_control"
        return finding

    async def _run_controls(self, context, finding: Finding) -> List[Tuple[str, str, int]]:
        """Send benign control payloads and return (body, error_classes, status) tuples."""
        controls = self._generate_controls(finding)
        results: List[Tuple[str, str, int]] = []

        for payload in controls[:self.max_control_payloads]:
            try:
                resp = await self._send(context, finding, payload)
                body = await resp.text() if hasattr(resp, "text") else ""
                status = getattr(resp, "status", 0)
                error_classes = self._extract_new_error_classes(
                    finding.baseline_body or "", body
                )
                results.append((body, error_classes, status))
            except Exception:
                continue

        return results

    def _generate_controls(self, finding: Finding) -> List[str]:
        """Generate benign control payloads that should NOT trigger the finding."""
        param = finding.param or "test"
        location = finding.location or "query"

        if location == "header":
            return [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept: text/html,application/xhtml+xml,application/xml",
                "Content-Type: application/json",
            ]

        if finding.attack_type.value in ("sqli", "nosqli"):
            return [
                "hello world",
                "test123",
                "normal_value",
                "",
                "1",
            ]

        if finding.attack_type.value in ("xss", "ssti"):
            return [
                "hello world",
                "test123",
                "<div>normal</div>",
                "",
            ]

        if finding.attack_type.value in ("ssrf", "lfi", "rce"):
            return [
                "hello world",
                "127.0.0.1",
                "localhost",
                "",
                "/normal/path",
            ]

        if finding.attack_type.value == "redirect":
            return [
                "https://example.com/",
                "/normal/page",
                "",
            ]

        return [
            "hello world",
            "test123",
            "",
            "normal_value",
        ]

    async def _send(self, context, finding: Finding, payload: str):
        """Send a control payload using the same method as the original finding."""
        if finding.location == "header":
            headers = {"Referer": finding.target}
            if finding.method.upper() == "GET":
                return await context.request.get(
                    finding.url, headers=headers, timeout=3000
                )
            return await context.request.post(
                finding.url, headers=headers, timeout=3000
            )

        params = {finding.param: payload}
        if finding.method.upper() == "GET":
            return await context.request.get(
                finding.url, params=params, headers={"Referer": finding.target}, timeout=3000
            )
        return await context.request.post(
            finding.url, data=params, headers={"Referer": finding.target}, timeout=3000
        )

    def _should_demote(
        self, finding: Finding, controls: List[Tuple[str, str, int]]
    ) -> bool:
        """Return True if the finding should be demoted based on control results."""
        original_body = finding.body or ""
        original_status = finding.status or 0
        original_error_classes = set(self._extract_new_error_classes(
            finding.baseline_body or "", original_body
        ))

        for control_body, control_error_classes, control_status in controls:
            if not control_body:
                continue

            # If control produces the same error classes as the original payload,
            # the finding is likely a false positive (error is in baseline)
            if original_error_classes and control_error_classes:
                if original_error_classes == control_error_classes:
                    return True

            # If control produces the same structural response (same status + similar body),
            # the finding is likely a false positive
            if control_status == original_status and original_status >= 400:
                similarity = self._body_similarity(original_body, control_body)
                if similarity > 0.7:
                    return True

        return False

    @staticmethod
    def _extract_new_error_classes(baseline_body: str, test_body: str) -> List[str]:
        """Return error classes that appear in test_body but NOT in baseline_body."""
        if not test_body:
            return []
        if baseline_body and test_body == baseline_body:
            return []

        baseline_classes = set()
        test_classes = set()

        error_patterns = [
            ("sql", ["sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlstate",
                     "unclosed quotation", "quoted string not properly terminated"]),
            ("filesystem", ["no such file", "file not found", "permission denied",
                            "access is denied", "system cannot find"]),
            ("xml", ["parser error", "not well-formed", "xml parsing"]),
            ("java", ["java.lang.", "exception in thread", "servlet", "springframework"]),
            ("python", ["traceback", "filenotfounderror", "valueerror", "typeerror"]),
            ("generic", ["internal server error", "500 internal", "server error",
                         "unhandled exception", "nullreferenceexception"]),
        ]

        test_lower = test_body.lower()
        baseline_lower = baseline_body.lower() if baseline_body else ""

        for cls, patterns in error_patterns:
            for pat in patterns:
                if pat in test_lower and pat not in baseline_lower:
                    test_classes.add(cls)
                if pat in baseline_lower:
                    baseline_classes.add(cls)

        return list(test_classes - baseline_classes)

    @staticmethod
    def _body_similarity(a: str, b: str) -> float:
        """Return similarity ratio between two response bodies."""
        if not a or not b:
            return 0.0
        return SequenceMatcher(None, a[:2000], b[:2000]).ratio()
