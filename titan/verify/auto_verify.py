"""Auto-verification with negative controls.

For each finding, re-run the payload with a controlled benign input and
compare the response against the original. If both responses are identical
or contain the same error classes, the finding is auto-demoted.

This eliminates the majority of scanner noise without any AI involvement.
"""
from __future__ import annotations

from difflib import SequenceMatcher

from titan.core.models import Finding


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

    async def _run_controls(self, context, finding: Finding) -> list[tuple[str, str, int]]:
        """Send benign control payloads and return (body, error_classes, status) tuples."""
        controls = self._generate_controls(finding)
        results: list[tuple[str, str, int]] = []

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

    def _generate_controls(self, finding: Finding) -> list[str]:
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
        self, finding: Finding, controls: list[tuple[str, str, int]]
    ) -> bool:
        """Return True if the finding should be demoted based on control results."""
        original_body = finding.body or ""
        original_status = finding.status or 0
        baseline_body = finding.baseline_body or ""
        original_error_classes = set(self._extract_new_error_classes(
            baseline_body, original_body
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

            # REFLECTION FP DETECTION (WordPress echo storm prevention):
            # If the endpoint returns 200 and both the original payload and
            # the control payload are simply reflected in the body (the body
            # structure is nearly identical minus the payload itself), the
            # endpoint is echoing input, not processing it. This catches
            # WordPress soft-404 pages and similar catch-all routes that
            # reflect every payload into an error page with HTTP 200.
            if (
                control_status == original_status
                and original_status == 200
                and self._is_reflection_finding(finding, original_body, control_body, baseline_body)
            ):
                return True

        return False

    def _is_reflection_finding(
        self,
        finding: Finding,
        original_body: str,
        control_body: str,
        baseline_body: str,
    ) -> bool:
        """Detect if a finding is just payload reflection (not real processing).

        A reflection FP occurs when the endpoint echoes any input back in
        the response body without actually processing it. The key signal:
        the response body structure is nearly identical across different
        payloads — only the payload substring changes.

        This catches WordPress echo storms, generic error pages, and any
        catch-all route that reflects input.
        """
        payload = finding.payload or ""
        if not payload or not original_body or not control_body:
            return False

        # Guard: require a baseline — without it we can't distinguish
        # reflection from genuine content change.
        if not baseline_body:
            return False

        # Signal 1: The payload appears in the original response but NOT
        # in the baseline. This means the endpoint reflects input.
        payload_in_response = payload.lower() in original_body.lower()
        payload_in_baseline = payload.lower() in baseline_body.lower()
        payload_reflected = payload_in_response and not payload_in_baseline

        if not payload_reflected:
            return False

        # Signal 2: The control body is structurally similar to the original
        # (same page layout, just different payload substring). High similarity
        # means the endpoint produces the same page for any input.
        similarity = self._body_similarity(original_body, control_body)

        # Signal 3: The control body does NOT contain NEW error classes that
        # the original has — the original's "verification" was just reflection,
        # not actual error triggering.
        original_errors = set(self._extract_new_error_classes(baseline_body, original_body))
        control_errors = set(self._extract_new_error_classes(baseline_body, control_body))
        no_new_errors = not control_errors or control_errors == original_errors

        # Signal 4: The response body is significantly larger than the payload
        # (the payload is a small substring in a large page, not the entire
        # response). This prevents false-flagging APIs that return the payload
        # as the full response body (which could be real processing).
        body_is_large = len(original_body) > len(payload) * 5

        # All four signals together = strong reflection FP signal
        return payload_reflected and similarity > 0.6 and no_new_errors and body_is_large

    @staticmethod
    def _extract_new_error_classes(baseline_body: str, test_body: str) -> list[str]:
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
