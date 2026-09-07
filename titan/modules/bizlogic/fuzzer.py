"""Parameter Fuzzing Engine — fuzz ALL parameters with business logic values.

A real attacker doesn't just test named parameters.
They fuzz EVERYTHING. Every header, every cookie, every hidden field.

This module:
1. Fuzzes all discovered parameters with business logic payloads
2. Tests parameter pollution (duplicate params)
3. Tests type confusion (string vs int vs array vs null)
4. Tests boundary values (min, max, overflow)
5. Tests injection in business logic context
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from titan.core.models import AttackType, Finding, Severity


@dataclass
class FuzzPayload:
    """A parameter fuzzing payload."""
    name: str
    value: Any
    expected_effect: str
    severity: Severity
    confidence: float


class ParameterFuzzer:
    """Deep parameter fuzzing engine."""

    # ── Universal Fuzz Payloads ────────────────────────────────────────

    # These work on ANY parameter regardless of name
    UNIVERSAL_PAYLOADS = [
        # Null/empty
        FuzzPayload("null", None, "null_bypass", Severity.MEDIUM, 0.60),
        FuzzPayload("empty_string", "", "empty_bypass", Severity.LOW, 0.50),
        FuzzPayload("undefined", "undefined", "undefined_bypass", Severity.LOW, 0.55),

        # Type confusion
        FuzzPayload("string_as_int", "1; DROP TABLE users--", "injection", Severity.CRITICAL, 0.75),
        FuzzPayload("array_in_field", ["admin", "superuser"], "type_confusion", Severity.HIGH, 0.70),
        FuzzPayload("object_in_field", {"role": "admin"}, "type_confusion", Severity.HIGH, 0.75),
        FuzzPayload("boolean_true", True, "type_confusion", Severity.MEDIUM, 0.60),
        FuzzPayload("boolean_false", False, "type_confusion", Severity.MEDIUM, 0.55),

        # Numeric boundary
        FuzzPayload("zero", 0, "zero_bypass", Severity.MEDIUM, 0.65),
        FuzzPayload("negative", -1, "negative_bypass", Severity.HIGH, 0.70),
        FuzzPayload("max_int", 2147483647, "overflow", Severity.MEDIUM, 0.55),
        FuzzPayload("overflow_int", 2147483648, "overflow", Severity.HIGH, 0.65),
        FuzzPayload("negative_overflow", -2147483648, "overflow", Severity.HIGH, 0.65),
        FuzzPayload("float_overflow", 1e308, "overflow", Severity.MEDIUM, 0.50),
        FuzzPayload("nan", float("nan"), "nan_injection", Severity.MEDIUM, 0.55),
        FuzzPayload("inf", float("inf"), "inf_injection", Severity.MEDIUM, 0.55),

        # String injection
        FuzzPayload("sql_single_quote", "' OR '1'='1", "injection", Severity.CRITICAL, 0.75),
        FuzzPayload("sql_double_quote", '" OR "1"="1', "injection", Severity.CRITICAL, 0.70),
        FuzzPayload("sql_comment", "-- ", "injection", Severity.HIGH, 0.60),
        FuzzPayload("sql_union", "' UNION SELECT NULL--", "injection", Severity.CRITICAL, 0.80),
        FuzzPayload("xss_script", "<script>alert(1)</script>", "injection", Severity.HIGH, 0.65),
        FuzzPayload("xss_img", '<img src=x onerror=alert(1)>', "injection", Severity.HIGH, 0.65),
        FuzzPayload("path_traversal", "../../etc/passwd", "path_traversal", Severity.CRITICAL, 0.70),
        FuzzPayload("path_traversal_windows", "..\\..\\windows\\system32", "path_traversal", Severity.CRITICAL, 0.65),
        FuzzPayload("ssrf", "http://169.254.169.254/latest/meta-data/", "ssrf", Severity.CRITICAL, 0.70),
        FuzzPayload("ssrf_localhost", "http://127.0.0.1:8080", "ssrf", Severity.HIGH, 0.60),
        FuzzPayload("crlf", "%0d%0aSet-Cookie:hacked=true", "crlf_injection", Severity.HIGH, 0.60),
        FuzzPayload("null_byte", "%00", "null_byte", Severity.HIGH, 0.65),
        FuzzPayload("unicode_escape", "\\u0027 OR 1=1--", "unicode_bypass", Severity.HIGH, 0.60),

        # Business logic specific
        FuzzPayload("admin_role", "admin", "role_escalation", Severity.CRITICAL, 0.80),
        FuzzPayload("superuser", "superadmin", "role_escalation", Severity.CRITICAL, 0.80),
        FuzzPayload("service_role", "service_role", "role_escalation", Severity.CRITICAL, 0.85),
        FuzzPayload("owner", "owner", "role_escalation", Severity.CRITICAL, 0.75),
        FuzzPayload("free_amount", 0, "free_item", Severity.CRITICAL, 0.85),
        FuzzPayload("negative_amount", -100, "negative_total", Severity.CRITICAL, 0.80),
        FuzzPayload("bypass_payment", "free", "payment_bypass", Severity.CRITICAL, 0.75),
        FuzzPayload("bypass_auth", "true", "auth_bypass", Severity.CRITICAL, 0.70),
        FuzzPayload("skip_validation", "true", "validation_bypass", Severity.HIGH, 0.65),

        # Encoding bypasses
        FuzzPayload("double_url_encode", "%2527%2520OR%25201%3D1", "encoding_bypass", Severity.HIGH, 0.60),
        FuzzPayload("html_entity", "&#39; OR 1=1--", "encoding_bypass", Severity.HIGH, 0.55),
        FuzzPayload("utf8_overlong", "%c0%27 OR 1=1--", "encoding_bypass", Severity.HIGH, 0.60),
    ]

    # ── Parameter Pollution Payloads ───────────────────────────────────

    PARAM_POLLUTION_PAYLOADS = [
        # Duplicate parameter with different values
        {"param": "role", "values": ["user", "admin"]},
        {"param": "amount", "values": [100, 0]},
        {"param": "status", "values": ["pending", "paid"]},
        {"param": "price", "values": [100, 0]},
        {"param": "discount", "values": [0, 100]},
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._findings: list[Finding] = []

    async def fuzz_endpoint(
        self,
        target_url: str,
        url: str,
        method: str,
        params: dict[str, Any],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Deep fuzz a single endpoint."""
        findings = []

        # 1. Get baseline
        baseline = await self._get_baseline(url, method, params, auth_headers)
        if baseline is None:
            return findings

        # 2. Universal fuzz all parameters
        findings.extend(await self._universal_fuzz(
            target_url, url, method, params, baseline, auth_headers
        ))

        # 3. Parameter pollution
        findings.extend(await self._param_pollution(
            target_url, url, method, params, baseline, auth_headers
        ))

        # 4. Type confusion on each parameter
        findings.extend(await self._type_confusion(
            target_url, url, method, params, baseline, auth_headers
        ))

        # 5. Boundary testing
        findings.extend(await self._boundary_testing(
            target_url, url, method, params, baseline, auth_headers
        ))

        return findings

    async def _universal_fuzz(
        self,
        target_url: str,
        url: str,
        method: str,
        params: dict[str, Any],
        baseline: dict[str, Any],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Fuzz each parameter with all universal payloads."""
        findings = []

        for param_name in params:
            for payload in self.UNIVERSAL_PAYLOADS:
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload.value

                    response = await self._send_request(url, method, test_params, auth_headers)
                    if response is None:
                        continue

                    if self._is_vulnerable(baseline, response, payload):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=method.upper(),
                            param=param_name,
                            location="query" if method.upper() == "GET" else "body",
                            payload=f"{param_name}={payload.value}",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=payload.severity,
                            verified=True,
                            confidence=payload.confidence,
                            status=response.get("status", 0),
                            body=response.get("body", "")[:2000],
                            diffs=[f"fuzz:{payload.name}", f"param:{param_name}"],
                            baseline_body=baseline.get("body", "")[:2000],
                            baseline_status=baseline.get("status", 0),
                            verification_body=response.get("body", "")[:2000],
                            verification_status=response.get("status", 0),
                            notes=f"Universal fuzz: {payload.name} on {param_name}",
                        )
                        findings.append(finding)

                except Exception:
                    continue

        self._findings.extend(findings)
        return findings

    async def _param_pollution(
        self,
        target_url: str,
        url: str,
        method: str,
        params: dict[str, Any],
        baseline: dict[str, Any],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test parameter pollution (duplicate params with different values)."""
        findings = []

        for pollution in self.PARAM_POLLUTION_PAYLOADS:
            param = pollution["param"]
            values = pollution["values"]

            if param not in params and param not in [
                k for k in params
            ]:
                continue

            try:
                # Method 1: JSON body with duplicate keys
                test_data = dict(params)
                # Most frameworks take the LAST value
                test_data[param] = values[0]
                pollution_data = {**test_data, f"{param}": values[1]}

                response = await self._send_request(url, method, pollution_data, auth_headers)
                if response is None:
                    continue

                resp_body = response.get("body", "")
                status = response.get("status", 0)

                if status in (200, 201, 202):
                    # Check which value was accepted
                    for val in values:
                        if str(val) in resp_body:
                            finding = Finding(
                                target=target_url,
                                url=url,
                                method=method.upper(),
                                param=param,
                                location="body",
                                payload=f"Pollution: {param}={values[0]}&{param}={values[1]}",
                                attack_type=AttackType.BUSINESS_LOGIC,
                                severity=Severity.HIGH,
                                verified=True,
                                confidence=0.75,
                                status=status,
                                body=resp_body[:2000],
                                diffs=[f"pollution:{param}={val}"],
                                baseline_body=baseline.get("body", "")[:2000],
                                baseline_status=baseline.get("status", 0),
                                verification_body=resp_body[:2000],
                                verification_status=status,
                                notes=f"Parameter pollution: {param} accepted value {val} from duplicate",
                            )
                            findings.append(finding)
                            break

            except Exception:
                continue

        self._findings.extend(findings)
        return findings

    async def _type_confusion(
        self,
        target_url: str,
        url: str,
        method: str,
        params: dict[str, Any],
        baseline: dict[str, Any],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test type confusion on each parameter."""
        findings = []

        type_payloads = [
            ("array", [1, 2, 3]),
            ("object", {"key": "value"}),
            ("nested_array", [{"role": "admin"}]),
            ("boolean_string", "true"),
            ("integer_string", "123"),
            ("float_string", "123.45"),
            ("empty_array", []),
            ("empty_object", {}),
            ("deeply_nested", {"a": {"b": {"c": "admin"}}}),
        ]

        for param_name in params:
            for type_name, type_value in type_payloads:
                try:
                    test_params = dict(params)
                    test_params[param_name] = type_value

                    response = await self._send_request(url, method, test_params, auth_headers)
                    if response is None:
                        continue

                    status = response.get("status", 0)
                    resp_body = response.get("body", "")

                    if status in (200, 201, 202) and resp_body != baseline.get("body", ""):
                        # Check if type confusion had an effect
                        if self._type_confusion_effect(type_name, type_value, resp_body):
                            finding = Finding(
                                target=target_url,
                                url=url,
                                method=method.upper(),
                                param=param_name,
                                location="body",
                                payload=f"{param_name}={type_value} (type: {type_name})",
                                attack_type=AttackType.BUSINESS_LOGIC,
                                severity=Severity.HIGH,
                                verified=True,
                                confidence=0.70,
                                status=status,
                                body=resp_body[:2000],
                                diffs=[f"type_confusion:{type_name}", f"param:{param_name}"],
                                baseline_body=baseline.get("body", "")[:2000],
                                baseline_status=baseline.get("status", 0),
                                verification_body=resp_body[:2000],
                                verification_status=status,
                                notes=f"Type confusion: {type_name} accepted for {param_name}",
                            )
                            findings.append(finding)

                except Exception:
                    continue

        self._findings.extend(findings)
        return findings

    async def _boundary_testing(
        self,
        target_url: str,
        url: str,
        method: str,
        params: dict[str, Any],
        baseline: dict[str, Any],
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Test boundary values on numeric parameters."""
        findings = []

        boundary_values = [
            ("min_int", -2147483648),
            ("max_int", 2147483647),
            ("overflow_plus", 2147483648),
            ("overflow_minus", -2147483649),
            ("zero", 0),
            ("one", 1),
            ("negative_one", -1),
            ("large_positive", 999999999),
            ("large_negative", -999999999),
            ("float_precision", 0.1 + 0.2),
            ("very_small_float", 0.0000001),
            ("very_large_float", 1e15),
        ]

        for param_name in params:
            # Only test numeric-looking params
            current_val = params.get(param_name)
            if current_val is not None and not isinstance(current_val, (int, float)):
                try:
                    float(str(current_val))
                except (ValueError, TypeError):
                    continue

            for bname, bvalue in boundary_values:
                try:
                    test_params = dict(params)
                    test_params[param_name] = bvalue

                    response = await self._send_request(url, method, test_params, auth_headers)
                    if response is None:
                        continue

                    status = response.get("status", 0)
                    resp_body = response.get("body", "")

                    if status in (200, 201, 202) and resp_body != baseline.get("body", ""):
                        finding = Finding(
                            target=target_url,
                            url=url,
                            method=method.upper(),
                            param=param_name,
                            location="body",
                            payload=f"{param_name}={bvalue}",
                            attack_type=AttackType.BUSINESS_LOGIC,
                            severity=Severity.HIGH if bname.startswith("overflow") else Severity.MEDIUM,
                            verified=True,
                            confidence=0.65,
                            status=status,
                            body=resp_body[:2000],
                            diffs=[f"boundary:{bname}", f"param:{param_name}={bvalue}"],
                            baseline_body=baseline.get("body", "")[:2000],
                            baseline_status=baseline.get("status", 0),
                            verification_body=resp_body[:2000],
                            verification_status=status,
                            notes=f"Boundary test: {param_name}={bvalue} ({bname}) accepted",
                        )
                        findings.append(finding)

                except Exception:
                    continue

        self._findings.extend(findings)
        return findings

    # ── Helpers ────────────────────────────────────────────────────────

    async def _get_baseline(self, url, method, params, headers):
        try:
            response = await self._send_request(url, method, params, headers)
            return response
        except Exception:
            return None

    async def _send_request(self, url, method, params, headers=None):
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                h = headers or {}
                if method.upper() == "GET":
                    async with session.get(url, params=params, headers=h, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "POST":
                    async with session.post(url, json=params, headers=h, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "PUT":
                    async with session.put(url, json=params, headers=h, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
                elif method.upper() == "PATCH":
                    async with session.patch(url, json=params, headers=h, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        return {"status": resp.status, "body": await resp.text(), "headers": dict(resp.headers)}
        except Exception:
            return None

    def _is_vulnerable(self, baseline, response, payload):
        """Check if the response indicates vulnerability."""
        status = response.get("status", 0)
        body = response.get("body", "")
        baseline_body = baseline.get("body", "")
        baseline_status = baseline.get("status", 0)

        # Must be successful
        if status not in (200, 201, 202):
            return False

        # Body must change
        if body == baseline_body:
            return False

        # Check specific indicators
        if payload.expected_effect in ("injection", "path_traversal", "ssrf"):
            error_indicators = ["error", "syntax", "exception", "traceback", "stack"]
            if any(kw in body.lower() for kw in error_indicators):
                return True
            # SSRF: check if we got a response from internal service
            if "meta-data" in body or "instance-id" in body:
                return True
            return False

        if payload.expected_effect == "role_escalation":
            role_indicators = ["admin", "superadmin", "superuser", "owner"]
            if any(kw in body.lower() for kw in role_indicators):
                if not any(kw in body.lower() for kw in ["error", "invalid", "denied"]):
                    return True
            return False

        if payload.expected_effect in ("free_item", "negative_total", "payment_bypass"):
            if re.search(r'"total":\s*0', body) or re.search(r'"total":\s*-\d+', body):
                return True
            if "free" in body.lower() and "paid" in body.lower():
                return True
            return False

        # Generic: if body changed significantly
        if len(body) != len(baseline_body):
            return True

        return False

    def _type_confusion_effect(self, type_name, value, body):
        """Check if type confusion had an effect."""
        if type_name == "array":
            # Check if array was processed (not rejected)
            if "error" not in body.lower():
                return True
        elif type_name == "object":
            if "admin" in str(value).lower() and "admin" in body.lower():
                return True
        return False

    def get_findings(self) -> list[Finding]:
        return self._findings
