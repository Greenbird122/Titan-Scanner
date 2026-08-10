"""Deserialization detection module for Titan Scanner."""

from __future__ import annotations

import base64
import re
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.verify import BaselineAnalyzer


class DeserDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        deser_params = [p for p in params if any(k in p.lower() for k in ["data", "payload", "object", "serialized", "json", "xml", "config", "settings", "state", "session", "cookie", "token", "obj"])]
        if not deser_params:
            return findings

        for param_name in deser_params[:3]:
            finding = await self._test_deserialization(context, target, method, url, param_name, params)
            if finding:
                findings.append(finding)

        return findings

    async def _test_deserialization(self, context, target, method, url, param_name, all_params) -> Optional[Finding]:
        try:
            if method == "GET":
                baseline_resp = await context.request.get(url, params=all_params, headers={"Referer": target}, timeout=3000)
            else:
                baseline_resp = await context.request.post(url, data=all_params, headers={"Referer": target}, timeout=3000)
            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status
        except Exception:
            return None

        body_lower = baseline_body.lower()

        java_gadget_patterns = [
            (r'java\.io\.', "Java IO deserialization"),
            (r'javax\.naming\.', "JNDI injection indicator"),
            (r'com\.sun\.rowset\.', "Java rowset deserialization"),
            (r'org\.apache\.commons\.collections\.', "Commons Collections deserialization"),
            (r'javassist', "Java bytecode manipulation"),
            (r'org\.springframework', "Spring deserialization"),
        ]

        for pattern, indicator in java_gadget_patterns:
            if re.search(pattern, body_lower):
                return Finding(
                    target=target,
                    url=str(baseline_resp.url or url),
                    method=method.upper(),
                    param=param_name,
                    location="query" if method == "GET" else "body",
                    payload=f"Deserialization indicator: {indicator}",
                    attack_type=AttackType.DESERIALIZATION,
                    severity=Severity.CRITICAL,
                    verified=True,
                    confidence=0.85,
                    status=baseline_status,
                    headers=dict(baseline_resp.headers),
                    body=baseline_body[:2000],
                    diffs=[f"deser:{indicator.lower().replace(' ', '_')}"],
                    baseline_body=baseline_body[:2000],
                    baseline_status=baseline_status,
                    verification_body=baseline_body[:2000],
                    verification_status=baseline_status,
                )

        php_unserialize_patterns = [
            (r' unserialize\(', "PHP unserialize usage"),
            (r'__wakeup', "PHP magic method"),
            (r'__destruct', "PHP destructor"),
            (r'php:\/\/filter', "PHP filter wrapper"),
            (r'php:\/\/input', "PHP input wrapper"),
        ]

        for pattern, indicator in php_unserialize_patterns:
            if re.search(pattern, body_lower):
                return Finding(
                    target=target,
                    url=str(baseline_resp.url or url),
                    method=method.upper(),
                    param=param_name,
                    location="query" if method == "GET" else "body",
                    payload=f"Deserialization indicator: {indicator}",
                    attack_type=AttackType.DESERIALIZATION,
                    severity=Severity.HIGH,
                    verified=True,
                    confidence=0.8,
                    status=baseline_status,
                    headers=dict(baseline_resp.headers),
                    body=baseline_body[:2000],
                    diffs=[f"deser:{indicator.lower().replace(' ', '_')}"],
                    baseline_body=baseline_body[:2000],
                    baseline_status=baseline_status,
                    verification_body=baseline_body[:2000],
                    verification_status=baseline_status,
                )

        python_pickle_patterns = [
            (r'pickle\.loads', "Python pickle deserialization"),
            (r'__reduce__', "Python pickle reduction"),
            (r'__setstate__', "Python pickle state manipulation"),
            (r'yaml\.load', "Unsafe YAML deserialization"),
            (r'ruamel\.yaml', "YAML deserialization"),
        ]

        for pattern, indicator in python_pickle_patterns:
            if re.search(pattern, body_lower):
                return Finding(
                    target=target,
                    url=str(baseline_resp.url or url),
                    method=method.upper(),
                    param=param_name,
                    location="query" if method == "GET" else "body",
                    payload=f"Deserialization indicator: {indicator}",
                    attack_type=AttackType.DESERIALIZATION,
                    severity=Severity.HIGH,
                    verified=True,
                    confidence=0.8,
                    status=baseline_status,
                    headers=dict(baseline_resp.headers),
                    body=baseline_body[:2000],
                    diffs=[f"deser:{indicator.lower().replace(' ', '_')}"],
                    baseline_body=baseline_body[:2000],
                    baseline_status=baseline_status,
                    verification_body=baseline_body[:2000],
                    verification_status=baseline_status,
                )

        dotnet_patterns = [
            (r'BinaryFormatter', "BinaryFormatter deserialization"),
            (r'NetDataContractSerializer', "NetDataContractSerializer"),
            (r'LosFormatter', "LosFormatter deserialization"),
            (r'ObjectStateFormatter', "ObjectStateFormatter"),
        ]

        for pattern, indicator in dotnet_patterns:
            if re.search(pattern, body_lower):
                return Finding(
                    target=target,
                    url=str(baseline_resp.url or url),
                    method=method.upper(),
                    param=param_name,
                    location="query" if method == "GET" else "body",
                    payload=f"Deserialization indicator: {indicator}",
                    attack_type=AttackType.DESERIALIZATION,
                    severity=Severity.CRITICAL,
                    verified=True,
                    confidence=0.85,
                    status=baseline_status,
                    headers=dict(baseline_resp.headers),
                    body=baseline_body[:2000],
                    diffs=[f"deser:{indicator.lower().replace(' ', '_')}"],
                    baseline_body=baseline_body[:2000],
                    baseline_status=baseline_status,
                    verification_body=baseline_body[:2000],
                    verification_status=baseline_status,
                )

        generic_errors = [
            "unserialize", "deserialize", "object not found",
            "class not found", "invalid serialization",
        ]
        matches = [ind for ind in generic_errors if ind in body_lower]

        if matches:
            return Finding(
                target=target,
                url=str(baseline_resp.url or url),
                method=method.upper(),
                param=param_name,
                location="query" if method == "GET" else "body",
                payload=f"Deserialization error: {', '.join(matches)}",
                attack_type=AttackType.DESERIALIZATION,
                severity=Severity.MEDIUM,
                verified=bool(matches),
                confidence=0.5,
                status=baseline_status,
                headers=dict(baseline_resp.headers),
                body=baseline_body[:2000],
                diffs=[f"deser:{m}" for m in matches],
                baseline_body=baseline_body[:2000],
                baseline_status=baseline_status,
                verification_body=baseline_body[:2000],
                verification_status=baseline_status,
            )

        return None
