"""Alternate injection surfaces for the SQLi detector.

Mixin for SQLiDetector: HTTP header injection and the nested JSON-body
AST walker. Both reuse the same finding shape and error-signature checks
as the core param oracle.
"""

from __future__ import annotations

import copy
import json
from typing import Any

from titan.core.logger import get_logger
from titan.core.models import AttackType, Finding, Severity
from titan.modules.sqli.signatures import (
    INJECTABLE_HEADERS as _INJECTABLE_HEADERS,
)
from titan.modules.sqli.signatures import (
    SQLI_ERROR_SIGNATURES as _SQLI_ERROR_SIGNATURES,
)
from titan.verify import BaselineAnalyzer

logger = get_logger("detector")


class SurfacesMixin:


    async def _scan_headers(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: dict[str, str],
        payloads: list[str],
    ) -> list[Finding]:
        """
        Many apps log raw headers straight into SQL without sanitization.
        Sends each payload in each high-risk header and applies the same
        differential oracles as param injection.
        """
        findings: list[Finding] = []
        safe_headers: dict[str, str] = {"Referer": target}

        # Baseline with clean headers
        try:
            if method == "GET":
                r0 = await context.request.get(url, params=params, headers=safe_headers, timeout=3000)
            else:
                r0 = await context.request.post(url, data=params, headers=safe_headers, timeout=3000)
            baseline_body = await r0.text()
            baseline_status = r0.status
        except Exception:
            return findings

        for header_name in _INJECTABLE_HEADERS:
            for payload in payloads[:20]:  # Top-20 per header to control budget
                try:
                    inject_headers = {**safe_headers, header_name: payload}
                    if method == "GET":
                        resp = await context.request.get(url, params=params, headers=inject_headers, timeout=3000)
                    else:
                        resp = await context.request.post(url, data=params, headers=inject_headers, timeout=3000)
                    body = await resp.text()

                    diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)
                    has_error = any(
                        s in body.lower() and s not in baseline_body.lower() for s in _SQLI_ERROR_SIGNATURES
                    )
                    if has_error:
                        for sig in _SQLI_ERROR_SIGNATURES:
                            if sig in body.lower() and sig not in baseline_body.lower():
                                diffs.append(f"error:{sig}")
                                break

                    if has_error or resp.status >= 500:
                        findings.append(
                            Finding(
                                target=target,
                                url=str(resp.url or url),
                                method=method.upper(),
                                param=header_name,
                                location="header",
                                payload=payload,
                                attack_type=AttackType.SQLI,
                                severity=Severity.HIGH,
                                verified=has_error,
                                confidence=0.75 if has_error else 0.40,
                                status=resp.status,
                                headers=dict(resp.headers),
                                body=body[:2000],
                                diffs=diffs,
                                baseline_body=baseline_body[:2000],
                                baseline_status=baseline_status,
                                verification_body=body[:2000],
                                verification_status=resp.status,
                                metadata={"injection_location": "http_header"},
                            )
                        )
                        break  # First confirmed payload per header is enough
                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue

        return findings


    async def _scan_json_body(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: dict[str, str],
        payloads: list[str],
    ) -> list[Finding]:
        """
        Recursively traverses a JSON body and injects each payload into every
        leaf string node. Non-destructive: injects one leaf at a time and
        restores the original value before moving to the next leaf.
        """
        findings: list[Finding] = []
        if method.upper() == "GET":
            return findings

        # Attempt to deserialize the body params as JSON
        body_str = next(iter(params.values()), "") if len(params) == 1 else ""
        if not body_str:
            try:
                body_str = json.dumps(params)
            except Exception:
                return findings

        try:
            tree = json.loads(body_str)
        except (json.JSONDecodeError, TypeError):
            return findings

        # Collect (path, value) for every string/numeric leaf
        leaves = list(self._json_leaves(tree))

        # Baseline with untampered JSON
        try:
            r0 = await context.request.post(
                url,
                data=json.dumps(tree),
                headers={"Content-Type": "application/json", "Referer": target},
                timeout=3000,
            )
            baseline_body = await r0.text()
            baseline_status = r0.status
        except Exception:
            return findings

        for path in leaves:
            for payload in payloads[:15]:
                try:
                    mutated = copy.deepcopy(tree)
                    self._json_set(mutated, path, payload)
                    resp = await context.request.post(
                        url,
                        data=json.dumps(mutated),
                        headers={"Content-Type": "application/json", "Referer": target},
                        timeout=3000,
                    )
                    body = await resp.text()

                    diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)
                    has_error = any(
                        s in body.lower() and s not in baseline_body.lower() for s in _SQLI_ERROR_SIGNATURES
                    )

                    if has_error:
                        for sig in _SQLI_ERROR_SIGNATURES:
                            if sig in body.lower() and sig not in baseline_body.lower():
                                diffs.append(f"error:{sig}")
                                break
                        findings.append(
                            Finding(
                                target=target,
                                url=str(resp.url or url),
                                method="POST",
                                param=".".join(str(p) for p in path),
                                location="json_body",
                                payload=payload,
                                attack_type=AttackType.SQLI,
                                severity=Severity.HIGH,
                                verified=True,
                                confidence=0.82,
                                status=resp.status,
                                headers=dict(resp.headers),
                                body=body[:2000],
                                diffs=diffs,
                                baseline_body=baseline_body[:2000],
                                baseline_status=baseline_status,
                                verification_body=body[:2000],
                                verification_status=resp.status,
                                metadata={"injection_location": "json_ast", "json_path": path},
                            )
                        )
                        break
                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue

        return findings


    def _json_leaves(self, node: Any, path: list | None = None):
        """Yield (path, value) for every string/int leaf in a nested JSON tree."""
        if path is None:
            path = []
        if isinstance(node, dict):
            for k, v in node.items():
                yield from self._json_leaves(v, path + [k])
        elif isinstance(node, list):
            for i, v in enumerate(node):
                yield from self._json_leaves(v, path + [i])
        elif isinstance(node, (str, int, float)):
            yield path


    def _json_set(self, tree: Any, path: list, value: Any) -> None:
        """Set a value at a given path in a nested JSON tree (in-place)."""
        node = tree
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
