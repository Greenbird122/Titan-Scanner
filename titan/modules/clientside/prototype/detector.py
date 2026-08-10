"""Client-side prototype pollution detection — browser-context module (Track A).

Injects a unique marker into the prototype chain via a JSON-parsed payload
(JSON.parse, deep-merge, query-string object builds are the classic polluters)
and checks whether a fresh plain object inherited the marker. The oracle: the
marker is present on ``Object.prototype`` AFTER the probe but was absent
before — a fresh object ``{}`` inheriting an attacker-set property is a
verified pollution.

A page that sanitizes __proto__ / constructor keys, or that never merges the
injected payload, produces no finding.
"""

from __future__ import annotations

import secrets
from typing import Any, Dict, List
from urllib.parse import urlencode, urlparse, urlunparse

from titan.core.models import Finding, Severity, AttackType

# True if any object in the chain has the marker (i.e. it survived into the
# prototype). Read AFTER the probe payload is processed by the app.
POLLUTION_READ_JS = """
(marker) => {
  try {
    const fresh = {};
    return fresh[marker] !== undefined ? String(fresh[marker]) : null;
  } catch (e) { return null; }
}
"""

# Payload shapes: __proto__ via JSON is the canonical client-side polluter.
# The marker name carries a nonce so a clean page can never contain it.
PROBE_KEYS = ["__proto__", "constructor.prototype"]


class PrototypePollutionDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, page, target: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []
        marker = "titanpp" + secrets.token_hex(6)
        probe_value = "polluted_" + marker

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=15000)

            # Probe 1: __proto__ as a query param (apps that build objects
            # from query strings / merge params are the classic sink).
            for key in PROBE_KEYS:
                try:
                    probe_url = self._with_nested_param(url, key, marker, probe_value)
                    await page.goto(probe_url, wait_until="domcontentloaded", timeout=12000)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=2000)
                    except Exception:
                        pass
                    hit = await page.evaluate(POLLUTION_READ_JS, marker)
                    if hit is not None:
                        findings.append(self._finding(target, str(page.url or url), key, marker, probe_value, "query"))
                        return findings
                except Exception:
                    continue

            # Probe 2: JSON body via a fetch to a captured API (apps that
            # JSON.parse untrusted input into a merge).
            api_url = await self._find_api_url(page, url)
            if api_url:
                try:
                    body = {"name": "test", PROBE_KEYS[0]: {marker: probe_value}}
                    await page.evaluate(
                        """(arg) => fetch(arg.url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(arg.body)}).catch(() => {})""",
                        {"url": api_url, "body": body},
                    )
                    await page.wait_for_timeout(500)
                    hit = await page.evaluate(POLLUTION_READ_JS, marker)
                    if hit is not None:
                        findings.append(self._finding(target, str(page.url or url), PROBE_KEYS[0], marker, probe_value, "json"))
                except Exception:
                    pass
        except Exception:
            return findings
        return findings

    async def _find_api_url(self, page, base_url: str) -> str:
        try:
            urls = await page.evaluate(
                """() => {
                    const out = [];
                    for (const a of document.querySelectorAll('a[href], form[action]')) {
                        out.push(a.href || a.action || '');
                    }
                    return out.filter(u => /api\\/|\\/v1\\/|\\/v2\\/|graphql/.test(u)).slice(0, 5);
                }"""
            )
            for u in urls or []:
                if u.startswith("http"):
                    return u
        except Exception:
            pass
        return ""

    @staticmethod
    def _with_nested_param(url: str, key: str, marker: str, value: str) -> str:
        parsed = urlparse(url)
        query = parsed.query
        encoded = urlencode({f"{key}[{marker}]": value})
        if query:
            query += "&" + encoded
        else:
            query = encoded
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

    def _finding(self, target, url, key, marker, probe_value, location) -> Finding:
        return Finding(
            target=target,
            url=url,
            method="GET" if location == "query" else "POST",
            param=key,
            location=location,
            payload=f"Client-side prototype pollution via {key}: marker inherited by fresh object",
            attack_type=AttackType.PROTO_POLLUTION,
            severity=Severity.HIGH,
            verified=True,
            confidence=0.85,
            status=200,
            body=probe_value[:2000],
            diffs=[f"proto:marker_inherited:{marker}", f"proto:key:{key}", f"proto:location:{location}"],
            verification_body=probe_value[:2000],
            verification_status=200,
            metadata={"marker": marker, "key": key},
        )
