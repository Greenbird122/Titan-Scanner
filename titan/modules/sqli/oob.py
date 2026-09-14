"""Out-of-band (OAST) SQLi engine for the SQLi detector.

Mixin for SQLiDetector: dialect-specific DNS/HTTP callback payloads via
Interactsh, fire-and-poll confirmation for async/background SQLi sinks.
"""

from __future__ import annotations

import asyncio

from titan.core.logger import get_logger
from titan.core.models import AttackType, Finding, Severity
from titan.modules.sqli.signatures import (
    OOB_TEMPLATES as _OOB_TEMPLATES,
)

logger = get_logger("detector")


class OobMixin:


    async def _scan_oob(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: dict[str, str],
    ) -> list[Finding]:
        """
        Send out-of-band payloads for async/background SQLi sinks.
        Fires dialect-specific DNS/HTTP callbacks via Interactsh and polls
        for a hit. If no Interactsh is configured, returns empty.
        """
        findings: list[Finding] = []
        try:
            from titan.integrations.interactsh import InteractshClient

            client = InteractshClient()
            registered = await client.register()
            if not registered:
                return findings
        except Exception:
            return findings

        domain = client.correlation_id + ".interactsh.com"

        for dialect, templates in _OOB_TEMPLATES.items():
            for template in templates:
                payload = template.format(domain=domain)
                for param_name in list(params.keys()):
                    try:
                        test_params = dict(params)
                        test_params[param_name] = payload
                        if method == "GET":
                            await context.request.get(url, params=test_params, timeout=5000)
                        else:
                            await context.request.post(url, data=test_params, timeout=5000)
                    except Exception as exc:
                        logger.debug(f"suppressed exception: {exc}")
                        pass

        # Wait for OOB callbacks
        try:
            await asyncio.sleep(8)
            interactions = await client.poll(timeout=15)
        except Exception:
            interactions = []

        if interactions:
            findings.append(
                Finding(
                    target=target,
                    url=url,
                    method=method.upper(),
                    param="oob_callback",
                    location="oob",
                    payload=f"oob_domain={domain}",
                    attack_type=AttackType.SQLI,
                    severity=Severity.CRITICAL,
                    verified=True,
                    confidence=0.95,
                    status=None,
                    diffs=[f"oob_interaction:{i.get('protocol', 'dns')}" for i in interactions[:3]],
                    metadata={
                        "oob_domain": domain,
                        "interactions": interactions[:5],
                        "injection_location": "oob_dns",
                    },
                )
            )

        try:
            await client.deregister()
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        return findings
