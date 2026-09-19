"""Deep Audit Prober — Automated exploitation-grade cloud service probing.

Orchestrates the deep audit: parses JavaScript for Firebase/Supabase
configs, hands off to the network probes in ``cloud_probes.py``, and
maps full attack chains from the collected findings.

Usage:
    from titan.modules.deep_audit.prober import DeepAuditor

    auditor = DeepAuditor()
    results = await auditor.audit("https://target.com")
"""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp

from titan.core.logger import get_logger
from titan.modules.deep_audit.cloud_probes import CloudProbes
from titan.modules.deep_audit.models import AuditFinding, AuditResult, CloudConfig

logger = get_logger("prober")

__all__ = ["AuditFinding", "AuditResult", "CloudConfig", "DeepAuditor"]


class DeepAuditor:
    """Automated deep auditor for Firebase/Supabase/cloud-backed sites."""

    # Data tables live on CloudProbes; aliased here because tests and
    # callers read them off the auditor instance.
    FIRESTORE_COLLECTION_NAMES = CloudProbes.FIRESTORE_COLLECTION_NAMES
    SENSITIVE_PATHS = CloudProbes.SENSITIVE_PATHS
    COMMON_JS_PATTERNS = CloudProbes.COMMON_JS_PATTERNS

    def __init__(self) -> None:
        self._cloud_probes = CloudProbes()

    async def audit(self, target: str, budget: float = 120.0, _session: Any = None) -> AuditResult:
        """Run a full deep audit against a target.

        Args:
            target: The target URL (e.g., "https://example.com")
            budget: Wall-clock budget in seconds
            _session: Pre-built session (test seam; default opens one)

        Returns:
            AuditResult with all findings, attack chains, and evidence.
        """
        t0 = time.time()
        result = AuditResult(target=target)
        deadline = t0 + budget

        try:
            import aiohttp
        except ImportError:
            result.findings.append(
                AuditFinding(
                    id="AUDIT-000",
                    severity="info",
                    title="aiohttp not installed",
                    description="Cannot run deep audit without aiohttp",
                    proof="ImportError: No module named 'aiohttp'",
                    impact="Audit cannot proceed",
                    remediation="pip install aiohttp",
                    category="dependency",
                )
            )
            return result

        session = _session
        if session is not None:
            await self._audit_phases(session, target, result, deadline)
        else:
            async with aiohttp.ClientSession() as new_session:
                await self._audit_phases(new_session, target, result, deadline)

        result.duration = time.time() - t0
        return result

    async def _audit_phases(self, session: Any, target: str, result: AuditResult, deadline: float) -> None:
        """Run the five audit phases against an open session."""
        # Phase 1: Parse JavaScript for cloud configs
        if time.time() < deadline:
            configs = await self._extract_cloud_configs(session, target)
            if configs:
                result.cloud_config = configs[0]
                for cfg in configs:
                    result.findings.extend(self._audit_cloud_config(cfg, target))

        # Phase 2: Probe sensitive files
        if time.time() < deadline:
            result.findings.extend(await self._probe_sensitive_files(session, target))

        # Phase 3: Probe cloud services
        if time.time() < deadline and result.cloud_config:
            cfg = result.cloud_config
            if cfg.provider == "firebase":
                result.findings.extend(await self._probe_firebase(session, cfg))
                result.collections = await self._enum_firestore(session, cfg)
            elif cfg.provider == "supabase":
                result.findings.extend(await self._probe_supabase(session, cfg))

        # Phase 4: Check security headers
        if time.time() < deadline:
            result.findings.extend(await self._check_security_headers(session, target))

        # Phase 5: Build attack chain
        result.attack_chain = self._build_attack_chain(result)
        result.positive_controls = self._build_positive_controls(result)

    async def _extract_cloud_configs(self, session: Any, target: str) -> list[CloudConfig]:
        """Parse JavaScript files for cloud service configurations."""
        configs = []

        try:
            async with session.get(target) as resp:
                html = await resp.text()
        except Exception:
            return configs

        # Find all script sources
        script_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)', html)

        # Also check common JS files
        common_js = [
            "/main.js",
            "/app.js",
            "/index.js",
            "/config.js",
            "/firebase-config.js",
            "/firebase.js",
            "/firebaseConfig.js",
            "/supabase.js",
            "/env.js",
            "/environment.js",
        ]
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for js in common_js:
            script_urls.append(base + js)

        # Fetch and parse each script
        for url in script_urls:
            if not url.startswith("http"):
                url = urljoin(target, url)
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        js = await resp.text()
                        configs.extend(self._parse_js_for_config(js, url))
            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        # Parse inline scripts from HTML
        inline_scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL)
        for js in inline_scripts:
            configs.extend(self._parse_js_for_config(js, target))

        return configs

    def _parse_js_for_config(self, js: str, source: str) -> list[CloudConfig]:
        """Extract cloud configs from JavaScript code."""
        configs = []

        # Firebase config
        firebase_match = re.search(r"firebaseConfig\s*=\s*\{([^}]+)\}", js)
        if firebase_match:
            config_str = firebase_match.group(1)
            cfg = CloudConfig(provider="firebase", raw={"source": source})

            api_key = re.search(r"apiKey[\"']?\s*:\s*[\"']([^\"']+)", config_str)
            if api_key:
                cfg.api_key = api_key.group(1)

            project_id = re.search(r"projectId[\"']?\s*:\s*[\"']([^\"']+)", config_str)
            if project_id:
                cfg.project_id = project_id.group(1)

            auth_domain = re.search(r"authDomain[\"']?\s*:\s*[\"']([^\"']+)", config_str)
            if auth_domain:
                cfg.auth_domain = auth_domain.group(1)

            storage_bucket = re.search(r"storageBucket[\"']?\s*:\s*[\"']([^\"']+)", config_str)
            if storage_bucket:
                cfg.storage_bucket = storage_bucket.group(1)

            if cfg.api_key or cfg.project_id:
                configs.append(cfg)

        # Supabase config
        supabase_match = re.search(r"supabase\.createClient\(", js)
        if supabase_match:
            # Extract the two string arguments
            args_str = js[supabase_match.end() : supabase_match.end() + 200]
            arg_matches = re.findall(r'"([^"]+)"', args_str)
            if len(arg_matches) >= 2:
                configs.append(
                    CloudConfig(
                        provider="supabase",
                        api_key=arg_matches[1],
                        raw={"url": arg_matches[0], "source": source},
                    )
                )

        # AWS keys
        aws_key = re.search(r"AKIA[0-9A-Z]{16}", js)
        if aws_key:
            configs.append(
                CloudConfig(
                    provider="aws",
                    api_key=aws_key.group(0),
                    raw={"source": source},
                )
            )

        # Stripe keys
        stripe_key = re.search(r"sk_live_[0-9a-zA-Z]+", js)
        if stripe_key:
            configs.append(
                CloudConfig(
                    provider="stripe",
                    api_key=stripe_key.group(0),
                    raw={"source": source},
                )
            )

        return configs

    def _audit_cloud_config(self, config: CloudConfig, target: str) -> list[AuditFinding]:
        """Generate findings from exposed cloud configs."""
        findings = []

        if config.provider == "firebase":
            findings.append(
                AuditFinding(
                    id="DEEP-FIREBASE-001",
                    severity="medium",
                    title="Firebase Config Exposed in Client-Side JavaScript",
                    description=(
                        f"Firebase configuration (API key: {config.api_key[:10]}..., "
                        f"project: {config.project_id}) is exposed in a JavaScript file. "
                        "While API keys are designed to be public in Firebase, they enable "
                        "direct access to Firebase services if Security Rules are misconfigured."
                    ),
                    proof=f"Source: {config.raw.get('source', 'unknown')}",
                    impact=(
                        "Attacker can use the API key to probe Firebase Auth, "
                        "Firestore, Storage, and Cloud Functions directly."
                    ),
                    remediation=(
                        "Ensure Firestore Security Rules require authentication. "
                        "Enable Firebase App Check for sensitive operations."
                    ),
                    category="misconfiguration",
                    verified=True,
                )
            )

            if config.project_id:
                findings.append(
                    AuditFinding(
                        id="DEEP-FIREBASE-002",
                        severity="info",
                        title=f"Firebase Project: {config.project_id}",
                        description=(
                            f"The Firebase project ID is {config.project_id}. "
                            "This enables enumeration of Firestore collections, "
                            "Firebase Auth, and Storage."
                        ),
                        proof=f"projectId: {config.project_id}",
                        impact="Attacker knows the exact Firebase project to target",
                        remediation="Use obfuscated project IDs or enable App Check",
                        category="information_disclosure",
                        verified=True,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Delegators to CloudProbes
    #
    # audit() dispatches these probes by attribute on self and tests
    # monkey-patch them on the auditor; the implementations live in
    # cloud_probes.py. _enum_firestore previously did not exist at all:
    # audit() called it whenever a Firebase config was found, so the
    # AttributeError (swallowed by the caller's except) silently ended
    # the deep audit. Defining it here fixes that call site.
    # ------------------------------------------------------------------

    async def _probe_sensitive_files(self, session: Any, target: str) -> list[AuditFinding]:
        """Delegate to CloudProbes (keeps the legacy attribute name)."""
        return await self._cloud_probes._probe_sensitive_files(session, target)

    async def _probe_firebase(self, session: Any, config: CloudConfig) -> list[AuditFinding]:
        """Delegate to CloudProbes (keeps the legacy attribute name)."""
        return await self._cloud_probes._probe_firebase(session, config)

    async def _probe_supabase(self, session: Any, config: CloudConfig) -> list[AuditFinding]:
        """Delegate to CloudProbes (keeps the legacy attribute name)."""
        return await self._cloud_probes._probe_supabase(session, config)

    async def _check_security_headers(self, session: Any, target: str) -> list[AuditFinding]:
        """Delegate to CloudProbes (keeps the legacy attribute name)."""
        return await self._cloud_probes._check_security_headers(session, target)

    async def _enum_firestore(self, session: Any, config: CloudConfig) -> list[dict[str, Any]]:
        """Delegate to CloudProbes.enum_firestore (legacy attribute name)."""
        return await self._cloud_probes.enum_firestore(session, config)

    def _build_attack_chain(self, result: AuditResult) -> list[str]:
        """Build a complete attack chain from findings."""
        chain = []
        categories = {f.category for f in result.findings}

        if "pii_exposure" in categories:
            chain.append("1. Read exposed data (PII, credentials, tokens)")

        if result.cloud_config and result.cloud_config.provider == "firebase":
            chain.append("2. Enumerate Firebase project structure")
            chain.append("3. Probe Firestore Security Rules")

        if any(f.category == "auth_bypass" for f in result.findings):
            chain.append("4. Obtain authentication token via bypass")

        if "misconfiguration" in categories:
            chain.append("5. Exploit missing security headers (XSS, clickjacking)")

        if any("sri" in f.title.lower() for f in result.findings):
            chain.append("6. Supply chain attack via compromised third-party script")

        if any(f.category == "auth_misconfiguration" for f in result.findings):
            chain.append("7. Abuse misconfigured authentication")

        chain.append("8. Exfiltrate data using obtained access")

        return chain

    def _build_positive_controls(self, result: AuditResult) -> list[str]:
        """List what's working correctly (positive controls)."""
        controls = []
        for f in result.findings:
            if f.category == "positive_control":
                controls.append(f"{f.title}: {f.description}")
        return controls

    def generate_test_suite(self, result: AuditResult) -> str:
        """Generate a pytest test suite from audit results."""
        lines = [
            '"""Auto-generated deep audit test suite."""',
            "",
            "import asyncio",
            "import aiohttp",
            "import pytest",
            "",
        ]

        verified_findings = [f for f in result.findings if f.verified]

        for finding in verified_findings:
            test_name = f"test_{finding.id.lower().replace('-', '_')}"
            lines.extend(
                [
                    f"class Test{finding.id.replace('-', '_')}:",
                    f'    """{finding.title}"""',
                    "",
                    "    @pytest.mark.asyncio",
                    f"    async def {test_name}(self):",
                    f'        """{finding.description}"""',
                    f"        # {finding.proof}",
                    "        async with aiohttp.ClientSession() as session:",
                    "            # TODO: Add live HTTP assertion",
                    "            pass",
                    "",
                ]
            )

        return "\n".join(lines)
