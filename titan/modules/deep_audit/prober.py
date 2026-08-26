"""Deep Audit Prober — Automated exploitation-grade cloud service probing.

Parses JavaScript for Firebase/Supabase configs, probes cloud services
directly, tests Security Rules bypass, and maps full attack chains.

Usage:
    from titan.modules.deep_audit.prober import DeepAuditor
    
    auditor = DeepAuditor()
    results = await auditor.audit("https://target.com")
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


@dataclass
class CloudConfig:
    """Extracted cloud service configuration."""
    provider: str  # "firebase", "supabase", "aws"
    project_id: str = ""
    api_key: str = ""
    auth_domain: str = ""
    storage_bucket: str = ""
    messaging_sender_id: str = ""
    app_id: str = ""
    region: str = "us-central1"
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditFinding:
    """A finding from the deep audit."""
    id: str
    severity: str  # "critical", "high", "medium", "low", "info"
    title: str
    description: str
    proof: str  # HTTP request/response or code evidence
    impact: str
    remediation: str
    category: str  # "pii_exposure", "auth_bypass", "misconfiguration", etc.
    cvss: float = 0.0
    verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditResult:
    """Complete audit results."""
    target: str
    findings: List[AuditFinding] = field(default_factory=list)
    cloud_config: Optional[CloudConfig] = None
    collections: List[Dict[str, Any]] = field(default_factory=list)
    attack_chain: List[str] = field(default_factory=list)
    positive_controls: List[str] = field(default_factory=list)
    duration: float = 0.0


class DeepAuditor:
    """Automated deep auditor for Firebase/Supabase/cloud-backed sites."""

    FIRESTORE_COLLECTION_NAMES = [
        "users", "farmers", "alerts", "profiles", "sms_logs", "weather_data",
        "waitlist", "subscriptions", "notifications", "admin", "settings",
        "logs", "payments", "messaging", "conversations", "messages",
        "crops", "locations", "counties", "regions", "partners",
        "feedback", "surveys", "reports", "analytics", "config",
        "tokens", "devices", "sessions", "api_keys", "secrets",
        "invoices", "orders", "products", "marketplace", "forum",
        "posts", "comments", "threads", "consultations", "bookings",
        "appointments", "radio_stations", "saccos", "ngo_partners",
    ]

    SENSITIVE_PATHS = [
        "/.env", "/.env.local", "/.env.production", "/.env.development",
        "/.git/config", "/.git/HEAD", "/.gitignore",
        "/.well-known/security.txt", "/firebase.json", "/.firebaserc",
        "/firestore.rules", "/storage.rules", "/vercel.json",
        "/package.json", "/robots.txt", "/sitemap.xml",
    ]

    COMMON_JS_PATTERNS = [
        r"firebaseConfig\s*=\s*\{([^}]+)\}",
        r"apiKey[\"']?\s*:\s*[\"']([^\"']+)",
        r"projectId[\"']?\s*:\s*[\"']([^\"']+)",
        r"authDomain[\"']?\s*:\s*[\"']([^\"']+)",
        r"storageBucket[\"']?\s*:\s*[\"']([^\"']+)",
        r"supabase\.createClient\([\"']([^\"']+)[\"'],\s*[\"']([^\"']+)",
        r"NEXT_PUBLIC_SUPABASE_URL[\"']?\s*:\s*[\"']([^\"']+)",
        r"AKIA[0-9A-Z]{16}",
        r"sk_live_[0-9a-zA-Z]+",
        r"pk_live_[0-9a-zA-Z]+",
    ]

    async def audit(self, target: str, budget: float = 120.0) -> AuditResult:
        """Run a full deep audit against a target.

        Args:
            target: The target URL (e.g., "https://example.com")
            budget: Wall-clock budget in seconds

        Returns:
            AuditResult with all findings, attack chains, and evidence.
        """
        t0 = time.time()
        result = AuditResult(target=target)
        deadline = t0 + budget

        try:
            import aiohttp
        except ImportError:
            result.findings.append(AuditFinding(
                id="AUDIT-000",
                severity="info",
                title="aiohttp not installed",
                description="Cannot run deep audit without aiohttp",
                proof="ImportError: No module named 'aiohttp'",
                impact="Audit cannot proceed",
                remediation="pip install aiohttp",
                category="dependency",
            ))
            return result

        async with aiohttp.ClientSession() as session:
            # Phase 1: Parse JavaScript for cloud configs
            if time.time() < deadline:
                configs = await self._extract_cloud_configs(session, target)
                if configs:
                    result.cloud_config = configs[0]
                    for cfg in configs:
                        result.findings.extend(
                            self._audit_cloud_config(cfg, target)
                        )

            # Phase 2: Probe sensitive files
            if time.time() < deadline:
                result.findings.extend(
                    await self._probe_sensitive_files(session, target)
                )

            # Phase 3: Probe cloud services
            if time.time() < deadline and result.cloud_config:
                cfg = result.cloud_config
                if cfg.provider == "firebase":
                    result.findings.extend(
                        await self._probe_firebase(session, cfg)
                    )
                    result.collections = await self._enum_firestore(
                        session, cfg
                    )
                elif cfg.provider == "supabase":
                    result.findings.extend(
                        await self._probe_supabase(session, cfg)
                    )

            # Phase 4: Check security headers
            if time.time() < deadline:
                result.findings.extend(
                    await self._check_security_headers(session, target)
                )

            # Phase 5: Build attack chain
            result.attack_chain = self._build_attack_chain(result)
            result.positive_controls = self._build_positive_controls(result)

        result.duration = time.time() - t0
        return result

    async def _extract_cloud_configs(
        self, session: Any, target: str
    ) -> List[CloudConfig]:
        """Parse JavaScript files for cloud service configurations."""
        configs = []

        try:
            async with session.get(target) as resp:
                html = await resp.text()
        except Exception:
            return configs

        # Find all script sources
        script_urls = re.findall(
            r'src=["\']([^"\']+\.js[^"\']*)', html
        )

        # Also check common JS files
        common_js = [
            "/main.js", "/app.js", "/index.js", "/config.js",
            "/firebase-config.js", "/firebase.js", "/firebaseConfig.js",
            "/supabase.js", "/env.js", "/environment.js",
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
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 200:
                        js = await resp.text()
                        configs.extend(self._parse_js_for_config(js, url))
            except Exception:
                continue

        # Parse inline scripts from HTML
        inline_scripts = re.findall(
            r"<script[^>]*>(.*?)</script>", html, re.DOTALL
        )
        for js in inline_scripts:
            configs.extend(self._parse_js_for_config(js, target))

        return configs

    def _parse_js_for_config(
        self, js: str, source: str
    ) -> List[CloudConfig]:
        """Extract cloud configs from JavaScript code."""
        configs = []

        # Firebase config
        firebase_match = re.search(
            r"firebaseConfig\s*=\s*\{([^}]+)\}", js
        )
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
        supabase_match = re.search(
            r'supabase\.createClient\(',
            js
        )
        if supabase_match:
            # Extract the two string arguments
            args_str = js[supabase_match.end():supabase_match.end()+200]
            arg_matches = re.findall(r'"([^"]+)"', args_str)
            if len(arg_matches) >= 2:
                configs.append(CloudConfig(
                    provider="supabase",
                    api_key=arg_matches[1],
                    raw={"url": arg_matches[0], "source": source},
                ))

        # AWS keys
        aws_key = re.search(r"AKIA[0-9A-Z]{16}", js)
        if aws_key:
            configs.append(CloudConfig(
                provider="aws",
                api_key=aws_key.group(0),
                raw={"source": source},
            ))

        # Stripe keys
        stripe_key = re.search(r"sk_live_[0-9a-zA-Z]+", js)
        if stripe_key:
            configs.append(CloudConfig(
                provider="stripe",
                api_key=stripe_key.group(0),
                raw={"source": source},
            ))

        return configs

    def _audit_cloud_config(
        self, config: CloudConfig, target: str
    ) -> List[AuditFinding]:
        """Generate findings from exposed cloud configs."""
        findings = []

        if config.provider == "firebase":
            findings.append(AuditFinding(
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
            ))

            if config.project_id:
                findings.append(AuditFinding(
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
                ))

        return findings

    async def _probe_sensitive_files(
        self, session: Any, target: str
    ) -> List[AuditFinding]:
        """Probe for exposed sensitive files."""
        findings = []
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.SENSITIVE_PATHS:
            try:
                async with session.get(
                    base + path,
                    timeout=aiohttp.ClientTimeout(total=3),
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        findings.append(AuditFinding(
                            id=f"DEEP-FILE-{path.replace('/', '-').strip('-')}",
                            severity="high" if ".env" in path or ".git" in path else "medium",
                            title=f"Sensitive File Exposed: {path}",
                            description=(
                                f"The file {path} is publicly accessible with "
                                f"{len(body)} bytes of content."
                            ),
                            proof=f"GET {base + path} -> 200 ({len(body)} bytes)",
                            impact=(
                                "May contain secrets, credentials, or "
                                "configuration information."
                            ),
                            remediation=f"Remove or restrict access to {path}",
                            category="information_disclosure",
                            verified=True,
                        ))
            except Exception:
                continue

        return findings

    async def _probe_firebase(
        self, session: Any, config: CloudConfig
    ) -> List[AuditFinding]:
        """Deep probe Firebase services."""
        findings = []

        # 1. Firestore collection enumeration
        accessible_collections = []
        for col in self.FIRESTORE_COLLECTION_NAMES:
            url = (
                f"https://firestore.googleapis.com/v1/projects/"
                f"{config.project_id}/databases/(default)/documents/"
                f"{col}?key={config.api_key}"
            )
            try:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=3)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        docs = data.get("documents", [])
                        accessible_collections.append({
                            "name": col,
                            "count": len(docs),
                            "fields": list(
                                docs[0].get("fields", {}).keys()
                            ) if docs else [],
                        })
                        findings.append(AuditFinding(
                            id=f"DEEP-FIRESTORE-{col.upper()}",
                            severity="critical" if col in (
                                "users", "admin", "secrets", "api_keys",
                                "tokens", "sessions",
                            ) else "high",
                            title=f"Firestore Collection Publicly Accessible: /{col}",
                            description=(
                                f"The /{col} collection is accessible without "
                                f"authentication. Contains {len(docs)} documents."
                            ),
                            proof=(
                                f"GET firestore.googleapis.com/v1/projects/"
                                f"{config.project_id}/databases/(default)/"
                                f"documents/{col}?key=... -> 200"
                            ),
                            impact=(
                                "Attacker can read all data in this collection "
                                "without authentication."
                            ),
                            remediation=(
                                "Update Firestore Security Rules to require "
                                "authentication for this collection."
                            ),
                            category="pii_exposure",
                            verified=True,
                            metadata={"collection": col, "doc_count": len(docs)},
                        ))
                    elif resp.status == 403:
                        findings.append(AuditFinding(
                            id=f"DEEP-FIRESTORE-{col.upper()}-DENIED",
                            severity="info",
                            title=f"Firestore Collection Exists (Denied): /{col}",
                            description=(
                                f"The /{col} collection exists but access is denied."
                            ),
                            proof=(
                                f"GET firestore.googleapis.com/v1/projects/"
                                f"{config.project_id}/databases/(default)/"
                                f"documents/{col}?key=... -> 403"
                            ),
                            impact="Collection exists but is protected",
                            remediation="N/A — access correctly denied",
                            category="information_disclosure",
                            verified=True,
                        ))
            except Exception:
                continue

        # 2. Firebase Auth probes
        auth_base = "https://identitytoolkit.googleapis.com/v1"

        # Password login check
        url = f"{auth_base}/accounts:signInWithPassword?key={config.api_key}"
        try:
            async with session.post(url, json={
                "email": "test@test.com",
                "password": "test",
                "returnSecureToken": True,
            }) as resp:
                data = await resp.json()
                err = data.get("error", {}).get("message", "")
                if "PASSWORD_LOGIN_DISABLED" in err:
                    findings.append(AuditFinding(
                        id="DEEP-AUTH-PWD-DISABLED",
                        severity="info",
                        title="Firebase Auth: Password Login Disabled",
                        description="Email/password login is disabled.",
                        proof=f"signInWithPassword -> PASSWORD_LOGIN_DISABLED",
                        impact="Positive control — password brute force not possible",
                        remediation="N/A — correctly configured",
                        category="positive_control",
                        verified=True,
                    ))
        except Exception:
            pass

        # Anonymous auth check
        url = f"{auth_base}/accounts:signUp?key={config.api_key}"
        try:
            async with session.post(url, json={
                "returnSecureToken": True,
            }) as resp:
                data = await resp.json()
                if resp.status == 200:
                    token = data.get("idToken", "")
                    findings.append(AuditFinding(
                        id="DEEP-AUTH-ANONYMOUS",
                        severity="high",
                        title="Firebase Auth: Anonymous Authentication Enabled",
                        description=(
                            "Anonymous sign-up is enabled. Attacker can get "
                            "a valid Firebase ID token without credentials."
                        ),
                        proof=f"signUp (anonymous) -> 200, token: {token[:30]}...",
                        impact=(
                            "Attacker can authenticate and potentially access "
                            "protected Firestore collections."
                        ),
                        remediation="Disable anonymous authentication in Firebase Console",
                        category="auth_misconfiguration",
                        verified=True,
                        metadata={"token_prefix": token[:30]},
                    ))

                    # Test token against Firestore
                    for col in ["users", "admin", "secrets", "marketplace"]:
                        furl = (
                            f"https://firestore.googleapis.com/v1/projects/"
                            f"{config.project_id}/databases/(default)/documents/"
                            f"{col}?key={config.api_key}"
                        )
                        try:
                            async with session.get(
                                furl,
                                headers={"Authorization": f"Bearer {token}"},
                                timeout=aiohttp.ClientTimeout(total=3),
                            ) as fresp:
                                if fresp.status == 200:
                                    fdata = await fresp.json()
                                    docs = fdata.get("documents", [])
                                    findings.append(AuditFinding(
                                        id=f"DEEP-AUTH-TOKEN-{col.upper()}",
                                        severity="critical",
                                        title=(
                                            f"Anonymous Token Grants Access to /{col}"
                                        ),
                                        description=(
                                            f"A Firebase ID token obtained via anonymous "
                                            f"sign-up grants read access to /{col} "
                                            f"({len(docs)} documents)."
                                        ),
                                        proof=(
                                            f"Bearer token from anonymous sign-up -> "
                                            f"200 on /{col}"
                                        ),
                                        impact=(
                                            "Attacker can read all data in this "
                                            "collection using anonymous auth."
                                        ),
                                        remediation=(
                                            "Update Firestore Security Rules to "
                                            "reject anonymous tokens"
                                        ),
                                        category="auth_bypass",
                                        verified=True,
                                    ))
                        except Exception:
                            pass
                else:
                    err = data.get("error", {}).get("message", "")
                    if "ADMIN_ONLY_OPERATION" in err:
                        findings.append(AuditFinding(
                            id="DEEP-AUTH-ANON-DISABLED",
                            severity="info",
                            title="Firebase Auth: Anonymous Auth Disabled",
                            description="Anonymous sign-up is disabled.",
                            proof=f"signUp (anonymous) -> ADMIN_ONLY_OPERATION",
                            impact="Positive control — anonymous auth not possible",
                            remediation="N/A — correctly configured",
                            category="positive_control",
                            verified=True,
                        ))
        except Exception:
            pass

        # 3. Firebase Storage probe
        url = (
            f"https://firebasestorage.googleapis.com/v0/b/"
            f"{config.storage_bucket}/o?key={config.api_key}"
        )
        try:
            async with session.get(url) as resp:
                data = await resp.json()
                items = data.get("items", [])
                if items:
                    findings.append(AuditFinding(
                        id="DEEP-STORAGE-EXPOSED",
                        severity="high",
                        title="Firebase Storage Objects Accessible",
                        description=(
                            f"Firebase Storage contains {len(items)} "
                            "accessible objects."
                        ),
                        proof=f"Storage listing -> {len(items)} objects",
                        impact="Attacker can download stored files",
                        remediation=(
                            "Update Firebase Storage Security Rules to "
                            "require authentication"
                        ),
                        category="pii_exposure",
                        verified=True,
                    ))
        except Exception:
            pass

        return findings

    async def _probe_supabase(
        self, session: Any, config: CloudConfig
    ) -> List[AuditFinding]:
        """Deep probe Supabase services."""
        findings = []
        base = config.raw.get("url", "")
        key = config.api_key

        if not base:
            return findings

        # REST API probe
        headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
        }

        # Try common tables
        for table in [
            "users", "profiles", "orders", "products", "messages",
            "admin", "settings", "logs", "tokens",
        ]:
            url = f"{base}/rest/v1/{table}?select=*&limit=5"
            try:
                async with session.get(
                    url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=3),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data:
                            findings.append(AuditFinding(
                                id=f"DEEP-SUPABASE-{table.upper()}",
                                severity="high",
                                title=f"Supabase Table Accessible: {table}",
                                description=(
                                    f"The {table} table is accessible via "
                                    f"the Supabase REST API. Contains "
                                    f"{len(data)} rows."
                                ),
                                proof=f"GET /rest/v1/{table} -> 200 ({len(data)} rows)",
                                impact=(
                                    "Attacker can read all data in this table."
                                ),
                                remediation=(
                                    "Enable Row Level Security (RLS) for "
                                    "this table."
                                ),
                                category="pii_exposure",
                                verified=True,
                            ))
            except Exception:
                continue

        return findings

    async def _check_security_headers(
        self, session: Any, target: str
    ) -> List[AuditFinding]:
        """Check for missing security headers."""
        findings = []

        required_headers = {
            "strict-transport-security": "HSTS",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "content-security-policy": "Content-Security-Policy",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
        }

        try:
            async with session.get(target) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                missing = [
                    name for header, name in required_headers.items()
                    if header not in headers
                ]
                if missing:
                    findings.append(AuditFinding(
                        id="DEEP-HEADERS-MISSING",
                        severity="high",
                        title=f"Missing Security Headers: {', '.join(missing)}",
                        description=(
                            f"The target is missing {len(missing)} security "
                            f"headers: {', '.join(missing)}"
                        ),
                        proof=f"GET {target} -> missing headers: {missing}",
                        impact=(
                            "Increased risk of XSS, clickjacking, "
                            "MIME sniffing, and other client-side attacks."
                        ),
                        remediation=(
                            "Add all missing security headers in your "
                            "hosting configuration."
                        ),
                        category="misconfiguration",
                        verified=True,
                    ))
        except Exception:
            pass

        return findings

    def _build_attack_chain(self, result: AuditResult) -> List[str]:
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

    def _build_positive_controls(self, result: AuditResult) -> List[str]:
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
            lines.extend([
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
            ])

        return "\n".join(lines)
