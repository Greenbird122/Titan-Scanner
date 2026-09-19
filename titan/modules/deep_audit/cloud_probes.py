"""Cloud service probes for the deep auditor: Firebase, Supabase,
sensitive files and security headers.

Split out of ``prober.py`` (where they were ~430 of its 826 lines).
Methods keep their original bodies, including the ``session`` handle
they were given, so the move stays behaviour-neutral.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import aiohttp

from titan.core.logger import get_logger
from titan.modules.deep_audit.models import AuditFinding, CloudConfig

logger = get_logger("cloud_probes")


class CloudProbes:
    """Network probes against cloud services; the data tables moved here."""

    FIRESTORE_COLLECTION_NAMES = [
        "users",
        "farmers",
        "alerts",
        "profiles",
        "sms_logs",
        "weather_data",
        "waitlist",
        "subscriptions",
        "notifications",
        "admin",
        "settings",
        "logs",
        "payments",
        "messaging",
        "conversations",
        "messages",
        "crops",
        "locations",
        "counties",
        "regions",
        "partners",
        "feedback",
        "surveys",
        "reports",
        "analytics",
        "config",
        "tokens",
        "devices",
        "sessions",
        "api_keys",
        "secrets",
        "invoices",
        "orders",
        "products",
        "marketplace",
        "forum",
        "posts",
        "comments",
        "threads",
        "consultations",
        "bookings",
        "appointments",
        "radio_stations",
        "saccos",
        "ngo_partners",
    ]

    SENSITIVE_PATHS = [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.env.development",
        "/.git/config",
        "/.git/HEAD",
        "/.gitignore",
        "/.well-known/security.txt",
        "/firebase.json",
        "/.firebaserc",
        "/firestore.rules",
        "/storage.rules",
        "/vercel.json",
        "/package.json",
        "/robots.txt",
        "/sitemap.xml",
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

    async def _probe_sensitive_files(self, session: Any, target: str) -> list[AuditFinding]:
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
                        findings.append(
                            AuditFinding(
                                id=f"DEEP-FILE-{path.replace('/', '-').strip('-')}",
                                severity="high" if ".env" in path or ".git" in path else "medium",
                                title=f"Sensitive File Exposed: {path}",
                                description=(
                                    f"The file {path} is publicly accessible with {len(body)} bytes of content."
                                ),
                                proof=f"GET {base + path} -> 200 ({len(body)} bytes)",
                                impact=("May contain secrets, credentials, or configuration information."),
                                remediation=f"Remove or restrict access to {path}",
                                category="information_disclosure",
                                verified=True,
                            )
                        )
            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        return findings

    async def _probe_firebase(self, session: Any, config: CloudConfig) -> list[AuditFinding]:
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
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        docs = data.get("documents", [])
                        accessible_collections.append(
                            {
                                "name": col,
                                "count": len(docs),
                                "fields": list(docs[0].get("fields", {}).keys()) if docs else [],
                            }
                        )
                        findings.append(
                            AuditFinding(
                                id=f"DEEP-FIRESTORE-{col.upper()}",
                                severity="critical"
                                if col
                                in (
                                    "users",
                                    "admin",
                                    "secrets",
                                    "api_keys",
                                    "tokens",
                                    "sessions",
                                )
                                else "high",
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
                                impact=("Attacker can read all data in this collection without authentication."),
                                remediation=(
                                    "Update Firestore Security Rules to require authentication for this collection."
                                ),
                                category="pii_exposure",
                                verified=True,
                                metadata={"collection": col, "doc_count": len(docs)},
                            )
                        )
                    elif resp.status == 403:
                        findings.append(
                            AuditFinding(
                                id=f"DEEP-FIRESTORE-{col.upper()}-DENIED",
                                severity="info",
                                title=f"Firestore Collection Exists (Denied): /{col}",
                                description=(f"The /{col} collection exists but access is denied."),
                                proof=(
                                    f"GET firestore.googleapis.com/v1/projects/"
                                    f"{config.project_id}/databases/(default)/"
                                    f"documents/{col}?key=... -> 403"
                                ),
                                impact="Collection exists but is protected",
                                remediation="N/A — access correctly denied",
                                category="information_disclosure",
                                verified=True,
                            )
                        )
            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        # 2. Firebase Auth probes
        auth_base = "https://identitytoolkit.googleapis.com/v1"

        # Password login check
        url = f"{auth_base}/accounts:signInWithPassword?key={config.api_key}"
        try:
            async with session.post(
                url,
                json={
                    "email": "test@test.com",
                    "password": "test",
                    "returnSecureToken": True,
                },
            ) as resp:
                data = await resp.json()
                err = data.get("error", {}).get("message", "")
                if "PASSWORD_LOGIN_DISABLED" in err:
                    findings.append(
                        AuditFinding(
                            id="DEEP-AUTH-PWD-DISABLED",
                            severity="info",
                            title="Firebase Auth: Password Login Disabled",
                            description="Email/password login is disabled.",
                            proof="signInWithPassword -> PASSWORD_LOGIN_DISABLED",
                            impact="Positive control — password brute force not possible",
                            remediation="N/A — correctly configured",
                            category="positive_control",
                            verified=True,
                        )
                    )
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        # Anonymous auth check
        url = f"{auth_base}/accounts:signUp?key={config.api_key}"
        try:
            async with session.post(
                url,
                json={
                    "returnSecureToken": True,
                },
            ) as resp:
                data = await resp.json()
                if resp.status == 200:
                    token = data.get("idToken", "")
                    findings.append(
                        AuditFinding(
                            id="DEEP-AUTH-ANONYMOUS",
                            severity="high",
                            title="Firebase Auth: Anonymous Authentication Enabled",
                            description=(
                                "Anonymous sign-up is enabled. Attacker can get "
                                "a valid Firebase ID token without credentials."
                            ),
                            proof=f"signUp (anonymous) -> 200, token: {token[:30]}...",
                            impact=(
                                "Attacker can authenticate and potentially access protected Firestore collections."
                            ),
                            remediation="Disable anonymous authentication in Firebase Console",
                            category="auth_misconfiguration",
                            verified=True,
                            metadata={"token_prefix": token[:30]},
                        )
                    )

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
                                    findings.append(
                                        AuditFinding(
                                            id=f"DEEP-AUTH-TOKEN-{col.upper()}",
                                            severity="critical",
                                            title=(f"Anonymous Token Grants Access to /{col}"),
                                            description=(
                                                f"A Firebase ID token obtained via anonymous "
                                                f"sign-up grants read access to /{col} "
                                                f"({len(docs)} documents)."
                                            ),
                                            proof=(f"Bearer token from anonymous sign-up -> 200 on /{col}"),
                                            impact=(
                                                "Attacker can read all data in this collection using anonymous auth."
                                            ),
                                            remediation=("Update Firestore Security Rules to reject anonymous tokens"),
                                            category="auth_bypass",
                                            verified=True,
                                        )
                                    )
                        except Exception as exc:
                            logger.debug(f"suppressed exception: {exc}")
                            pass
                else:
                    err = data.get("error", {}).get("message", "")
                    if "ADMIN_ONLY_OPERATION" in err:
                        findings.append(
                            AuditFinding(
                                id="DEEP-AUTH-ANON-DISABLED",
                                severity="info",
                                title="Firebase Auth: Anonymous Auth Disabled",
                                description="Anonymous sign-up is disabled.",
                                proof="signUp (anonymous) -> ADMIN_ONLY_OPERATION",
                                impact="Positive control — anonymous auth not possible",
                                remediation="N/A — correctly configured",
                                category="positive_control",
                                verified=True,
                            )
                        )
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        # 3. Firebase Storage probe
        url = f"https://firebasestorage.googleapis.com/v0/b/{config.storage_bucket}/o?key={config.api_key}"
        try:
            async with session.get(url) as resp:
                data = await resp.json()
                items = data.get("items", [])
                if items:
                    findings.append(
                        AuditFinding(
                            id="DEEP-STORAGE-EXPOSED",
                            severity="high",
                            title="Firebase Storage Objects Accessible",
                            description=(f"Firebase Storage contains {len(items)} accessible objects."),
                            proof=f"Storage listing -> {len(items)} objects",
                            impact="Attacker can download stored files",
                            remediation=("Update Firebase Storage Security Rules to require authentication"),
                            category="pii_exposure",
                            verified=True,
                        )
                    )
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        return findings

    async def _probe_supabase(self, session: Any, config: CloudConfig) -> list[AuditFinding]:
        """Deep probe Supabase services."""
        findings: list[AuditFinding] = []
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
            "users",
            "profiles",
            "orders",
            "products",
            "messages",
            "admin",
            "settings",
            "logs",
            "tokens",
        ]:
            url = f"{base}/rest/v1/{table}?select=*&limit=5"
            try:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=3),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data:
                            findings.append(
                                AuditFinding(
                                    id=f"DEEP-SUPABASE-{table.upper()}",
                                    severity="high",
                                    title=f"Supabase Table Accessible: {table}",
                                    description=(
                                        f"The {table} table is accessible via "
                                        f"the Supabase REST API. Contains "
                                        f"{len(data)} rows."
                                    ),
                                    proof=f"GET /rest/v1/{table} -> 200 ({len(data)} rows)",
                                    impact=("Attacker can read all data in this table."),
                                    remediation=("Enable Row Level Security (RLS) for this table."),
                                    category="pii_exposure",
                                    verified=True,
                                )
                            )
            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue

        return findings

    async def _check_security_headers(self, session: Any, target: str) -> list[AuditFinding]:
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
                missing = [name for header, name in required_headers.items() if header not in headers]
                if missing:
                    findings.append(
                        AuditFinding(
                            id="DEEP-HEADERS-MISSING",
                            severity="high",
                            title=f"Missing Security Headers: {', '.join(missing)}",
                            description=(
                                f"The target is missing {len(missing)} security headers: {', '.join(missing)}"
                            ),
                            proof=f"GET {target} -> missing headers: {missing}",
                            impact=(
                                "Increased risk of XSS, clickjacking, MIME sniffing, and other client-side attacks."
                            ),
                            remediation=("Add all missing security headers in your hosting configuration."),
                            category="misconfiguration",
                            verified=True,
                        )
                    )
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        return findings

    async def enum_firestore(
        self,
        session: Any,
        config: CloudConfig,
        collections: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Enumerate publicly-readable Firestore collections.

        This primitive existed only as a call site: ``DeepAuditor.audit``
        called ``self._enum_firestore`` although no such method was ever
        defined, so every audit that found a Firebase config crashed with
        AttributeError (silently swallowed by the caller's except). The
        loop is the same request sequence _probe_firebase performs, so
        the two stay consistent.
        """
        results: list[dict[str, Any]] = []
        names = collections if collections is not None else self.FIRESTORE_COLLECTION_NAMES
        for col in names:
            url = (
                f"https://firestore.googleapis.com/v1/projects/"
                f"{config.project_id}/databases/(default)/documents/"
                f"{col}?key={config.api_key}"
            )
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        docs = data.get("documents", [])
                        results.append(
                            {
                                "name": col,
                                "count": len(docs),
                                "fields": list(docs[0].get("fields", {}).keys()) if docs else [],
                            }
                        )
            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue
        return results
