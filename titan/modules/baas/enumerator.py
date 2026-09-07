"""BaaS Enumeration Engine — auto-detect platform and select appropriate module.

This module:
1. Auto-detects which BaaS is used (Supabase, Firebase, AppWrite, Clerk, Auth0)
2. Extracts API keys, project IDs, endpoints from page source
3. Enumerates tables, collections, buckets, functions
4. Selects and runs appropriate testing modules
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from titan.core.models import AttackType, Finding, Severity


@dataclass
class BaasFingerprint:
    """Detected BaaS platform information."""
    platform: str  # "supabase", "firebase", "appwrite", "clerk", "auth0", "unknown"
    confidence: float
    endpoint: str | None = None
    api_key: str | None = None
    project_id: str | None = None
    region: str | None = None
    tables: list[str] = field(default_factory=list)
    buckets: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    collections: list[str] = field(default_factory=list)
    auth_config: dict[str, Any] = field(default_factory=dict)
    raw_detection: str = ""


class BaaSEnumerator:
    """Auto-detect and enumerate BaaS platforms."""

    # ── Detection Patterns ──────────────────────────────────────────────

    SUPABASE_PATTERNS = [
        (r"supabase\.co", "supabase", 0.95),
        (r"supabase\.net", "supabase", 0.90),
        (r"sbp_[a-zA-Z0-9]+", "supabase_anon_key", 0.85),
        (r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.*supabase", "supabase_jwt", 0.80),
        (r"createClient\s*\([^)]*supabase", "supabase_client", 0.85),
        (r"@supabase/supabase-js", "supabase_js", 0.90),
        (r"supabaseUrl|supabaseKey", "supabase_config", 0.85),
        (r"NEXT_PUBLIC_SUPABASE", "supabase_env", 0.90),
        (r"supabase\.from\(", "supabase_query", 0.80),
    ]

    FIREBASE_PATTERNS = [
        (r"firebase\.app", "firebase", 0.95),
        (r"firebaseio\.com", "firebase_realtime", 0.90),
        (r"firestore\.googleapis\.com", "firebase_firestore", 0.90),
        (r"firebase\.js", "firebase_js", 0.85),
        (r"initializeApp\s*\(", "firebase_init", 0.80),
        (r"firebaseConfig", "firebase_config", 0.85),
        (r"FIREBASE_", "firebase_env", 0.90),
        (r"identitytoolkit", "firebase_auth", 0.85),
        (r"projectId.*[a-z]+-[a-z0-9]+", "firebase_project", 0.70),
    ]

    APPWRITE_PATTERNS = [
        (r"appwrite\.io", "appwrite", 0.95),
        (r"appwrite\.org", "appwrite", 0.90),
        (r"X-Appwrite-Key", "appwrite_key", 0.85),
        (r"X-Appwrite-Project", "appwrite_project", 0.85),
        (r"createClient\s*\([^)]*appwrite", "appwrite_client", 0.80),
        (r"@appwrite/sdk", "appwrite_sdk", 0.90),
        (r"APPWRITE_", "appwrite_env", 0.90),
        (r"appwrite\.endpoint", "appwrite_endpoint", 0.85),
    ]

    CLERK_PATTERNS = [
        (r"clerk\.com", "clerk", 0.95),
        (r"clerk\.dev", "clerk", 0.90),
        (r"pk_[a-zA-Z0-9]+", "clerk_publishable_key", 0.85),
        (r"sk_[a-zA-Z0-9]+", "clerk_secret_key", 0.85),
        (r"@clerk/clerk-react", "clerk_react", 0.90),
        (r"@clerk/nextjs", "clerk_nextjs", 0.90),
        (r"CLERK_", "clerk_env", 0.90),
        (r"clerk\.frontendApi", "clerk_frontend", 0.85),
        (r"clerk\.publishableKey", "clerk_key", 0.85),
    ]

    AUTH0_PATTERNS = [
        (r"auth0\.com", "auth0", 0.95),
        (r"auth0\.com/api/v2", "auth0_api", 0.90),
        (r"AUTH0_", "auth0_env", 0.90),
        (r"auth0Client", "auth0_client", 0.85),
        (r"@auth0/auth0-react", "auth0_react", 0.90),
        (r"AUTH0_DOMAIN|AUTH0_CLIENT_ID", "auth0_config", 0.85),
    ]

    # ── Common Table/Collection Names ───────────────────────────────────

    COMMON_TABLES = [
        "users", "user", "accounts", "profiles", "profile",
        "orders", "order", "products", "product", "items",
        "payments", "payment", "invoices", "invoice",
        "sessions", "session", "tokens", "token",
        "messages", "message", "comments", "comment",
        "posts", "post", "articles", "article",
        "files", "file", "uploads", "upload",
        "settings", "setting", "config", "configuration",
        "admin", "admins", "roles", "role",
        "teams", "team", "organizations", "organization",
        "subscriptions", "subscription", "plans", "plan",
        "credits", "credit", "balances", "balance",
    ]

    COMMON_BUCKETS = [
        "avatars", "avatar", "images", "image", "photos", "photo",
        "documents", "document", "files", "file", "uploads", "upload",
        "public", "private", "media", "assets", "static",
    ]

    COMMON_FUNCTIONS = [
        "send-email", "sendEmail", "send_email",
        "process-payment", "processPayment", "process_payment",
        "create-user", "createUser", "create_user",
        "delete-user", "deleteUser", "delete_user",
        "generate-report", "generateReport", "generate_report",
        "webhook", "callback", "notify", "notification",
        "upload", "download", "export", "import",
        "admin", "dashboard", "analytics",
    ]

    def __init__(self, context: Any = None):
        self.context = context
        self._fingerprints: list[BaasFingerprint] = []

    async def enumerate(self, target_url: str, page_source: str = "") -> list[BaasFingerprint]:
        """Full BaaS enumeration pipeline."""
        self._fingerprints = []

        # Phase 1: Detect from page source
        if page_source:
            self._detect_from_source(page_source, target_url)

        # Phase 2: Detect from headers/API responses
        await self._detect_from_headers(target_url)

        # Phase 3: Detect from JavaScript bundles
        await self._detect_from_js(target_url)

        # Phase 4: Enumerate common resources
        for fp in self._fingerprints:
            await self._enumerate_resources(fp)

        return self._fingerprints

    def _detect_from_source(self, source: str, target_url: str):
        """Detect BaaS from page source."""
        all_patterns = [
            *self.SUPABASE_PATTERNS,
            *self.FIREBASE_PATTERNS,
            *self.APPWRITE_PATTERNS,
            *self.CLERK_PATTERNS,
            *self.AUTH0_PATTERNS,
        ]

        for pattern, detection_type, confidence in all_patterns:
            matches = re.findall(pattern, source, re.IGNORECASE)
            if matches:
                # Determine platform
                platform = detection_type.split("_")[0]
                if platform not in ("supabase", "firebase", "appwrite", "clerk", "auth0"):
                    platform = detection_type

                # Check if we already have this platform
                existing = next((f for f in self._fingerprints if f.platform == platform), None)
                if existing:
                    existing.confidence = max(existing.confidence, confidence)
                    existing.raw_detection += f" | {detection_type}: {matches[0][:50]}"
                else:
                    self._fingerprints.append(BaasFingerprint(
                        platform=platform,
                        confidence=confidence,
                        raw_detection=f"{detection_type}: {matches[0][:100]}",
                    ))

        # Extract API keys from source
        key_patterns = [
            (r"sbp_[a-zA-Z0-9]{30,}", "supabase", "api_key"),
            (r"pk_[a-zA-Z0-9]{30,}", "clerk", "publishable_key"),
            (r"sk_[a-zA-Z0-9]{30,}", "clerk", "secret_key"),
            (r"AIza[a-zA-Z0-9_-]{35}", "firebase", "api_key"),
            (r"eyJ[a-zA-Z0-9_-]{100,}", "jwt", "token"),
        ]

        for pattern, platform, key_type in key_patterns:
            matches = re.findall(pattern, source)
            for match in matches:
                fp = next((f for f in self._fingerprints if f.platform == platform), None)
                if fp and not fp.api_key:
                    fp.api_key = match

        # Extract endpoints
        endpoint_patterns = [
            (r"https://([a-z0-9]+)\.supabase\.co", "supabase", "endpoint"),
            (r"https://[a-z0-9]+\.firebaseio\.com", "firebase", "realtime_url"),
            (r"https://firestore\.googleapis\.com/v1/projects/([a-z0-9-]+)", "firebase", "project_id"),
            (r"https://([a-z0-9]+)\.appwrite\.io", "appwrite", "endpoint"),
            (r"https://([a-z0-9]+)\.clerk\.accounts\.dev", "clerk", "domain"),
            (r"https://([a-z0-9]+)\.auth0\.com", "auth0", "domain"),
        ]

        for pattern, platform, field_name in endpoint_patterns:
            matches = re.findall(pattern, source)
            for match in matches:
                fp = next((f for f in self._fingerprints if f.platform == platform), None)
                if fp:
                    if field_name == "endpoint":
                        fp.endpoint = f"https://{match}.supabase.co"
                    elif field_name == "domain":
                        fp.endpoint = match if match.startswith("http") else f"https://{match}"
                    elif field_name == "project_id":
                        fp.project_id = match

    async def _detect_from_headers(self, target_url: str):
        """Detect BaaS from HTTP headers."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    headers = dict(resp.headers)
                    await resp.text()

                    # Check for BaaS headers
                    if "x-supabase" in str(headers).lower():
                        fp = next((f for f in self._fingerprints if f.platform == "supabase"), None)
                        if not fp:
                            self._fingerprints.append(BaasFingerprint(
                                platform="supabase",
                                confidence=0.80,
                                raw_detection="x-supabase header",
                            ))

                    if "x-appwrite" in str(headers).lower():
                        fp = next((f for f in self._fingerprints if f.platform == "appwrite"), None)
                        if not fp:
                            self._fingerprints.append(BaasFingerprint(
                                platform="appwrite",
                                confidence=0.80,
                                raw_detection="x-appwrite header",
                            ))

        except Exception:
            pass

    async def _detect_from_js(self, target_url: str):
        """Detect BaaS from JavaScript bundles."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    body = await resp.text()

                # Find JS bundles
                js_urls = re.findall(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', body)

                for js_url in js_urls[:5]:
                    full_js_url = js_url if js_url.startswith("http") else f"{target_url.rstrip('/')}/{js_url.lstrip('/')}"
                    try:
                        async with session.get(full_js_url, timeout=aiohttp.ClientTimeout(total=10)) as js_resp:
                            js_body = await js_resp.text()

                            # Detect from JS content
                            for pattern, detection_type, confidence in [
                                *self.SUPABASE_PATTERNS,
                                *self.FIREBASE_PATTERNS,
                                *self.APPWRITE_PATTERNS,
                                *self.CLERK_PATTERNS,
                                *self.AUTH0_PATTERNS,
                            ]:
                                if re.search(pattern, js_body, re.IGNORECASE):
                                    platform = detection_type.split("_")[0]
                                    if platform in ("supabase", "firebase", "appwrite", "clerk", "auth0"):
                                        fp = next((f for f in self._fingerprints if f.platform == platform), None)
                                        if fp:
                                            fp.confidence = max(fp.confidence, confidence)
                                        else:
                                            self._fingerprints.append(BaasFingerprint(
                                                platform=platform,
                                                confidence=confidence,
                                                raw_detection=f"JS: {detection_type}",
                                            ))

                                    # Extract keys from JS
                                    key_match = re.search(r"sbp_[a-zA-Z0-9]{30,}", js_body)
                                    if key_match:
                                        fp = next((f for f in self._fingerprints if f.platform == "supabase"), None)
                                        if fp:
                                            fp.api_key = key_match.group(0)

                                    key_match = re.search(r"pk_[a-zA-Z0-9]{30,}", js_body)
                                    if key_match:
                                        fp = next((f for f in self._fingerprints if f.platform == "clerk"), None)
                                        if fp:
                                            fp.api_key = key_match.group(0)

                    except Exception:
                        continue

        except Exception:
            pass

    async def _enumerate_resources(self, fingerprint: BaasFingerprint):
        """Enumerate resources for a detected BaaS."""
        if fingerprint.platform == "supabase" and fingerprint.endpoint:
            await self._enumerate_supabase(fingerprint)
        elif fingerprint.platform == "firebase" and fingerprint.project_id:
            await self._enumerate_firebase(fingerprint)
        elif fingerprint.platform == "appwrite" and fingerprint.endpoint:
            await self._enumerate_appwrite(fingerprint)

    async def _enumerate_supabase(self, fingerprint: BaasFingerprint):
        """Enumerate Supabase resources."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                # Try to list tables via REST API
                headers = {
                    "apikey": fingerprint.api_key or "",
                    "Authorization": f"Bearer {fingerprint.api_key or ''}",
                }

                # Try common table names
                for table in self.COMMON_TABLES:
                    try:
                        url = f"{fingerprint.endpoint}/rest/v1/{table}?select=*&limit=1"
                        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                            if resp.status == 200:
                                body = await resp.text()
                                if body and body != "[]":
                                    fingerprint.tables.append(table)
                    except Exception:
                        continue

                # Try to list storage buckets
                try:
                    url = f"{fingerprint.endpoint}/storage/v1/bucket"
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            data = json.loads(body)
                            if isinstance(data, list):
                                for bucket in data:
                                    if isinstance(bucket, dict) and "id" in bucket:
                                        fingerprint.buckets.append(bucket["id"])
                except Exception:
                    pass

        except Exception:
            pass

    async def _enumerate_firebase(self, fingerprint: BaasFingerprint):
        """Enumerate Firebase resources."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                # Try common Realtime DB paths
                for table in self.COMMON_TABLES:
                    try:
                        url = f"https://{fingerprint.project_id}.firebaseio.com/{table}.json?shallow=true"
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                            if resp.status == 200:
                                body = await resp.text()
                                if body and body != "null":
                                    fingerprint.collections.append(table)
                    except Exception:
                        continue

        except Exception:
            pass

    async def _enumerate_appwrite(self, fingerprint: BaasFingerprint):
        """Enumerate AppWrite resources."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                # Try to list databases
                try:
                    url = f"{fingerprint.endpoint}/v1/databases"
                    headers = {"X-Appwrite-Key": fingerprint.api_key or ""}
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            data = json.loads(body)
                            if isinstance(data, dict) and "databases" in data:
                                for db in data["databases"]:
                                    if "name" in db:
                                        fingerprint.collections.append(db["name"])
                except Exception:
                    pass

        except Exception:
            pass

    def get_fingerprints(self) -> list[BaasFingerprint]:
        """Get all detected BaaS fingerprints."""
        return self._fingerprints

    def get_primary_fingerprint(self) -> BaasFingerprint | None:
        """Get the most likely BaaS platform."""
        if not self._fingerprints:
            return None
        return max(self._fingerprints, key=lambda f: f.confidence)

    def to_finding(self, target_url: str) -> Finding | None:
        """Convert enumeration to a finding (for reporting)."""
        primary = self.get_primary_fingerprint()
        if not primary:
            return None

        severity_map = {
            "supabase": Severity.HIGH,
            "firebase": Severity.HIGH,
            "appwrite": Severity.HIGH,
            "clerk": Severity.MEDIUM,
            "auth0": Severity.MEDIUM,
        }

        return Finding(
            target=target_url,
            url=target_url,
            method="GET",
            param="baas_detection",
            location="page_source",
            payload=json.dumps({
                "platform": primary.platform,
                "endpoint": primary.endpoint,
                "tables": primary.tables[:10],
                "buckets": primary.buckets[:5],
                "functions": primary.functions[:5],
            }),
            attack_type=AttackType.INFO_LEAK,
            severity=severity_map.get(primary.platform, Severity.INFO),
            confidence=primary.confidence,
            status=200,
            evidence=primary.raw_detection[:500],
            tier="confirmed" if primary.confidence > 0.85 else "suspicious",
            tags=["baas", "enumeration", primary.platform],
            notes=f"BaaS detected: {primary.platform} (confidence: {primary.confidence:.0%})",
        )
