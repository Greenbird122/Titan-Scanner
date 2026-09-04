"""BaaS Detector — integrated with Titan engine.

This module wraps the Supabase and Firebase testers and integrates
them with the Titan engine's context, fingerprinting, and state management.

Key improvements over standalone modules:
1. Uses engine's Playwright context for requests
2. Auto-detects BaaS platform from fingerprint
3. Enumerates tables/collections/functions before testing
4. Tests with different auth states (no auth, anon, user, admin)
5. Chains findings into attack paths
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType
from titan.modules.baas.supabase import SupabaseTester
from titan.modules.baas.firebase import FirebaseTester


class BaasDetector:
    """BaaS detector integrated with Titan engine."""

    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint
        self.supa = SupabaseTester()
        self.fire = FirebaseTester()
        self._detected_platform: Optional[str] = None
        self._supabase_url: Optional[str] = None
        self._firebase_url: Optional[str] = None
        self._api_key: Optional[str] = None

    async def scan(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        """Main scan entry point — tests BaaS-specific vulnerabilities."""
        findings: List[Finding] = []

        # Auto-detect BaaS platform from fingerprint
        self._detect_platform()

        if self._detected_platform == "supabase":
            findings.extend(await self._scan_supabase(context, target))
        elif self._detected_platform == "firebase":
            findings.extend(await self._scan_firebase(context, target))

        return findings

    def _detect_platform(self) -> None:
        """Detect BaaS platform from fingerprint."""
        techs = [t.lower() for t in self.fingerprint.get("technologies", [])]
        body = self.fingerprint.get("body", "").lower()

        if "supabase" in body or "supabase" in techs:
            self._detected_platform = "supabase"
            # Extract Supabase URL from fingerprint
            self._supabase_url = self._extract_supabase_url()
        elif "firebase" in body or "firebase" in techs:
            self._detected_platform = "firebase"
            self._firebase_url = self._extract_firebase_url()
            self._api_key = self._extract_firebase_api_key()

    def _extract_supabase_url(self) -> Optional[str]:
        """Extract Supabase URL from fingerprint."""
        body = self.fingerprint.get("body", "")
        # Look for Supabase URL pattern
        match = re.search(r'https://[a-z0-9]+\.supabase\.co', body)
        if match:
            return match.group(0)
        return None

    def _extract_firebase_url(self) -> Optional[str]:
        """Extract Firebase URL from fingerprint."""
        body = self.fingerprint.get("body", "")
        # Look for Firebase URL pattern
        match = re.search(r'https://[a-z0-9]+\.firebaseio\.com', body)
        if match:
            return match.group(0)
        return None

    def _extract_firebase_api_key(self) -> Optional[str]:
        """Extract Firebase API key from fingerprint."""
        body = self.fingerprint.get("body", "")
        # Look for API key pattern
        match = re.search(r'AIza[A-Za-z0-9_-]{35}', body)
        if match:
            return match.group(0)
        return None

    async def _scan_supabase(self, context, target: str) -> List[Finding]:
        """Scan Supabase for vulnerabilities."""
        findings = []

        if not self._supabase_url:
            return findings

        # Set credentials
        self.supa.set_credentials(self._supabase_url)

        # Enumerate tables
        tables = await self._enumerate_supabase_tables(context, target)

        # Test RLS policies
        if tables:
            rls_findings = await self.supa.test_rls_policies(target, tables)
            findings.extend(rls_findings)

        # Test auth enumeration
        auth_findings = await self.supa.test_auth_enumeration(target)
        findings.extend(auth_findings)

        # Enumerate Edge Functions
        functions = await self._enumerate_supabase_functions(context, target)

        # Test Edge Functions
        if functions:
            func_findings = await self.supa.test_edge_functions(target, functions)
            findings.extend(func_findings)

        # Enumerate Storage buckets
        buckets = await self._enumerate_supabase_buckets(context, target)

        # Test Storage
        if buckets:
            storage_findings = await self.supa.test_storage_abuse(target, buckets)
            findings.extend(storage_findings)

        # Test metadata escalation (requires auth)
        # This would be tested with authenticated session

        # Test JWT manipulation
        jwt_findings = await self.supa.test_jwt_manipulation(target)
        findings.extend(jwt_findings)

        # Test DB functions
        if functions:
            db_findings = await self.supa.test_db_functions(target, functions)
            findings.extend(db_findings)

        return findings

    async def _scan_firebase(self, context, target: str) -> List[Finding]:
        """Scan Firebase for vulnerabilities."""
        findings = []

        if not self._firebase_url:
            return findings

        # Set credentials
        self.fire.set_credentials(self._firebase_url, self._api_key)

        # Enumerate collections
        collections = await self._enumerate_firebase_collections(context, target)

        # Test Firestore rules
        if collections:
            firestore_findings = await self.fire.test_firestore_rules(target, collections)
            findings.extend(firestore_findings)

        # Test auth settings
        auth_findings = await self.fire.test_auth_settings(target)
        findings.extend(auth_findings)

        # Enumerate Storage buckets
        buckets = await self._enumerate_firebase_buckets(context, target)

        # Test Storage rules
        if buckets:
            storage_findings = await self.fire.test_storage_rules(target, buckets)
            findings.extend(storage_findings)

        # Test Realtime Database
        db_findings = await self.fire.test_realtime_db(target)
        findings.extend(db_findings)

        return findings

    async def _enumerate_supabase_tables(self, context, target: str) -> List[str]:
        """Enumerate Supabase tables."""
        tables = []

        # Common table names to try
        common_tables = [
            "users", "profiles", "orders", "products", "sessions",
            "admin", "settings", "configs", "logs", "audit",
            "payments", "subscriptions", "invoices", "items", "categories",
        ]

        for table in common_tables:
            try:
                url = f"{self._supabase_url}/rest/v1/{table}?select=id&limit=1"
                resp = await context.request.get(
                    url, headers={"apikey": self.supa._anon_key or ""}, timeout=3000
                )
                body = await resp.text()

                if resp.status == 200 and body not in ("[]", "null", ""):
                    tables.append(table)
                elif resp.status == 404:
                    # Table doesn't exist
                    continue
                elif "permission" in body.lower() or "rls" in body.lower():
                    # Table exists but RLS blocked
                    tables.append(table)

            except Exception:
                continue

        return tables

    async def _enumerate_supabase_functions(self, context, target: str) -> List[str]:
        """Enumerate Supabase Edge Functions."""
        functions = []

        # Common function names to try
        common_functions = [
            "health", "status", "ping", "auth", "user", "admin",
            "payment", "webhook", "api", "data", "export",
            "gemini-chat", "travel-intelligence", "text-to-speech",
        ]

        for function in common_functions:
            try:
                url = f"{self._supabase_url}/functions/v1/{function}"
                resp = await context.request.get(
                    url, headers={"apikey": self.supa._anon_key or ""}, timeout=3000
                )
                body = await resp.text()

                if resp.status in (200, 403, 401):
                    # Function exists (even if unauthorized)
                    functions.append(function)

            except Exception:
                continue

        return functions

    async def _enumerate_supabase_buckets(self, context, target: str) -> List[str]:
        """Enumerate Supabase Storage buckets."""
        buckets = []

        try:
            url = f"{self._supabase_url}/storage/v1/bucket"
            resp = await context.request.get(
                url, headers={"apikey": self.supa._anon_key or ""}, timeout=3000
            )
            body = await resp.text()

            if resp.status == 200:
                data = json.loads(body)
                if isinstance(data, list):
                    for bucket in data:
                        if isinstance(bucket, dict) and "id" in bucket:
                            buckets.append(bucket["id"])

        except Exception:
            pass

        # Also try common bucket names
        common_buckets = ["uploads", "images", "files", "documents", "avatars"]
        for bucket in common_buckets:
            if bucket not in buckets:
                try:
                    url = f"{self._supabase_url}/storage/v1/object/{bucket}/"
                    resp = await context.request.get(
                        url, headers={"apikey": self.supa._anon_key or ""}, timeout=3000
                    )
                    if resp.status in (200, 403):
                        buckets.append(bucket)
                except Exception:
                    continue

        return buckets

    async def _enumerate_firebase_collections(self, context, target: str) -> List[str]:
        """Enumerate Firebase Firestore collections."""
        collections = []

        # Common collection names
        common_collections = [
            "users", "profiles", "orders", "products", "sessions",
            "admin", "settings", "configs", "logs", "audit",
        ]

        for collection in common_collections:
            try:
                url = f"https://firestore.googleapis.com/v1/projects/{self._firebase_url}/databases/(default)/documents/{collection}"
                resp = await context.request.get(url, timeout=3000)
                body = await resp.text()

                if resp.status == 200 and "documents" in body:
                    collections.append(collection)

            except Exception:
                continue

        return collections

    async def _enumerate_firebase_buckets(self, context, target: str) -> List[str]:
        """Enumerate Firebase Storage buckets."""
        buckets = []

        try:
            url = f"https://storage.googleapis.com/storage/v1/b?project={self._firebase_url}"
            resp = await context.request.get(url, timeout=3000)
            body = await resp.text()

            if resp.status == 200:
                data = json.loads(body)
                if "items" in data:
                    for item in data["items"]:
                        if "name" in item:
                            buckets.append(item["name"].split("/")[0])

        except Exception:
            pass

        return list(set(buckets))
