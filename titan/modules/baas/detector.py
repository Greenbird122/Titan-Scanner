"""BaaS Detector — integrated with Titan engine.

This module wraps the Supabase and Firebase testers and integrates
them with the Titan engine's context, fingerprinting, and state management.

Key improvements over standalone modules:
1. Uses engine's Playwright context for requests
2. Auto-detects BaaS platform from fingerprint
3. Enumerates tables/collections/functions before testing
4. Tests with different auth states (no auth, anon, user, admin)
5. Chains findings into attack paths
6. Sweeps the fake/proxied BaaS path family on the TARGET's own origin
   (rest/v1 object listings, .json, storage/v1 object listings) with
   control-differentiation: a byte-identical response to a nonsense
   control path is a canned/honeypot surface and is demoted (no finding)

Lesson baked in from the adversarial-honeypot negative control: a BaaS
finding is not dead until the full path family has been swept on the app
origin AND responses have been differentiated from canned controls.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

from titan.core.models import AttackType, Finding, Severity
from titan.modules.baas.firebase import FirebaseTester
from titan.modules.baas.supabase import SupabaseTester


class BaasDetector:
    """BaaS detector integrated with Titan engine."""

    # Origins already swept for the on-origin family (once per engine
    # process — the module matrix dispatches this detector per route, and
    # the family sweep must not repeat per endpoint).
    _SWEPT_ORIGINS: set = set()

    @classmethod
    def reset_sweep_cache(cls) -> None:
        """Clear the once-per-origin sweep cache (test isolation)."""
        cls._SWEPT_ORIGINS = set()

    def __init__(self, payload_smith, fingerprint: dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint
        self.supa = SupabaseTester()
        self.fire = FirebaseTester()
        self._detected_platform: str | None = None
        self._supabase_url: str | None = None
        self._firebase_url: str | None = None
        self._api_key: str | None = None

    async def scan(
        self,
        context,
        target: str,
        method: str,
        url: str,
        params: dict[str, str],
    ) -> list[Finding]:
        """Main scan entry point — tests BaaS-specific vulnerabilities."""
        findings: list[Finding] = []

        # Auto-detect BaaS platform from fingerprint
        self._detect_platform()

        if self._detected_platform == "supabase":
            findings.extend(await self._scan_supabase(context, target))
        elif self._detected_platform == "firebase":
            findings.extend(await self._scan_firebase(context, target))

        # On-origin fake/proxied BaaS family sweep (control-differentiated).
        # Catches surfaces the external-host scan can't see: an app origin
        # serving rest/v1, storage/v1, .json, functions/v1, auth/v1 shapes
        # with canned responses (honeypot / proxy) or real open data.
        findings.extend(await self._sweep_on_origin(context, target, url))

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

    def _extract_supabase_url(self) -> str | None:
        """Extract Supabase URL from fingerprint."""
        body = self.fingerprint.get("body", "")
        # Look for Supabase URL pattern
        match = re.search(r'https://[a-z0-9]+\.supabase\.co', body)
        if match:
            return match.group(0)
        return None

    def _extract_firebase_url(self) -> str | None:
        """Extract Firebase URL from fingerprint."""
        body = self.fingerprint.get("body", "")
        # Look for Firebase URL pattern
        match = re.search(r'https://[a-z0-9]+\.firebaseio\.com', body)
        if match:
            return match.group(0)
        return None

    def _extract_firebase_api_key(self) -> str | None:
        """Extract Firebase API key from fingerprint."""
        body = self.fingerprint.get("body", "")
        # Look for API key pattern
        match = re.search(r'AIza[A-Za-z0-9_-]{35}', body)
        if match:
            return match.group(0)
        return None

    # ── On-origin fake/proxied BaaS family sweep ───────────────────────
    #
    # Negative-control lesson (adversarial honeypot): a BaaS finding is not
    # dead until the full path family on the TARGET's own origin has been
    # swept (rest/v1, .json, storage/v1, functions/v1, auth/v1, firestore,
    # identitytoolkit), and results have been differentiated from canned
    # controls. Apps that proxy or fake BaaS on their own origin answer
    # every path with the same byte-identical body (or one canned guest
    # row). The discipline: probe a nonsense control path per family; if a
    # real path returns a byte-identical body, it is canned — demoted, no
    # finding.

    ON_ORIGIN_COMMON_TABLES = [
        "users", "admin", "products", "payments", "profiles",
        "orders", "sessions", "settings", "messages",
    ]

    ON_ORIGIN_COMMON_BUCKETS = [
        "uploads", "images", "files", "documents", "avatars",
    ]

    ON_ORIGIN_CONTROL_NAME = "zz_titan_ctl_nonexistent_7f3a"

    # Family markers — the sweep only fires when the fingerprint body or
    # the URL under test shows BaaS-shaped paths, so ordinary endpoints
    # are not probed. ".json" is deliberately NOT included: modern apps
    # (RSC payloads, JSON-LD, manifests) mention .json constantly and
    # would false-positive the gate.
    ON_ORIGIN_MARKERS = (
        "supabase", "firebase", "firestore", "identitytoolkit", "appwrite",
        "/rest/v1", "storage/v1", "/functions/v1", "/auth/v1", "postgrest",
    )

    def _on_origin_base(self, url: str) -> str | None:
        """Return scheme://host for a URL (the on-origin probe base)."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None
        return f"{parsed.scheme}://{parsed.netloc}"

    def _origin_sweep_hinted(self, url: str) -> bool:
        """True when the page body/techs or current URL hints at BaaS shapes."""
        body = (self.fingerprint.get("body", "") or "").lower()
        techs = " ".join(str(t).lower() for t in self.fingerprint.get("technologies", []))
        hay = f"{body} {techs} {url or ''}".lower()
        return any(m in hay for m in self.ON_ORIGIN_MARKERS)

    async def _sweep_on_origin(self, context, target: str, url: str) -> list[Finding]:
        """Sweep BaaS-shaped path families served from the target's own origin.

        Every candidate path is probed alongside a nonsense CONTROL path of
        the same family. When the real path's body is byte-identical to the
        control's, the surface is canned (fake/proxied demo data) and is
        demoted — no finding is filed. Bodies are also compared across
        sibling tables so a canned row served for every table is dismissed
        even if the control path 404s.

        Runs once per origin per engine process (module-level dedupe) and
        only when BaaS markers appear in the fingerprint or current URL.
        """
        findings: list[Finding] = []
        base = self._on_origin_base(target) or self._on_origin_base(url)
        if not base:
            return findings

        if base in BaasDetector._SWEPT_ORIGINS:
            return findings
        if not self._origin_sweep_hinted(url):
            return findings
        BaasDetector._SWEPT_ORIGINS.add(base)

        try:
            # Supabase REST family: /rest/v1/{table} (+ /api prefix variant)
            findings.extend(await self._probe_supabase_rest_family(context, target, base))
            # Firebase RTDB family: /.json (root + common child paths)
            findings.extend(await self._probe_firebase_rtdb_family(context, target, base))
            # Supabase storage family: /storage/v1/bucket + common buckets
            findings.extend(await self._probe_storage_family(context, target, base))
        except Exception:
            pass

        return findings

    async def _get_on_origin(self, context, url: str) -> dict[str, Any] | None:
        """GET a URL via the engine context; return {"status", "body"}."""
        try:
            resp = await context.request.get(url, timeout=4000)
            try:
                body = await resp.text()
            except Exception:
                body = ""
            return {"status": resp.status, "body": body or ""}
        except Exception:
            return None

    @staticmethod
    def _normalize_body(body: str) -> str:
        """Normalize a body for byte-identity comparison."""
        return re.sub(r"\s+", "", body or "").strip()

    def _looks_like_data(self, body: str) -> bool:
        """True if a body looks like real data (not error/empty shell)."""
        b = (body or "").strip()
        if not b or b in ("[]", "{}", "null", "null\n"):
            return False
        low = b.lower()
        if any(k in low for k in ("<html", "<!doctype", "not found", "cannot get")):
            return False
        # JSON arrays/objects are the strongest signal; accept both.
        if b.startswith("[") or b.startswith("{"):
            return True
        return len(b) > 20 and len(b) < 20000

    async def _probe_supabase_rest_family(self, context, target: str, base: str) -> list[Finding]:
        """Probe {base}/rest/v1/{table} (+ /api variant) with control demotion."""
        findings: list[Finding] = []
        prefixes = ["", "/api"]
        for prefix in prefixes:
            ctl_url = f"{base}{prefix}/rest/v1/{self.ON_ORIGIN_CONTROL_NAME}?select=*&limit=1"
            ctl = await self._get_on_origin(context, ctl_url)
            ctl_body = self._normalize_body(ctl["body"]) if ctl else ""

            live_rows = []
            for table in self.ON_ORIGIN_COMMON_TABLES:
                probe_url = f"{base}{prefix}/rest/v1/{table}?select=*&limit=1"
                resp = await self._get_on_origin(context, probe_url)
                if not resp or resp["status"] != 200:
                    continue
                norm = self._normalize_body(resp["body"])
                # Byte-identical to the nonsense control => canned surface.
                if ctl and norm == ctl_body and self._looks_like_data(resp["body"]):
                    continue
                if self._looks_like_data(resp["body"]):
                    live_rows.append((table, resp["body"][:500]))

            # A canned row served identically for EVERY table (control 404s
            # but all real tables share one body) is still a honeypot.
            if live_rows:
                distinct = {self._normalize_body(b) for _, b in live_rows}
                if len(distinct) == 1 and len(live_rows) > 1:
                    continue
                findings.append(self._make_on_origin_finding(
                    target=target,
                    url=f"{base}{prefix}/rest/v1/",
                    name="supabase-rest-on-origin",
                    detail=f"Public PostgREST-style API on app origin serving live data across {len(live_rows)} tables ({', '.join(t for t, _ in live_rows[:5])})",
                    evidence=live_rows[0][1],
                    severity=Severity.HIGH,
                    attack=AttackType.INFO_LEAK,
                    tags=["baas", "supabase", "on_origin", "rest_v1"],
                ))
        return findings

    async def _probe_firebase_rtdb_family(self, context, target: str, base: str) -> list[Finding]:
        """Probe {base}/.json with control demotion.

        Control is itself a .json-shaped path: a fake RTDB answers EVERY
        .json path (root, child, nonsense) with one canned body, so root
        and control are byte-identical and the surface is demoted. A real
        open RTDB returns data at root and null at a nonsense child.
        """
        findings: list[Finding] = []
        ctl_url = f"{base}/{self.ON_ORIGIN_CONTROL_NAME}/.json"
        ctl = await self._get_on_origin(context, ctl_url)
        ctl_body = self._normalize_body(ctl["body"]) if ctl else ""

        url = f"{base}/.json"
        resp = await self._get_on_origin(context, url)
        if resp and resp["status"] == 200:
            norm = self._normalize_body(resp["body"])
            canned = bool(ctl) and norm == ctl_body
            if not canned and self._looks_like_data(resp["body"]):
                findings.append(self._make_on_origin_finding(
                    target=target,
                    url=url,
                    name="firebase-rtdb-on-origin",
                    detail="Firebase-RTDB-shaped .json endpoint on app origin exposes data",
                    evidence=resp["body"][:500],
                    severity=Severity.HIGH,
                    attack=AttackType.INFO_LEAK,
                    tags=["baas", "firebase", "on_origin", "rtdb"],
                ))
        return findings

    async def _probe_storage_family(self, context, target: str, base: str) -> list[Finding]:
        """Probe {base}/storage/v1 object listings with control demotion.

        A bucket NAME listing alone is not a vulnerability (config noise
        that honeypots plant). The real signal is OBJECT exposure: an
        object path returning actual file data. Cross-bucket byte-identity
        demotes a canned row served for every bucket.
        """
        findings: list[Finding] = []
        prefixes = ["", "/api"]
        for prefix in prefixes:
            ctl_url = f"{base}{prefix}/storage/v1/{self.ON_ORIGIN_CONTROL_NAME}"
            ctl = await self._get_on_origin(context, ctl_url)
            ctl_body = self._normalize_body(ctl["body"]) if ctl else ""

            # Object paths for common bucket names (public read).
            live_objs = []
            for bucket in self.ON_ORIGIN_COMMON_BUCKETS:
                obj_url = f"{base}{prefix}/storage/v1/object/{bucket}/"
                resp = await self._get_on_origin(context, obj_url)
                if not resp or resp["status"] != 200:
                    continue
                norm = self._normalize_body(resp["body"])
                if ctl and norm == ctl_body:
                    continue
                if self._looks_like_data(resp["body"]):
                    live_objs.append((bucket, obj_url, resp["body"][:500]))

            if live_objs:
                distinct = {self._normalize_body(b) for _, _, b in live_objs}
                if len(distinct) == 1 and len(live_objs) > 1:
                    continue  # canned row across every bucket — honeypot
                bucket, obj_url, snippet = live_objs[0]
                findings.append(self._make_on_origin_finding(
                    target=target,
                    url=obj_url,
                    name="storage-object-list-on-origin",
                    detail=f"Storage bucket '{bucket}' object listing readable on app origin ({len(live_objs)} buckets respond)",
                    evidence=snippet,
                    severity=Severity.HIGH,
                    attack=AttackType.INFO_LEAK,
                    tags=["baas", "storage", "on_origin", "objects"],
                ))
        return findings

    def _make_on_origin_finding(
        self, target: str, url: str, name: str, detail: str,
        evidence: str, severity: Severity, attack: AttackType, tags: list[str],
    ) -> Finding:
        """Build an on-origin BaaS finding."""
        return Finding(
            target=target,
            url=url,
            method="GET",
            param=name,
            location="on_origin_baas",
            payload="",
            attack_type=attack,
            severity=severity,
            confidence=0.75,
            status=200,
            evidence=evidence[:500],
            tier="suspicious",
            tags=tags + [name],
            notes=detail,
        )

    async def _scan_supabase(self, context, target: str) -> list[Finding]:
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

    async def _scan_firebase(self, context, target: str) -> list[Finding]:
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

    async def _enumerate_supabase_tables(self, context, target: str) -> list[str]:
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

    async def _enumerate_supabase_functions(self, context, target: str) -> list[str]:
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

    async def _enumerate_supabase_buckets(self, context, target: str) -> list[str]:
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

    async def _enumerate_firebase_collections(self, context, target: str) -> list[str]:
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

    async def _enumerate_firebase_buckets(self, context, target: str) -> list[str]:
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
