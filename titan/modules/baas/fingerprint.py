"""BaaS fingerprinting — detect Supabase/Firebase/AppWrite from responses.

Runs early in the scan and feeds the hostile surface profiler / module
selection so BaaS-specific modules are prioritized when a backend is found.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


_SUPABASE_INDICATORS = [
    "supabase",
    ".supabase.co",
    "supabase.co",
    "/rest/v1/",
    "/auth/v1/",
    "postgrest",
    "postgrest-js",
    "realtime.supabase.com",
    "supabase.js",
    "@supabase",
    "supabaseUrl",
    "SUPABASE_URL",
    "SUPABASE_ANON_KEY",
    "supabase_anon",
    "supabase_key",
]

_FIREBASE_INDICATORS = [
    "firebase",
    ".firebaseio.com",
    ".cloudfunctions.net",
    "firebaseauth",
    "firebaseapp.com",
    "gstatic.com/firebase",
    "firebase.js",
    "firebase-app",
    "firebase-auth",
]

_APPWRITE_INDICATORS = [
    "appwrite",
    "/v1/",
    "appwrite.io",
    "appwrite.cloud",
    "appwrite.js",
]


class BaaSDetector:
    """Detect backend-as-a-service platforms from scan artifacts."""

    def detect(
        self,
        html: str = "",
        headers: Dict[str, str] = None,
        js_hints: List[str] = None,
        api_hints: List[str] = None,
    ) -> List[Dict[str, Any]]:
        headers = headers or {}
        js_hints = js_hints or []
        api_hints = api_hints or []
        blob = " ".join([html or "", " ".join(headers.values()), " ".join(js_hints), " ".join(api_hints)])
        lower = blob.lower()
        hits: List[Dict[str, Any]] = []

        for indicator in _SUPABASE_INDICATORS:
            if indicator.lower() in lower:
                hits.append({"platform": "supabase", "indicator": indicator})
                break

        for indicator in _FIREBASE_INDICATORS:
            if indicator.lower() in lower:
                hits.append({"platform": "firebase", "indicator": indicator})
                break

        for indicator in _APPWRITE_INDICATORS:
            if indicator.lower() in lower:
                hits.append({"platform": "appwrite", "indicator": indicator})
                break

        seen = set()
        deduped = []
        for h in hits:
            key = h["platform"]
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped
