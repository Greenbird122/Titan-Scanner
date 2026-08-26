#!/usr/bin/env python3
"""Firebase RTDB / Firestore / Storage probe — owned, consented (ownership).
Targets the tulia-tag project (id 488585644867) whose Web API key is exposed
in database-tulia.vercel.app.
"""
import asyncio
import json
from pathlib import Path

import aiohttp

API_KEY = "AIzaSyB-wn4pMXrk7GpnTKEUELY290qpQ0kIQgI"
PROJECT = "tulia-tag"
RESULTS = {}


async def get(s, url, label, **kw):
    try:
        async with s.get(url, timeout=12, ssl=False, allow_redirects=True, **kw) as r:
            text = await r.text(errors="replace")
            RESULTS[label] = {
                "url": url,
                "status": r.status,
                "ctype": r.headers.get("Content-Type", ""),
                "body": text[:2000],
            }
            print(f"  [{r.status}] {label}: {url[:80]}  {text[:120]!r}")
    except Exception as e:
        RESULTS[label] = {"url": url, "error": str(e)}
        print(f"  [ERR] {label}: {e}")


async def post(s, url, label, payload):
    try:
        async with s.post(url, json=payload, timeout=12, ssl=False) as r:
            text = await r.text(errors="replace")
            RESULTS[label] = {
                "url": url,
                "status": r.status,
                "body": text[:2000],
            }
            print(f"  [{r.status}] {label}: {text[:120]!r}")
    except Exception as e:
        RESULTS[label] = {"url": url, "error": str(e)}
        print(f"  [ERR] {label}: {e}")


async def main():
    print("=" * 70)
    print("FIREBASE RTDB / FIRESTORE / STORAGE PROBE — tulia-tag")
    print("=" * 70)
    async with aiohttp.ClientSession() as s:
        print("\n[Realtime Database]")
        await get(s, f"https://{PROJECT}.firebaseio.com/.json", "rtdb_root")
        await get(s, f"https://{PROJECT}-default-rtdb.firebaseio.com/.json", "rtdb_default")
        await get(s, f"https://{PROJECT}-default-rtdb.firebaseio.com/.json?auth={API_KEY}", "rtdb_auth_key")

        print("\n[Firestore]")
        await get(
            s,
            f"https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents",
            "firestore_list",
        )
        await get(
            s,
            f"https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents?key={API_KEY}",
            "firestore_key",
        )

        print("\n[Cloud Storage]")
        await get(s, f"https://firebasestorage.googleapis.com/v0/b/{PROJECT}.appspot.com/o", "storage_list")
        await get(
            s,
            f"https://firebasestorage.googleapis.com/v0/b/{PROJECT}.appspot.com/o?key={API_KEY}",
            "storage_key",
        )

        print("\n[Firebase Hosting]")
        await get(s, f"https://{PROJECT}.web.app", "webapp")
        await get(s, f"https://{PROJECT}.firebaseapp.com", "firebaseapp")

        print("\n[Identity extras]")
        await post(
            s,
            f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={API_KEY}",
            "sendOobCode_reset",
            {"requestType": "PASSWORD_RESET", "email": "nobody@example.com"},
        )
        await post(
            s,
            f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={API_KEY}",
            "accounts_lookup",
            {"emails": ["test@example.com"]},
        )

    p = Path("findings/FIREBASE-RTDB-FIRESTORE-STORAGE.json")
    p.write_text(json.dumps(RESULTS, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[+] written to {p}")


if __name__ == "__main__":
    asyncio.run(main())