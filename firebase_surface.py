#!/usr/bin/env python3
"""Firebase + Railway surface probe — owned, consented (ownership).

Follow-up to firebase_probe.py. Project `tulia-tag` (id 488585644867) was
confirmed. Probe:
  - Realtime Database (tulia-tag.firebaseio.com)
  - Firestore
  - Cloud Storage
  - firebaseapp.com / web.app hosting

Railway backend tulia-ai-production.up.railway.app was leaked by Firebase
config, but is intentionally not probed here until explicitly named in-scope.
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
                "body": text[:1500],
            }
            print(f"  [{r.status}] {label}: {url[:80]}  {text[:80]!r}")
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
                "body": text[:1500],
            }
            print(f"  [{r.status}] {label}: {text[:80]!r}")
    except Exception as e:
        RESULTS[label] = {"url": url, "error": str(e)}
        print(f"  [ERR] {label}: {e}")


async def main():
    print("=" * 70)
    print("FIREBASE + RAILWAY SURFACE — tulia-tag")
    print("=" * 70)
    async with aiohttp.ClientSession() as s:
        print("\n[RTDB]")
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

        print("\n[Storage]")
        await get(s, f"https://firebasestorage.googleapis.com/v0/b/{PROJECT}.appspot.com/o", "storage_list")
        await get(
            s,
            f"https://firebasestorage.googleapis.com/v0/b/{PROJECT}.appspot.com/o?key={API_KEY}",
            "storage_key",
        )

        print("\n[Hosting]")
        await get(s, f"https://{PROJECT}.web.app", "webapp")
        await get(s, f"https://{PROJECT}.firebaseapp.com", "firebaseapp")

        
        print("\n[Identity extras]")
        await post(
            s,
            f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={API_KEY}",
            "sendOobCode_reset",
            {"requestType": "PASSWORD_RESET", "email": "nobody@example.com"},
        )

    p = Path("findings/FIREBASE-SURFACE.json")
    p.write_text(json.dumps(RESULTS, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[+] written to {p}")


if __name__ == "__main__":
    asyncio.run(main())
