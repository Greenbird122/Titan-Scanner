"""Estate mapping probe (read-only).

Fetches the target homepage, discovers JS bundles, and scans them for:
  - API base URLs + endpoint fragments
  - secrets: api keys, sk_/pk_, AKIA, AIza, supabase, firebase, service_role
  - third-party integrations (payments / SMS / LLM / storage / auth)

Usage:
    python bundle_scan.py https://target.example [--out findings/<slug>/estate.json]

Prints findings to stdout; writes the estate map JSON when --out is given.
Consent: read-only — no consent file required, but flags are printed if present.
"""
import argparse
import html
import json
import os
import re
import sys
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

UA = {"User-Agent": "Mozilla/5.0 (audit probe)"}

SECRET_RE = [
    (r"AIza[0-9A-Za-z_\-]{35}", "firebase-api-key"),
    (r"AKIA[0-9A-Z]{16}", "aws-access-key"),
    (r"(sk|pk)_(live|test)_[0-9a-zA-Z]{16,}", "stripe/paystack-key"),
    (r"service_role", "supabase-service-role"),
    (r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "jwt-bearer"),
    (r"x-admin-api-key", "admin-api-key-header"),
    (r"upload_preset", "cloudinary-upload-preset"),
    (r"(api[_-]?key|apikey|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]", "generic-secret"),
    (r"sk-[0-9A-Za-z]{20,}", "openai-key"),
]

INTEGRATIONS = {
    "supabase": "supabase",
    "firebase": "firebase",
    "firestore": "firestore",
    "firebaseio": "firebase-rtdb",
    "paystack": "paystack",
    "stripe": "stripe",
    "cloudinary": "cloudinary",
    "africastalking": "africa's-talking",
    "deepseek": "deepseek",
    "openai": "openai",
    "anthropic": "anthropic",
    "twilio": "twilio",
    "mapbox": "mapbox",
    "googleapis": "google-apis",
    "sentry": "sentry",
}


def fetch(url, timeout=30):
    r = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


def find_bundles(html_body, base_url):
    """Extract JS asset URLs from script/link tags."""
    from urllib.parse import urljoin
    urls = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html_body):
        urls.append(urljoin(base_url, m.group(1)))
    for m in re.finditer(r'<link[^>]+href=["\']([^"\']+\.js)["\']', html_body):
        urls.append(urljoin(base_url, m.group(1)))
    return list(dict.fromkeys(urls))


def scan_text(text, name):
    hits = []
    for pat, kind in SECRET_RE:
        for m in re.finditer(pat, text):
            val = m.group(0)
            if len(val) > 48:
                val = val[:20] + "…" + val[-12:]
            hits.append({"kind": kind, "value": val, "in": name})
    return hits


def main():
    ap = argparse.ArgumentParser(description="Estate/bundle mapping probe")
    ap.add_argument("target")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    target = args.target.rstrip("/")
    estate = {"target": target, "status": None, "headers": {}, "bundles": [],
              "secrets": [], "integrations": [], "api_endpoints": []}

    st, headers, body = fetch(target)
    estate["status"] = st
    estate["headers"] = {k: v for k, v in headers.items()
                         if k.lower() in ("server", "x-powered-by", "x-generator",
                                          "x-vercel-id", "x-nextjs-cache", "cf-ray",
                                          "set-cookie", "content-security-policy")}
    print(f"[bundle_scan] {target} -> {st}")
    print(f"  server: {headers.get('Server', headers.get('server', '-'))}")

    if st >= 400 and st < 500:
        # error page may be a backend fingerprint (Django DEBUG / Flask / etc.)
        snippet = re.sub(r"<[^>]+>", " ", body)[:300]
        print(f"  error body: {' '.join(snippet.split())[:200]}")

    # discover bundles
    for u in find_bundles(body, target):
        estate["bundles"].append(u)
        bst, _, bbody = fetch(u, timeout=30)
        print(f"  bundle {u} -> {bst} ({len(bbody)} bytes)")
        if bst == 200:
            for hit in scan_text(bbody, u):
                estate["secrets"].append(hit)
            for key, label in INTEGRATIONS.items():
                if re.search(key, bbody, re.I):
                    estate["integrations"].append(label)
            # endpoint fragments — bundles often use template literals
            # (`/api/...`) and/or single/double quotes; catch all three.
            for m in re.finditer(r"[`\"'](/api/[a-zA-Z0-9_\-/{}.?]+)[`\"']", bbody):
                ep = m.group(1)
                if ep not in estate["api_endpoints"]:
                    estate["api_endpoints"].append(ep)

    estate["integrations"] = sorted(set(estate["integrations"]))
    estate["api_endpoints"] = sorted(set(estate["api_endpoints"]))

    print("\n[integrations]", estate["integrations"] or "none detected")
    print("[secrets]")
    for s in estate["secrets"]:
        print(f"  {s['kind']}: {s['value']}  ({s['in'][:60]})")
    if estate["api_endpoints"]:
        print("[api_endpoints]")
        for ep in estate["api_endpoints"][:40]:
            print(f"  {ep}")

    if args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(estate, f, indent=2)
        print(f"\n[wrote] {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
