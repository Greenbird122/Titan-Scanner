"""Django / DRF probe.

1. DEBUG URLconf leak — GET an undefined /api/<random>/ path; DEBUG=True
   renders the full route list (and settings on a triggered 500).
2. Endpoint authz sweep — walk a candidate endpoint list with a low-priv
   token; print 200/401/403/405 so IDORs and missing authz stand out.
3. (Optional) trigger a DEBUG 500 for the settings table via a known-broken
   endpoint and dump the settings section.

Read-only (GET + POST to error paths with a throwaway token). Consent is
checked before any authenticated call.

Usage:
    python probe_django.py https://target.example --token <jwt> \
        [--endpoints /api/patients/ /api/clinical/] [--settings-500 /api/auth/profile/]
"""
import argparse
import json
import os
import re
import sys
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from consent import load_consent  # noqa: E402


def http(method, url, data=None, token=None, timeout=20):
    h = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}
    if token:
        h["Authorization"] = "Bearer " + token
    body = None
    if data is not None:
        body = json.dumps(data).encode()
    r = urllib.request.Request(url, method=method, data=body, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def urlconf_leak(base):
    import random
    probe = f"/api/nonexistent-{random.randrange(10**8)}/xyz/"
    st, body = http("GET", base + probe)
    leaked = []
    if "Using the URLconf" in body:
        for m in re.findall(r"(?:api|admin|swagger|redoc|media|static)/[a-z0-9_\-/.]*", body):
            leaked.append(m.rstrip("/"))
    print(f"[django] DEBUG URLconf leak: {'LEAKED (' + str(len(set(leaked))) + ' routes)' if leaked else 'no leak'}")
    for r in sorted(set(leaked)):
        print(f"    {r}")
    return sorted(set(leaked))


def settings_dump(base, token, path):
    st, body = http("GET", base + path, token=token)
    if st == 500 and "Settings" in body:
        print(f"[django] DEBUG 500 on {path} -> SETTINGS LEAKED ({len(body)} bytes)")
        for key in ("DEBUG", "DATABASES", "ALLOWED_HOSTS", "CORS_", "SECRET_KEY",
                    "AFRICASTALKING", "GOOGLE_", "REDIS", "CELERY"):
            if re.search(key, body):
                m = re.search(key + r".{0,90}", body, re.S)
                val = " ".join(m.group(0).split())[:110] if m else ""
                print(f"    {key}: {val}")
    else:
        print(f"[django] {path} -> {st} (no settings leak)")


def authz_sweep(base, token, endpoints):
    print(f"[django] authz sweep with {'token' if token else 'NO token'}")
    for ep in endpoints:
        for m in ("GET", "POST"):
            st, body = http(m, base + ep, data={} if m == "POST" else None, token=token)
            snippet = " ".join(body[:90].split())
            print(f"  {m:4s} {ep:48s} -> {st}  {snippet}")
            break  # GET only unless --post-all


def main():
    ap = argparse.ArgumentParser(description="Django/DRF probe")
    ap.add_argument("target")
    ap.add_argument("--token", default=None, help="JWT (throwaway account)")
    ap.add_argument("--endpoints", nargs="*", default=[])
    ap.add_argument("--settings-500", default=None,
                    help="endpoint that 500s for all users, e.g. /api/auth/profile/")
    args = ap.parse_args()

    base = args.target.rstrip("/")
    if args.token:
        # authenticated phase — require a consent file for the domain
        from urllib.parse import urlparse
        host = urlparse(base).netloc
        c = load_consent(host)
        print(f"[consent] {host} flags={c.get('flags')}")

    if args.endpoints:
        authz_sweep(base, args.token, args.endpoints)
    else:
        routes = urlconf_leak(base)
        if routes and args.token and args.settings_500:
            settings_dump(base, args.token, args.settings_500)
        if routes and not args.endpoints:
            print("\n[tip] re-run with --endpoints to sweep specific routes "
                  "(see leaked list above)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
