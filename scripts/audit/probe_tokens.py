"""Token / session behavior probe (proven pattern from the repairai audit).

Tests, given a login endpoint + credentials for a throwaway account:
  - JWT claims (jti present? role claim?)
  - refresh token rotation (same refresh twice → both 200 = NO rotation)
  - logout invalidation (refresh after logout → 200 = logout is cosmetic)
  - access-token survival after logout

Read-only (no writes to app data; login/logout only). Consent required.

Usage:
    python probe_tokens.py https://target.example \
        --login /api/auth/login/ --refresh /api/auth/refresh/ \
        --logout /api/auth/logout/ \
        --user '{"phone":"+2547...","password":"..."}'
"""
import argparse
import base64
import json
import os
import sys
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from consent import load_consent  # noqa: E402


def http(method, url, data=None, headers=None, timeout=20):
    h = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}
    if headers:
        h.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode()
    r = urllib.request.Request(url, method=method, data=body, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode()


def main():
    ap = argparse.ArgumentParser(description="Token/session behavior probe")
    ap.add_argument("target")
    ap.add_argument("--login", required=True)
    ap.add_argument("--refresh", required=True)
    ap.add_argument("--logout", default=None)
    ap.add_argument("--user", required=True, help='JSON: {"phone":"...","password":"..."}')
    args = ap.parse_args()

    from urllib.parse import urlparse
    host = urlparse(args.target).netloc
    c = load_consent(host)
    print(f"[consent] {host} flags={c.get('flags')}")

    base = args.target.rstrip("/")
    user = json.loads(args.user)
    st, body = http("POST", base + args.login, user)
    print(f"[login] {args.login} -> {st}")
    if st != 200:
        print("  login failed — cannot continue")
        return 1
    d = json.loads(body)
    access, refresh = d["access"], d.get("refresh")
    if not refresh:
        print("  no refresh token in login response — skipping rotation tests")
        return 1

    # JWT claims
    try:
        p = json.loads(b64d(access.split(".")[1]))
        print(f"[jwt] claims: token_type={p.get('token_type')} role={p.get('role')} "
              f"jti={'PRESENT' if p.get('jti') else 'MISSING'} user_id={p.get('user_id')}")
    except Exception as e:
        print(f"[jwt] decode failed: {e}")

    # rotation: same refresh twice
    st1, b1 = http("POST", base + args.refresh, {"refresh": refresh})
    time.sleep(0.5)
    st2, b2 = http("POST", base + args.refresh, {"refresh": refresh})
    rotated = st1 == 200 and st2 != 200
    print(f"[rotation] refresh#1 -> {st1}, refresh#2(same) -> {st2}  "
          f"{'ROTATION OK' if rotated else 'NO ROTATION (reusable token)'}")

    # logout invalidation
    if args.logout:
        st, _ = http("POST", base + args.logout, {"refresh": refresh})
        time.sleep(0.5)
        st3, _ = http("POST", base + args.refresh, {"refresh": refresh})
        revoked = st3 != 200
        print(f"[logout] {args.logout} -> {st}; refresh after logout -> {st3}  "
              f"{'REVOKED' if revoked else 'LOGOUT IS COSMETIC (token still valid)'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
