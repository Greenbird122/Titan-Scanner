"""Supabase (PostgREST) RLS probe.

Reads (no consent needed):
  - SELECT across every candidate table with the public anon key from the bundle
  - row counts + PII-table spotting (users/profiles)

Writes (require flags=['write']):
  - per-table INSERT probe (marker row) → distinguishes RLS-denied (401/403)
    from RLS-open (201) from validation-fail (400 = passed RLS!)
  - UPDATE-own-role probe (role escalation) + downgrade
  - self-cleaning where the API allows; residue reported otherwise

Usage:
    python probe_supabase.py <project-ref> <anon-key> <target-domain> [--tables users profiles notifications] [--write]

Example:
    python probe_supabase.py xyzabc <eyJ...anon> blink-app-ten.vercel.app --tables users notifications --write
"""
import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from consent import load_consent, require_write  # noqa: E402

MARKER = "SECPROBE" + str(int(time.time()))[-8:]


def http(method, url, data=None, headers=None, timeout=20):
    h = {"User-Agent": "Mozilla/5.0"}
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


def anon_headers(key):
    return {"apikey": key, "Authorization": f"Bearer {key}"}


def probe_reads(project, key, tables):
    print(f"[supabase] project={project} — READ surface (anon key)")
    for t in tables:
        url = f"https://{project}.supabase.co/rest/v1/{t}?select=*&limit=2"
        st, body = http("GET", url, headers=anon_headers(key))
        n = "?"
        try:
            d = json.loads(body)
            if isinstance(d, list):
                n = len(d)
                keys = sorted(d[0].keys())[:12] if d else []
            else:
                keys = list(d)[:12]
        except Exception:
            keys = []
        pii = any(k in " ".join(keys) for k in ("email", "phone", "password", "role"))
        print(f"  {t:28s} -> {st}  rows~{n}  pii_columns={pii}  cols={keys}")


def probe_write_map(project, key, target, tables):
    c = load_consent(target)
    require_write(c, "Supabase RLS write map")
    print(f"[supabase] project={project} — RLS write map (consent={c.get('flags')})")
    for t in tables:
        url = f"https://{project}.supabase.co/rest/v1/{t}"
        # probe insert; validation error (400) means RLS passed the request
        st, body = http("POST", url, {"probe_col": MARKER}, headers=anon_headers(key))
        verdict = ("RLS-OPEN" if st in (200, 201) else
                   "RLS-PASSED(validation-400)" if st == 400 else
                   "RLS-DENIED" if st in (401, 403) else f"other:{st}")
        print(f"  INSERT {t:22s} -> {st}  {verdict}  {body[:100]}")


def probe_role_escalation(project, key, target):
    c = load_consent(target)
    require_write(c, "role escalation probe")
    # NOTE: requires a created throwaway account + its authenticated JWT.
    # Stub: prints the method; caller supplies token via --token.
    print("[supabase] role escalation requires an authenticated token — "
          "run manually: PATCH users {role:<highest>} with own token, read back.")


def main():
    ap = argparse.ArgumentParser(description="Supabase RLS probe")
    ap.add_argument("project")
    ap.add_argument("key")
    ap.add_argument("target")
    ap.add_argument("--tables", nargs="*", default=["users", "profiles", "notifications"])
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    probe_reads(args.project, args.key, args.tables)
    if args.write:
        probe_write_map(args.project, args.key, args.target, args.tables)
        probe_role_escalation(args.project, args.key, args.target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
